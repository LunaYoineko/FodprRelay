## server.nim
## Fodpr のリレーサーバー（WebSocket サーバー）を実装するモジュール。
##
## Fodpr ライブラリ (protocol.nim / crypto.nim) を依存パッケージとして利用する。
## ワイヤプロトコルは Fodpr 側で定義されており、本モジュールはサーバー
## としての保存・配信のみを担当する。
##
## クライアントからのイベント投稿（EVENT）を受け取り、
## 署名検証を行ってから保存する。また購読要求（REQ）に対しては、
## 条件に一致する保存済みイベントを PUSH 形式で返信する。
## さらに削除要求（DEL）を受け取り、送信者本人のイベントを
## LMDB から削除する。
##
## LMDB への保存値はすべて AES-256-GCM で暗号化する（平文保存はしない）。
## 暗号化キーは環境変数 FODPR_DB_KEY(64桁hex) があればそれを使い、
## なければ起動時にランダム生成して data/db.key に保存する。
##
## 起動方法:  nimble build   → ./src/server
##
## Ctrl+C (SIGINT) を押すと、リスニングソケットを閉じて
## 安全にサーバーを終了する。

import std/atomics
import std/json
import asynchttpserver, asyncdispatch, streams, strutils, endians, os, times, random
import ws_limited
import lmdb
import nimcrypto
import nimSHA2
import Fodpr

# イベント削除 (DEL) の定義は Fodpr ライブラリ (protocol.nim) に含まれる。
# 既存の 0x01 (EVENT) / 0x02 (REQ) / 0x81 (PUSH) には影響を与えない追加プロトコル。

# LMDB の環境とデータベースハンドル。
# サーバーは content の意味 (プロフィール管理など) を一切解釈せず、
# 送信方法 (transType) ごとのストレージに暗号化して追記保存するだけである。
var dbenv: LMDBEnv
var dbiJson: Dbi      # TransTypeJSON   用 (キー: 現在時刻+乱数 = 追記)
var dbiString: Dbi    # TransTypeString 用 (キー: 現在時刻+乱数 = 追記)
var dbiBinary: Dbi    # TransTypeBinary 用 (キー: 現在時刻+乱数 = 追記)
var dbiSigned: Dbi    # TransTypeSigned 用 (全体署名イベント)
var dbiEncrypted: Dbi # TransTypeEncrypted 用 (宛先別暗号化エンベロープ)

# LMDB 保存値の暗号化設定。
# 保存形式: バージョン(1バイト) | nonce(12バイト) | 暗号文 | 認証タグ(16バイト)
# バージョンは暗号化済みレコードの識別と、将来の方式変更用。
const
  EncVersionByte = char(0x01)   # 暗号化済みレコードの先頭バイト
  EncNonceLen = 12              # GCM nonce の長さ
  EncTagLen = 16                # GCM 認証タグの長さ
  EncHeaderLen = 1 + EncNonceLen
  DbKeyLen = 32                 # AES-256 用キー長(バイト)
  DefaultDbMapSize = uint(256 * 1024 * 1024)  # LMDB マップサイズのデフォルト (256MB, 1GBメモリ環境向け)
  MaxPacketBytes = 16 * 1024 * 1024           # 受信パケットの上限(ws 側の上限と同じ。OOM 対策)

# 暗号化キー (32 バイト)。起動時に環境変数 / ファイルから読み込む。
var dbKey: seq[byte]

# リアルタイム配信用の購読登録。REQ を受けたクライアントはここに記録され、
# 以後に保存されたイベントが PUSH パケットとして即時配信される。
# (asyncdispatch のシングルスレッドイベントループ上でのみ操作される)
type Subscription = object
  subId: string
  ws: WebSocket
  req: FodprReq
var subscriptions: seq[Subscription]

# 特定の WebSocket の購読登録を解除する(切断時)
proc removeSubs(ws: WebSocket) {.gcsafe.} =
  {.gcsafe.}:
    var i = 0
    while i < subscriptions.len:
      if subscriptions[i].ws == ws:
        subscriptions.delete(i)
      else:
        inc i

# ---------------------------------------------------------------------------
# 読取認証 (AUTH, NIP-42 相当) の状態管理
# ---------------------------------------------------------------------------
# 宛先限定イベント (tags に "to:<fpub>" を持つ) は、宛先本人として認証された
# 購読にのみ配信する (メールボックスモデル)。認証フロー:
#   1. クライアントが tagKey="to" の REQ を送る
#   2. サーバーは未認証ならチャレンジ nonce を送る (MsgTypeChallenge)
#   3. クライアントは nonce に署名して AUTH を送る (MsgTypeAuth)
#   4. サーバーは署名を検証し、接続を認証済みとして REQ を再開する
type
  AuthedConn* = object
    ws*: WebSocket
    pubkeyFpub*: string   # 小文字化した fpub1... (to: タグとの比較用)

  PendingAuth* = object
    ws*: WebSocket
    nonce*: array[32, byte]
    createdAt*: float     # epochTime (チャレンジ TTL 判定用)
    pendingReq*: FodprReq # 認証後に再開する REQ (未設定なら subId が空)

var authedKeys: seq[AuthedConn]
var pendingAuths: seq[PendingAuth]

# 認証情報とチャレンジ情報を WebSocket ごとに削除する (切断時)
proc removeAuth(ws: WebSocket) {.gcsafe.} =
  {.gcsafe.}:
    var i = 0
    while i < authedKeys.len:
      if authedKeys[i].ws == ws:
        authedKeys.delete(i)
      else:
        inc i
    i = 0
    while i < pendingAuths.len:
      if pendingAuths[i].ws == ws:
        pendingAuths.delete(i)
      else:
        inc i

# 接続が指定の fpub として認証済みか判定する。
proc isAuthedAs(ws: WebSocket, fpubLower: string): bool =
  {.gcsafe.}:
    for a in authedKeys:
      if a.ws == ws and a.pubkeyFpub == fpubLower:
        return true
  return false

# イベントのタグから宛先リスト (to:<fpub>) を取り出す (小文字化して返す)。
proc toRecipients(ev: FodprEvent): seq[string] =
  for t in ev.tags:
    if t.len > 3 and t[0..2] == "to:":
      result.add(t[3..^1].toLowerAscii())

# REQ のタグ条件 (tagKey/tagVal) にイベントが一致するか判定する。
#   tagKey="pubkey" : 送信者の公開鍵 (33バイト圧縮のバイト列) と比較
#   tagKey="to"     : イベントの to:<fpub> タグに宛先が含まれるか比較
#   tagKey=""       : 条件なし (全イベント一致)
proc eventMatchesReq(evt: FodprEvent, req: FodprReq): bool =
  if req.tagKey == "pubkey" and req.tagVal != "":
    if $evt.pubkey.toRawCompressed() != req.tagVal:
      return false
  elif req.tagKey == "to" and req.tagVal != "":
    if req.tagVal.toLowerAscii() notin toRecipients(evt):
      return false
  return true

# イベントがこの購読者 (接続 + REQ) から読めるか判定する。
# プライバシールール: `to:<fpub>` タグ付きイベントは、宛先本人として認証された
# 購読にのみ配信する。公開イベント (to: タグなし) は通常のタグ条件で照合する。
proc eventVisibleTo(evt: FodprEvent, req: FodprReq, ws: WebSocket): bool =
  let recipients = toRecipients(evt)
  if recipients.len > 0:
    # 宛先限定イベント: 購読者の認証鍵が宛先に含まれている必要がある
    if req.tagKey != "to" or req.tagVal == "":
      return false
    if req.tagVal.toLowerAscii() notin recipients:
      return false
    return isAuthedAs(ws, req.tagVal.toLowerAscii())
  return eventMatchesReq(evt, req)

# 保存されたイベントを、購読条件(transType / pubkey)に一致するクライアントへ
# リアルタイム配信する。購読中クライアントの subId を使った PUSH パケットを作る。
proc broadcastEvent(event: FodprEvent) {.async, gcsafe.} =
  # 一致する購読を先に集める(送信中に購読一覧が変わっても影響しないようにコピーする)
  var targets: seq[tuple[subId: string, ws: WebSocket]]
  {.gcsafe.}:
    for sub in subscriptions:
      if sub.ws.readyState != Open:
        continue
      if sub.req.transType != TransTypeAll and sub.req.transType != event.transType:
        continue
      # タグ条件 + プライバシー (to: 宛先限定イベントは認証済み宛先のみ)
      if not eventVisibleTo(event, sub.req, sub.ws):
        continue
      targets.add((sub.subId, sub.ws))

  for (subId, ws) in targets:
    # PUSH パケット: [MsgTypePush(1)] [SubIdLen(2)] [SubId] [encodedEvent]
    var pushData = ""
    pushData.add(MsgTypePush)
    let subIdLen = uint16(subId.len)
    var siNet: uint16
    bigEndian16(addr siNet, unsafeAddr subIdLen)
    var siBytes: array[2, byte]
    copyMem(addr siBytes[0], addr siNet, 2)
    pushData.add(char(siBytes[0]))
    pushData.add(char(siBytes[1]))
    pushData.add(subId)
    pushData.add(encodeEvent(event))
    try:
      await ws.send(pushData, Binary)
    except:
      discard  # 送信失敗は次回の掃除で除去する

  # 閉じた接続の購読登録を掃除する
  {.gcsafe.}:
    var i = 0
    while i < subscriptions.len:
      if subscriptions[i].ws.readyState != Open:
        subscriptions.delete(i)
      else:
        inc i

# Ctrl+C (SIGINT) を受けたことを記録するフラグ。
# シグナルハンドラは「シグナル割り込みの中」で実行されるため、
# ヒープ確保や echo などの操作は禁止されている。
# そのためアトミック変数への書き込みのみを行う。
var stopFlag: Atomic[bool]

# Ctrl+C を受けたときに OS から呼び出されるハンドラ。
# 安全のため、フラグを立てるだけで他の処理は行わない。
proc ctrlcHandler() {.noconv.} =
  stopFlag.store(true)

# 暗号化キー (32 バイト) を読み込む。
# 優先順位: 環境変数 FODPR_DB_KEY(64桁hex) > data/db.key ファイル > 新規生成して保存。
proc loadOrCreateDbKey(): seq[byte] =
  # 環境変数 FODPR_DB_KEY が最優先
  let envKey = getEnv("FODPR_DB_KEY", "").strip()
  if envKey.len == DbKeyLen * 2:
    result = newSeq[byte](DbKeyLen)
    for i in 0..<DbKeyLen:
      result[i] = byte(parseHexInt(envKey[i*2 ..< i*2+2]))
    echo "[DB] 暗号化キーを環境変数 FODPR_DB_KEY から読み込みました"
    return

  # 次に data/db.key ファイル
  let keyFile = "data" / "db.key"
  if fileExists(keyFile):
    let content = readFile(keyFile).strip()
    if content.len != DbKeyLen * 2:
      raise newException(IOError, "暗号化キーファイルが不正です: " & keyFile)
    result = newSeq[byte](DbKeyLen)
    for i in 0..<DbKeyLen:
      result[i] = byte(parseHexInt(content[i*2 ..< i*2+2]))
    echo "[DB] 暗号化キーを ", keyFile, " から読み込みました"
    return

  # どちらも無ければランダム生成してファイルに保存する
  result = newSeq[byte](DbKeyLen)
  discard randomBytes(result)
  var hexStr = ""
  for b in result: hexStr.add(b.toHex(2))
  writeFile(keyFile, hexStr)
  setFilePermissions(keyFile, {fpUserRead, fpUserWrite})
  echo "[警告] 暗号化キーが未設定のため、新規生成して ", keyFile, " に保存しました"
  echo "[警告] このファイルを失うと保存済みデータを復号できなくなります(必ずバックアップしてください)"

# 平文データを AES-256-GCM で暗号化する。
# 保存形式: バージョン(1) | nonce(12) | 暗号文 | 認証タグ(16)
# dbKey は起動時(initDatabase)に一度だけ設定され、以後は読み取り専用で使われるため
# 既存コードと同じく {.gcsafe.} ブロックで囲んで参照する。
proc encryptValue(data: string): string =
  if data.len == 0:
    return ""
  {.gcsafe.}:
    var keyArr: array[DbKeyLen, byte]
    copyMem(addr keyArr[0], addr dbKey[0], DbKeyLen)
    var nonce: array[EncNonceLen, byte]
    discard randomBytes(nonce)
    var noAad: array[0, byte]
    var ctx: GCM[rijndael256]
    ctx.init(keyArr, nonce, noAad)
    var input = newSeq[byte](data.len)
    if data.len > 0:
      copyMem(addr input[0], unsafeAddr data[0], data.len)
    var ct = newSeq[byte](data.len)
    var tag: array[EncTagLen, byte]
    ctx.encrypt(input, ct, tag)
    result = newString(EncHeaderLen + data.len + EncTagLen)
    result[0] = EncVersionByte
    copyMem(addr result[1], addr nonce[0], EncNonceLen)
    copyMem(addr result[EncHeaderLen], addr ct[0], data.len)
    copyMem(addr result[EncHeaderLen + data.len], addr tag[0], EncTagLen)

# encryptValue の逆変換。認証失敗(キー不一致・改ざんなど)は ValueError を投げる。
proc decryptValue(blob: string): string =
  if blob.len < EncHeaderLen + EncTagLen or blob[0] != EncVersionByte:
    raise newException(ValueError, "暗号化されていない、または不正なデータ")
  {.gcsafe.}:
    var keyArr: array[DbKeyLen, byte]
    copyMem(addr keyArr[0], addr dbKey[0], DbKeyLen)
    var nonce: array[EncNonceLen, byte]
    copyMem(addr nonce[0], unsafeAddr blob[1], EncNonceLen)
    let ctLen = blob.len - EncHeaderLen - EncTagLen
    var noAad: array[0, byte]
    var ctx: GCM[rijndael256]
    ctx.init(keyArr, nonce, noAad)
    var ct = newSeq[byte](ctLen)
    if ctLen > 0:
      copyMem(addr ct[0], unsafeAddr blob[EncHeaderLen], ctLen)
    var tag: array[EncTagLen, byte]
    copyMem(addr tag[0], unsafeAddr blob[EncHeaderLen + ctLen], EncTagLen)
    var outData = newSeq[byte](ctLen)
    if ctLen > 0 and not ctx.decrypt(ct, outData, tag):
      raise newException(ValueError, "復号の認証に失敗しました(キー不一致?)")
    result = newString(ctLen)
    if ctLen > 0:
      copyMem(addr result[0], addr outData[0], ctLen)

# 旧バージョンで平文のまま保存されたレコードを検出し、
# 現在の暗号化キーで暗号化し直す(起動時に一度だけ実行)。
proc migrateLegacyData() =
  let txn = dbenv.newTxn()
  var migrated = 0
  for dbi in [dbiJson, dbiString, dbiBinary, dbiSigned, dbiEncrypted]:
    # 1) カーソルで平文レコードを集める(カーソル反復中の書換えを避ける)
    var plainRecords: seq[tuple[key: string, value: string]]
    let cursor = txn.cursorOpen(dbi)
    var kVal, dVal: Val
    while cursorGet(cursor, addr kVal, addr dVal, NEXT) == 0:
      var keyStr = newString(int(kVal.mvSize))
      if kVal.mvSize > 0:
        copyMem(addr keyStr[0], kVal.mvData, int(kVal.mvSize))
      var blob = newString(int(dVal.mvSize))
      if dVal.mvSize > 0:
        copyMem(addr blob[0], dVal.mvData, int(dVal.mvSize))
      if blob.len > 0 and blob[0] == EncVersionByte:
        # 暗号化済みの形式。現在のキーで復号できるかだけ確認する。
        try:
          discard decryptValue(blob)
        except Exception:
          echo "[DB] 復号できないレコードを検出しました(キーが異なる可能性): ", keyStr
        continue
      # 平文レコード
      plainRecords.add((keyStr, blob))
    cursor.cursorClose()
    # 2) カーソルを閉じた後に暗号化して同じキーで書き戻す
    for (key, value) in plainRecords:
      txn.put(dbi, key, encryptValue(value))
      inc migrated
  txn.commit()
  if migrated > 0:
    echo "[DB] 平文データ ", migrated, " 件を暗号化に変換しました"

# LMDB の初期化処理
proc initDatabase() =
  # データ保存ディレクトリの作成
  if not dirExists("data"):
      createDir("data")

  # 暗号化キーの読み込み(環境変数 > data/db.key > 新規生成)
  dbKey = loadOrCreateDbKey()
  
  # 環境の作成とオープン(複数のDBIを使うためmaxdbsを指定)。
  # デフォルトのマップサイズ(1MB)はすぐに上限に達して MDB_BAD_TXN 等で
  # 書き込みが失敗するため、大きめのサイズを設定する。
  # 値は環境変数 FODPR_DB_MAPSIZE(バイト) で上書きできる。
  # (メモリ1GBの小規模環境向けに、既定値は 256MB に抑えている)
  var newEnv: LMDBEnv
  let mapSizeEnv = getEnv("FODPR_DB_MAPSIZE", "").strip()
  let mapSize: uint =
    if mapSizeEnv.len > 0: uint(parseBiggestInt(mapSizeEnv))
    else: DefaultDbMapSize
  if envCreate(addr newEnv) != 0:
    raise newException(Exception, "LMDB 環境の作成に失敗しました")
  newEnv.setMaxDBs(5)
  if envSetMapsize(newEnv, mapSize) != 0:
    raise newException(Exception, "LMDB マップサイズの設定に失敗しました")
  if envOpen(newEnv, "data".cstring, 0.cuint, 0o0664) != 0:
    raise newException(Exception, "LMDB 環境のオープンに失敗しました")
  dbenv = newEnv
  
  # トランザクションを開始して送信タイプごとのDBIを開く
  let txn = dbenv.newTxn()
  dbiJson = txn.dbiOpen("json", CREATE)
  dbiString = txn.dbiOpen("string", CREATE)
  dbiBinary = txn.dbiOpen("binary", CREATE)
  dbiSigned = txn.dbiOpen("signed", CREATE)
  dbiEncrypted = txn.dbiOpen("encrypted", CREATE)
  txn.commit()

  # 旧バージョンの平文データを暗号化に変換する
  migrateLegacyData()
  
  echo "[DB] LMDB ストレージの初期化が完了しました(./data, AES-256-GCM 暗号化保存)"

# 指定 DBI の保存イベントを走査し、購読条件に一致するものを PUSH パケット
# (バイナリフレーム) としてクライアントへ送信する。
# サーバーは content の意味を解釈せず、送信方法 (transType) による DBI の選択と
# タグ条件 (pubkey など) による絞り込みのみを行う。
proc pushEventsFromDbi(txn: LMDBTxn, dbi: Dbi, subReq: FodprReq, ws: WebSocket) {.async, gcsafe.} =
    let cursor = txn.cursorOpen(dbi)
    var kVal, dVal: Val

    # カーソルで全イベントを走査
    while cursorGet(cursor, addr kVal, addr dVal, NEXT) == 0:
        # 保存値は暗号化されているため、まず復号する
        var blob = newString(int(dVal.mvSize))
        if dVal.mvSize > 0:
            copyMem(addr blob[0], dVal.mvData, int(dVal.mvSize))
        var encoded = ""
        try:
            encoded = decryptValue(blob)
        except Exception:
            continue  # 復号できないレコードは読み飛ばす
        if encoded.len == 0:
            continue

        # タグ条件 + プライバシー (to: 宛先限定) による絞り込み
        let evt = decodeEvent(newStringStream(encoded))
        if not eventVisibleTo(evt, subReq, ws):
            continue

        # PUSH パケット作成・送信
        var pushData = ""
        pushData.add(MsgTypePush)
        let subIdLen = uint16(subReq.subId.len)
        var siNet: uint16
        bigEndian16(addr siNet, unsafeAddr subIdLen)
        var siBytes: array[2, byte]
        copyMem(addr siBytes[0], addr siNet, 2)
        pushData.add(char(siBytes[0]))
        pushData.add(char(siBytes[1]))
        pushData.add(subReq.subId)
        pushData.add(encoded)
        await ws.send(pushData, Binary)

    cursor.cursorClose()

# ---------------------------------------------------------------------------
# DEL (イベント削除) プロトコル
# ---------------------------------------------------------------------------
# パケット形式 (クライアント → サーバー):
#   msgType(1) | transType(2) | targetType(1) | pubkey(33) |
#   [createdAt(8) | contentHash(32)]  ← DelTargetEvent の場合
#   [eventId(32)]                     ← DelTargetEventId の場合
#   | signature(64)
#
# 署名対象 (transType 以降、signature を除いたバイト列):
#   transType(2) | targetType(1) | pubkey(33) | 識別子部分
# 署名は送信者本人の秘密鍵で行い、サーバーは要求内の pubkey で検証する。
# これにより「自分の投稿だけを自分が消せる」ことを保証する。
#
# targetType による削除対象の違い:
#   DelTargetPubkey(0)  : その pubkey のイベントを transType 単位で全削除
#   DelTargetEvent(1)   : createdAt と contentHash が一致する特定イベントを削除
#   DelTargetEventId(2) : eventId が一致する特定イベントを削除

# パケット(種別バイト以降)から削除要求を復元する処理と、署名対象バイト列の
# 生成は Fodpr ライブラリ (protocol.nim の decodeDelReq / encodeDelSignedData) が
# 提供している。サーバー側はその型・関数を使って削除処理のみを実装する。

# 指定 DBI から削除条件に一致するイベントを削除し、削除件数を返す。
# 削除条件: イベントの公開鍵が要求の公開鍵と一致し、
#           DelTargetEvent の場合は createdAt / contentHash も一致する。
proc deleteEventsFromDbi(txn: LMDBTxn, dbi: Dbi, delReq: FodprDelReq, targetPubkey: string): int =
    let cursor = txn.cursorOpen(dbi)
    var kVal, dVal: Val

    # カーソルで全イベントを走査し、一致したレコードを削除する
    while cursorGet(cursor, addr kVal, addr dVal, NEXT) == 0:
        # 暗号化された保存値を復号する
        var blob = newString(int(dVal.mvSize))
        if dVal.mvSize > 0:
            copyMem(addr blob[0], dVal.mvData, int(dVal.mvSize))
        var encoded = ""
        try:
            encoded = decryptValue(blob)
        except Exception:
            continue  # 復号できないレコードは削除対象外
        if encoded.len == 0:
            continue

        var evt = decodeEvent(newStringStream(encoded))
        if $evt.pubkey.toRawCompressed() != targetPubkey:
            continue
        if delReq.targetType == DelTargetEvent:
            if evt.createdAt != delReq.createdAt:
                continue
            if computeSHA256(evt.content) != delReq.contentHash:
                continue
        elif delReq.targetType == DelTargetEventId:
            # eventId (署名対象バイト列の SHA-256) で照合する
            if eventId(evt) != delReq.eventId:
                continue

        # 削除するキーをコピーしてからカーソル位置のレコードを削除する
        # (mdb_cursor_del 後は MDB_NEXT で次のレコードに進める)
        var keyStr = newString(int(kVal.mvSize))
        if kVal.mvSize > 0:
            copyMem(addr keyStr[0], kVal.mvData, int(kVal.mvSize))
        discard cursorDel(cursor, 0)
        inc result

    cursor.cursorClose()

# 削除要求を実行し、削除したイベント総数を返す。
# 走査中に復号エラーなどが起きた場合はトランザクションを中止して例外を再送する
# (未コミットの書込みトランザクションが残ると後続の保存・削除が全て詰まるため)。
proc deleteEvents(delReq: FodprDelReq): int =
    {.gcsafe.}:
        let txn = dbenv.newTxn()
        try:
            let targetPubkey = $delReq.pubkey.toRawCompressed()
            case delReq.transType
            of TransTypeJSON:
                result += deleteEventsFromDbi(txn, dbiJson, delReq, targetPubkey)
            of TransTypeString:
                result += deleteEventsFromDbi(txn, dbiString, delReq, targetPubkey)
            of TransTypeBinary:
                result += deleteEventsFromDbi(txn, dbiBinary, delReq, targetPubkey)
            of TransTypeSigned:
                result += deleteEventsFromDbi(txn, dbiSigned, delReq, targetPubkey)
            of TransTypeEncrypted:
                result += deleteEventsFromDbi(txn, dbiEncrypted, delReq, targetPubkey)
            of TransTypeAll:
                result += deleteEventsFromDbi(txn, dbiJson, delReq, targetPubkey)
                result += deleteEventsFromDbi(txn, dbiString, delReq, targetPubkey)
                result += deleteEventsFromDbi(txn, dbiBinary, delReq, targetPubkey)
                result += deleteEventsFromDbi(txn, dbiSigned, delReq, targetPubkey)
                result += deleteEventsFromDbi(txn, dbiEncrypted, delReq, targetPubkey)
            else:
                discard  # 未定義の transType はハンドラ側で拒否済み
            txn.commit()
        except:
            txn.abort()
            raise

# 購読要求 (REQ) の処理本体。保存済みイベントの配信とリアルタイム購読の登録を行う。
# 認証フロー (チャレンジ → AUTH) の完了後に呼ばれることもある。
proc handleReq(ws: WebSocket, subReq: FodprReq) {.async, gcsafe.} =
    # タグ条件の検証 (未知の tagKey は拒否する)
    if subReq.tagKey != "" and subReq.tagKey != "pubkey" and subReq.tagKey != "to":
        await ws.send("ERR: Unknown tag key")
        return
    if subReq.tagKey == "to" and subReq.tagVal == "":
        await ws.send("ERR: Missing tag value")
        return

    echo "[購読] サブスクリプション要求受領 [ID: ", subReq.subId, "] (TransType: ", transTypeName(subReq.transType), " tagKey: ", subReq.tagKey, ")"

    # 保存済みイベントから transType に一致するものを PUSH 配信する
    {.gcsafe.}:
        let txn = dbenv.newTxn()

        case subReq.transType
        of TransTypeJSON:
            await pushEventsFromDbi(txn, dbiJson, subReq, ws)
        of TransTypeString:
            await pushEventsFromDbi(txn, dbiString, subReq, ws)
        of TransTypeBinary:
            await pushEventsFromDbi(txn, dbiBinary, subReq, ws)
        of TransTypeSigned:
            await pushEventsFromDbi(txn, dbiSigned, subReq, ws)
        of TransTypeEncrypted:
            await pushEventsFromDbi(txn, dbiEncrypted, subReq, ws)
        else:
            # TransTypeAll: すべてのタイプを順番に配信する
            await pushEventsFromDbi(txn, dbiJson, subReq, ws)
            await pushEventsFromDbi(txn, dbiString, subReq, ws)
            await pushEventsFromDbi(txn, dbiBinary, subReq, ws)
            await pushEventsFromDbi(txn, dbiSigned, subReq, ws)
            await pushEventsFromDbi(txn, dbiEncrypted, subReq, ws)
        txn.commit()

    # 保存済みイベントの配信が終わったことを通知
    await ws.send("EOE: End of stored events for " & subReq.subId)

    # 購読登録: 以後に保存されるイベントをリアルタイム配信する
    {.gcsafe.}:
        var i = 0
        while i < subscriptions.len:
            if subscriptions[i].ws == ws and subscriptions[i].subId == subReq.subId:
                subscriptions.delete(i)
            else:
                inc i
        subscriptions.add(Subscription(subId: subReq.subId, ws: ws, req: subReq))

# 各 HTTP リクエストを処理するコールバック。
# URL が "/" (ルートパス) で WebSocket アップグレードヘッダがあるときだけ
# WebSocket として扱い、それ以外は 404 を返す。
proc cb(req: Request) {.async, gcsafe.} =
    let isWebSocket = (req.url.path == "/") and req.headers.hasKey("upgrade") and req.headers.getOrDefault("upgrade").toLowerAscii() == "websocket"

    if isWebSocket:
        var ws: WebSocket = nil  # except 節でも購読解除に使うため try の外で宣言する
        try:
            # HTTP リクエストを WebSocket 接続にアップグレード
            ws = await newWebSocket(req)
            echo "[接続] クライアントが接続しました"

            # 接続が開いている限りパケットを受信し続ける
            while ws.readyState == Open:
                # バイナリフレームで受信する。テキストフレームは UTF-8 エンコードのため、
                # 公開鍵や署名などの任意バイト列(0x80以上)をそのまま運べない。
                let packetBytes = await ws.receiveBinaryPacket()
                var packet = newString(packetBytes.len)
                if packetBytes.len > 0:
                    copyMem(addr packet[0], unsafeAddr packetBytes[0], packetBytes.len)
                if packet.len == 0:
                    continue  # 空パケットは無視

                # メモリ1GB環境のOOM対策: 上限を超えるパケットは破棄して切断する。
                # (ws 側でもフレーム受信時に上限チェック済み。ここは二重の防御)
                if packet.len > MaxPacketBytes:
                    echo "[拒否] サイズ上限を超えるパケットを受信しました(サイズ: ", packet.len, " bytes)"
                    await ws.send("ERR: Packet too large")
                    ws.hangup()
                    continue

                echo "[受信] バイナリパケット受信(サイズ: ", packet.len, " bytes)"

                # パケットをストリームとして開き、先頭 1 バイトで種別を判別
                var strm = newStringStream(packet)
                let msgType = strm.readChar()

                # --- イベント投稿 (EVENT) の処理 ---
                if msgType == MsgTypeEvent:
                    try:
                        # バイナリデータからイベントを復元
                        let event = decodeEvent(strm)

                        # 署名を検証する。偽装・改ざんされたイベントは拒否する。
                        #  - TransTypeSigned / TransTypeEncrypted (全体署名):
                        #    createdAt / pubkey / tags を含む全フィールドに対して検証する
                        #  - 既存タイプ (1〜3): 後方互換のため content のみ署名を検証する
                        let isFullSig = event.transType == TransTypeSigned or
                                        event.transType == TransTypeEncrypted
                        let sigValid =
                            if isFullSig:
                                verifyEvent(event.pubkey, event, event.signature)
                            else:
                                verifyContent(event.pubkey, event.content, event.signature)
                        if not sigValid:
                            echo "[拒否] 不正な署名のイベントを検知しました"
                            await ws.send("ERR: Invalid signature")
                            continue

                        # 未定義の送信タイプは拒否する
                        if event.transType != TransTypeJSON and
                           event.transType != TransTypeString and
                           event.transType != TransTypeBinary and
                           event.transType != TransTypeSigned and
                           event.transType != TransTypeEncrypted:
                            echo "[拒否] 未定義の送信タイプです: ", event.transType
                            await ws.send("ERR: Unknown trans type")
                            continue

                        # TransTypeEncrypted: エンベロープ構造と to: タグの一致を検証する
                        # (内容は復号しない。to: タグがエンベロープ内の受信者と対応して
                        #  いることを確認し、「読めない人への配送」を防ぐ)
                        if event.transType == TransTypeEncrypted:
                            if not isValidEnvelope(event.content):
                                echo "[拒否] 不正な暗号化エンベロープです"
                                await ws.send("ERR: Invalid envelope")
                                continue
                            var encRecips: seq[string]
                            try:
                                for pub in envelopeRecipients(event.content):
                                    encRecips.add($pub.toRawCompressed())
                            except EnvelopeError:
                                echo "[拒否] エンベロープの受信者を抽出できません"
                                await ws.send("ERR: Invalid envelope")
                                continue
                            # to:<fpub> タグがエンベロープ内の受信者と一致することを確認
                            var toCount = 0
                            var toValid = true
                            for t in event.tags:
                                if t.len > 3 and t[0..2] == "to:":
                                    inc toCount
                                    try:
                                        let toPub = fpubDecode(t[3..^1])
                                        if $toPub.toRawCompressed() notin encRecips:
                                            toValid = false
                                            echo "[拒否] to: タグがエンベロープの受信者と一致しません"
                                            await ws.send("ERR: to: tag not in envelope recipients")
                                            break
                                    except:
                                        toValid = false
                                        echo "[拒否] to: タグの fpub が不正です"
                                        await ws.send("ERR: Invalid to: tag")
                                        break
                            if not toValid:
                                continue
                            if toCount == 0:
                                echo "[拒否] 暗号化イベントには to: タグが必須です"
                                await ws.send("ERR: Encrypted event requires to: tag")
                                continue

                        # JSON タイプは content が正しい JSON であることを検証する
                        if event.transType == TransTypeJSON:
                            try:
                                discard parseJson(event.content)
                            except:
                                echo "[拒否] JSON として不正な content を検知しました"
                                await ws.send("ERR: Invalid JSON content")
                                continue

                        # 検証に成功したイベントを保存
                        # (サーバーは content の意味を解釈しない。送信方法
                        #  (transType) ごとのストレージに一意なキーで追記保存する)
                        {.gcsafe.}:
                            let txn = dbenv.newTxn()

                            # 平文のまま保存せず、AES-256-GCM で暗号化して保存する
                            let encoded = encodeEvent(event)
                            let encrypted = encryptValue(encoded)

                            # 一意なキー(現在時刻+乱数)で追記保存
                            let timeKey = "evt_" & $epochTime() & "_" & $event.transType & "_" & $rand(100000)
                            case event.transType
                            of TransTypeJSON:
                                txn.put(dbiJson, timeKey, encrypted)
                            of TransTypeString:
                                txn.put(dbiString, timeKey, encrypted)
                            of TransTypeSigned:
                                txn.put(dbiSigned, timeKey, encrypted)
                            of TransTypeEncrypted:
                                txn.put(dbiEncrypted, timeKey, encrypted)
                            else:
                                txn.put(dbiBinary, timeKey, encrypted)
                            echo "[保存] イベントを保存しました(TransType: ", transTypeName(event.transType), ")"
                            txn.commit()

                        # 保存したイベントを購読中のクライアントへリアルタイム配信する
                        await broadcastEvent(event)

                        await ws.send("OK: Event accepted")
                    except Exception as e:
                        echo "[エラー] イベントパース失敗: ", e.msg
                        await ws.send("ERR: Invalid event")

                # --- 購読要求 (REQ) の処理 ---
                elif msgType == MsgTypeReq:
                    try:
                        let subReq = decodeReq(strm)

                        # 宛先限定 (tagKey="to") の購読は認証が必要。
                        # 未認証ならチャレンジを発行し、REQ は認証後に再開する。
                        if subReq.tagKey == "to" and subReq.tagVal != "":
                            if not isAuthedAs(ws, subReq.tagVal.toLowerAscii()):
                                var nonce: array[32, byte]
                                discard randomBytes(nonce)
                                {.gcsafe.}:
                                    var i = 0
                                    while i < pendingAuths.len:
                                        if pendingAuths[i].ws == ws:
                                            pendingAuths.delete(i)
                                        else:
                                            inc i
                                    pendingAuths.add(PendingAuth(
                                        ws: ws, nonce: nonce,
                                        createdAt: epochTime(), pendingReq: subReq))
                                await ws.send(encodeChallenge(nonce), Binary)
                                echo "[認証] チャレンジを送信しました (REQ: ", subReq.subId, ")"
                                continue

                        await handleReq(ws, subReq)
                    except Exception as e:
                        echo "[エラー] REQ処理失敗: ", e.msg
                        await ws.send("ERR: Invalid request")

                # --- 認証応答 (AUTH) の処理 ---
                elif msgType == MsgTypeAuth:
                    try:
                        let auth = decodeAuth(strm)

                        # 発行済みチャレンジを探す (接続 + nonce 一致)
                        var found = -1
                        {.gcsafe.}:
                            for i in 0..<pendingAuths.len:
                                if pendingAuths[i].ws == ws and pendingAuths[i].nonce == auth.nonce:
                                    found = i
                                    break
                        if found == -1:
                            await ws.send("ERR: Invalid or expired challenge")
                            continue

                        # TTL チェック (発行から 60 秒以内)
                        var challengeAge = 0.0
                        {.gcsafe.}: challengeAge = epochTime() - pendingAuths[found].createdAt
                        if challengeAge > 60.0:
                            {.gcsafe.}: pendingAuths.delete(found)
                            await ws.send("ERR: Challenge expired")
                            continue

                        # 署名検証: nonce(32) | pubkey(33) に対する署名
                        if not verifyContent(auth.pubkey, encodeAuthSignedData(auth), auth.signature):
                            {.gcsafe.}: pendingAuths.delete(found)
                            await ws.send("ERR: Invalid auth signature")
                            continue

                        # 認証成功。保留していた REQ を再開する。
                        var pendingReq = FodprReq(subId: "", transType: 0, tagKey: "", tagVal: "")
                        {.gcsafe.}: pendingReq = pendingAuths[found].pendingReq
                        let fpub = fpubEncode(auth.pubkey).toLowerAscii()
                        {.gcsafe.}:
                            var i = 0
                            while i < authedKeys.len:
                                if authedKeys[i].ws == ws:
                                    authedKeys.delete(i)
                                else:
                                    inc i
                            authedKeys.add(AuthedConn(ws: ws, pubkeyFpub: fpub))
                            pendingAuths.delete(found)
                        echo "[認証] 接続を認証しました (fpub: ", fpub[0..<12], "...)"
                        await ws.send("OK: Authenticated")

                        if pendingReq.subId != "":
                            await handleReq(ws, pendingReq)
                    except Exception as e:
                        echo "[エラー] AUTH処理失敗: ", e.msg
                        await ws.send("ERR: Invalid auth")

                # --- イベント削除 (DEL) の処理 ---
                elif msgType == MsgTypeDel:
                    try:
                        let delReq = decodeDelReq(strm)

                        # 未定義の送信タイプは拒否する
                        if delReq.transType != TransTypeAll and
                           delReq.transType != TransTypeJSON and
                           delReq.transType != TransTypeString and
                           delReq.transType != TransTypeBinary and
                           delReq.transType != TransTypeSigned and
                           delReq.transType != TransTypeEncrypted:
                            echo "[拒否] 未定義の送信タイプの削除要求です: ", delReq.transType
                            await ws.send("ERR: Unknown trans type")
                            continue

                        # 未定義の削除対象タイプは拒否する
                        if delReq.targetType != DelTargetPubkey and
                           delReq.targetType != DelTargetEvent and
                           delReq.targetType != DelTargetEventId:
                            echo "[拒否] 未定義の削除対象タイプです: ", delReq.targetType
                            await ws.send("ERR: Unknown target type")
                            continue

                        # 署名を検証する。送信者本人だけが自分のイベントを削除できる。
                        if not verifyContent(delReq.pubkey, encodeDelSignedData(delReq), delReq.signature):
                            echo "[拒否] 不正な署名の削除要求を検知しました"
                            await ws.send("ERR: Invalid signature")
                            continue

                        # 削除を実行する(公開鍵・transType が一致するイベントのみ削除)
                        let deleted = deleteEvents(delReq)
                        echo "[削除] 削除要求を処理しました(件数: ", deleted, ")"
                        await ws.send("OK: " & $deleted & " event(s) deleted")
                    except Exception as e:
                        echo "[エラー] DEL処理失敗: ", e.msg
                        await ws.send("ERR: Invalid delete request")

        # クライアントが接続を閉じたときのハンドリング
        except WebSocketClosedError:
            echo "[切断] クライアントが切断しました"
            removeSubs(ws)
            removeAuth(ws)
        except Exception as e:
            echo "[エラー] WebSocket例外: ", e.msg
            removeSubs(ws)
            removeAuth(ws)
    else:
        if req.url.path == "/":
            await req.respond(Http200, "クライアントから接続してください (Fodpr Relay Server)")
        else:
            await req.respond(Http404, "Not Found")

# サーバーのエントリーポイント。デフォルトは 8000 番で WebSocket を待ち受ける。
proc main() {.async.} =
    # LMDB の初期化(起動時に実行)
    initDatabase()

    let port = Port(parseInt(getEnv("FODPR_PORT", "8000")))
    echo "================================================"
    echo " Fodpr Relay Server running on ws://0.0.0.0:", port.int, "/"
    echo " (Ctrl+C で安全に終了できます)"
    echo "================================================"

    # Ctrl+C で安全に終了できるようシグナルハンドラを登録
    setControlCHook(ctrlcHandler)

    var server = newAsyncHttpServer()

    # serve は無限ループするため、バックグラウンドタスクとして起動する
    var serveTask = server.serve(port, cb)

    # Ctrl+C が押されるまで待機
    while not stopFlag.load():
        await sleepAsync(100)

    echo "[終了] Ctrl+C を受信しました。サーバーを終了します..."

    # リスニングソケットを閉じる。
    # これにより serve 内部の acceptAddr が失敗し、serve ループが終了する。
    server.close()
    try:
        await serveTask
    except CatchableError:
        # close() による acceptAddr の失敗は正常な終了経路なので無視する
        discard

    # LMDB のクローズ
    dbenv.close(dbiJson)
    dbenv.close(dbiString)
    dbenv.close(dbiBinary)
    dbenv.envClose()
        
    echo "[終了] サーバーは正常に終了しました。"

# このファイルが直接実行されたときだけ main を起動する
when isMainModule:
    waitFor main()
