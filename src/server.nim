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
##
## 起動方法:  nimble build   → ./src/server
##
## Ctrl+C (SIGINT) を押すと、リスニングソケットを閉じて
## 安全にサーバーを終了する。

import std/atomics
import std/json
import asynchttpserver, asyncdispatch, streams, strutils, endians, os, times, random
import ws
import lmdb
import Fodpr

# LMDB の環境とデータベースハンドル。
# サーバーは content の意味 (プロフィール管理など) を一切解釈せず、
# 送信方法 (transType) ごとのストレージに追記保存するだけである。
var dbenv: LMDBEnv
var dbiJson: Dbi      # TransTypeJSON   用 (キー: 現在時刻+乱数 = 追記)
var dbiString: Dbi    # TransTypeString 用 (キー: 現在時刻+乱数 = 追記)
var dbiBinary: Dbi    # TransTypeBinary 用 (キー: 現在時刻+乱数 = 追記)

# Ctrl+C (SIGINT) を受けたことを記録するフラグ。
# シグナルハンドラは「シグナル割り込みの中」で実行されるため、
# ヒープ確保や echo などの操作は禁止されている。
# そのためアトミック変数への書き込みのみを行う。
var stopFlag: Atomic[bool]

# Ctrl+C を受けたときに OS から呼び出されるハンドラ。
# 安全のため、フラグを立てるだけで他の処理は行わない。
proc ctrlcHandler() {.noconv.} =
  stopFlag.store(true)
  
# LMDB の初期化処理
proc initDatabase() =
  # データ保存ディレクトリの作成
  if not dirExists("data"):
      createDir("data")
  
  # 環境の作成とオープン(複数のDBIを使うためmaxdbsを指定)
  dbenv = newLMDBEnv("data", maxdbs = 3)
  
  # トランザクションを開始して送信タイプごとのDBIを開く
  let txn = dbenv.newTxn()
  dbiJson = txn.dbiOpen("json", CREATE)
  dbiString = txn.dbiOpen("string", CREATE)
  dbiBinary = txn.dbiOpen("binary", CREATE)
  txn.commit()
  
  echo "[DB] LMDB ストレージの初期化が完了しました(./data)"

# 指定 DBI の保存イベントを走査し、購読条件に一致するものを PUSH パケット
# (バイナリフレーム) としてクライアントへ送信する。
# サーバーは content の意味を解釈せず、送信方法 (transType) による DBI の選択と
# タグ条件 (pubkey など) による絞り込みのみを行う。
proc pushEventsFromDbi(txn: LMDBTxn, dbi: Dbi, subReq: FodprReq, ws: WebSocket) {.async, gcsafe.} =
    let cursor = txn.cursorOpen(dbi)
    var kVal, dVal: Val

    # カーソルで全イベントを走査
    while cursorGet(cursor, addr kVal, addr dVal, NEXT) == 0:
        # pubkey タグによる絞り込み (イベントをデコードして公開鍵を比較)
        if subReq.tagKey == "pubkey" and subReq.tagVal != "":
            var enc = newString(int(dVal.mvSize))
            if dVal.mvSize > 0:
                copyMem(addr enc[0], dVal.mvData, int(dVal.mvSize))
            let evt = decodeEvent(newStringStream(enc))
            if $evt.pubkey.toRawCompressed() != subReq.tagVal:
                continue

        # 保存済みイベント本体を取り出す
        var encoded = newString(int(dVal.mvSize))
        if dVal.mvSize > 0:
            copyMem(addr encoded[0], dVal.mvData, int(dVal.mvSize))

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

# 各 HTTP リクエストを処理するコールバック。
# URL が "/" (ルートパス) で WebSocket アップグレードヘッダがあるときだけ
# WebSocket として扱い、それ以外は 404 を返す。
proc cb(req: Request) {.async, gcsafe.} =
    let isWebSocket = (req.url.path == "/") and req.headers.hasKey("upgrade") and req.headers.getOrDefault("upgrade").toLowerAscii() == "websocket"

    if isWebSocket:
        try:
            # HTTP リクエストを WebSocket 接続にアップグレード
            var ws = await newWebSocket(req)
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
                        if not verifyContent(event.pubkey, event.content, event.signature):
                            echo "[拒否] 不正な署名のイベントを検知しました"
                            await ws.send("ERR: Invalid signature")
                            continue

                        # 未定義の送信タイプは拒否する
                        if event.transType != TransTypeJSON and
                           event.transType != TransTypeString and
                           event.transType != TransTypeBinary:
                            echo "[拒否] 未定義の送信タイプです: ", event.transType
                            await ws.send("ERR: Unknown trans type")
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
                            let encoded = encodeEvent(event)

                            # 一意なキー(現在時刻+乱数)で追記保存
                            let timeKey = "evt_" & $epochTime() & "_" & $event.transType & "_" & $rand(100000)
                            case event.transType
                            of TransTypeJSON:
                                txn.put(dbiJson, timeKey, encoded)
                            of TransTypeString:
                                txn.put(dbiString, timeKey, encoded)
                            else:
                                txn.put(dbiBinary, timeKey, encoded)
                            echo "[保存] イベントを保存しました(TransType: ", transTypeName(event.transType), ")"
                            txn.commit()

                        await ws.send("OK: Event accepted")
                    except Exception as e:
                        echo "[エラー] イベントパース失敗: ", e.msg
                        await ws.send("ERR: Invalid event")

                # --- 購読要求 (REQ) の処理 ---
                elif msgType == MsgTypeReq:
                    try:
                        let subReq = decodeReq(strm)
                        echo "[購読] サブスクリプション要求受領 [ID: ", subReq.subId, "] (TransType: ", transTypeName(subReq.transType), ")"

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
                            else:
                                # TransTypeAll: すべてのタイプを順番に配信する
                                await pushEventsFromDbi(txn, dbiJson, subReq, ws)
                                await pushEventsFromDbi(txn, dbiString, subReq, ws)
                                await pushEventsFromDbi(txn, dbiBinary, subReq, ws)
                            txn.commit()

                        # 保存済みイベントの配信が終わったことを通知
                        await ws.send("EOE: End of stored events for " & subReq.subId)
                    except Exception as e:
                        echo "[エラー] REQ処理失敗: ", e.msg

        # クライアントが接続を閉じたときのハンドリング
        except WebSocketClosedError:
            echo "[切断] クライアントが切断しました"
        except Exception as e:
            echo "[エラー] WebSocket例外: ", e.msg
    else:
        if req.url.path == "/":
            await req.respond(Http200, "クライアントから接続してください (Fodpr Relay Server)")
        else:
            await req.respond(Http404, "Not Found")

# サーバーのエントリーポイント。ポート 8000 で WebSocket を待ち受ける。
proc main() {.async.} =
    # LMDB の初期化(起動時に実行)
    initDatabase()

    let port = Port(8000)
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
