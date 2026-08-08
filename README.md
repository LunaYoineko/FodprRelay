# Fodpr Relay Server

**Fodpr（ふぉどぷる）のリレーサーバー** です。
[Fodpr](https://github.com/LunaYoineko/Fodpr) プロトコルで通信するクライアントが
投稿したイベントを、WebSocket 経由で受け取り・保存・配信します。

> English version is available at [README.en.md](README.en.md)

## これは何?

- クライアントは **署名付きイベント** をリレーサーバーへ投稿します（EVENT）
- サーバーは署名を検証し、改ざん・偽装されたイベントを拒否します
- クライアントは **購読要求（REQ）** を送ると、条件に一致する保存済みイベントと、
  以後に投稿されるイベントをリアルタイムに受け取れます（PUSH）
- 投稿者は自分のイベントを **削除要求（DEL）** で削除できます
- 保存データはすべて **暗号化** して LMDB に保存します（平文では保存しません）

## 特徴

- **署名検証つき保存** — 全イベントを secp256k1 (ECDSA) で検証してから保存
  （TransTypeSigned / Encrypted は全フィールド署名を検証）
- **リアルタイム配信** — REQ で購読中のクライアントへ即時配信（PUSH）
- **送信タイプ (TransType)** — JSON / String / Binary / Signed / Encrypted の
  5 タイプに対応。サーバーは content の意味を一切解釈せず、送信タイプに基づいて
  保存・配信するだけ
- **宛先限定のプライバシー配信** — `to:<fpub>` タグ付きイベントは、
  宛先本人として認証（AUTH）した購読にのみ配信（NIP-42 相当の読取認証）
- **暗号化イベントの構造検証** — TransTypeEncrypted はエンベロープの構造と
  to: タグの一致を検証（内容は復号せず、サーバーには読めない）
- **LMDB 永続ストレージ** — 再起動後もデータを保持
- **保存データの暗号化** — AES-256-GCM で暗号化して保存（後述）
- **イベント削除 API** — 送信者本人だけが自分の投稿を削除可能（後述）
- **Docker 対応** — `docker compose up` で簡単に起動
- **省メモリ・OOM 対策** — 受信フレームの上限（16MB）と LMDB マップサイズ
  （既定 256MB）の制御により、メモリ 1GB の小規模 VPS でも安定稼働（後述）
- **安全な終了** — Ctrl+C でリスニングを閉じて正常終了

## 必要なもの

| 実行方法 | 必要環境 |
|----------|----------|
| ネイティブ実行 | [Nim](https://nim-lang.org/) 2.2.10 以上、[Nimble](https://github.com/nim-lang/nimble)、LMDB ランタイムライブラリ（Debian/Ubuntu では `liblmdb0`） |
| Docker 実行 | [Docker Engine](https://docs.docker.com/engine/) と [Docker Compose](https://docs.docker.com/compose/) |

## ビルドと起動

### ネイティブで実行する場合

```bash
git clone https://github.com/LunaYoineko/FodprRelay
cd FodprRelay

# 依存ライブラリのインストール
nimble install -d

# ビルド（バイナリは server に生成されます）
nimble build

# 起動（デフォルトは ws://0.0.0.0:8000/）
./server
```

> **本番運用時はリリースビルドを推奨します:**
> ```bash
> nimble build -d:release
> ```
> `config.nims` により、リリースビルドでは小メモリ環境向けに `--opt:size` と
> stackTrace / lineTrace の無効化が自動で有効になります（詳細は後述）。

起動ログの例:

```
[DB] 暗号化キーを data/db.key から読み込みました
[DB] LMDB ストレージの初期化が完了しました(./data, AES-256-GCM 暗号化保存)
================================================
 Fodpr Relay Server running on ws://0.0.0.0:8000/
 (Ctrl+C で安全に終了できます)
================================================
```

**Ctrl+C** を押すと安全に終了します。

### Docker で実行する場合

```bash
cd FodprRelay
docker compose up -d --build
```

ログを確認する場合:

```bash
docker compose logs -f
```

## 設定（環境変数）

| 環境変数 | 既定値 | 説明 |
|----------|--------|------|
| `FODPR_PORT` | `8000` | リッスンするポート番号 |
| `FODPR_DB_KEY` | （未設定） | LMDB 保存値の暗号化キー（64 桁の 16 進数 = 32 バイト）。未設定の場合は `data/db.key` を読み、それも無ければ自動生成して保存します。詳しくは「保存データの暗号化」を参照 |
| `FODPR_DB_MAPSIZE` | `268435456`（256MB） | LMDB のマップサイズ（バイト単位）。データの蓄積上限になります。1GB メモリ環境の既定値は 256MB で、増やしたい場合はこの変数で上書きします（詳しくは「小メモリ環境（1GB）での運用」を参照） |

## 小メモリ環境（1GB）での運用

Oracle Cloud Always Free（AMD, 1GB）のようなメモリの少ない VPS でも
OOMKiller を気にせず動かせるよう、以下の対策が入っています。

- **リリースビルドの省メモリ化** — `config.nims` により release ビルドでは
  `--opt:size` と stackTrace / lineTrace の無効化が有効になり、バイナリサイズと
  ビルド時のメモリピークを抑えます
- **受信フレーム上限（16MB）** — WebSocket ライブラリを
  `src/ws_limited.nim` にベンダリングし、フレーム長を検証して上限を超える
  巨大フレームは受信せずに切断します（クライアント起因のメモリ肥大化を防止）
- **LMDB マップサイズの既定値を 256MB** に設定 — DB が実メモリを圧迫しない
  上限で自動管理します（`FODPR_DB_MAPSIZE` で変更可）

実測では、起動時・負荷時ともに RSS 約 6〜8MB で動作します。

## 使い方（クライアント）

クライアント側は [Fodpr](https://github.com/LunaYoineko/Fodpr) リポジトリのサンプルが利用できます。

```bash
# 別ターミナルで（リレーサーバー起動中に）
nim c -r examples/fodpr_client.nim
```

サンプルクライアントは、鍵ペアを生成して JSON / String / Binary の 3 タイプの
イベントを投稿し、REQ（全タイプ購読）で保存済みイベントを受け取ります。

## ワイヤプロトコル

Fodpr プロトコルの定義（EVENT / REQ / PUSH のエンコード・デコード）は
[Fodpr ライブラリ](https://github.com/LunaYoineko/Fodpr) 側にあります。
数値はすべて **ビッグエンディアン** です。

### メッセージ種別（先頭 1 バイト）

| 値 | 種別 | 方向 | 説明 |
|----|------|------|------|
| `0x01` | EVENT | クライアント → サーバー | 署名付きイベントの投稿 |
| `0x02` | REQ   | クライアント → サーバー | 購読要求 |
| `0x03` | DEL   | クライアント → サーバー | イベント削除要求 |
| `0x04` | AUTH  | クライアント → サーバー | 読取認証の署名応答（NIP-42 相当） |
| `0x81` | PUSH  | サーバー → クライアント | イベント配信 |
| `0x82` | CHALLENGE | サーバー → クライアント | 認証チャレンジ（nonce 32 バイト） |

### EVENT パケット（0x01）

```
transType(2) | createdAt(8) | pubkey(33) | tagCount(2)
| (tagLen(2) | tag) × tagCount | contentLen(4) | content | signature(64)
```

- `transType` — 送信タイプ（uint16: 0=All(REQ のみ), 1=JSON, 2=String, 3=Binary, 4=Signed, 5=Encrypted）
- `createdAt` — Unix タイムスタンプ（秒, uint64）
- `pubkey` — 送信者の公開鍵（圧縮形式 33 バイト）
- `tags` — タグ文字列のリスト
- `content` — 本文（タイプに応じて JSON / 文字列 / バイナリ / エンベロープ）
- `signature` — 署名（64 バイト）
  - TransType 1〜3: content の SHA-256 に対する ECDSA 署名
  - TransType 4・5: `createdAt` / `pubkey` / `tags` を含む全フィールドに対する署名

### REQ パケット（0x02）

```
MsgTypeReq(1) | subIdLen(2) | subId | transType(2) | tagKeyLen(2) | tagKey | tagValLen(2) | tagVal
```

- `transType=0`（TransTypeAll）はすべてのタイプを購読
- `tagKey` / `tagVal` による絞り込みに対応
  - `tagKey="pubkey"` — 送信者（公開鍵）で絞り込み
  - `tagKey="to"` — 宛先で絞り込み。`to:` 宛先限定イベントは、
    宛先本人として認証（後述の AUTH）した購読にのみ配信されます

### 読取認証（AUTH / CHALLENGE, NIP-42 相当）

`to:<fpub>` タグで宛先を限定したイベントは、その宛先本人だけが受け取れるように
するため、リレーがチャレンジ認証を行います。

```
1. クライアント → REQ(subId, tagKey="to", tagVal=fpub)
2. サーバー   → CHALLENGE(0x82) nonce(32)
3. クライアント → AUTH(0x04) nonce(32) | pubkey(33) | signature(64)
4. サーバー   → 認証OK の購読にのみ to: 宛先限定イベントを配信
```

- `AUTH` の署名対象は `nonce(32) | pubkey(33)` のバイト列
- 認証に成功した購読だけが宛先限定イベントを受け取れます
- 公開イベント（`to:` タグなし）は従来どおり認証なしで購読できます
- 認証に失敗した購読には宛先限定イベントを配信しません（存在も明かしません）

### TransTypeEncrypted（暗号化イベント）の受信時検証

TransTypeEncrypted の content は送信者が [Fodpr の envelope.nim](https://github.com/LunaYoineko/Fodpr/blob/main/src/envelope.nim)
で作った **宛先別暗号化エンベロープ**（gift-wrap 相当）です。リレーは本文を復号せず、
構造だけを検証して保存・配信します。

受信時に検証する内容:

1. `to:` タグが 1 つ以上ある
2. `to:` タグの公開鍵（fpub 形式）が、エンベロープ内の受信者一覧と一致する
3. 全体署名（全フィールド署名）が送信者の公開鍵で検証できる

これにより「宛先に含まれない人に届ける」「宛先を偽って送る」といった
不正を防ぎつつ、**サーバーは内容を読めない**（E2EE を維持）設計です。

復号は受信者側のクライアントで行います:

```nim
let body = decryptEnvelope(ev.content, myPriv, ev.pubkey)  # Fodpr.envelope
```

### タグ規約

タグは `"<キー>:<値>"` 形式の文字列です。

| タグ | 説明 |
|------|------|
| `to:<fpub>` | 宛先の公開鍵。宛先限定イベント（特に Encrypted）で必須 |
| `p:<fpub>` | 関係者（participant）の公開鍵（参照用） |
| `e:<eventId>` | 参照イベント（reply-to / スレッド結合に使用） |

### PUSH パケット（0x81）

```
MsgTypePush(1) | subIdLen(2) | subId | EVENT本体
```

### DEL パケット（0x03）— イベント削除 API

DEL の定義（定数・型・エンコード/デコード）は [Fodpr ライブラリ](https://github.com/LunaYoineko/Fodpr)
の protocol.nim に含まれており、このサーバーはそれを使って削除処理を実装しています。
既存の EVENT / REQ / PUSH には影響しません。

```
MsgTypeDel(1) | transType(2) | targetType(1) | pubkey(33)
| [createdAt(8) | contentHash(32)] | [eventId(32)] | signature(64)
```

**署名対象**（`signature` を除いた以下のバイト列）:

```
transType(2) | targetType(1) | pubkey(33) | [createdAt(8) | contentHash(32)] | [eventId(32)]
```

| フィールド | 説明 |
|------------|------|
| `transType` | 削除対象の送信タイプ（`0`=全タイプ, `1`=JSON, `2`=String, `3`=Binary, `4`=Signed, `5`=Encrypted） |
| `targetType` | 削除対象の指定方法（下記参照） |
| `pubkey` | 削除対象イベントの公開鍵（削除できるのは本人の公開鍵のみ） |
| `createdAt` | `targetType=1` のときのみ有効。削除するイベントの作成時刻（秒） |
| `contentHash` | `targetType=1` のときのみ有効。削除するイベントの content の SHA-256（32 バイト） |
| `eventId` | `targetType=2` のときのみ有効。全体署名イベントのイベント ID（32 バイト） |
| `signature` | 上記の「署名対象」を送信者の秘密鍵で署名した ECDSA 署名（64 バイト） |

`targetType` の値:

| 値 | 定数名 | 削除対象 |
|----|--------|----------|
| `0` | `DelTargetPubkey` | その公開鍵のイベントを `transType` 単位で全削除 |
| `1` | `DelTargetEvent` | `createdAt` と `contentHash` が一致する特定イベントを削除 |
| `2` | `DelTargetEventId` | `eventId` が一致する特定イベントを削除（全体署名イベント推奨） |

サーバーは署名を検証し、**イベントの公開鍵が要求の公開鍵と一致するものだけを削除** します。
つまり「自分の投稿を自分だけが消せる」仕組みです。

応答はテキストフレームで返ります:

| 応答 | 意味 |
|------|------|
| `OK: N event(s) deleted` | N 件のイベントを削除しました |
| `ERR: Invalid signature` | 署名検証に失敗（他人のイベントは削除できない） |
| `ERR: Unknown trans type` | 未定義の送信タイプ |
| `ERR: Unknown target type` | 未定義の削除対象タイプ |
| `ERR: Invalid delete request` | パケット形式が不正 |

## 保存データの暗号化

LMDB に保存する値（イベント本体）はすべて **AES-256-GCM** で暗号化します。

### 保存形式

```
バージョン(1) | nonce(12) | 暗号文 | 認証タグ(16)
```

- `バージョン` — 常に `0x01`。暗号化済みレコードの識別と、将来の方式変更用
- `nonce` — レコードごとに毎回ランダム生成（同じ暗号文は 2 つと作られません）
- `認証タグ` — GCM の完全性検証用。キーが違う・改ざんがあると復号時にエラーになります

### 暗号化キーの管理（優先順位）

1. 環境変数 `FODPR_DB_KEY`（64 桁の 16 進数 = 32 バイト）があればそれを使用
2. `data/db.key` ファイルがあればそれを読み込む
3. どちらも無ければ **起動時にランダム生成して `data/db.key` に保存**（権限 0600）

> **注意:** `data/db.key` を失うと、それまでに保存したデータを復号できなくなります。
> 必ずバックアップしてください。複数サーバーでデータを共有する場合も同じキーが必要です。

### 既存データの移行

以前のバージョンで平文のまま保存されたレコードは、起動時に自動で検出して
暗号化へ変換します（ログ: `[DB] 平文データ N 件を暗号化に変換しました`）。
変換はキーごとに行われるため、削除などの手間は不要です。

### データ保存場所

| 項目 | 場所 |
|------|------|
| LMDB データ | `./data/data.mdb` |
| 暗号化キー | `./data/db.key` |

LMDB 内のキーは `evt_<現在時刻>_<transType>_<乱数>` の追記形式です。
サーバーは content の意味を解釈しないため、送信タイプ（json / string / binary /
signed / encrypted）ごとのデータベースにそのまま保存します。

LMDB のマップサイズ（データの蓄積上限）は既定で **256MB** です。
データが上限に達すると書き込みに失敗するため、長期的にデータを蓄積する場合は
`FODPR_DB_MAPSIZE` で十分なサイズに設定してください。
なお、マップサイズは仮想メモリの予約でありファイルは必要に応じて伸びますが、
1GB メモリ環境では実メモリと同程度以上に設定しないのが無難です。

## セキュリティ上の注意

- 投稿・購読・削除はすべて **暗号化されていない WebSocket（ws://）** でも動作します。
  本番運用では **wss://**（TLS 終端をリバースプロキシ等で行う）を推奨します
- 公開イベントの購読・閲覧は認証なしで行えます（公開リレーとしての運用を想定）。
  宛先限定イベント（`to:` タグ）の購読には AUTH（読取認証）が必要です
- LMDB のファイルは暗号化されていますが、OS のメモリやページングに
  平文が残る可能性は一般的な暗号化ソフトウェアと同じです

## ディレクトリ構成

```
FodprRelay/
├── src/
│   ├── server.nim      # リレーサーバー本体
│   └── ws_limited.nim  # WebSocket ライブラリ（受信フレーム上限 16MB を追加したベンダリング版）
├── FodprRelay.nimble   # Nimble パッケージ定義
├── config.nims         # ビルド設定（ローカル開発用）
├── Dockerfile          # Docker イメージ定義
├── docker-compose.yml  # Docker Compose 設定（ポート 8000 / データボリューム）
├── README.md           # このファイル（日本語）
├── README.en.md        # 英語版 README
├── data/               # LMDB データベースと暗号化キー（自動生成・gitignore）
└── server              # ビルドで生成されるバイナリ（gitignore）
```

## ライセンス

MIT License
