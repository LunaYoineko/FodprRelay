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
- **リアルタイム配信** — REQ で購読中のクライアントへ即時配信（PUSH）
- **送信タイプ (TransType)** — JSON / String / Binary の 3 タイプに対応。
  サーバーは content の意味を一切解釈せず、送信タイプに基づいて保存・配信するだけ
- **LMDB 永続ストレージ** — 再起動後もデータを保持
- **保存データの暗号化** — AES-256-GCM で暗号化して保存（後述）
- **イベント削除 API** — 送信者本人だけが自分の投稿を削除可能（後述）
- **Docker 対応** — `docker compose up` で簡単に起動
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
| `0x03` | DEL   | クライアント → サーバー | イベント削除要求（このサーバーが追加） |
| `0x81` | PUSH  | サーバー → クライアント | イベント配信 |

### EVENT パケット（0x01）

```
transType(2) | createdAt(8) | pubkey(33) | tagCount(2)
| (tagLen(2) | tag) × tagCount | contentLen(4) | content | signature(64)
```

- `transType` — 送信タイプ（uint16: 1=JSON, 2=String, 3=Binary）
- `createdAt` — Unix タイムスタンプ（秒, uint64）
- `pubkey` — 送信者の公開鍵（圧縮形式 33 バイト）
- `tags` — タグ文字列のリスト
- `content` — 本文（タイプに応じて JSON / 文字列 / バイナリ）
- `signature` — content の SHA-256 に対する ECDSA 署名（64 バイト）

### REQ パケット（0x02）

```
MsgTypeReq(1) | subIdLen(2) | subId | transType(2) | tagKeyLen(2) | tagKey | tagValLen(2) | tagVal
```

- `transType=0`（TransTypeAll）はすべてのタイプを購読
- `tagKey` / `tagVal` による絞り込みに対応（現在は `tagKey="pubkey"` で公開鍵を指定）

### PUSH パケット（0x81）

```
MsgTypePush(1) | subIdLen(2) | subId | EVENT本体
```

### DEL パケット（0x03）— イベント削除 API

このサーバーが独自に追加した拡張です。既存の EVENT / REQ / PUSH には影響しません。

```
MsgTypeDel(1) | transType(2) | targetType(1) | pubkey(33)
| [createdAt(8) | contentHash(32)] | signature(64)
```

**署名対象**（`signature` を除いた以下のバイト列）:

```
transType(2) | targetType(1) | pubkey(33) | [createdAt(8) | contentHash(32)]
```

| フィールド | 説明 |
|------------|------|
| `transType` | 削除対象の送信タイプ（`0`=全タイプ, `1`=JSON, `2`=String, `3`=Binary） |
| `targetType` | 削除対象の指定方法（下記参照） |
| `pubkey` | 削除対象イベントの公開鍵（削除できるのは本人の公開鍵のみ） |
| `createdAt` | `targetType=1` のときのみ有効。削除するイベントの作成時刻（秒） |
| `contentHash` | `targetType=1` のときのみ有効。削除するイベントの content の SHA-256（32 バイト） |
| `signature` | 上記の「署名対象」を送信者の秘密鍵で署名した ECDSA 署名（64 バイト） |

`targetType` の値:

| 値 | 定数名 | 削除対象 |
|----|--------|----------|
| `0` | `DelTargetPubkey` | その公開鍵のイベントを `transType` 単位で全削除 |
| `1` | `DelTargetEvent` | `createdAt` と `contentHash` が一致する特定イベントを削除 |

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
サーバーは content の意味を解釈しないため、送信タイプ（json / string / binary）ごとの
データベースにそのまま保存します。

## セキュリティ上の注意

- 投稿・購読・削除はすべて **暗号化されていない WebSocket（ws://）** でも動作します。
  本番運用では **wss://**（TLS 終端をリバースプロキシ等で行う）を推奨します
- 削除要求は署名必須ですが、購読・閲覧には認証がありません。
  公開リレーとしての運用を想定しています
- LMDB のファイルは暗号化されていますが、OS のメモリやページングに
  平文が残る可能性は一般的な暗号化ソフトウェアと同じです

## ディレクトリ構成

```
FodprRelay/
├── src/
│   └── server.nim      # リレーサーバー本体
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
