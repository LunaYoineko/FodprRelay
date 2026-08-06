# Fodpr Relay Server

This is the **relay server for Fodpr**.
It receives, stores, and delivers events from clients that communicate over the
[Fodpr](https://github.com/LunaYoineko/Fodpr) protocol using WebSocket.

> 日本語版は [README.md](README.md) をご覧ください。

## What is this?

- Clients post **signed events** to the relay server (EVENT)
- The server verifies the signature and rejects tampered or forged events
- Clients send a **subscription request (REQ)** and receive both stored matching
  events and newly posted ones in real time (PUSH)
- Authors can delete their own events with a **delete request (DEL)**
- All stored data is **encrypted** before being written to LMDB (never stored in plaintext)

## Features

- **Signature-verified storage** — every event is verified with secp256k1 (ECDSA) before saving
- **Real-time delivery** — events are pushed instantly to clients subscribed via REQ
- **Transmission types (TransType)** — JSON / String / Binary. The server never
  interprets the semantics of `content`; it only stores and delivers based on the type
- **Persistent LMDB storage** — data survives server restarts
- **Encrypted storage at rest** — values are encrypted with AES-256-GCM (see below)
- **Event delete API** — only the author of an event can delete it (see below)
- **Docker support** — start with `docker compose up`
- **Graceful shutdown** — press Ctrl+C to close the listener and exit cleanly

## Requirements

| Run method | Requirements |
|------------|--------------|
| Native | [Nim](https://nim-lang.org/) 2.2.10+, [Nimble](https://github.com/nim-lang/nimble), and the LMDB runtime library (on Debian/Ubuntu: `liblmdb0`) |
| Docker | [Docker Engine](https://docs.docker.com/engine/) and [Docker Compose](https://docs.docker.com/compose/) |

## Build & Run

### Native run

```bash
git clone https://github.com/LunaYoineko/FodprRelay
cd FodprRelay

# install dependencies
nimble install -d

# build (the binary is created as ./server)
nimble build

# start (default: ws://0.0.0.0:8000/)
./server
```

Example startup log:

```
[DB] 暗号化キーを data/db.key から読み込みました
[DB] LMDB ストレージの初期化が完了しました(./data, AES-256-GCM 暗号化保存)
================================================
 Fodpr Relay Server running on ws://0.0.0.0:8000/
 (Ctrl+C で安全に終了できます)
================================================
```

Press **Ctrl+C** to shut down gracefully.

### Docker run

```bash
cd FodprRelay
docker compose up -d --build
```

Watch the logs:

```bash
docker compose logs -f
```

## Configuration (environment variables)

| Variable | Default | Description |
|----------|---------|-------------|
| `FODPR_PORT` | `8000` | Port number to listen on |
| `FODPR_DB_KEY` | (unset) | Encryption key (64 hex chars = 32 bytes) for LMDB values. If unset, `data/db.key` is read; if that is also missing, a key is generated and saved automatically. See "Encrypted storage" below |

## Usage (client)

The client side can use the sample in the
[Fodpr](https://github.com/LunaYoineko/Fodpr) repository.

```bash
# in another terminal (while the relay server is running)
nim c -r examples/fodpr_client.nim
```

The sample client generates a key pair, posts JSON / String / Binary events, and
receives the stored events by subscribing to all types (REQ).

## Wire Protocol

The Fodpr protocol definitions (EVENT / REQ / PUSH encode/decode) live in the
[Fodpr library](https://github.com/LunaYoineko/Fodpr). All integers are
**big-endian**.

### Message types (first byte)

| Value | Type | Direction | Description |
|-------|------|-----------|-------------|
| `0x01` | EVENT | client → server | Post a signed event |
| `0x02` | REQ   | client → server | Subscription request |
| `0x03` | DEL   | client → server | Delete-events request (added by this server) |
| `0x81` | PUSH  | server → client | Event delivery |

### EVENT packet (0x01)

```
transType(2) | createdAt(8) | pubkey(33) | tagCount(2)
| (tagLen(2) | tag) × tagCount | contentLen(4) | content | signature(64)
```

- `transType` — transmission type (uint16: 1 = JSON, 2 = String, 3 = Binary)
- `createdAt` — Unix timestamp in seconds (uint64)
- `pubkey` — sender's public key (compressed, 33 bytes)
- `tags` — list of tag strings
- `content` — body (JSON, string, or binary depending on the type)
- `signature` — ECDSA signature over the SHA-256 digest of `content` (64 bytes)

### REQ packet (0x02)

```
MsgTypeReq(1) | subIdLen(2) | subId | transType(2) | tagKeyLen(2) | tagKey | tagValLen(2) | tagVal
```

- `transType=0` (TransTypeAll) subscribes to all types
- Filtering by tag is supported (`tagKey="pubkey"` filters by public key)

### PUSH packet (0x81)

```
MsgTypePush(1) | subIdLen(2) | subId | EVENT payload
```

### DEL packet (0x03) — event delete API

This is an extension added by this server. It does not affect the existing
EVENT / REQ / PUSH messages.

```
MsgTypeDel(1) | transType(2) | targetType(1) | pubkey(33)
| [createdAt(8) | contentHash(32)] | signature(64)
```

**Signed data** (the bytes below, excluding `signature`):

```
transType(2) | targetType(1) | pubkey(33) | [createdAt(8) | contentHash(32)]
```

| Field | Description |
|-------|-------------|
| `transType` | Transmission type of the target events (`0` = all, `1` = JSON, `2` = String, `3` = Binary) |
| `targetType` | How to select the target events (see below) |
| `pubkey` | Public key of the events to delete (only your own pubkey can be used) |
| `createdAt` | Only for `targetType=1`. Creation time (seconds) of the event to delete |
| `contentHash` | Only for `targetType=1`. SHA-256 (32 bytes) of the event's `content` to delete |
| `signature` | ECDSA signature (64 bytes) of the above "signed data" made with the author's private key |

Values of `targetType`:

| Value | Constant | Delete target |
|-------|----------|---------------|
| `0` | `DelTargetPubkey` | All events of that public key, within the given `transType` |
| `1` | `DelTargetEvent` | The specific event whose `createdAt` and `contentHash` match |

The server verifies the signature and deletes **only events whose public key
matches the one in the request** — i.e., only the author can delete their own posts.

Responses are sent as text frames:

| Response | Meaning |
|----------|---------|
| `OK: N event(s) deleted` | N events were deleted |
| `ERR: Invalid signature` | Signature verification failed (you cannot delete others' events) |
| `ERR: Unknown trans type` | Undefined transmission type |
| `ERR: Unknown target type` | Undefined target type |
| `ERR: Invalid delete request` | Malformed packet |

## Encrypted Storage

Every value written to LMDB (the encoded event) is encrypted with **AES-256-GCM**.

### Stored format

```
version(1) | nonce(12) | ciphertext | auth tag(16)
```

- `version` — always `0x01`. Identifies encrypted records and allows future format changes
- `nonce` — randomly generated for each record (no two ciphertexts are identical)
- `auth tag` — GCM integrity check. Wrong keys or tampering cause a decrypt error

### Encryption key management (priority order)

1. If the environment variable `FODPR_DB_KEY` (64 hex chars = 32 bytes) is set, use it
2. Otherwise, if the file `data/db.key` exists, read it
3. Otherwise, **generate a random key at startup and save it to `data/db.key`** (permissions 0600)

> **Caution:** Losing `data/db.key` makes all previously stored data undecryptable.
> Always back it up. Servers sharing the same data must use the same key.

### Migrating existing data

Records stored in plaintext by older versions are detected automatically at
startup and converted to encrypted form (log:
`[DB] 平文データ N 件を暗号化に変換しました`). No manual steps are required.

### Where data lives

| Item | Location |
|------|----------|
| LMDB data | `./data/data.mdb` |
| Encryption key | `./data/db.key` |

LMDB keys use the append-style format `evt_<current time>_<transType>_<random>`.
Since the server never interprets `content`, events are stored as-is in a
per-type database (json / string / binary).

## Security notes

- Posting, subscribing, and deleting all work over plain `ws://` as well.
  For production use, **wss://** (terminate TLS with a reverse proxy etc.) is recommended
- Delete requests require a signature, but subscribing and viewing are open —
  this relay is intended to operate as a public relay
- LMDB files are encrypted, but like any encryption software, plaintext may
  transiently exist in OS memory or swap

## Directory Layout

```
FodprRelay/
├── src/
│   └── server.nim      # The relay server
├── FodprRelay.nimble   # Nimble package definition
├── config.nims         # Build configuration (for local development)
├── Dockerfile          # Docker image definition
├── docker-compose.yml  # Docker Compose config (port 8000 / data volume)
├── README.md           # 日本語版 README
├── README.en.md        # This file (English)
├── data/               # LMDB database and encryption key (auto-generated, git-ignored)
└── server              # Build output binary (git-ignored)
```

## License

MIT License
