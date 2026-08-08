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

- **Signature-verified storage** — every event is verified with secp256k1 (ECDSA)
  before saving (Signed / Encrypted events are verified over all fields)
- **Real-time delivery** — events are pushed instantly to clients subscribed via REQ
- **Transmission types (TransType)** — JSON / String / Binary / Signed / Encrypted.
  The server never interprets the semantics of `content`; it only stores and
  delivers based on the type
- **Recipient-limited privacy delivery** — events with a `to:<fpub>` tag are
  delivered only to subscriptions authenticated as that recipient via AUTH
  (read authentication, NIP-42 equivalent)
- **Encrypted-event structure validation** — TransTypeEncrypted envelopes are
  validated for structure and `to:` tag consistency without being decrypted
  (the server cannot read them)
- **Persistent LMDB storage** — data survives server restarts
- **Encrypted storage at rest** — values are encrypted with AES-256-GCM (see below)
- **Event delete API** — only the author of an event can delete it (see below)
- **Docker support** — start with `docker compose up`
- **Low-memory / OOM protection** — inbound frame size is capped (16 MB) and the
  LMDB map size defaults to 256 MB, so the server stays stable even on small
  1 GB VPS instances (see below)
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

> **We recommend a release build for production:**
> ```bash
> nimble build -d:release
> ```
> Thanks to `config.nims`, release builds automatically enable `--opt:size` and
> disable stack/line tracing for low-memory environments (details below).

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
| `FODPR_DB_MAPSIZE` | `268435456` (256 MB) | LMDB map size in bytes — the upper bound for stored data. The default for 1 GB memory environments is 256 MB; override it with this variable when you need more (see "Running on low-memory (1 GB) environments") |

## Running on low-memory (1 GB) environments

The following protections are built in so the server runs on low-memory VPSes
(e.g. Oracle Cloud Always Free, AMD 1 GB) without worrying about the OOM killer:

- **Lean release builds** — `config.nims` enables `--opt:size` and disables
  stack/line tracing for release builds, reducing binary size and the memory
  peak during compilation
- **Inbound frame cap (16 MB)** — the WebSocket library is vendored as
  `src/ws_limited.nim` with a frame-length check; frames exceeding the limit are
  rejected and the connection is closed instead of allocating huge buffers
- **LMDB map size defaults to 256 MB** — keeps the database from growing past
  a bound that could pressure physical memory (override via `FODPR_DB_MAPSIZE`)

Measured RSS is about 6-8 MB both at startup and under load.

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
| `0x03` | DEL   | client → server | Delete-events request |
| `0x04` | AUTH  | client → server | Read-authentication signature response (NIP-42 equivalent) |
| `0x81` | PUSH  | server → client | Event delivery |
| `0x82` | CHALLENGE | server → client | Authentication challenge (32-byte nonce) |

### EVENT packet (0x01)

```
transType(2) | createdAt(8) | pubkey(33) | tagCount(2)
| (tagLen(2) | tag) × tagCount | contentLen(4) | content | signature(64)
```

- `transType` — transmission type (uint16: 0=All (REQ only), 1=JSON, 2=String, 3=Binary, 4=Signed, 5=Encrypted)
- `createdAt` — Unix timestamp in seconds (uint64)
- `pubkey` — sender's public key (compressed, 33 bytes)
- `tags` — list of tag strings
- `content` — body (JSON, string, binary, or envelope depending on the type)
- `signature` — ECDSA signature (64 bytes)
  - TransType 1–3: over the SHA-256 digest of `content`
  - TransType 4–5: over all fields including `createdAt`, `pubkey`, and `tags`

### REQ packet (0x02)

```
MsgTypeReq(1) | subIdLen(2) | subId | transType(2) | tagKeyLen(2) | tagKey | tagValLen(2) | tagVal
```

- `transType=0` (TransTypeAll) subscribes to all types
- Filtering by tag is supported:
  - `tagKey="pubkey"` — filter by sender (public key)
  - `tagKey="to"` — filter by recipient. `to:` recipient-limited events are
    delivered only to subscriptions authenticated as that recipient (see AUTH below)

### Read authentication (AUTH / CHALLENGE, NIP-42 equivalent)

Events with a `to:<fpub>` tag (recipient-limited) are only delivered to that
recipient, so the relay runs a challenge authentication.

```
1. client   → REQ(subId, tagKey="to", tagVal=fpub)
2. server   → CHALLENGE (0x82): nonce(32)
3. client   → AUTH (0x04): nonce(32) | pubkey(33) | signature(64)
4. server   → delivers `to:` recipient-limited events only to authenticated subscriptions
```

- The bytes signed in `AUTH` are `nonce(32) | pubkey(33)`
- Only subscriptions that pass authentication receive recipient-limited events
- Public events (no `to:` tag) remain available without authentication
- Subscriptions that fail authentication are not given recipient-limited events
  (their existence is not revealed either)

### TransTypeEncrypted (encrypted-event) validation on receive

The `content` of TransTypeEncrypted is a **per-recipient encrypted envelope**
(gift-wrap equivalent) built by the sender with
[Fodpr's envelope.nim](https://github.com/LunaYoineko/Fodpr/blob/main/src/envelope.nim).
The relay does **not** decrypt the body; it validates only the structure.

On receive the relay verifies:

1. At least one `to:` tag is present
2. The `to:` tags (fpub form) match the recipients inside the envelope
3. The full-event signature verifies with the sender's public key

This prevents "delivery to someone not on the recipient list" and "forged
recipients" while keeping the **content unreadable to the server** (E2EE).

Decryption happens on the recipient's client:

```nim
let body = decryptEnvelope(ev.content, myPriv, ev.pubkey)  # Fodpr.envelope
```

### Tag conventions

Tags are strings in `"<key>:<value>"` form.

| Tag | Description |
|-----|-------------|
| `to:<fpub>` | Recipient's public key. Required for recipient-limited events (especially Encrypted) |
| `p:<fpub>` | Participant's public key (for reference) |
| `e:<eventId>` | Referenced event (reply-to / thread linking) |

### PUSH packet (0x81)

```
MsgTypePush(1) | subIdLen(2) | subId | EVENT payload
```

### DEL packet (0x03) — event delete API

The DEL definitions (constants, types, encode/decode) live in the
[Fodpr library](https://github.com/LunaYoineko/Fodpr)'s protocol.nim, and this
server uses them to implement the delete logic. It does not affect the existing
EVENT / REQ / PUSH messages.

```
MsgTypeDel(1) | transType(2) | targetType(1) | pubkey(33)
| [createdAt(8) | contentHash(32)] | [eventId(32)] | signature(64)
```

**Signed data** (the bytes below, excluding `signature`):

```
transType(2) | targetType(1) | pubkey(33) | [createdAt(8) | contentHash(32)] | [eventId(32)]
```

| Field | Description |
|-------|-------------|
| `transType` | Transmission type of the target events (`0` = all, `1` = JSON, `2` = String, `3` = Binary, `4` = Signed, `5` = Encrypted) |
| `targetType` | How to select the target events (see below) |
| `pubkey` | Public key of the events to delete (only your own pubkey can be used) |
| `createdAt` | Only for `targetType=1`. Creation time (seconds) of the event to delete |
| `contentHash` | Only for `targetType=1`. SHA-256 (32 bytes) of the event's `content` to delete |
| `eventId` | Only for `targetType=2`. Event ID (32 bytes) of the full-event-signed event to delete |
| `signature` | ECDSA signature (64 bytes) of the above "signed data" made with the author's private key |

Values of `targetType`:

| Value | Constant | Delete target |
|-------|----------|---------------|
| `0` | `DelTargetPubkey` | All events of that public key, within the given `transType` |
| `1` | `DelTargetEvent` | The specific event whose `createdAt` and `contentHash` match |
| `2` | `DelTargetEventId` | The specific event whose `eventId` matches (recommended for full-event-signed events) |

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
per-type database (json / string / binary / signed / encrypted).

The LMDB map size (the upper bound for stored data) defaults to **256 MB**.
When the limit is reached, writes start to fail, so set a large enough value via
`FODPR_DB_MAPSIZE` if you plan to accumulate data long-term. Note that the map
size is only a virtual reservation and the file grows on demand, but on a 1 GB
machine it is safer not to set it much larger than the physical memory.

## Security notes

- Posting, subscribing, and deleting all work over plain `ws://` as well.
  For production use, **wss://** (terminate TLS with a reverse proxy etc.) is recommended
- Subscribing to and viewing **public** events is open — this relay is intended
  to operate as a public relay. Subscribing to **recipient-limited** events
  (`to:` tag) requires AUTH (read authentication)
- LMDB files are encrypted, but like any encryption software, plaintext may
  transiently exist in OS memory or swap

## Directory Layout

```
FodprRelay/
├── src/
│   ├── server.nim      # The relay server
│   └── ws_limited.nim  # WebSocket library (vendored, with a 16 MB inbound frame cap)
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
