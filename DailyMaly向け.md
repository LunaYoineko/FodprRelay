# DailyMaly 向け: Fodpr の E2EE メール対応状況への回答

> この文書は、DailyMaly 開発時の検討で「Fodpr は E2EE メールに足りない」と
> 指摘された点（メタデータ非署名・暗号化なし・読取認証なし・スレッド参照なし・
> 鍵スキーム・アドレス解決）に対する回答です。
> 指摘のうち **1〜4 は実装済み**、**5 は設計判断として問題なし**、**6 は今後の課題**です。

---

## 結論

DailyMaly に必要な E2EE メールの構成要素は、現在の Fodpr で揃っています。

| 要件 | 状況 | 実装 |
|------|------|------|
| メール本文の機密性（E2EE） | **実装済み** | TransTypeEncrypted + envelope.nim（宛先別暗号化エンベロープ） |
| 送信者・メタデータの完全検証 | **実装済み** | TransTypeSigned（全フィールド署名）+ イベント ID |
| 宛先本人だけが読める制御 | **実装済み** | `to:<fpub>` + 読取認証 AUTH（NIP-42 相当） |
| 返信・スレッドの参照 | **実装済み** | `e:<eventId>` タグ（イベント ID による厳密参照） |
| リレーに内容を読まれない | **実装済み** | リレーはエンベロープの構造のみ検証し復号しない |
| 人に読めるアドレス（user@domain 等） | **未実装**（課題） | NIP-05 相当の解決機構は今後の実装項目 |

---

## 指摘 1. 署名が本文のみでメタデータが無防備 → 実装済み

**従来の Fodpr（TransType 1〜3）は content のみに署名していた**ため、
`createdAt`（送信日時）や `pubkey`（送信者）、`tags` をリレーが改ざんしても
検出できませんでした。

**対応: TransTypeSigned（値 4）= 全体署名イベント**を追加しました。

- `signature` を除く全フィールド（`transType | createdAt | pubkey | tags | content`）
  を署名対象にします（`encodeEventSignedData(ev)`）。
- この署名対象バイト列の **SHA-256 がイベント ID（`eventId`）** になります。

```nim
let evId = eventIdHex(ev)                     # 64 桁の 16 進文字列
let ok   = verifyEvent(ev.pubkey, ev, ev.signature)  # 全フィールド署名の検証
```

メール用途では、**日時・送信者・宛先タグの改ざんを検出**できるため、
「なりすまし」「改竄されたヘッダ」を防げます。

## 指摘 2. 暗号化レイヤーがない → 実装済み

**対応: TransTypeEncrypted（値 5）と envelope.nim（宛先別暗号化エンベロープ）**を
追加しました。gift-wrap / seal に相当する方式です。

エンベロープのバイナリ形式（すべてビッグエンディアン）:

```
version(1) | recipientCount(2) |
(recipientPubkey(33) | wrapNonce(12) | wrappedKey(32) | wrappedKeyTag(16)) × recipientCount |
bodyNonce(12) | bodyTag(16) | bodyCiphertext
```

鍵スキーム:

- 本文は**メッセージ鍵 K（32 バイト乱数）で AES-256-GCM 暗号化**
- K は各受信者向けに **ECDH 共有鍵から導出したラップ鍵 W** でラップ
  - `W = SHA-256(ECDH(送信者秘密鍵, 受信者公開鍵) || "FodprEnvelopeV1" || 受信者公開鍵)`
- 受信者は `ECDH(自分の秘密鍵, 送信者の公開鍵)` で W を復元し、K を取り出して復号

```nim
# 送信: 複数受信者へ（一括送信・CC 対応）
let envelope = encryptEnvelope(body, senderPriv, @[recip1.publicKey, recip2.publicKey])
# 受信: イベントの pubkey（= 送信者）と自分の秘密鍵で復号
let body = decryptEnvelope(ev.content, myPriv, ev.pubkey)
```

**リレーは本文を復号できません。** サーバー側は構造の検証と受信者一致の確認だけを
行います（`isValidEnvelope` / `envelopeRecipients`）。保存レコードも AES-256-GCM で
暗号化されるため、ディスク上でも E2EE の意味を保ちます。

## 指摘 3. 読取認証がない → 実装済み

**対応: AUTH（0x04）/ CHALLENGE（0x82）** を追加しました。NIP-42 相当です。

```
1. クライアント → REQ(subId, tagKey="to", tagVal=fpub)
2. サーバー     → チャレンジ nonce(32)
3. クライアント → AUTH: nonce(32) | pubkey(33) | signature(64)
4. サーバー     → 認証OK の購読にのみ宛先限定イベントを配信
```

- `to:<fpub>` 宛先限定イベントは、**宛先本人として認証した購読にしか配信されません**
- 認証失敗の購読には配信しない（存在も明かさない）
- 公開イベントは従来どおり認証なしで購読可能

メール用途では「**自分宛てのメールを他人が購読できない**」ことを保証します。

## 指摘 4. スレッド参照がない → 実装済み

**対応: イベント ID と `e:<eventId>` タグ**を追加しました。

- 全体署名イベントはイベント ID で**一意に参照可能**
- 返信は `e:<元メールのeventId>`、関係者は `p:<fpub>`、宛先は `to:<fpub>` で表現

```nim
var reply = FodprEvent(
  transType: TransTypeEncrypted,
  pubkey: kp.publicKey,
  tags: @["e:" & parentEventId, "to:" & recipientFpub],
  content: envelope)
```

メール用途では「返信・転送・スレッド結合」を厳密に表現できます。
さらに DEL に `DelTargetEventId`（値 2）を追加したので、
イベント ID を指定した削除も可能です。

## 指摘 5. 署名スキームが異なる（ECDSA vs Schnorr）→ 設計判断として問題なし

- Fodpr は **secp256k1 上の ECDSA**、nostr は **BIP-340 Schnorr** です。
  これは「nostr 互換にするか」ではなく「自前プロトコルの鍵として何を使うか」の
  選択であり、Fodpr は nostr の互換実装ではないため **問題になりません**。
- メールに必要な「署名で送信者を検証」「ECDH で鍵共有」は、どちらのスキームでも
  提供されます。Fodpr は `nim-secp256k1` の ECDSA + ECDH を利用しています。
- Schnorr の利点（鍵集約・バッチ検証・Taproot）は**メール用途では必須ではありません**。
- 両者とも **secp256k1 曲線上の公開鍵**であるため、公開鍵・秘密鍵の形式は
  互換性があり、将来の移行も鍵を変えずに可能です。

## 指摘 6. アドレス解決（NIP-05 相当）がない → 今後の課題（ロードマップ）

`fpub1...` という鍵文字列のままでは「誰に送るか」が人間に扱いにくいため、
**user@domain 形式のアドレス → fpub の解決機構**が必要です。これは未実装です。

実装候補（採用は DailyMaly 側と相談して決めたい）:

| 方式 | 概要 | 特徴 |
|------|------|------|
| DNS TXT | `_fodpr.<domain>` の TXT に `fpub=<fpub>` を置く | サーバー不要・中央機関なし。解決が速い |
| WebFinger / well-known | `https://<domain>/.well-known/fodpr.json` に fpub を置く | NIP-05 相当で実績がある。HTTPS が必要 |
| リレー内レジストリ | `user@domain` をリレーに登録して解決 | リレーが提供するが、リレーを信頼する必要 |

---

## まとめ: DailyMaly の要件との対応表

| DailyMaly の要件 | Fodpr の対応 |
|------------------|--------------|
| メール本文の機密性 | TransTypeEncrypted + envelope.nim（AES-256-GCM + ECDH ラップ） |
| 送信者認証 | 全体署名（TransTypeSigned）で日時・送信者・タグも検証 |
| 受信者限定 | `to:<fpub>` + リレーの受信者一致検証 + 読取認証 AUTH |
| 返信・スレッド | `e:<eventId>` タグ + イベント ID |
| 一括送信 / CC | エンベロープの recipientCount が複数受信者に対応 |
| 削除 | DEL + DelTargetEventId（イベント ID 指定、署名必須） |
| リレー非信頼 | サーバーは本文を復号不能。E2EE はエンドツーエンドで維持 |
| 人間に読めるアドレス | **未実装**（DNS TXT / WebFinger / レジストリのいずれかを導入） |

Fodpr は DailyMaly の E2EE メール基盤として十分に使えます。
残る課題はアドレス解決（指摘 6）だけで、これは Fodpr 側・DailyMaly 側の
いずれでも実装できる独立した機能です。
