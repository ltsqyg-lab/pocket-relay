# Pocket end-to-end encryption — protocol v1

Status: implementation spec, phase 1 (2026-10-08); §6 pairing code replaces the six verification words (2026-10-09).
The key words MUST, SHOULD and MAY are used as in RFC 2119.
Companion documents: [RELAY.md](RELAY.md) (open-source relay), [COORD.md](COORD.md) (coordination server API),
[ASR.md](ASR.md) (speech recognition), [MAPPING.md](MAPPING.md) (old endpoints → new), [BUILD-PLAN.md](BUILD-PLAN.md).
Reference implementation and test vectors: [gen-vectors.mjs](gen-vectors.mjs), [vectors.json](vectors.json)
(`node docs/protocol/gen-vectors.mjs --check`); device pairing (§6): [pake.mjs](pake.mjs)
(`node --test docs/protocol/pake.test.mjs`).

> **中文摘要**　每台设备自己生成两把 P-256 钥匙(签名 + 密钥交换),私钥不出设备。账号里「哪些设备可信」记在一条
> 只能追加、每条都由已有可信设备签名的「设备锁日志」里:协调服务器只存、只转,伪造不了(§5)。新设备加入时显示一个
> 6 位数配对码,用户在已有的管理设备上输入,两边跑 SPAKE2:服务器拿不到码、没法离线猜,在线猜一次只有百万分之一(§6)。内容按**电脑**分「领域」:每台电脑自己生成内容钥匙(分代,撤销设备时换代),
> 用对方的公钥包好发给允许看它的手机(§8)。手机和电脑之间的命令、事件是签名 + 加密的信封(§9);会话记录、附件是
> 电脑签名加密后存到中继的对象和分块密文(§10、§11)。中继只凭协调服务器签发的短期票据放行,并要求设备当场用私钥证明身份(§12、§13)。
> 算法:ECDSA P-256 / ECDH P-256 / HKDF-SHA256 / AES-256-GCM,JSON + base64url。

---

## 1. Goals and non-goals

Goals
- The operator of the coordination server, of any relay and of any object store cannot read conversation content,
  attachments, approval cards, commands, usage figures, project paths or model lists (the "content", §14).
- A compromised coordination server cannot add a device that the user's devices will trust, cannot hand devices a
  content key it knows, and cannot lift an access restriction (device lock, §5).
- A revoked device loses relay access at once and cannot decrypt anything written after the next key epoch (§8.3).
- Relays and object stores are interchangeable and may be self-hosted; they never hold secrets of ours (§12, RELAY.md).
- Every construction is standard and available natively on iOS (CryptoKit), Android (javax.crypto / Keystore),
  Node.js 22 and Bun (§15).

Non-goals (v1)
- Hiding metadata: who talks to whom, when, sizes, IP addresses (§14).
- Protecting against the publisher of the App or desktop agent shipping a malicious build, or against malware running as
  the same OS user on a device.
- Forward secrecy per message. Content keys rotate per epoch (§8.3), not per message.
- Direct device-to-device connections. All traffic goes through one relay per account (RELAY.md).
- Recovery codes. If every device of an account loses its keys, the account starts a new lock (§5.6) and computers
  re-upload from the original transcripts they hold.

## 2. Parties and threat model

| Party | Runs | Holds | Can | Cannot |
|---|---|---|---|---|
| Phone (App) | user | its private keys; realm keys it was granted; decrypted cache | read and command computers its ACL allows | — |
| Computer (desktop agent + tray) | user | its private keys; its own realm keyring; original transcripts | write its realm; approve devices | — |
| Coordination server | Pocket (closed source) | accounts, password hashes, device public keys, the lock log, ACL (inside the log), relay registry, grants (ciphertext), coordination signing keys | issue/withhold tickets, suspend devices, see metadata, deny service | forge lock statements, read grants, mint content keys, make a computer obey an unknown device |
| Relay | Pocket (official) or the user (self-hosted), open source AGPL-3.0 | ciphertext envelopes, objects, blobs; ticket verification keys | drop, delay, reorder, replay ciphertext; see metadata | read or forge content; impersonate devices |
| Object store (S3-compatible) | a cloud provider | ciphertext blobs | same as relay for blobs | same as relay |
| ASR gateway | Pocket (official), the user, or nobody | audio for the length of one request (cloud modes only) | hear audio in cloud modes | — (see ASR.md) |

Assumptions: TLS (WebPKI) protects transport; device OS key storage protects private keys against other OS users and
offline disk access; the user types the pairing code shown on the new device into a device they already trust (§6).

Residual risks the UI and privacy policy must state: metadata (§14); a malicious coordination server can hide lock
statements from some devices (withholding / equivocation, §5.5) — detectable, not preventable; cloud voice modes
necessarily let the gateway hear the audio (the privacy policy says where recordings go); whoever ships the clients could ship a backdoor (mitigated only by publishing this spec
so others can check behaviour against it).

## 3. Conventions

### 3.1 Encodings
- **base64url**: RFC 4648 §5 alphabet, **no padding**. Decoders MUST reject `=`, whitespace, characters outside the
  alphabet, length ≡ 1 (mod 4), and non-canonical trailing bits (re-encoding must give the same string).
  Written `b64u(x)` below. Vectors: `encoding.b64u`, `encoding.b64uInvalid`.
- **JSON**: RFC 8259, UTF-8, no byte-order mark; the top level of every signed or encrypted JSON value is an object.
  Integers are JSON numbers within ±(2^53−1), written without fraction or exponent (`2`, never `2.0` or `2e0`;
  receivers MAY reject other spellings). Time is milliseconds since the Unix epoch (`ts`, `at`, `iat`, `exp`).
  Signers MUST NOT emit duplicate object keys; verifiers SHOULD reject them where their parser allows.
- **Exact bytes rule**: whatever is signed or used as AEAD associated data is transmitted as the exact bytes that were
  signed (base64url inside JSON, or raw in binary framing). Receivers verify those bytes and only then parse them.
  No canonical-JSON step exists anywhere in this protocol.
- `||` is concatenation, `U32BE(n)` / `U64BE(n)` are big-endian unsigned integers, `UTF8(s)` the UTF-8 bytes of `s`.

### 3.2 Algorithm suite v1
| Use | Algorithm |
|---|---|
| Signatures | ECDSA over P-256 with SHA-256. Signature = `r \|\| s`, 32 bytes each, big-endian (IEEE P1363, 64 bytes). DER is not accepted. Randomized or RFC 6979 nonces are both fine; verifiers MUST reject r or s outside [1, n−1]. Signatures are not unique (`s` and `n − s` both verify): never use signature bytes as an identifier or a de-duplication key. |
| Key agreement | ECDH over P-256; the shared secret is the 32-byte big-endian x-coordinate. |
| KDF | HKDF-SHA256 (RFC 5869). An empty salt means HashLen zero bytes. |
| AEAD | AES-256-GCM, 96-bit nonce, 128-bit tag appended to the ciphertext. |
| Hash / MAC | SHA-256, HMAC-SHA256. |
| Compression | raw DEFLATE (RFC 1951), only where a header says `"zip": "deflate"` (§10.7). |

### 3.3 Keys on the wire
- Public keys: uncompressed SEC1 point, 65 bytes (`0x04 || X || Y`), as `b64u` (87 characters).
  Receivers MUST check the length, the `0x04` prefix, `X, Y < p`, and that the point is on the curve before any use
  (compressed points are rejected). Vectors: `ecdsa.invalidPublicKeys`.
- Private keys never appear on the wire. Test vectors include private scalars only as test material.

### 3.4 Domain separation
Every signature covers

```
SigInput(label, h, c) = UTF8("pocket/v1 " + label) || 0x00 || U32BE(len(h)) || h || c
```

where `h` is a header or payload (bytes) and `c` the ciphertext (empty when nothing is encrypted).
Labels: `lock`, `env`, `obj`, `grant`, `ticket`, `netmap`, `revocations`, `purge`, `keys`, `relay-auth`, `asr-auth`,
`enroll-auth`.
A verifier MUST use the label of the structure it expects; a valid signature under one label never validates another
(vector: `coord.labelConfusion`). KDF info strings, hash prefixes and HMAC messages also begin with `pocket/v1 ` —
except in the pairing (§6.2), which keeps RFC 9382's `ConfirmationKeys` and uses `pocket-pair/1` and `pocket-pair-w`;
none of these starts with `pocket/v1 `, so they cannot collide with the strings above.
Vector: `encoding.sigInput`.

### 3.5 Signed documents and seals
- **Signed document**: JSON `{"p": b64u(payload), "s": b64u(signature)}` with `signature` over
  `SigInput(label, payload, "")`. Used for lock statements (label `lock`, signed by a device) and coordination documents
  (§12, signed by a coordination key). A ticket is the same thing written compactly as `b64u(payload) + "." + b64u(signature)`.
- **Seal**: the triple `(h, c, s)` — header bytes, ciphertext, signature over `SigInput(label, h, c)`. Two encodings
  carry the same three byte strings and MUST be accepted wherever the transport allows:
  - JSON form: `{"h": b64u(h), "c": b64u(c), "s": b64u(s)}` (WebSocket frames, control messages, coordination storage);
  - binary form: `U32BE(len h) || h || U32BE(len c) || c || s` (64-byte `s`). A **seal stream** is binary forms
    concatenated with nothing in between (bulk HTTP, RELAY.md §7). `2 ≤ len(h) ≤ 4096`.
  Vectors: `encoding.sealJson`, `encoding.sealBinaryHex`, `encoding.sealStreamOfTwoHex`.

### 3.6 SEAL and OPEN
Every encrypted structure carries, in its plaintext JSON header `h`, a random `id` (16 bytes) and `nonce` (12 bytes):

```
k = HKDF-SHA256(IKM, salt = id, info = UTF8("pocket/v1 " + label + " key"), L = 32)
c = AES-256-GCM-Encrypt(k, nonce, plaintext, aad = h)          # ciphertext || tag
```

OPEN recomputes `k` and decrypts with the same `aad = h`. `id` and `nonce` MUST come from a CSPRNG and MUST NOT be
reused with the same IKM. The per-structure key makes nonce collisions under one content key harmless and separates
labels. IKM is a 32-byte realm epoch key (§8) for `env` and `obj`, and the ECIES input of §8.4 for `grant`.
Vectors: `seal` (with the derived key shown).

### 3.7 Identifiers
| Name | Definition | Form |
|---|---|---|
| device id (`did`) | `SHA-256(UTF8("pocket/v1 did") \|\| 0x00 \|\| sigPub \|\| kxPub)[0:12]` | b64u, 16 chars |
| key id (`kid`) of a realm key K | `HMAC-SHA256(K, UTF8("pocket/v1 kid"))[0:16]` | b64u, 22 chars |
| random ids (`id`, blob ids, dispatch ids) | 16 bytes from a CSPRNG (dispatch ids: `"d_"` + b64u(9 bytes)) | b64u |
| virtual address (`addr`) | assigned by coordination, unique, inside 100.64.0.0/10, dotted quad without leading zeros | e.g. `100.71.4.9` |
| account (`acct`) | the coordination account id (today's `users.id`) | string |

The device id is self-certifying: anyone recomputes it from the two public keys, so nobody can attach an existing id
to other keys. The virtual address is Pocket's own addressing (like a Tailscale IP); nothing installs a network
interface and no OS traffic is routed through it.

## 4. Device keys

### 4.1 Two key pairs per device
Each phone and each computer generates, on first use of protocol v1, with a CSPRNG:
- `sig` — ECDSA P-256 signing key (identity: lock statements, envelopes, objects, grants, relay proofs);
- `kx` — ECDH P-256 key-agreement key (receives grants).

Separate pairs because platform keystores bind a key to one purpose and because this keeps signature and key agreement
from sharing a key. Private keys MUST NOT leave the device, MUST NOT be logged, uploaded, synced to a cloud backup or
included in diagnostics. Storage requirements per platform are in §15. Deleting the App, logging out (§5.7) or
resetting the agent discards both keys; the next run is a **new device** (new id, needs approval).

### 4.2 Device entry
How a device appears in the lock (exactly these eight keys, nothing else):

```json
{ "id": "<did>", "kind": "phone" | "computer", "platform": "ios" | "android" | "mac" | "windows" | "linux",
  "name": "<1-64 code points, no C0/C1 controls, no bidi controls>", "addr": "100.x.y.z",
  "sig": "<b64u 65-byte point>", "kx": "<b64u 65-byte point>", "admin": true | false }
```

`id` MUST equal the did of `sig` and `kx`. `admin` devices may sign lock changes (§5.2). The name is the one shown
when approving; the user can see it was signed (renaming = not supported in v1).

## 5. The device lock

The account's set of trusted devices, their access rules and each computer's key epochs are an append-only, hash-chained
log of **lock statements**. Every statement is a signed document (label `lock`) produced by a device. The coordination
server stores the log, validates it and serves it, but holds no key that can produce a statement.
Each device verifies the whole log from the genesis it trusts; this is what makes "the operator cannot add a device"
true (the equivalent of Tailscale's Tailnet Lock).

### 5.1 Statement payload
```json
{ "v": 1, "t": "lock", "acct": "<account id>", "seq": 1, "prev": null | "<b64u SHA-256 of the previous payload>",
  "ts": 1791417660000, "by": "<did of the signer>", "op": { "type": "…", … } }
```
`seq` starts at 1 (the genesis) and increases by exactly 1. `prev` is the hash of the previous statement's payload
bytes (null for the genesis). The **head** is `{seq, h}` with `h = b64u(SHA-256(payload))` of the last statement.
The genesis hash `G = SHA-256(payload of statement 1)` identifies the lock. Payloads are at most 16 KiB.

### 5.2 Operations
| `op.type` | Fields | Who may sign | Effect |
|---|---|---|---|
| `genesis` | `device` (device entry, `admin: true`), `resetOf?` `{genesis, seq, h}` | the device itself; only as statement 1 | first trusted device; `resetOf` declares a reset of an earlier lock (§5.6) |
| `add` | `device`, `sas` (boolean: `true` = the approver paired with the device; `false` only in logs from before 2026-10-09, §6.4) | an admin | trust a new device (§6) |
| `revoke` | `device` (did), `reason?` (≤64 chars) | an admin, or the device itself | permanent; the id can never be added again |
| `policy` | `acl` (full ACL document, §7), `admins?` `{did: bool}` | an admin | replaces the ACL; changes admin flags |
| `realm` | `realm` (did of a computer), `epoch`, `kid`, `reason` ∈ `init`, `revoke`, `acl`, `rotate`, `reset` | **only that computer** | commits to the computer's next content-key epoch (§8) |

### 5.3 Validation (normative)
Start from `state = {acct, seq: 0, head: null, genesis: null, devices: {}, acl: {phones: {}, computers: {}}, realms: {}}`
and apply statements in order; any failure rejects that statement and everything after it. Reference: `applyStatement`.

1. Decode `p` and `s` strictly; parse the payload (≤16 KiB). Require `v = 1`, `t = "lock"`, integer `seq ≥ 1` and `ts ≥ 1`,
   a did in `by`, an object `op` — else `bad-format`.
2. `acct` equals the account → else `bad-acct`. `seq = state.seq + 1` → else `bad-seq`. `prev` equals `state.head.h`
   (or null at seq 1) → else `bad-prev`.
3. Signer: at seq 1 `op.type` must be `genesis` (`not-genesis`), the device entry must be valid with `admin: true` and
   `by = device.id` (`bad-device`); later a `genesis` is `bad-op`, and the signer must exist (`unknown-signer`) and not be
   revoked (`revoked-signer`).
4. Verify `s` over `SigInput("lock", payload, "")` with the signer's `sig` key → else `bad-sig`.
5. Apply the operation:
   - `add`: signer is admin (`not-admin`); device entry valid (`bad-device`); `sas` boolean (`bad-op`); id never seen
     before (`dup-device`); address not used by a live device (`dup-addr`).
   - `revoke`: target exists and is live (`bad-target`); signer is admin or the target itself (`not-admin`);
     at least one live admin remains (`last-admin`).
   - `policy`: signer is admin (`not-admin`); ACL valid per §7.1 and `admins` only names live devices with boolean
     values (`bad-acl`); at least one live admin remains (`last-admin`).
   - `realm`: `by = op.realm` and the signer is a computer (`not-owner`); `epoch = current epoch of that realm + 1`
     (first is 1) (`bad-epoch`); `kid` is 16 bytes b64u and `reason` from the list (`bad-op`). Record `kids[epoch] = kid`.
   - unknown `op.type`: `bad-op`.
6. `state.seq = seq`, `state.head = {seq, h}`, and at seq 1 `state.genesis = h`.

Vectors: `lock.chain` (9 statements), `lock.states` (state after each), `lock.invalid` (16 rejections with their code).

### 5.4 Appending
A device appends by sending the statement to coordination with its `prev` equal to the head it knows; coordination
accepts only if that is still the head (compare-and-swap) and the statement validates. On conflict the device fetches
the new statements, re-validates, re-checks its intent (e.g. the device it wanted to add may already be there) and
signs again with the new `prev`. Statements are small and rare; there is no merging of forks.

### 5.5 Head gossip and fork detection
Envelopes carry the sender's head (`lock` field, §9.1). A receiver whose verified head is older fetches the log from
coordination. If coordination cannot produce statements leading to the gossiped head, or a peer reports a different hash
for the same `seq`, the device MUST show a security warning ("the server may be hiding device changes") and SHOULD
fetch the missing statements from the peer (op `lock`, §9.5). It keeps working with the statements it can
verify; it never accepts statements it cannot verify.

A device that appends a `revoke` or a restricting `policy` SHOULD also send the statement directly to every computer
it can reach (`rpc` op `lock`), so a coordination server that withholds the change from a computer is bypassed; a
computer that learns of a revocation this way stops accepting the revoked device at once and rotates (§8.3).

### 5.6 Reset (every device lost)
If no device holding a trusted key remains, the user resets from a new device: coordination requires the password and a
fresh email code (COORD.md §12), then accepts a new log whose genesis carries `resetOf = {genesis: G_old, seq, h}`.
Existing devices that still hold the old lock and see a new genesis with `resetOf.genesis = G_old`:
- MUST NOT trust any device of the new lock automatically;
- MUST stop sending content to devices they do not already trust;
- show "the device lock of this account was reset — if this wasn't you, change your password" and only after the local
  user confirms on that device, join the new lock as a new device (§6), pairing with a code again.
A computer that joins a reset lock creates realm epoch 1 again (`reason: reset`) and re-uploads its sessions from the
original transcripts. Vector: `lock.reset`.

### 5.7 Coordination-level suspension vs. lock revocation
Two different things:
- **Suspension** (coordination only): logging a device out, "log out all devices", disabling an account. Coordination
  stops issuing tickets, publishes a ticket cut-off for the device's address (§12.4) and pushes it to relays.
  Suspension is reversible (a fresh login of the same device lifts it); it needs no signature because it can only reduce
  access. Computers MUST also refuse commands from suspended devices (`suspended-sender`).
- **Revocation** (lock, signed): permanent; triggers key rotation (§8.3). When the user logs out a phone, the App signs
  a self-revoke and deletes its keys; a later login is a new device.

## 6. Adding a device: the pairing code

> 中文摘要　新设备 B 显示一个 6 位数**配对码**(「482 913」,所有语言都是数字),用户在已经在锁里的管理设备 A 上**输入**它;
> 两边拿这个码当口令跑 SPAKE2(RFC 9382)。服务器只转发看不懂的四个值,猜码只能在线一次一猜(每次一百万分之一),
> 每个待批准条目最多 5 次;B 核对过 A 的确认值才钉住锁,A 核对过 B 的确认值才签 `add`,新设备上不用再点任何东西。
> 参考实现 [pake.mjs](pake.mjs),向量 `spake2` / `pair`。接口见 COORD §4.5 配对。

### 6.1 Flow
`A` = the approver: a device that is live and admin in the lock it pinned, in front of the user. `B` = the new device.
`G` = the 32-byte genesis hash (§5.1). Endpoints and pushes: COORD §4.5 (pairing).

```
new device B                         coordination                             approver A (live admin)
generate sig, kx
login (password) ──────────────────▶ enroll {name, platform, sig, kx, proof (§13)}
           ◀──────────────────────── {pendingId, did, addr, lock head, genesis}  ── enroll_pending ──▶
fetch + validate the lock from its genesis G
code ← 6 random digits; show "482 913"
pB ← startB(code, ctxW)   (§6.2)
POST /v2/pair/offer {pendingId, attempt, pB} ──── pair_offer {pendingId, attempt, pB, name, platform, sig, kx} ──▶
                                                                            the user types the code shown on B
                                                                            pA, cA ← answerA(code, ctx, pB)
           ◀──── pair_answer {pendingId, attempt, by: A's did, pA, cA} ──── POST /v2/pair/answer
sigA, kxA ← A's entry in the lock B validated
check cA → pins G
POST /v2/pair/confirm {pendingId, attempt, cB} ──── pair_confirm {pendingId, attempt, cB} ──▶ check cB
           ◀──────────────── push lock ◀──── statement add{device: B, sas: true} signed by A (CAS on head, §5.4)
B sees itself in the verified log of its pinned G, obtains tickets, receives grants (§8.4)

cA wrong → B: POST /v2/pair/fail {pendingId, attempt}, shows a new code, offers attempt + 1 (at most 5 per entry)
```

The new device trusts the lock it downloaded only because the pairing succeeded: the code is shown on B alone, the user
types it on A, and the key confirmation binds the code to `G`, to both devices' keys, to the account, the pending entry
and the attempt (§6.2). A coordination server that shows B a fake lock, shows A substituted keys for B, or names another
admin as the one that answered makes the two sides derive different keys, and the confirmation fails as it does for a
mistyped code. **Both** devices act only on a verified confirmation (normative):
- B **pins `G` only after `cA` verified** — this replaces the local "They match" of the first release and is the
  phase-3 H1 requirement (a coordination server must not be able to show B a lock of its own making, with a genesis by a
  device it controls and an `add` for B, and have B accept it without any human involved). Until B has pinned a genesis it
  MUST NOT act as a member of any lock it was shown — a computer creates no realm, grants nothing and connects to no
  relay; a phone sends no commands and approves nothing — even if that lock contains an `add` for B. B turns on when it
  sees itself added in the log that descends from its pinned `G`; a lock with another genesis never turns it on.
- A **signs the `add` only after `cB` verified**, and adds exactly the device whose keys were in the context (name,
  platform and address from the pending entry). Nothing on B needs to be tapped: after the user typed the code on A, both
  sides finish by themselves.

Exceptions: the device that creates a genesis (or a reset genesis, §5.6) pins its own `G`; a device whose keys changed
keeps the `G` it had pinned (still the same person's lock); a device that has not pinned a genesis pairs against whichever
lock coordination shows it — the pairing succeeds only if that is the lock the approver holds.

### 6.2 SPAKE2 with Pocket's context
Ciphersuite **SPAKE2-P256-SHA256-HKDF-HMAC** of RFC 9382 (§3.3, §4, §6). Roles: A uses `M`, B uses `N`. `P` is the
P-256 base point (RFC 9382 calls it P; this document uses `G` for the genesis hash), `n` the group order (cofactor 1).

```
code  = 6 ASCII digits, uniform over "000000"–"999999" (CSPRNG; a new code for every attempt)
M     = 02886e2f97ace46e55ba9dd7242579f2993b64e16ef3dcab95afd497333d8fa12f      # RFC 9382 §6, SEC1 compressed
N     = 03d8bbd6c639c62937b04d997f38c3770719c629d7014d49a24b4f98baa1292b49
L16(s) = U16BE(len(UTF8(s))) || UTF8(s)                                    # acct and pendingId: 1–255 bytes
base  = UTF8("pocket-pair/1") || L16(acct) || L16(pendingId) || U8(attempt) || G   # attempt 1–255; G as each side holds it
ctxW  = base || sigB || kxB                     # what B knows when it offers
ctx   = base || sigA || kxA || sigB || kxB      # the full context; sig, kx: 65-byte public keys (§3.3)
w     = OS2IP(HKDF-SHA256(IKM = UTF8(code), salt = 32 zero bytes, info = UTF8("pocket-pair-w") || ctxW, L = 48)) mod n
        # w = 0 is a failure: draw a new code (probability ≈ 2^−256)
x, y  = uniform in [1, n − 1] (rejection sampling), fresh for every attempt, kept in memory only
pA    = x·P + w·M                               # A
pB    = y·P + w·N                               # B
K     = x·(pB − w·N)    (A)    = y·(pA − w·M)    (B)          # the point at infinity is a failure (bad-point)
idA   = UTF8(acct + "/" + didA),   idB = UTF8(acct + "/" + didB)  # did of each side's two keys (§3.7)
TT    = len(idA) || idA || len(idB) || idB || len(pA) || pA || len(pB) || pB || len(K) || K || len(w) || w
        # len = 8-byte little-endian length; pA, pB, K as 65-byte SEC1 uncompressed; w as 32 bytes big-endian
Ke || Ka   = SHA-256(TT)                        # 16 + 16 bytes; Ke is not used
KcA || KcB = HKDF-SHA256(IKM = Ka, salt = empty, info = UTF8("ConfirmationKeys") || ctx, L = 32)   # AAD = ctx
cA    = HMAC-SHA256(KcA, TT),   cB = HMAC-SHA256(KcB, TT)                 # 32 bytes; compared in constant time
```
On the wire `pA`, `pB` are b64u of the 65 bytes and `cA`, `cB` b64u of the 32 bytes (COORD §4.5). Received points MUST be
exactly 65 bytes with prefix `0x04`, `x < p`, `y < p` and on the curve (with cofactor 1 that also puts them in the group;
the point at infinity has no 65-byte encoding); anything else fails the attempt (`bad-point`), as does `K` = infinity.
Scalar multiplications MUST NOT branch or vary their number of operations on secret bits (the reference uses a fixed
256-step Montgomery ladder over complete projective formulas).

Relation to RFC 9382 — the construction is the RFC's; these are the choices the RFC leaves to protocols, and two
departures from its sample flow:
- **Who knows what when.** B's offer goes out before any admin has answered, and an account usually has several admin
  devices (phones, and computers approved with `admin: true`), so B cannot know A's keys when it computes `pB`. `w`
  therefore derives from `ctxW`; A's keys are bound by `idA` in the transcript and by `ctx` as the AAD of the
  confirmation keys, both of which B computes when the answer arrives. (`ctx` is the context as first agreed; `ctxW` is
  the same bytes without `sigA || kxA`.)
- **Message order.** RFC 9382 §3.1 shows A's share first; here B's share travels first (the offer) and A's share travels
  together with `cA`. The two shares do not depend on each other, so the order does not affect security; the roles
  (A ↔ `M`, B ↔ `N`) are fixed and the confirmation order is the RFC's (`cA`, verified by B, before `cB`, verified by A).
- **No memory-hard function.** RFC 9382 §3.2 says `w` SHOULD come from an MHF of the password. An MHF slows an *offline*
  search by someone who holds `w` or a password verifier; here nothing holding either exists outside the two devices'
  memory during one attempt: the code is fresh per attempt and never stored or sent, and SPAKE2 gives a man in the
  middle one guess per run and no offline test (§6.7). HKDF-SHA256 keeps the derivation identical and cheap on every
  platform. 48 output bytes (≥ 256 + 64 bits) keep the bias of `mod n` below 2^−128, as RFC 9382 §3.2 advises.
- `x` and `y` come from [1, n − 1] instead of [0, n); `w` is bound to the pairing context instead of the bare password;
  identities are `acct/did`. All three are protocol choices the RFC allows.
- The labels `pocket-pair/1`, `pocket-pair-w` and the RFC's `ConfirmationKeys` do not start with `pocket/v1 ` (§3.4);
  none of them can collide with a string that does.

Reference implementation: [pake.mjs](pake.mjs) (MIT; `startB`, `answerA`, `finishB`, `confirmB`, `pairCtx`, `pairCtxW`,
`pairW`, `newPairCode`, `formatPairCode`, `parsePairCode`; tests `node --test docs/protocol/pake.test.mjs`). Vectors:
`spake2.rfc9382` (the RFC's four, which every implementation MUST reproduce), `spake2.invalidPoints`, `pair.valid` (three
complete runs with every intermediate value), `pair.invalid` (wrong code, another genesis, another admin, substituted
keys, another pending entry or attempt, a modified `cB`, `K` at infinity on either side), `pair.codes`.

### 6.3 Rules for the two sides (normative)
New device B:
1. After its enrollment is `pending` (COORD §4.1), B validates the lock coordination shows it from that lock's genesis.
   Then it offers: attempt 1, or the next number after the last one coordination has seen (a restarted B lost `y` and
   simply starts the next attempt).
2. Every attempt has a new code and a new `y`. B shows the code and keeps code, `y` and `w` in memory only — never in a
   file, a log or a request (the only exception is §6.6).
3. On the answer for its current attempt, B takes `sigA`, `kxA` of the device named in `by` from **the lock it validated**
   (never from the message); if `by` is not a live admin there, the attempt failed. Then it checks `cA`:
   - correct → B pins `G` (the genesis of that lock, the one in `ctx`), sends `cB`, and waits for its `add` (§6.1);
   - wrong, or `bad-point` → B reports the attempt as failed, forgets `y`, shows a new code and offers the next attempt.
   B uses at most one answer per attempt and ignores answers for other attempts.
4. B starts **at most 5 attempts** per pending entry and counts them itself (the count is not secret; persist it with
   `pendingId`). When the fifth has failed, or a sixth would be needed, B stops and asks the user to sign in again
   (coordination voids the entry too, but B MUST NOT rely on that). A "new code" action fails the current attempt and
   starts the next one; it counts.

Approver A:
1. Only a device that is live and admin in its own pinned lock answers, and only for a pending device of its account.
2. A builds `ctx` from its own account id, its own keys and pinned `G`, and from the pending entry: `pendingId`, the
   attempt of the offer, and B's `sig`/`kx`, which MUST hash to the entry's `did` (§3.7).
3. A uses a typed code for **one** attempt and answers each `(pendingId, attempt)` at most once: when the offer changes,
   the user types the new code. If A cannot answer (`bad-point`: only an attacker or a broken peer produces it) it sends
   nothing and tells the user the pairing failed and to get a new code on the new device.
4. On B's confirmation A checks `cB`: correct → A appends `add {device: B's entry, sas: true}` (§5.4) with exactly the
   keys that were in `ctx`; wrong → A does not sign and says the pairing failed. A keeps its side of an attempt in memory
   only (after a restart the attempt is lost and the user gets a new code on B).
5. There is no way to approve a device without pairing (the first release's "approve without comparing" is gone).

Coordination (COORD §4.5) relays the four values without being able to use them, keeps the order (offer → answer →
confirm or fail), voids a pending entry after its fifth attempt, rate-limits each call, and accepts an `add` only for a
device that completed a pairing with the statement's signer — a second line of defence; the devices' own checks above
are the first.

### 6.4 The `sas` field of `add`
`add` keeps its boolean `sas` so that devices running an earlier release keep validating new statements (§5.3 requires
the field). Since 2026-10-09 every new `add` carries `sas: true` — "the approver paired with this device (§6.2)" —
on every account, the demo account included; coordination refuses any other (`pair-required`). `sas: false` remains
valid where it already is: logs written before that date by approvers who skipped comparing the six verification words of
the first release (vector: statement 5 of `lock.chain`). Clients show no words any more and offer no comparison; they MAY
mark such devices "added without verification" in the device list (removing them is the only action). The six words
(SAS: BIP-39 indices of `SHA-256("pocket/v1 sas" || 0x00 || G || sigPub || kxPub)`), their word lists and `sasLang` are
no longer part of the protocol; `vectors.json` keeps its `sas` and `wordlists` entries only until every implementation
has removed that code.

### 6.5 Who creates the genesis
- **Phones** create the genesis when they log in to an account that has no lock.
- **Computers never create a genesis on their own.** A computer that signs in to an account without a lock stays
  `waiting` (COORD §4.1), syncs nothing (MAPPING.md §1) and shows that a phone has to sign in first; it becomes `pending`
  when the first phone creates the genesis, and then pairs with that phone. This avoids a computer-only lock that would
  force the user to approve their phone while sitting at the computer.
- Exceptions: the server-side demo computer (COORD §15) and a user-initiated reset from the tray (§5.6).

### 6.6 The review (demo) account
The demo account's only admin is the demo computer on the server (COORD §15): it has no screen and nobody can type into
it. When enrollment answers `demo: true`, B adds the code it shows to its offers (`demoCode`) and the demo computer runs
A with it; B's side is unchanged (it checks `cA`, pins `G`, sends `cB`), and the `add` carries `sas: true` like any other.
On this one account the code passes through coordination by design, which is acceptable only because the account holds
sample data. Only phones send `demoCode`; computers never do and ignore `demo: true` (reviewers use only a phone, and
the demo computer runs on the server). A phone MUST send `demoCode` only when coordination says `demo: true` **and** the
account the user signed in with is the review account built into the client: otherwise a malicious coordination
server could answer `demo: true` for a real account, learn the code and run A itself — the very attack the pairing
exists to stop.

### 6.7 Why six digits are enough
The attacker is coordination, or whoever controls it or the network beyond TLS. It wants B to pin a lock it controls,
A to add a device it controls, or the code itself.
- **No offline guessing.** A 6-digit code used as a hash input or MAC key could be searched by the server in well under a
  second. SPAKE2 leaves nothing to search: testing a candidate code `c` against an observed or self-made run needs
  `K_c = CDH(pA − w_c·M, pB − w_c·N)`, a gap Diffie–Hellman problem (RFC 9382 §7). The shares are uniformly distributed
  whatever `w` is and the confirmations are keyed by `K`, so watching runs teaches nothing about the code either.
- **One online guess per attempt.** Whoever plays A or B fixes its guess `w′` when it sends its share; the other side's
  confirmation check tells it right (probability 10^−6, the code being uniform) or wrong, and the attempt is used up.
- **Attempts are bounded by people, not by the server.** Playing A against B: B accepts at most 5 attempts per pending
  entry by its own count, and a new entry needs the user to sign in again — at most 5 × 10^−6 per sign-in. Playing B
  against A: every attempt needs the user to type a code on A, which answers each attempt once — one guess per typed code.
- **Binding.** `ctxW` (in `w`) and `ctx` (in the confirmation keys), together with the identities in `TT`, fix the account,
  the pending entry, the attempt, the genesis each side holds and both devices' keys. Any difference between the two
  sides' views — a fake lock for B, substituted keys for A, another admin named as the answerer, another entry or attempt —
  fails exactly like a wrong code (vectors `pair.invalid`), so it is caught with the same 10^−6 bound.
- **The code never travels** (except §6.6). It is read by the user from B's screen and typed on A; coordination sees
  `pA`, `pB`, `cA`, `cB`, attempt numbers and failures.
- **Compared with the six words:** the words carried 66 bits but relied on the user really comparing them and on taps
  that a misclick could give ("They match" by accident), and the approver could skip them. Typing the code makes the
  comparison impossible to skip, and nothing remains to tap by mistake.
- **Residual risks.** BigInt arithmetic is not constant-time at the machine level; the secrets live for one attempt in one
  process, and only something running on the same device could time them (out of scope, §1). The server can always
  deny service (drop messages, void entries). Someone who knows the password can create pending entries, but cannot
  finish one without the code being typed on an admin device — hence the approver's warning (§6.8).

### 6.8 What the user sees
- **B** shows the code as two groups of three ASCII digits — `482 913` — in every UI language, and the line
  「在已经登录的设备上输入这个配对码」 / "Enter this pairing code on a device that's already signed in", plus a
  "new code" action (§6.3). It asks nothing else; it continues by itself once the pairing succeeded. Computers show it
  in the tray (Mac menu bar, Windows notification area), phones on the waiting screen.
- **A** shows the pending device (name, platform) with 「输入新设备上显示的配对码」 / "Enter the pairing code shown on
  the new device", a six-digit field (numeric keyboard), and the warning 「如果你刚才没有在新设备上登录,不要输入,并修改密码。」 /
  "If you didn't just sign in on a new device, don't enter anything, and change your password." The term is
  「配对码」 / "pairing code" everywhere; nothing is compared by eye.
- **Typed input** is normalised before use (`parsePairCode`, vectors `pair.codes.parse`): NFKC, then every Unicode decimal
  digit (General Category Nd — full-width, Arabic-Indic, Persian, Devanagari, …) counts as its value, white space and
  dashes are ignored, and anything else or a count other than six is refused without computing.
- **A wrong code**: A says the code didn't match and asks for the new code now shown on the new device; after the fifth
  failure B asks the user to sign in again.

## 7. Access control (ACL)

### 7.1 Document
```json
{ "phones":    { "<phone did>":    { "computers": "*" | ["<computer did>", …], "control": true | false } },
  "computers": { "<computer did>": { "phones": "*" | ["<phone did>", …] } } }
```
No other keys are allowed at any level in v1 (`bad-acl`), so a future restriction cannot be silently ignored by an old
client. Keys of `phones` must be phone devices of the lock, keys of `computers` computer devices; lists likewise;
lists hold at most 256 entries. An absent entry means "no restriction". The empty document is the default.

### 7.2 Evaluation
```
access(P, C):
  if P or C is unknown or revoked, or P is not a phone, or C is not a computer: read = control = false
  read    = (no phones[P] or phones[P].computers = "*" or C ∈ phones[P].computers)
            and (no computers[C] or computers[C].phones = "*" or P ∈ computers[C].phones)
  control = read and (no phones[P] or phones[P].control ≠ false)
```
Phones never talk to phones and computers never talk to computers in v1. Reference: `access`; vectors: `acl.fromChain`,
`acl.documents`.

### 7.3 Enforcement points
- **Computers** are authoritative: they verify every envelope against the lock they hold (§9.3) and only grant their keys
  to devices with `read` (§8.5).
- **Coordination** derives each ticket's `peers` list from the same ACL (COORD.md §7); **relays** deliver and serve only
  between peers (RELAY.md §4). This is defence in depth and stops wasted traffic; it is not trusted for secrecy.
- **Phones** hide controls they lack; a restricted phone that is not admin cannot sign a `policy` that frees itself.

## 8. Realms, content keys and grants

### 8.1 Realms
Content originates on computers, so each computer owns one **realm**: everything it writes (sessions, messages,
attachments, usage, its info) and every command addressed to it is encrypted under the realm's keys. Each realm has a
**keyring**: epoch keys `K_1, K_2, …` (32 random bytes each). The lock records `kid(K_e)` for each epoch (§5.2), so
every device can check a key it receives. Derived values:

```
namesKey = HKDF-SHA256(K_1, salt = "", info = UTF8("pocket/v1 names"))
sk(sessionId, xv) = b64u( HMAC-SHA256(namesKey, UTF8("sess") || 0x00 || UTF8(sessionId) || 0x00 || UTF8(decimal xv))[0:16] )
```
`sk` is the opaque session key used as an object name at the relay (§10.4); `xv` is the agent's transcript-splitting
version (today's `extractVer`), so a new splitting rule writes a fresh namespace. Vectors: `kid`, `names`.

`namesKey` comes from the lowest epoch the computer holds — normally `K_1`. A computer that lost `K_1` (its keys and
its self-grant are gone) rotates (§8.3) and derives `namesKey` from the oldest epoch it still holds; every `sk` changes,
so it rewrites its `sess`, `msg` and `lite` objects under the new names and deletes the old ones. Phones never derive
names: they learn each session's `sk` from the `sess` objects the relay lists.

### 8.2 Creating a realm
When a computer first sees itself live in the lock it: generates `K_1`; appends `realm {epoch: 1, kid, reason: init}`;
grants the keyring to itself (a self-grant, so state loss without key loss is survivable) and to every phone with
`read` (§8.4); then starts writing objects.

### 8.3 Rotation
A computer MUST create epoch `e+1` (new random key, `realm` statement, grants of the full keyring to every device that
still has `read`, and a self-grant) as soon as it sees:
- a `revoke` of a device that had `read` on it (`reason: revoke`);
- a `policy` that removed `read` from some device (`reason: acl`);
- optionally on a schedule or user request (`reason: rotate`).
From then on it seals everything under the newest epoch. Old objects stay under their old epochs (the revoked device
may have downloaded them already; relays stop serving it at once, §12.4). Senders always use the newest epoch they hold;
receivers accept any epoch they hold.

### 8.4 Grants (wrapping keys for a device)
A grant is a seal with label `grant` from a granter device to one recipient device:

```json
h = { "v": 1, "t": "grant", "id": "<16 B>", "nonce": "<12 B>", "realm": "<computer did>",
      "to": "<recipient did>", "toKx": "<recipient kx, b64u>", "by": "<granter did>", "ts": …,
      "eph": "<b64u ephemeral P-256 public key>", "epochs": [ { "epoch": 1, "kid": "…" }, … ] }
plaintext = { "realm": "<computer did>", "keys": [ { "epoch": 1, "key": "<b64u 32 B>" }, … ] }   # same order as h.epochs
IKM = ECDH(eph_priv, recipient.kx) || ephPub(65) || recipientKxPub(65)
c   = SEAL(IKM, "grant", h, plaintext);   s = ECDSA(granter.sig, SigInput("grant", h, c))
```
A fresh ephemeral key per grant; the ephemeral private key is discarded immediately.

Recipient checks (reference `openGrant`), in order: header fields (`bad-header`); `to` and `toKx` are its own
(`not-for-me`); granter known and live (`unknown-sender`, `revoked-sender`); realm is a live computer (`bad-realm`);
authority: `by = realm`, or the granter is an admin with `read` on the realm (`denied`); signature (`bad-sig`); decrypt;
same realm and epochs in header and plaintext (`bad-grant`); each key's kid equals both the header and the lock's
`kids[epoch]` (`bad-kid`). A `bad-kid` can mean the recipient's copy of the lock is behind: refresh the lock once and
retry before treating it as an attack. Vectors: `grant`.

### 8.5 Who grants what
- The realm owner grants its keyring to every device with `read`: when it creates or rotates an epoch, and when it sees
  a new device with `read` (an `add` or a `policy` change).
- An admin phone MAY re-grant a realm keyring it holds to a newly added device that has `read` — so a new phone can read
  history while the computer is asleep.
- Grants travel only through coordination (COORD.md §6). They cannot ride the relay: envelopes are sealed under a
  realm key, and the device that needs a grant does not hold that key yet.
- Coordination accepts a grant only for the realm itself (a self-grant) or a device with `read` on it, and only when
  every epoch's `kid` in the header equals the `kid` the lock records for that epoch (`bad-kid`). A computer therefore
  appends its `realm` statement (§8.2, §8.3) before it uploads the grants of that epoch.
- Nobody ever grants to a device without `read` on that realm, nor to a revoked device.

## 9. Envelopes

Envelopes carry everything that moves between a phone and a computer in real time: commands, replies, events.
An envelope is a seal with label `env`, signed by the sender, encrypted under the realm's epoch key.

### 9.1 Header
```json
{ "v": 1, "t": "env", "id": "<16 B>", "nonce": "<12 B>",
  "from": "<sender did>", "to": "<recipient did>" | "*", "realm": "<computer did>",
  "epoch": 2, "seq": 1834411622400001, "ts": 1791417601000,
  "kind": "cmd" | "rpc" | "res" | "evt",
  "re": "<id of the request envelope; only and always on res>",
  "lock": { "seq": 9, "h": "<head hash>" },          // optional gossip, §5.5
  "zip": "deflate" }                                   // optional, §10.7
```
- `cmd`: phone → its computer, needs `control`. `rpc`: phone → computer, read-only operations, needs `read`.
- `res`: computer → the phone that sent the request; `re` names it. `evt`: computer → one phone or `"*"` (every
  phone with `read`; the relay fans out).
- `seq`: strictly increasing per sender across all of its envelopes. RECOMMENDED `seq = max(previous + 1, unixMillis × 1024)`
  so a restart without saved state still moves forward (stays below 2^53 until about the year 2248).
- Limits: header ≤ 4 KiB; ciphertext ≤ 1 MiB; inflated payload ≤ 1 MiB. Larger data goes in a blob (§11).

### 9.2 Sending
`c = SEAL(K_epoch, "env", h, payload)` with `payload` the UTF-8 JSON of §9.5 (deflated first if `zip`), then
`s = ECDSA(sender.sig, SigInput("env", h, c))`. The relay frame around it carries the routing (RELAY.md §5.2).

### 9.3 Receiving (normative order)
Nothing is decrypted before the signature and the ACL pass. Reference: `openEnvelope`.

1. Sizes (`too-large`); parse the header; `v = 1`, `t = "env"`, kind known; `id` 16 B, `nonce` 12 B; types of
   `from/to/realm/epoch/seq/ts`; `re` present exactly on `res`; `zip` absent or `deflate` (`bad-header`).
2. Sender in the lock (`unknown-sender`), not revoked (`revoked-sender`), not suspended (`suspended-sender`).
3. Addressed to me: `to` is my did, or `"*"` on an `evt` (`not-for-me`).
4. Signature over `SigInput("env", h, c)` with the sender's `sig` (`bad-sig`).
5. ACL: `cmd`/`rpc` — I am a computer, `realm` is me, sender is a phone, `access(sender, me)` gives `control` / `read`.
   `res`/`evt` — sender is the realm's computer (`from = realm`), I am a phone with `read` on it. Else `denied`.
6. Replay: `seq` greater than the last accepted `seq` from this sender (`replay`); for `cmd` and `rpc` also
   `|now − ts| ≤ 10 minutes` (`stale`).
7. Key for `(realm, epoch)` (`no-key`); OPEN (`bad-tag`); inflate if `zip` (`too-large`, `bad-zip`); parse; payload has a
   string `op` (`bad-payload`).
8. Only now record `seq` as the sender's last.

Computers MUST persist the last accepted `seq` per sender (it protects commands across restarts within the 10-minute
window); phones MAY keep it in memory. A computer answers a signed, authorised request that fails later with a `res`
`{op: "result", ok: false, code, error}` — `code` ∈ `stale`, `no-key`, `bad-tag`, `bad-payload`, `unknown-op`, `error`
a sentence in the request's `lang` — so the phone can explain (for example, a wrong clock). Everything that fails steps
1–5, and every replay, is dropped without an answer and logged without content. Vectors: `envelope.valid` (4), `envelope.invalid` (12).

### 9.4 Delivery semantics
The relay may lose, delay, duplicate or reorder envelopes; it cannot forge or alter them. Requests carry their own
id (`h.id`) and the phone matches `res.re` to it; a phone keeps waiting for a late `res` for 5 minutes after it gave up
(today's "late" result). Commands are not queued for long (relay TTL ≤ 60 s, RELAY.md §5.2), and computers refuse
commands older than 10 minutes, so a sleeping computer never executes a stale instruction when it wakes up.

### 9.5 Payload operations
Field shapes follow today's protocol (docs/PROTOCOL.md) unless stated. `lang` (`zh` | `en`) selects the language of
human-readable text in the reply. `BlobRef` is defined in §11.4.

| kind | `op` | Fields | Reply (`res`, `op: "result"`) |
|---|---|---|---|
| cmd | `dispatch` | `dispatchId`, `sessionId` (null = new session), `target?`, `text`, `model?`, `effort?`, `mode?`, `cwd?`, `attachments?` [BlobRef ≤ 5], `team?`, `lang?` | `ok`, `delivered`, `queued?`, `note?`, `sessionId?`, `error?`, `code?` |
| cmd | `answer` | `sessionId`, `promptAt?`, one of `answers` / `key`+`text?` / `keys` / `chat`, `lang?` | `ok`, `delivered?`, `queued?`, `note?`, `error?` |
| cmd | `stop` | `sessionId`, `lang?` | `ok`, `error?` |
| cmd | `handoff` | `sessionId`, `target`, `note?`, `lang?` | `ok`, `file`, `prompt`, `cwd`, `stopped`, `error?` |
| cmd | `mkdir` | `name`, `parent?`, `lang?` | `ok`, `path?`, `reused?`, `exists?`, `error?` |
| cmd | `voice` | `audio` (BlobRef, WAV), `speechLang` (`zh`/`en`/`auto`), and the `dispatch` fields except `text` | dispatch fields + `text`, `stage` (`asr`/`dispatch`/`done`); recognition failure: `ok: false`, `stage: "asr"`, `error` |
| rpc | `search` | `q` (1–100 chars), `limit?` | `sessions` [as today's /v1/search], `partial` |
| rpc | `usage_refresh` | — | `ok`, `throttled?` |
| rpc | `lock` | `statements` [signed documents] (a phone pushes a revocation or policy directly, §5.5) | `ok`, `head` |
| res | `result` | as listed per request; `late: true` if sent after the phone's timeout | — |
| evt | `notify` | `kind: "session_end"`, `sessionId`, `state`, `title`, `body`, `host`, `agent` | — |
| evt | `lock` | `statements` [signed documents] (gossip, §5.5) | — |

Unknown `op` in a `cmd`/`rpc`: reply `ok: false, code: "unknown-op"`. Unknown `op` in `evt`/`res`: ignore.
Session list changes, messages, usage and the computer's info are **objects** (§10), not envelopes; the relay tells
subscribers when an object changes (RELAY.md §5.4).

## 10. Stored objects (history cache)

### 10.1 Kinds
Objects are written only by the realm's computer and read by phones with `read`. The relay stores them under
`(realm addr, kind, key, seq?)` with an owner-chosen version.

| kind | key | seq | Plaintext (JSON) | Max plaintext |
|---|---|---|---|---|
| `info` | `info` | — | `host, ver, extractVer, projects, models, engines, permissions, wants{lang,prefs,handoff,team,mkdir}, folderParents, asr?` (today's `hello` contents) plus `agentId` (the computer's v1 id, so phones can match the two lists during the dual run) and `platform` | 256 KiB |
| `usage` | `usage` | — | today's `usage` shape (PROTOCOL.md §3 用量) | 16 KiB |
| `sess` | `sk` | — | session metadata: today's shape (including `state`) plus `id` (the session id), `xv`, `lastSeq` (= `msgCount`) | 64 KiB |
| `msg` | `sk` | message seq | one message `{seq, role, ts, blocks}` (attachment blocks per §11.4) | 4 MiB |
| `lite` | `sk` | message seq | the same message reduced for first display (§10.6) | 1 MiB |

The set of a computer's current sessions is the set of its `sess` objects; a session that leaves the computer's list
(older than the account's "show N days") has its `sess` object deleted. `msg`/`lite` objects expire at the relay
(RELAY.md §8).

### 10.2 Header and sealing
```json
{ "v": 1, "t": "obj", "id": "<16 B>", "nonce": "<12 B>", "realm": "<computer did>", "kind": "msg",
  "key": "<sk>", "seq": 7, "ver": 5, "epoch": 2, "by": "<computer did>", "ts": …, "zip": "deflate" }
```
`seq` is present exactly for `msg` and `lite`. `ver` is chosen by the owner and increases every time the object is
rewritten (a growing message is rewritten every few seconds): RECOMMENDED `ver = max(last known + 1, unixMillis)`.
`c = SEAL(K_epoch, "obj", h, plaintext)`, `s = ECDSA(owner.sig, SigInput("obj", h, c))`.

### 10.3 Reader checks (normative, reference `openObject`)
Header shape (`bad-header`); the header's `realm`, `kind`, `key` and `seq` equal what the reader asked the relay for
(`wrong-object` — stops a relay from serving one message in place of another); the realm is a computer in the lock
(`bad-realm`) and not revoked (`revoked-sender`); `by = realm` (`not-owner`); size (`too-large`); signature (`bad-sig`);
`ver` not lower than the highest version this reader already accepted for that object (`rollback`; keep showing the
newer copy); key (`no-key`); OPEN; inflate with the kind's cap. Vectors: `object`.

### 10.4 Names
Relays see `sk`, never the session id. `sk` depends on `xv`, so when the agent's splitting rules change it writes the
session under a new `sk` and deletes the old namespace; phones notice the new `xv` in the `sess` object and drop their
local cache for that session (as today's `xv` check does).

### 10.5 Sizes and growth
The relay sees each object's size and version history. Messages that grow are rewritten whole (today's behaviour);
the owner SHOULD space rewrites by size (4 s for small, up to 15 s for large) as the agent does now.

### 10.6 Lite variant
For a message whose plaintext exceeds 4 KiB the computer also writes `lite` at the same `seq`: tool steps reduced to
`{kind: "tool", name, brief (≤ 60 chars), ok, cut: true}`, thinking to `{kind: "thinking", cut: true}`, `lite: true` on
the message; text and attachment blocks unchanged (today's `lite=1` rules, moved from the server to the computer).
Phones ask the relay for "lite where it exists" when they have nothing cached, then replace with full messages.

### 10.7 Compression
Plaintexts MAY be raw-DEFLATEd before sealing when that makes them smaller; the header then says `"zip": "deflate"`.
Readers MUST cap inflation at the limit for that structure (`too-large`; vector: `object.invalid` "inflates beyond the
limit"). Envelopes SHOULD NOT be compressed unless larger than 4 KiB. Compression before encryption can leak through
sizes when attacker-chosen and secret text share an object; messages are compressed anyway for the slow cross-border
links Pocket runs on, and this residual leak is listed in §14.

## 11. Attachments (blobs)

### 11.1 Identity and keys
Every uploaded file and every thumbnail is a blob with a random 16-byte `blobId` and its own random 32-byte file key
`FK`. Blob ids are not content hashes, so the relay cannot test whether a user holds a known file. The same file
uploaded twice is two blobs (the computer SHOULD reuse its own earlier upload by keeping a local sha → BlobRef map).

### 11.2 Stream format (`PKB1`)
```
header H = "PKB1" || 0x01 (version) || 0x10 (log2 of chunk size: 65536) || blobId (16)        # 22 bytes
K        = HKDF-SHA256(FK, salt = blobId, info = UTF8("pocket/v1 blob key"))
n        = max(1, ceil(len(plaintext) / 65536))
chunk i  = AES-256-GCM-Encrypt(K, nonce_i, plaintext[i·65536 : (i+1)·65536], aad = H)
nonce_i  = U32BE(1 if i = n−1 else 0) || U64BE(i)                                           # 12 bytes
blob     = H || chunk_0 || … || chunk_{n−1}                    # every chunk but the last is 65536 + 16 bytes
```
An empty file is one empty last chunk (16 bytes of tag). Size = 22 + len + 16·n.

### 11.3 Decryption (normative, reference `decryptBlob`)
Check the 22-byte header (magic, version, chunk size, `blobId` equals the id asked for) → `bad-blob`. Split the rest into
65552-byte pieces; the final piece (1–65552 bytes, at least 16) is the last chunk and is opened with the last-flag
nonce; any failure is `bad-tag` — this catches truncation at a chunk boundary, reordering, and appended data.
Streaming readers keep one piece of look-ahead so they know which piece is last, and MUST NOT release plaintext of a
chunk before its tag verified. After the whole blob, compare length and SHA-256 with the BlobRef. Vectors: `blob`
(0, 5, 65536, 65537, 200000 bytes; five tamperings).

### 11.4 References inside messages and commands
```json
BlobRef = { "blob": "<b64u 16 B>", "key": "<b64u FK>", "sha": "<hex SHA-256 of the plaintext>", "bytes": 123,
            "name": "shot.png", "mime": "image/png" }
attachment block = { "kind": "attachment", "name", "mime", "bytes", "sha", "blob", "key",
                     "thumb"?: { "blob", "key", "bytes", "sha" } }        // thumb is always image/jpeg
not uploaded     = { "kind": "attachment", "name", "mime", "bytes", "skip": "large" }   // no sha, blob or key
```
The key travels only inside a signed, encrypted message or command, so the relay holds ciphertext without any way to
open it. `sha` stays the plaintext hash so the App's local cache keeps working; it is visible only to key holders.

Computers upload the files their sessions produce automatically only up to **20 MiB** (the limit for files sent from the
phone); a larger one appears as the `skip: "large"` block: name, type and size only, nothing to download (the App shows
"too large, not sent to the phone"). Readers MUST treat any block with `skip` as not downloadable and ignore unknown
`skip` values the same way.

**Upload order and quota.** A computer uploads one blob at a time and picks the next by priority: thumbnails, then
blobs of at most 2 MiB, then larger ones; within each, the newest message first. After pairing or a relay change it
waits for the first sync to queue its blobs (at most 20 s) before it starts, so a quota that runs short goes to the
recent pictures first. When the relay answers `429 quota` (RELAY.md §8.3) the computer stops sending large blobs until
`Retry-After` and keeps sending small ones (the relay's small-file allowance); when a small one is refused too, it waits
for all. Waiting blobs are not failures (no retry count, never given up). A renewed ticket whose `quota` differs, or
another relay, ends the wait at once.

### 11.5 Thumbnails
Computers make thumbnails (≤ 1280 px JPEG, quality 72, for bitmap images ≥ 150 KB the platform can decode, skipped if
not at least 10 % smaller — today's rules) **before** encryption: macOS with `sips`, Windows with GDI+ in the console
helper (PNG, JPEG, GIF, BMP, TIFF; no WebP/HEIC there). The server no longer makes thumbnails (it cannot see images).
Thumbnails upload before the original (an original waits up to 15 s for its thumbnail being made).

### 11.6 Uploads from the phone
When a phone sends files with a command, it uploads each as a blob into the target computer's realm (it has the realm
key relationship and `control`), then sends the `dispatch` with their BlobRefs. The computer downloads, decrypts,
checks `bytes` and `sha`, and writes to its inbox as today. Audio for the computer's local speech recognition goes the
same way (ASR.md §8).

## 12. Coordination-signed documents

### 12.1 Coordination keys
Coordination signs with P-256 keys identified by `kid`. The key set is published as a document signed by keys the
reader already trusts:
```json
keys.json = { "p": b64u({ "v": 1, "t": "keys", "at": …, "keys": [ { "kid", "pub", "use": [...], "nbf", "exp" } ] }),
              "sigs": [ { "kid": "<an existing key>", "s": b64u(sig over SigInput("keys", p, "")) } ] }
```
`use` lists the labels a key may sign (`keys`, `ticket`, `netmap`, `revocations`, `purge`). Clients and relays ship with
the current key pinned; they accept a new set only if one signature verifies with a key they already trust and that
key is inside its validity window (± 5 minutes). Rotation: publish the next key under the old one long before the old
`exp`. Reference: `verifyKeysDoc`; vector: `coord.keys` (test keys `test-c1`, `test-c2`).

### 12.2 Tickets
Short-lived permission for one device to use one relay (or one ASR gateway):
```json
{ "v": 1, "t": "ticket", "kid": "c1", "iss": "pocket.pocketcli.net", "aud": "<relayId | asr:<gatewayId>>",
  "acct": "<account>", "dev": "<did>", "addr": "100.x.y.z", "kind": "phone" | "computer",
  "sig": "<the device's signing public key>", "peers": ["<addr>", …], "iat": …, "exp": …,
  "quota"?: { "dayMB": 200, "monthMB": 2048, "smallMB": 50, "storeMB": 5120 }, "asrQuota"?: { "dayMin": 120, "monthMin": 1500 } }
```
Compact form `b64u(payload).b64u(sig)`, label `ticket`. Verification (reference `verifyTicket`): signature by a key
with `use: ticket` (`unknown-key`, `key-not-valid`, `bad-sig`); `aud` equals the verifier's id (`wrong-aud`);
`exp − iat ≤ 24 h` (`bad-ticket`; coordination issues 6 h); `iat − 5 min ≤ now ≤ exp + 5 min` (`expired`); a relay bound
to one account checks `acct` (`wrong-account`); well-formed `addr`, `dev`, `kind`, `peers`, `sig` (`bad-ticket`).
A ticket is useless without the device's private key (§13). Coordination issues tickets only to live, unsuspended
devices of the lock and computes `peers` from the ACL (`read` relations). `quota` (official relays only): attachment
traffic caps, the small-file allowance and the stored-bytes cap (0 = unlimited); a relay applies the caps of the account's
newest ticket to all its devices (RELAY.md §8.3). `asrQuota` (tickets for the official ASR gateway only): minutes of audio
the account may have recognized per day and per month (0 = unlimited; COORD.md §16). Vectors: `coord.ticket`.

### 12.3 Netmap
What coordination tells a device about its account (label `netmap`, COORD.md §8): devices with `addr`, keys, status
(`pending`/`active`/`suspended`/`revoked`), presence; the lock head; the account's relay and the other registered
relays; account preferences; ASR endpoints. Devices use it for discovery and presence only: **trust always comes from
the lock** (keys in the netmap that are not in the verified lock are ignored).

### 12.4 Revocation feed
Signed (label `revocations`) list of ticket cut-offs: `{addr, dev, nbf, gone?, at}` — "tickets for this address and
this device issued before `nbf` are void"; `gone: true` with `nbf = 2^53−1` for revoked or deleted devices. A cut-off
applies to the pair `(addr, dev)`: an address that later shows up in a ticket for a different `dev` belongs to a new
device, and the relay deletes whatever the previous owner stored under it. Coordination does not reassign an address
for 180 days after its device was revoked or deleted (the same time relays keep `gone` items). Coordination pushes the
document to the official relay at once; self-hosted relays poll it; any device MAY hand a document it received to its
relay (RELAY.md §6.5). Computers apply the same cut-offs as suspensions.

### 12.5 Purge orders
Signed (label `purge`) `{acct, at, relay: <relayId> | "*", addrs?}`: delete everything stored for that account (or
those realms). Sent when an account is deleted or a computer is removed. Relays act on each order once and only if
`at` is within the last 7 days; a repeat of an order already applied is answered `200 {already: true}` so senders stop
retrying. Coordination signs a fresh copy (new `at`) every time it retries, so a retry after more than 7 days still
counts.

## 13. Proof of possession

A device proves it holds the private key named in its ticket by signing the relay's one-time challenge:
```json
a = { "v": 1, "t": "relay-auth", "relay": "<relayId>", "nonce": "<challenge>", "th": "<b64u SHA-256 of the ticket string>", "ts": … }
s = ECDSA(device.sig, SigInput("relay-auth", a, ""))
```
The relay checks the ticket (§12.2), that `relay` and `nonce` match the challenge it issued (single use, ≤ 60 s;
`bad-nonce`), that `th` matches the presented ticket (`bad-proof`), `|now − ts| ≤ 5 min` (`stale`) and the signature
with the ticket's `sig` key (`bad-sig`). ASR gateways use the same idea per request with `t: "asr-auth"` and the
SHA-256 of the audio body (ASR.md §3). Vectors: `coord.relayAuth`, `coord.asrAuth`.

**Enrollment** (COORD.md §4.1) carries the same kind of proof, so a stolen password alone cannot move another device's
binding or suspend it by enrolling its public keys:
```json
a = { "v": 1, "t": "enroll-auth", "th": "<b64u SHA-256 of the bearer token>", "sig": "<the enrolled sig key>",
      "kx": "<the enrolled kx key>", "ts": … }
s = ECDSA(device.sig, SigInput("enroll-auth", a, ""))
```
sent as `"proof": {"a": b64u(a), "s": b64u(s)}`. Coordination checks (reference `verifyEnrollAuth`): `v = 1`,
`t = "enroll-auth"`, `sig` and `kx` equal the keys in the request and `th` equals the SHA-256 of the presented token
(`bad-proof`); `|now − ts| ≤ 5 min` (`stale`); the signature with that `sig` key (`bad-sig`). The token binding makes a
captured proof useless with any other login. Vectors: `coord.enrollAuth`.

## 14. What stays visible

| Data | Coordination | Relay / object store | ASR gateway |
|---|---|---|---|
| Messages, tool output, thinking, approval cards, plans, questions, commands, replies, titles, project paths, models, engines, usage figures, attachment names and contents, thumbnails, search queries and results | no | no (ciphertext) | no |
| Account email, password hash, login times and IPs, device names, platforms, public keys, virtual addresses, lock statements, ACL, which relay is used | yes | see the next two rows | — |
| Lock contents in detail: who approved whom and when, the `sas` flag (§6.4), admin flags, realm epochs, `kid`s and the reason of each rotation (`init`/`revoke`/`acl`/`rotate`/`reset`), revocation reasons (e.g. `logout`), lock resets; pending approvals (name, platform, kind) and their pairing progress: attempt numbers, failures and the SPAKE2 values `pA`, `pB`, `cA`, `cB`, which reveal nothing about the code (§6.7) — the code itself only on the demo account (§6.6) | yes | no | — |
| Grant metadata (who wrapped which computer's keys for whom, when, which epochs and `kid`s, the ephemeral public key); the size of each grant | yes | no | — |
| Client version (`hello.ver`), UI language, the account's list-days preference (`listDays`), self-hosted relays' URLs and names, online status of each device (control socket), when a computer switched off v1 | yes | no | — |
| Device ids (`did`), device kind (phone / computer), signing public keys and the peer list of each ticket, addresses, the account id | yes | yes | ticket only (ASR.md §3) |
| Envelope headers in clear: kind (`cmd` / `rpc` / `res` / `evt`), which request a response answers (`re`), sender and recipient `did`, epoch, per-sender `seq`, send time, the lock head a device forwards (`lock: {seq, h}`), compression flag | presence only | yes | — |
| Object headers in clear: kind (`info` / `usage` / `sess` / `msg` / `lite`), the opaque session name `sk`, message index `seq`, version `ver` (= rewrite time in milliseconds, §10.2), write time, epoch, compression flag | — | yes | — |
| Who sent to whom and when, sizes, number of sessions and messages per session, how often a message is rewritten, which messages exceed 4 KiB (lite exists), blob sizes and download times | presence only | yes | — |
| Client IP addresses | yes | yes | yes |
| Audio and recognised text | no | no | only in the official or self-hosted cloud modes (ASR.md) |
| Approximate content length leaked by compression | — | yes (§10.7) | — |

Checked against the implementations in the phase-3 attack tests (2026-10-08). Everything in the first row stays inside
signed and encrypted payloads; the rest is what the protocol needs to route, authorise and order messages, or what an
account service holds anyway. The privacy policy states these categories.

## 15. Platform notes

| Platform | Primitives | Private key storage (MUST: readable only by the user; not in backups or cloud sync) |
|---|---|---|
| iOS 15+ (App) | CryptoKit: `P256.Signing`, `P256.KeyAgreement`, `HKDF<SHA256>`, `AES.GCM`, `SHA256`, `HMAC`; Secure Enclave variants where present | Keychain, `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly` (works during background sends); Secure Enclave keys stored as their `dataRepresentation` |
| Android 7+ (App, minSdk 24) | `KeyPairGenerator("EC")` + `Signature("SHA256withECDSA")` (convert DER ↔ r‖s), `KeyAgreement("ECDH")`, `Cipher("AES/GCM/NoPadding")`, HKDF over `Mac("HmacSHA256")`; validate peer points yourself | `sig` in AndroidKeyStore (API 23+, StrongBox when available). `kx`: in AndroidKeyStore with `PURPOSE_AGREE_KEY` on API 31+; below that a software key whose PKCS#8 bytes are encrypted by an AndroidKeyStore AES-256-GCM key |
| macOS shell (debug only) | CryptoKit as on iOS | Keychain |
| Desktop agent (Node 22 / Bun) | `node:crypto` (`sign/verify` with `dsaEncoding: "ieee-p1363"`, `createECDH`, `hkdfSync`, `aes-256-gcm`), or WebCrypto where Bun lacks an option | macOS: a 0600 file under `~/.pocket/keys/` excluded from Time Machine, or the login Keychain via the signed helper; Windows: DPAPI (CurrentUser) protected file under `%USERPROFILE%\.pocket\keys\` |
| Trays (Swift, C#) | none — they show the pairing code of a new computer, or take the code the user types for a new device and pass it to the agent, which runs the pairing | — |

Dart in the App composes the protocol (JSON, headers, order of checks) over a native channel that exposes only
primitives and key handles; private keys never enter Dart. The pure-Dart SHA-256 the App already has may be used for
hashing. The pairing (§6.2) needs point addition and multiplication on arbitrary points (`M`, `N`, the peer's share),
which CryptoKit, the Android Keystore and .NET do not offer: it runs in Dart (BigInt, like [pake.mjs](pake.mjs)) and, on
computers, in the agent (an inlined copy of pake.mjs). Its secrets (`x`, `y`, `w`, the code) live for one attempt and
are not device keys.

## 16. Versioning
Every structure carries `v: 1`, every label starts `pocket/v1 `. A future suite or format change uses `v: 2` and
`pocket/v2 ` labels; receivers reject versions they do not know. The lock log has no version upgrade path inside v1 —
a v2 lock would start with a new genesis that references the v1 head the same way a reset does (§5.6).

## 17. Test vectors
`vectors.json` is generated by `gen-vectors.mjs` and is fully deterministic (signatures use RFC 6979 so the file can be
rebuilt byte-for-byte; products may sign with random nonces). Every implementation — relay (JS), coordination (JS),
agent (JS), App (Dart over Swift/Kotlin primitives), ASR gateway (JS) — MUST pass every valid and invalid case relevant
to it, with the expected error **code** for each invalid case. `about.contexts` explains how vector contexts (`prefix`,
device handles) map to state. The pairing vectors (`spake2`, `pair`) come from a second, independent SPAKE2 in
`gen-vectors.mjs`; `spake2.rfc9382` are RFC 9382's own. [pake.mjs](pake.mjs) must reproduce all of them: `--check`
runs it against the file, and `node --test docs/protocol/pake.test.mjs` tests it further (Node's ECDH as an oracle for
the scalar multiplication, malformed points, the inlined form the desktop agent uses).

## Appendix A. Error codes
`bad-b64u`, `bad-utf8`, `bad-json`, `too-large`, `bad-key`, `bad-tag`, `bad-zip`, `bad-seal`, `bad-header`, `bad-format`,
`bad-acct`, `bad-seq`, `bad-prev`, `not-genesis`, `bad-op`, `bad-device`, `unknown-signer`, `revoked-signer`, `bad-sig`,
`not-admin`, `dup-device`, `dup-addr`, `bad-target`, `last-admin`, `bad-acl`, `not-owner`, `bad-epoch`, `not-for-me`,
`unknown-sender`, `revoked-sender`, `suspended-sender`, `denied`, `replay`, `stale`, `no-key`, `bad-payload`,
`wrong-object`, `bad-realm`, `rollback`, `bad-grant`, `bad-kid`, `bad-blob`, `unknown-key`, `key-not-valid`,
`bad-ticket`, `wrong-aud`, `expired`, `wrong-account`, `bad-proof`, `bad-nonce`, `body-mismatch`.
Pairing (§6, pake.mjs): `bad-code` (not six digits), `bad-params` (a context field is malformed), `bad-point` (a received
share is not a valid point, or `K` is the point at infinity), `bad-confirm` (the key confirmation failed: wrong code or
different views of the context), `used` (an attempt answered twice).
These are for logs and tests; users see plain sentences.

## Appendix B. Why these choices
- **P-256 rather than X25519/Ed25519**: the Secure Enclave, Android Keystore, CryptoKit and .NET all support P-256
  natively; Ed25519/X25519 would force software keys on Android before API 33 and rule out hardware storage on iOS.
- **ECDSA r‖s**: what CryptoKit, WebCrypto, .NET and Node (`ieee-p1363`) produce or accept; one conversion on Android.
- **Per-structure HKDF with a random salt and a random nonce**: removes the 2^32 random-nonce limit of AES-GCM under one
  epoch key, separates labels, and costs one HMAC pair.
- **Encrypt-then-sign with the header as AAD and inside the signature**: the relay can neither alter routing fields
  nor strip and re-sign; realm members (who could re-encrypt anyway) are told apart by their signatures.
- **Signing exact bytes, no canonical JSON**: removes a whole class of cross-language bugs.
- **Per-computer realms**: content originates on computers, so each computer is the natural authority for its own key;
  revocation and ACL changes are local decisions of the computer, and "total loss" recovery is simply a new realm.
- **Lock log instead of server-issued certificates**: the server can store and order trust, but only devices can extend
  it.
- **STREAM-style chunking** (chunk index and last flag in the nonce): random-access, resumable downloads, and
  truncation detection without a trailer.
- **A typed 6-digit code with SPAKE2 instead of comparing words**: digits read the same in every language and are typed,
  not tapped, so the comparison cannot be skipped or confirmed by a misclick; SPAKE2 makes a short code safe against a
  server that sees everything (one online guess per attempt, nothing to search offline), where hashing or MACing six
  digits would not be. SPAKE2 rather than CPace or OPAQUE: RFC 9382 gives P-256 parameters and test vectors and needs
  nothing beyond plain point arithmetic (CPace maps the password onto the curve), and no stored verifier has to be
  protected (what OPAQUE is for) because the code lives for one attempt.
