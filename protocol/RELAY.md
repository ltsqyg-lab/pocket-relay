# Pocket relay — protocol and behaviour v1

Status: implementation spec, phase 1 (2026-10-08); §12.1 (relays without a domain: self-signed certificate, pin,
claim) added 2026-10-09; storage limits after the 2026-10-09 security review (stored bytes for objects and blobs,
§8.3; free disk space, §8.4; no direct uploads past a bucket, §6.4; renewal by real downloads, §8.2; 15-minute presigned
PUTs and their late uploads swept, §9; small frames before authentication, §3.1). License of the relay implementation:
**AGPL-3.0**.
Crypto, identifiers and verification rules come from [E2EE.md](E2EE.md); this document defines what a relay stores,
which requests it accepts and how it answers. Paths below are relative to the relay's **base URL**
(official relay: `https://pocket.pocketcli.net/relay`; a self-hosted relay: the base URL of its connection line, §12.1).

> **中文摘要**　中继只搬运和暂存密文:实时转发信封、短时排队、保存会话记录的加密对象、保存加密附件(本机磁盘或任意
> S3 兼容对象存储)。它凭协调服务器签的短期票据放行(离线校验,不需要我们的任何秘密),并要求设备当场用私钥签一次
> 挑战;只在同一账号、ACL 允许的设备之间转发;自建中继只服务绑定的那个账号。它看得到大小、时间、谁和谁通信,看不到内容。
> 自建中继不需要域名(§12.1,照 Tailscale DERP 的做法):中继自己生成自签证书、问协调服务器自己的公网 IP,打印一行
> `pocket-relay://IP:端口?pin=sha256:…&claim=…`;用户贴进 App,协调服务器钉住这个证书指纹调 `POST /v1/claim` 把中继认领到账号下。

---

## 1. Role

A relay:
- routes **envelopes** (E2EE §9) between the devices of an account, in real time, with a short offline queue;
- stores **objects** (E2EE §10: a computer's session list, messages, lite messages, usage, info) and serves them to
  the computer's phones;
- stores **blobs** (E2EE §11) on local disk or in an S3-compatible bucket, with presigned direct transfers;
- tells connected devices about **presence** and **object changes**;
- enforces **tickets**, **revocation cut-offs**, the **peers** relation, **quotas** and **retention**.

A relay never decrypts, never needs a Pocket secret, and never sees a private key. Everything it needs to verify a
device is public (coordination public keys, E2EE §12.1). It may parse the plaintext JSON headers of seals to
cross-check routing fields; it must not depend on anything inside ciphertext.

## 2. Configuration

A relay is one process with a data directory. Configuration file (JSON; every value may instead come from an
environment variable `RELAY_<UPPER_SNAKE>`; secrets SHOULD come from the environment):

```json
{
  "relayId": "hk1",                         // must equal the `aud` of tickets; null (with account) = claimed later, §12.1
  "account": "*",                           // "*" = any account (official); otherwise the one account this relay serves
  "publicUrl": "https://relay.example.com", // base URL as devices reach it; null = https://<IP from whoami>:<listen.port>
  "listen": { "host": "0.0.0.0", "port": 8443 },
  "tls": "auto",                            // "auto" | "self" | null (plain HTTP behind a TLS proxy) | {"cert","key"}
  "trustProxy": false,                      // true only behind a reverse proxy that sets X-Forwarded-For
  "coord": {
    "url": "https://pocket.pocketcli.net",  // keys: <url>/.well-known/pocket/keys.json; feed: <url>/v2/relay/revocations;
                                            // public address: <url>/v2/whoami
    "pinnedKeys": [ { "kid": "c1", "pub": "<b64u 65 B>", "use": ["keys","ticket","revocations","purge"], "nbf": 0, "exp": 0 } ]
  },
  "dataDir": "/var/lib/pocket-relay",
  "blobs": { "store": "disk" },             // or { "store": "s3", "backends": [ … ] } — §9
  "timezone": "Asia/Shanghai",              // day/month boundaries for traffic quotas
  "quota": { "dayMB": null, "monthMB": null, "storeMB": 5120,   // §8.3
             "smallMB": 50, "smallFileMB": 2, "useTicketQuota": true },
  "disk": { "minFreeMB": 5120 },            // §8.4
  "retention": { "objectDays": 30, "blobDays": 30, "queueMaxSeconds": 604800 },
  "limits": { }                             // overrides of §10
}
```

`relayId` and `account` come together: both given = bound by the configuration (the official relay; the old self-hosting
flow); both absent = bound by a claim (§12.1), kept in `dataDir/binding.json`. Startup MUST fail if only one is given,
or if no coordination key is pinned. The reference relay pins the official coordination key (`c1`) by default, so a
configuration may leave `coord` out. The pinned keys bootstrap trust; the relay then refreshes `keys.json` (every 6 h
and when it meets an unknown `kid`) and adopts new keys only when signed by a key it already trusts (E2EE §12.1).

`tls`: `"auto"` (default) = the relay's own self-signed certificate (§12.1), except with `trustProxy: true`, where it
serves plain HTTP behind the proxy; `"self"` = always the self-signed certificate; `null` (also `false`, `"off"`) =
plain HTTP, TLS terminated in front; `{"cert", "key"}` = PEM files, reloaded when they change. `publicUrl`, when given,
MUST be an `https://` URL without query or fragment; a base path is allowed (the official relay has one), but a relay
added from the App is reached at the root of its host and port (§12.1). Without it a relay that terminates TLS itself
learns its address from coordination (§12.1).

## 3. Authentication

### 3.1 WebSocket
`GET /v1/ws` upgrades without credentials. The relay immediately sends a challenge; the device has 10 s to answer
(then close 4408). Until `ready` a socket may send frames of at most 64 KiB (`limits.authFrame`; an `auth` frame is
about 15 KB; more closes 4413), and at most 1000 such sockets (`limits.unauthSockets`, all clients together) are open
at once: beyond that the upgrade is answered `503` with `Retry-After: 5`. The full frame size (§5) comes with `ready`.

```json
relay → device  { "t": "challenge", "relay": "hk1", "nonce": "<b64u 16 random bytes>", "ts": 1791417600000 }
device → relay  { "t": "auth", "ticket": "<compact ticket>", "a": "<b64u proof JSON>", "s": "<b64u signature>" }
relay → device  { "t": "ready", "addr": "100.64.0.11", "dev": "<did>", "acct": "u_…", "exp": <ticket exp>,
                  "token": "rt_<b64u 32 B>", "tokenExp": …, "queued": 3, "peers": [ { "addr": "…", "online": true } ] }
```
The proof is E2EE §13 (`relay-auth`): ticket valid for this `relayId` (and for this `account` on a bound relay),
nonce = the one just issued (single use), `th` = SHA-256 of the ticket string, `|now − ts| ≤ 5 min`, signature by the
ticket's `sig` key. Failure: `{"t":"error","code":…}` then close 4401 (`revoked` and `wrong-account` close 4403).
`ready.token` is the HTTP bearer token of §3.2 — a device that has a socket needs no separate `/v1/auth`.

Before the ticket expires the device sends `{"t":"renew"}`; the relay answers with a new `challenge` and the device
authenticates again on the same socket with a fresh ticket of the **same device** (another device's ticket closes
4401). The new `ready` may list different `peers`; subscriptions to realms the new ticket cannot read are dropped.
Devices also renew right after their lock or netmap changes, since `peers` may have changed. At ticket expiry without renewal the relay closes 4401
(`expired`). A device MAY hold two sockets at once (e.g. App foreground + background transfer); a third closes the
oldest with 4409.

### 3.2 HTTP
HTTP requests carry `Authorization: Bearer rt_…` — the token from `ready`, or from:
```
POST /v1/auth/challenge            → { "relay": "hk1", "nonce": "…", "ts": …, "exp": … }     (nonce valid 60 s, single use;
                                     at most `limits.nonces` outstanding for all clients together, then 429 `rate`)
POST /v1/auth  { ticket, a, s }    → { "token": "rt_…", "exp": …, "addr": "…", "dev": "…" }
```
Tokens are 32 random bytes; the relay keeps only their SHA-256, in memory, bound to the ticket's identity
(`acct, dev, addr, kind, peers, quota, iat, exp`). Lifetime = the ticket's `exp`. A restart forgets tokens; clients then
authenticate again (401 `token`). Tokens are never logged.

### 3.3 Revocation cut-offs
The relay keeps a table `addr → {nbf, gone}` built from signed revocation documents (E2EE §12.4):
- a ticket with `iat < nbf` for its `addr` is rejected (`revoked`); live sockets and tokens of that address issued
  earlier are closed (4403) or invalidated at once;
- `gone: true` additionally deletes everything stored for that address as a realm (objects, blobs, queued envelopes)
  and drops future envelopes addressed to it.

Sources, all verified with coordination keys (`use: revocations`):
1. `POST /v1/revocations` with the document as body (anyone may deliver it — coordination pushes to the official relay,
   devices forward what they receive);
2. polling `GET <coord.url>/v2/relay/revocations?acct=<acct>&since=<cursor>` every 60 s (± jitter) for each account
   that has a live connection or stored data (a bound relay polls its one account).
Cut-offs are kept for 48 h past the latest `exp` any affected ticket could have; `gone` entries are kept 180 days.
A cut-off belongs to the pair `(addr, dev)` from the item: it voids tickets of that device only. When a ticket shows an
address with a different `dev` than the one the relay last saw there, the address has a new owner — the relay deletes
what the previous owner stored under it and starts fresh — but only when the previous device is `gone` (a cut-off says
so) or has not authenticated for 180 days, the time coordination holds a released address (COORD.md §13). Any other
claim is refused (`denied`, or `wrong-account`) and the data stays.

**How soon a relay learns of a revocation** (and closes the device's sockets and tokens):
- official relay: at once — coordination pushes the document over loopback and pushes again every minute until it is
  delivered (it also polls like a self-hosted relay);
- self-hosted relay: at its next poll (`coord.pollSeconds`, default 60 s, at least 5 s) for an account with a live
  connection, or within `coord.idlePollHours` (default 6 h) for one without; sooner when a device of the account
  forwards the document (devices receive it on their control channel);
- if the relay cannot reach coordination at all, the upper bound is the lifetime of the revoked device's tickets
  (6 h as issued by the official coordination, never more than 24 h — relays refuse longer tickets). The device's keys
  are out of the lock immediately in any case, so the other devices ignore whatever it sends (E2EE §9.3).

Coordination can always revoke, cut off or purge (it signs these documents); a relay that deletes data on its word —
`gone`, a reassigned address, a purge order — loses only a cache: computers rebuild their objects, and what is lost
for good is attachments nobody downloaded yet and queued envelopes. That is the "coordination can deny service"
part of the threat model (E2EE §2), not a way to read or forge anything.

## 4. Addressing and authorization

- A connection's identity is its ticket: `acct`, `dev`, `addr`, `kind`, `peers`.
- A **realm** is identified at the relay by the owning computer's **address**. The owner of realm `X` is a
  `kind: computer` identity with `addr = X`.
- **Envelopes**: `A` may send to `B` iff `B ∈ A.peers`. `to: "*"` means every address in `A.peers`.
- **Read** realm `X` (objects, blobs, object-change notifications, presence): `addr = X` or `X ∈ peers`.
- **Write objects** in realm `X`: owner only.
- **Write blobs** in realm `X`: the owner or a peer (phones upload attachments for their commands).
- **Delete**: objects — owner; blobs — owner or the identity that uploaded it.
- The relay records `addr → acct` from tickets it has seen and refuses any operation that would cross accounts
  (defence in depth; `peers` already comes from one account).

## 5. WebSocket protocol

Frames are JSON text, at most 2 MiB each (64 KiB before `ready`, §3.1). After `ready`, either side may send at any time.

### 5.1 Frames from the device
| `t` | Fields | Meaning |
|---|---|---|
| `auth`, `renew` | §3.1 | |
| `send` | `id` (≤ 64 chars, the device's frame id), `to` (addr or `"*"`), `env` (seal JSON, E2EE §3.5), `ttl` (seconds, 0–604800) | route an envelope |
| `ack` | `q` (one queue id, or an array of up to 1000) | queued envelopes were processed; delete them. Acks have their own rate budget (200 per second), so a long backlog is never throttled |
| `sub` | `realms` [addr…], `since?` {addr: rev} | object-change notifications for these realms (must be readable); replaces the previous subscription |
| `ping` | `ts` | relay answers `pong` (WebSocket ping frames are also answered) |

### 5.2 Delivery and queueing
On `send` the relay checks: authenticated; `to` allowed (§4); ciphertext ≤ 1 MiB and header ≤ 4 KiB (`too-large`);
rate (`rate`); and the plaintext envelope header: `h.from` must be the ticket's `dev`; with `to: "*"`, `h.to` must be
`"*"`; with an address whose device the relay knows, `h.to` must be that device's did or `"*"` (otherwise `denied`).
A malformed frame (id, to, ttl or env shape) is answered `{"t":"error","code":"bad-request","id":…,"what":…}`.
Then for each recipient address:
- online → write `{"t":"msg", "from": <sender addr>, "env": …, "at": <receive time>}` to its sockets;
- offline and `ttl > 0` → append to that recipient's queue with an expiry, as `{q: <queue id>}`;
- offline and `ttl = 0` → nothing.

The relay answers the sender: `{"t":"sent","id":…,"status":S,"n":<delivered>,"queued":<count>}` with
`S` = `delivered` (all recipients got it now), `partial` (some delivered, some queued), `queued`, `offline`, `denied`,
`too-large`, `rate`, `full` (recipient queue full, or the relay's disk nearly full, §8.4: nothing is queued then, live
delivery goes on) or `quota`.

Queues: FIFO per recipient; envelopes from one sender stay in order. At most 1000 envelopes and 32 MiB per recipient
(over that: `full`). On authentication the relay sends the recipient's queue in order as `msg` frames carrying `q`; the
device acks each after handling it. Unacked messages are re-sent on the next connection (duplicates are caught by the
receiver's replay check, E2EE §9.3). When a queued envelope expires, the relay sends the original sender
`{"t":"expired","id":…,"to":…}` if it is connected (best effort).

TTL guidance for senders (E2EE §9.4): commands and rpcs ≤ 60 s; results 300 s; `notify` events 600 s; other events 0.

### 5.3 Presence
`ready.peers` lists each peer address and whether it is online now. Afterwards the relay sends
`{"t":"presence","addr":…,"online":true|false,"at":…}` to connected peers when a device's first socket opens or its last
socket closes (debounced 5 s).

### 5.4 Object-change notifications
After every object write or delete in a realm, the relay sends subscribers of that realm
`{"t":"obj","realm":…,"kind":…,"key":…,"seq"?:…,"ver":…,"rev":…,"bytes":…,"del"?:true}`. `rev` is the realm's change
counter (§6.3). With `sub.since` the relay first replays changes after that `rev` (or answers
`{"t":"resync","realm":…}` if the history is gone — the device then lists objects over HTTP).

### 5.5 Keep-alive and close codes
The relay pings every 30 s and closes connections silent for 90 s. Close codes: 4400 malformed, 4401 auth failed or
expired, 4403 revoked or not allowed (reason `unclaimed`: the relay was unbound, §12.1), 4408 no `auth` within 10 s,
4409 replaced by a newer socket, 4413 frame too large (over 64 KiB before `ready`), 4429 rate limited. Other errors on a live socket are frames: `{"t":"error","code":…,"id"?:…}`. Frames the relay
sends before closing: `replaced` (4409), `expired` (4401), `revoked` (4403). A `sub` naming realms the ticket cannot
read is answered `{"t":"error","code":"denied","realms":[…]}` and the readable rest is subscribed.

## 6. HTTP API

JSON responses use `application/json`; errors are `{"error": "<code>", "message"?: "<English text for logs>"}` with the
HTTP status of §14. Clients translate codes into their own sentences.

### 6.1 Public
- `GET /v1/info` → `{ "service": "pocket-relay", "version", "state": "claimed" | "unclaimed", "relayId", "account", "time", "features": ["ws","objects","blobs","presign"], "limits": {"envelope": 1048576, "object": {…}, "blob": 104857600} }`
  (`relayId` and `account` are null while unclaimed).
- `GET /.well-known/pocket-relay` → `{ "v": 1, "state": "claimed", "relayId", "account", "version" }`, or `{ "v": 1, "state": "unclaimed" }`
  before a claim (coordination checks a self-hosted relay with it).
- `POST /v1/claim` — §12.1.
- `GET /v1/health` → `{ "ok": true, "version" }`; 503 `unclaimed` before a claim.

`version` is major.minor only (`"0.2"`), so the exact build is not advertised; clients go by `features` and never by
the version. `--version` on the command line prints the full one.

While a relay is unclaimed (§12.1) it answers only `GET /v1/info`, `GET /.well-known/pocket-relay` and `POST /v1/claim`:
every other request (`/v1/health` included) and the WebSocket upgrade get `503 {"error":"unclaimed","code":"unclaimed"}`.

### 6.2 Auth
§3.2.

### 6.3 Objects
Objects are binary seals (`application/x-pocket-seal`, E2EE §3.5). `{realm}` is an address; `{kind}` ∈ `info`, `usage`,
`sess`, `msg`, `lite`; `{key}` matches `[A-Za-z0-9_-]{1,64}`; `{seq}` is a positive integer (only for `msg`, `lite`).

| Request | Who | Behaviour |
|---|---|---|
| `PUT /v1/o/{realm}/{kind}/{key}[/{seq}]` + `X-Pocket-Ver: <int>` | owner | Store if `ver` is greater than the stored version (else `409 {"error":"ver","ver":<stored>}`). Size ≤ the kind's limit + 4096 + 88 bytes (header, tag and framing). The relay parses the seal header and rejects (`400 mismatch`) a header whose `realm` or `by` is not the ticket's did, or whose `kind`, `key`, `seq` or `ver` (= `X-Pocket-Ver`) disagree with the request. What the account stores grows by the difference to the version replaced: over `storeMB` → `429 quota` (§8.3; a version that is not larger always goes); disk nearly full → `503 full` (§8.4). With a `Content-Length` both are answered from the headers, before the body is read (clients wait `Retry-After` before trying again). Answer `{ "ver", "rev" }`; bump the realm `rev`; notify (§5.4). |
| `GET` same path | reader | The seal, with `X-Pocket-Ver` and `ETag: "<ver>"`; `If-None-Match` → 304. |
| `DELETE /v1/o/{realm}/{kind}/{key}[/{seq}]` | owner | Without `{seq}` on `msg`/`lite`: delete every seq of that key. Bumps `rev`, notifies. |
| `GET /v1/o/{realm}?since=<rev>&kinds=info,usage,sess&limit=500&inline=65536` | reader | Changes after `rev`, ordered by `rev`: `{ "rev": <current>, "more": bool, "full"?: true, "items": [ {kind, key, seq?, ver, bytes, at, rev, del?, seal?} ] }` — `seal` (b64u binary seal) included when `bytes ≤ inline`. Several writes of one object since `rev` collapse into its latest version. A deletion is an item with `del: true` (no `seq` when a whole `msg` key was deleted). `full: true` means the list is complete — `since=0`, or `since` older than the deletion markers the relay still keeps (30 days) — and the reader drops cached objects of those kinds that are not listed. |
| `GET /v1/o/{realm}/heads?kind=msg` | reader | `{ "heads": [ { "key", "last": <highest seq>, "ver": <its ver>, "count" } ] }` — the computer resumes uploads from it after a restart (today's `have`). |
| `GET /v1/o/{realm}/msg/{key}/range?after=<seq>&limit=<n>&max=<bytes>&prefer=lite&skip=<seq>:<ver>` | reader | `application/x-pocket-seal-stream`: seals for seq > `after`, ascending, at most `limit` (≤ 500). `prefer=lite`: for each seq return the `lite` object if one exists, else `msg`. `skip`: omit that seq if its current `ver` equals. Byte cap: `max` if given, else 2 MiB when the window reaches the last seq and 16 MiB otherwise; at least one item is always returned. Headers `X-Pocket-More: 1` when cut short, `X-Pocket-Last: <highest seq stored>`. |

Readers verify everything they receive (E2EE §10.3); the relay's checks only catch honest mistakes early.

### 6.4 Blobs
Blob bodies are `PKB1` streams (E2EE §11.2), `application/octet-stream`. `{blobId}` is 22 base64url characters.

| Request | Who | Behaviour |
|---|---|---|
| `POST /v1/b/{realm}/{blobId}/upload` `{ "bytes": n }` | writer | Reserve. `bytes` is the length of the encrypted `PKB1` stream (22 + plaintext + 16·⌈plaintext/65536⌉). `409 {"error":"exists"}` if present; `429 rate` while a direct upload of the same blob is under way. Quota checked against `bytes` now (`429 quota`, §8.3: traffic, with the small-file allowance, and stored bytes — a reservation counts as stored). Answer `{ "mode": "presigned", "url", "method": "PUT", "headers": {"Content-Length": "<n>"}, "expires" }` (S3 store; the URL is valid **15 minutes**, the upload must start within them; the length is signed into the URL, send the header as given) or `{ "mode": "direct" }` (no bucket, or the bucket unreachable now; `503 full` when the relay's disk is nearly full, §8.4). |
| `PUT /v1/b/{realm}/{blobId}` | writer | Direct upload; `Content-Length` required and equal to the reserved `bytes`; ≤ 100 MiB + 22 + 16·⌈n/65536⌉. **With a bucket configured** only a live reservation in mode `direct` can be filled this way; anything else — no reservation, an expired one, a presigned one — is `403 denied`, so nothing reaches the relay's disk while the bucket works. **Without a bucket** a PUT without a (live) reservation is reserved on the spot, with the reservation's checks. `503 full` when the disk is nearly full. The relay checks the 22-byte header (magic, version, chunk size, blob id) and the length formula; if the reservation is gone when the last byte arrives (deleted, purged), the bytes are dropped (`404`). |
| `POST /v1/b/{realm}/{blobId}/commit` `{ "bytes": n }` | writer | Presigned mode: the relay HEADs the bucket object — its size must equal the reservation — and reads its first 22 bytes, which must be the header of this blob; otherwise it deletes the object (`409 size`, `400 bad-blob`). Charges traffic. |
| `GET /v1/b/{realm}/{blobId}` | reader | Disk: 200 with the bytes, `Range` supported (single range), charged by the bytes sent. S3: `302` to a presigned GET valid 2 minutes (the client follows **without** its `Authorization` header, at once; a download that started keeps going after the expiry); charged the **stored size** whatever `Range` was asked — the URL serves the whole object and can be replayed until it expires. What counts as a download for retention: §8.2. |
| `HEAD /v1/b/{realm}/{blobId}` | reader | Size only; free. |
| `DELETE /v1/b/{realm}/{blobId}` | owner or uploader | Delete. |

Unfinished reservations expire after 1 hour (their bucket objects are deleted; a direct upload still coming in keeps
its reservation until it ends). Uploads that land in the bucket after their blob is gone are swept (§9).

### 6.5 Control
| Request | Body | Behaviour |
|---|---|---|
| `POST /v1/revocations` | signed revocation document (E2EE §12.4) | Verify, apply (§3.3); `{ "applied": n }`. No token needed. |
| `POST /v1/purge` | signed purge order (E2EE §12.5) | Verify; if `relay` is this relay or `"*"` and `at` within 7 days and not seen before, delete everything for the account (or the listed realms); `{ "deleted": {objects, blobs, queued} }`. An order already applied answers `200 {"already": true}` (so the sender's retry queue stops). No token needed. |
| `GET /v1/me/quota` | — | `{ "day": {used, cap}, "month": {used, cap}, "small": {used, cap, file}, "store": {used, cap} }` for the caller's account (bytes; `cap` 0 = unlimited, except `small.cap` 0 = no allowance; `small.file` = the largest blob that counts as small; `store.used` = objects and blobs together), §8.3. |

The two control documents are open to anyone because their **coordination signature is the authorization**: a
revocation document counts only when it verifies under a coordination key whose `use` includes `revocations`, a purge
order only under one with `purge` (label, `kid`, the key's validity and the signature, E2EE §12). Anything else changes
nothing: `400 bad-format` (not the document's label, e.g. a ticket), `401 bad-sig`, `401 unknown-key` (a `kid` the relay
does not know makes it fetch `keys.json`, at most once a minute), `401 key-not-valid` (a key not allowed to sign it).
Bodies over 2 MiB (revocations) or 64 KiB (purge) are not read (`413`); 60 requests per minute per client IP, loopback
excepted.

## 7. Binary encodings
- Seal (`application/x-pocket-seal`): `U32BE(len h) || h || U32BE(len c) || c || s` (64 bytes), E2EE §3.5.
- Seal stream (`application/x-pocket-seal-stream`): seals back to back. Clients parse incrementally and verify each.
- Blob: `PKB1` stream, E2EE §11.2.
- WebSocket frames always use the JSON seal form.

## 8. Storage, retention, quotas

### 8.1 Storage
- Index and queues: an embedded database (SQLite via `node:sqlite` in the reference relay): identities seen
  (`addr → acct, dev, kind, lastSeen`), cut-offs, objects (`realm, kind, key, seq, ver, bytes, at, lastRead, rev, path`;
  a deleted object keeps a deletion marker for 30 days — one row per object serves as the change log, so `since` lists
  and subscription replays return each changed object once, at its latest version), queue entries, blobs
  (`realm, blobId, bytes, store, backend, uploader, createdAt, lastRead`), presigned uploads handed out in the last day
  (`realm, blobId, backend, at`; §9), traffic counters (`acct, period, bytes`: the day, the month and the day's
  small-file allowance), and per account the `iat` and `quota` of the newest ticket seen (§8.3).
- Object bodies: files under `dataDir/o/…` written atomically (temp + rename), or rows in the database.
- Blob bodies: `dataDir/b/<realm>/<blobId>` or the bucket key `<prefix><realm>/<blobId>`; nothing else (no names, no
  account ids in plain, no content types).
- The relay's own state (§12.1), all 0600: `dataDir/tls/self-key.pem` + `self-cert.pem` (self-signed certificate),
  `claim.json` (claim code, while unclaimed), `binding.json` (relay id and account, once claimed), `public.json` (the
  address coordination reported), `connect.txt` (the connection line). Unlike the ciphertext cache, losing the
  certificate or the binding means adding the relay again.

### 8.2 Retention (defaults; configurable)
- Objects: deleted when neither written nor read for `objectDays` (30). `sess`, `info` and `usage` objects of a computer
  that is still connected at least weekly are kept.
- Blobs: deleted `blobDays` (30) after the last download, or after upload if never downloaded (today's policy). A
  download counts when it delivered at least half of the blob to the client (from disk: the response reached its end;
  from a bucket: every `302`, which is charged the whole size). A few bytes of a range, the last byte included, or a
  download the client cut off do not renew a blob.
- Queue: by `ttl`; at most `queueMaxSeconds`.
- `gone` cut-offs and purge orders delete at once.
- Deleted data is gone: no trash, no backups of ciphertext beyond what the operator's disk snapshots keep.

### 8.3 Quotas
Per account: blob traffic per day and per month (uploads and downloads count, `HEAD` does not), stored bytes, and a
**small-file allowance**. Day and month follow `timezone`.

**Stored bytes** (`storeMB`) are what the account keeps on this relay: its live objects (session lists, messages, lite
messages, info, usage) and its blobs, open reservations included, wherever they are kept (disk or bucket). The
configuration's default is 5120 MB; a ticket's `storeMB` replaces it (0 = unlimited). An object write is checked against
the growth it causes (a new version no larger than the one it replaces always passes), a blob reservation against its
`bytes`: over the cap → `429 quota` with `quota.store` and an hour's `Retry-After`. Deleting objects or blobs, and
retention, make room at once.

**Where the caps come from.** From the configuration, or, when `useTicketQuota` is true, from the `quota` of the
**newest ticket the relay has seen for the account** (the largest `iat`, whichever of the account's devices presented
it, over WebSocket or HTTP): `dayMB`, `monthMB`, `storeMB` (0 = unlimited) and `smallMB` (0 = no allowance); a field
the ticket leaves out comes from the configuration, and a newest ticket without `quota` means the configuration's caps.
Every device of the account is held to the same caps, whichever ticket it holds itself: counters are per account, so
caps per ticket would let two devices with different tickets disagree (one pushes the counters past a cap the other
still has). The relay keeps the newest ticket's `iat` and `quota` per account (across restarts, until the account is
purged); an older ticket presented later changes nothing. A quota change therefore takes effect as soon as any device of
the account renews its ticket, and coordination makes the devices renew within a minute or so of a change (COORD.md §7).

**Small-file allowance.** A blob is small when its stored size is at most that of `smallFileMB` of plaintext
(default 2 MiB, so `PKB1` size 22 + 2 MiB + 16·32 bytes); smallness goes by the blob's whole size, so a large blob read in
small ranges is not small. While the day and the month have room, every transfer counts there. Once they do not, a
small blob still moves (upload or download) and counts on the day's allowance of `smallMB` (default 50 MB) instead of
the day and month, so thumbnails and voice clips keep working after big files used the quota up. The allowance is
per day only, starts again every day even when the month is used up, and never counts in the day or the month.
Stored bytes (`storeMB`) have no allowance.

**Over quota:** `429 {"error":"quota","quota":{"day":{used,cap},"month":{used,cap},"small":{used,cap,file},"store"?:{used,cap}},"retryAfter":<s>}`
with `Retry-After`: until the next day for a small blob (the allowance comes back, even with the month used up) and for
a large blob when only the day is used up; until the next month for a large blob when the month is used up; an hour
for stored bytes. Clients SHOULD stop sending large blobs until then and keep trying small ones.
Envelope and object traffic is not counted against the blob quota (limits of §10 still apply); objects do count as
stored bytes.

### 8.4 Free disk space
`disk.minFreeMB` (default 5120; 0 = no minimum) is the space the relay leaves free on the disk of its data directory,
since a relay usually shares a disk with the system. When storing something would leave less, the relay stores nothing
new on that disk — object writes, blob reservations and uploads kept on disk answer `503 {"error":"full",
"retryAfter":600}` with `Retry-After: 600`, and envelopes for offline devices are not queued (`sent` status `full`).
Reads, deletes, live delivery, renewals and blobs that go to a bucket carry on. The relay logs `disk-low` and `disk-ok`
when it crosses the line, and checks the free space at most every 2 seconds. Free space it cannot read never blocks.

## 9. S3-compatible blob storage

```json
"blobs": { "store": "s3", "backends": [
  { "name": "cn", "when": "cn-ip", "endpoint": "https://cos.ap-shanghai.myqcloud.com", "region": "ap-shanghai",
    "bucket": "…", "accessKeyEnv": "RELAY_S3_CN_KEY", "secretKeyEnv": "RELAY_S3_CN_SECRET", "pathStyle": false, "prefix": "pocket/" },
  { "name": "default", "when": "default", "endpoint": "https://s3.example.com", "region": "…", "bucket": "…", … } ],
  "cnIpFile": "/var/lib/pocket-relay/cn-ip.json" }
```
- Signing: AWS Signature Version 4, presigned query strings, `UNSIGNED-PAYLOAD` with `content-length` signed for PUT.
  This works with AWS S3, Cloudflare R2, MinIO, Tencent COS (S3-compatible endpoint) and Aliyun OSS (S3-compatible API).
- Backend choice per new blob: the first backend whose `when` matches the **uploading client's IP** (`cn-ip` = inside the
  CIDR list in `cnIpFile`, refreshed weekly by the operator; `default` matches everything). The choice is recorded per
  blob; downloads go to where the blob is.
- If the bucket is unreachable at reservation time the relay answers `{mode: "direct"}` and stores on disk instead
  (subject to §8.4). That is the only way a blob reaches the disk of a relay with a bucket: a direct PUT without such a
  reservation is refused (§6.4).
- Presigned PUTs are valid 15 minutes and can be used more than once while valid. The relay remembers each one it hands
  out for a day: once the URL can no longer start an upload, and then at every sweep (hourly) until the day is over, it
  HEADs the object, and deletes it unless the blob is committed there or a reservation of it is open. So an upload that
  lands after its blob is gone — the reservation expired, the blob was deleted, the account purged — does not stay.
- The relay deletes bucket objects on retention, purge and `gone`.
- Each relay needs its own bucket or `prefix`.

## 10. Limits (defaults)
| What | Default |
|---|---|
| WebSocket frame | 2 MiB; 64 KiB before `ready` (`authFrame`) |
| WebSocket sockets not authenticated yet | 1000 at once, all clients together (`unauthSockets`); 10 s each (`authSeconds`) |
| Envelope ciphertext / header | 1 MiB / 4 KiB |
| Frames per connection | burst 50, sustained 20 per second |
| Sockets per device | 2 |
| Queue per recipient | 1000 envelopes, 32 MiB, TTL ≤ 7 days |
| Object sizes | `info` 256 KiB, `usage` 16 KiB, `sess` 64 KiB, `msg` 4 MiB, `lite` 1 MiB (+ 4096 + 88 bytes for header, tag and framing) |
| Object writes | 30 per second per owner |
| Blob size | 100 MiB of plaintext |
| Concurrent blob uploads per device | 4 |
| Presigned PUT / GET | valid 15 minutes / 2 minutes |
| Stored bytes per account | 5120 MB (`quota.storeMB`, or the ticket's) |
| Free space kept on the data directory's disk | 5120 MB (`disk.minFreeMB`) |
| JSON request bodies | 64 KiB, 30 s (a revocation document: 2 MiB) |
| Connections per IP | 100 |
| HTTP challenges | 120 per IP per minute; 200 000 outstanding in total (`limits.nonces`) |

## 11. Logging and privacy
What a relay can see is listed in E2EE §14. Besides addresses, sizes and times, the plaintext headers it must route by
show: an envelope's `kind` (command, read request, reply, event) and, on a reply, which request it answers (`re`);
the lock head a device gossips (`lock`); an object's kind, its opaque session key `sk`, message number and version
(a version is usually a timestamp, so it shows when a message was rewritten) and whether it was compressed.
Log: time, relay id, account id, address, operation, sizes, status, latency, client IP (needed for abuse handling).
Never log: envelope, object or blob bytes; seal headers; tickets; tokens; nonces; presigned URLs; Authorization headers.
Expose counts and sizes only in metrics. The official relay keeps logs 7 months (the coordination server's policy);
self-hosters decide for themselves.

## 12. Self-hosting
A server with a public IP address; 1 vCPU / 1 GB RAM is enough for one person. No domain is needed.

1. Start the relay without `relayId`/`account` (the reference relay's Docker image needs no configuration at all:
   `docker run -d --name pocket-relay --restart unless-stopped -p 8443:8443 -v pocket-relay:/var/lib/pocket-relay pocket-relay`).
   It makes a self-signed certificate for its public address and prints one line (also in `dataDir/connect.txt`):
   `pocket-relay://203.0.113.7:8443?pin=sha256:<hex>&claim=<code>` — §12.1.
2. Open that TCP port in the firewall / security group.
3. In the Pocket app: Settings → Relay → Add your own relay, then paste the line. Coordination registers the relay for the
   account (a new relay id `r_…`), connects to it with TLS pinned to `pin`, and claims it (`POST /v1/claim`). The relay
   then serves that account only.
4. Switching relays: computers re-upload their sessions to the new relay automatically; phones re-download. The old
   relay's data can be deleted by its owner.
5. If your relay is unreachable, the App offers to switch back to the official relay.

**With a domain** the same flow works (`publicUrl` = `https://relay.example.com:8443`, self-signed certificate for that
name, pinned). Besides:
- `publicUrl` = `https://relay.example.com` behind a reverse proxy that terminates TLS with a certificate from a public
  CA (`tls: null` or `trustProxy: true`): the line carries no `pin`, devices verify the proxy like any website.
- `tls: {cert, key}` with a certificate from a public CA for the domain name in `publicUrl`: no `pin` either (a pin
  would break at the next renewal); any other certificate given in files is pinned like the self-signed one.
- **Bound by configuration** (the flow before 2026-10-09, still accepted): register the URL in the App
  (`POST /v2/relays`, COORD.md §10), put the `relayId` and `account` it shows into the configuration, start the relay,
  then verify (coordination fetches `/.well-known/pocket-relay`). Such a relay never answers a claim (409 `claimed`).

### 12.1 Without a domain: pinned self-signed certificate and claim
The way Tailscale's DERP servers run on a bare IP address: the relay makes its own certificate; coordination
distributes its fingerprint; devices accept exactly that certificate.

**Certificate.** ECDSA P-256 key; X.509 v3, self-signed (issuer = subject), CN = the host, subjectAltName = the IP
address (or the DNS name when `publicUrl` names one), basicConstraints CA:FALSE (critical), keyUsage digitalSignature
(critical), extKeyUsage serverAuth, a random positive 16-byte serial, ecdsa-with-SHA256, valid from one day before
creation for 10 years. Kept as `dataDir/tls/self-key.pem` and `self-cert.pem` (0600) and reused across restarts; a new
one is made only when the files are missing or broken, the certificate expires within 30 days, or the public host
changes. A relay that does not know its address yet serves a certificate without subjectAltName (CN
`pocket-self-signed`) and replaces it once it does; it prints no line meanwhile.

**Pin** = `"sha256:"` + the lower-case hex SHA-256 of the leaf certificate's DER (64 digits).

**Public address.** `publicUrl` when configured. Otherwise, when the relay terminates TLS itself, it asks
`GET <coord.url>/v2/whoami` → `{ "ip": "<the address the request came from>" }` at every start (before making a
certificate) and assumes devices reach it at `https://<ip>:<listen.port>`; the answer is kept in `dataDir/public.json`
and used when a later lookup fails; while it has none, it retries every minute (doubling up to 15 minutes) and prints
how to set `publicUrl` (`RELAY_PUBLIC_URL`). Behind a proxy (`tls` off) `publicUrl` is required for a line.

**Connection line.**
```
pocket-relay://<host>:<port>[?pin=sha256:<hex>][&claim=<code>]
```
- `host`: an IPv4 address, an IPv6 address in brackets, or a DNS name (lower case, IDN in punycode; not a name a
  resolver would read as an IPv4 address, such as `127.1`); `port` always present. The relay's base URL is
  `https://<host>:<port>`: no path (a client tolerates one trailing `/`). A relay whose `publicUrl` has a path prints
  no line and says why.
- `pin`: always present for an IP address. For a DNS name it is left out only when TLS is terminated by a proxy, or
  the configured certificate chains to a public CA and covers the name. A line for an IP address without a pin is
  invalid (a relay behind a proxy at an IP address prints no line). Clients MUST refuse a pin of another form.
- `claim`: 32 random bytes, base64url without padding (43 characters); present only while the relay is unclaimed.
- `pin` and `claim` appear at most once; clients ignore parameters they do not know (later additions). No user name,
  no fragment.
- The relay prints the line on standard output with "In the Pocket app: Settings → Relay → Add your own relay, then paste this
  line" in English and Chinese and a reminder to open the TCP port, and writes it to `dataDir/connect.txt` (0600).

**Unclaimed state.** No `relayId`/`account` in the configuration and no `dataDir/binding.json`: the relay keeps a claim
code in `dataDir/claim.json` (0600; reused across restarts until claimed) and answers only `GET /.well-known/pocket-relay`
(`{"v":1,"state":"unclaimed"}`), `GET /v1/info` and `POST /v1/claim` (§6.1); everything else is 503 `unclaimed`.

**Claim.**
```
POST /v1/claim  { "claim": "<code>", "relayId": "r_…", "account": "<account id>" }
→ 200 { "ok": true, "relayId", "account" }
```
- `relayId` matches `^[A-Za-z0-9_:.-]{1,64}$`; `account` is one account id (non-empty, ≤ 128 characters, not `"*"`).
- The code is compared in constant time with the stored one. On success the relay writes `dataDir/binding.json`
  `{relayId, account, at}` (0600), deletes `claim.json`, and serves at once without a restart: tickets must have
  `aud = relayId` and `acct = account` (§3), as on any bound relay. Data that other accounts left in the data directory
  (from before a `reset-claim`) is deleted.
- Errors (the code also repeated as `code`): 400 `bad-request` (malformed body, `relayId` or `account`; the claim code
  stays valid), 403 `bad-claim`, 409 `claimed` (already claimed, or bound by its configuration), 413 `too-large`
  (body > 4 KiB), 429 `rate` with `Retry-After` and `retryAfter` (more than 5 attempts per client IP per minute,
  whatever their outcome).
- A caller whose answer got lost and who then gets 409 checks `/.well-known/pocket-relay`: `relayId` and `account` equal
  to what it sent mean its claim went through.

**Who calls it.** The App hands the pasted line to coordination; coordination parses it, applies its SSRF rules
(COORD.md §10), assigns the relay id, connects over TLS **pinned** to `pin` and sends the claim. Devices then reach the
relay at the line's base URL with the same pin (it travels with the relay's registration).

**Clients and the pin (normative).** With a `pin`, a client — device or coordination — opens TLS without CA
verification and without host name checks, computes the SHA-256 of the DER of the certificate the server presented
and compares it with the pin **before sending anything** (no request line, no headers, no ticket); a mismatch closes
the connection. SNI is sent only for DNS names. Without a `pin`, normal CA and host name verification applies.

**Operator commands.** `node src/main.mjs connect-string` prints the line again (without a claim code once claimed).
`node src/main.mjs reset-claim` writes a new claim code, then removes `binding.json`; a running relay re-reads both
every few seconds, closes every socket (4403 `unclaimed`), forgets its tokens and waits for a claim again. A relay bound
by its configuration refuses `reset-claim`.

**Security considerations.**
- The claim code appears only in the relay's standard output and in its data directory (0600): whoever can read those
  controls the server anyway. It is single use, 256 random bits, compared in constant time, and the per-IP limit keeps
  even guessing noise small. A code that leaked before use is replaced with `reset-claim`.
- Pinning makes the claim and all later traffic safe from interception without any certificate authority: an attacker
  between coordination (or a device) and the relay cannot present the pinned certificate. Clients do not consult
  system root certificates for pinned relays, so a mis-issued CA certificate does not help either.
- The pin and the relay's address are not secret; the account id is visible on `/.well-known/pocket-relay`, as for any
  bound relay. The relay never learns more than §11 lists: the claim gives it a relay id and an account id, not a key.
- Whoever holds the certificate's private key can impersonate the relay — which is the relay, and only ever sees
  ciphertext (E2EE §2). To replace the key: delete `dataDir/tls/`, restart, `reset-claim`, add the relay again.
- A changed public address means a new certificate and pin: devices keep the old ones and cannot connect until the
  relay is added again. Operators who expect changes use a static address or a domain in `publicUrl`.
- The whoami lookup trusts coordination for the address only; a wrong answer makes an unusable line, nothing worse.

## 13. Official relay
`relayId` = `hk1`, base URL `https://pocket.pocketcli.net/relay` (WebSocket `wss://pocket.pocketcli.net/relay/v1/ws`),
`account` = `*`, hosted in Hong Kong next to the coordination server. Blob backends: Tencent COS Shanghai for clients in
mainland China, Tencent COS Hong Kong for everyone else (`cn-ip` rule), quotas from tickets (today 200 MB/day,
2 GB/month and 5 GB stored per account, and a 50 MB/day small-file allowance). Coordination pushes revocations to it
over loopback.

## 14. Errors
| HTTP | `error` codes |
|---|---|
| 400 | `bad-request`, `mismatch`, `bad-blob` |
| 401 | `token`, `bad-ticket`, `expired`, `bad-proof`, `bad-nonce`, `bad-sig`, `stale`, `unknown-key`, `key-not-valid`, `wrong-aud` |
| 403 | `denied`, `revoked`, `wrong-account`, `bad-claim` |
| 404 | `not-found` |
| 409 | `ver`, `exists`, `size`, `claimed` |
| 413 | `too-large` |
| 429 | `rate`, `quota` |
| 503 | `storage`, `unclaimed`, `full` (the relay's disk is nearly full, §8.4) |

Errors of the claim flow (§12.1: `POST /v1/claim`, and `unclaimed` answers) repeat the code as `"code"` next to `"error"`.

## 15. Conformance tests (the relay's own suite)
- Ticket and proof verification: every case in `vectors.json` `coord.ticket` and `coord.relayAuth`; challenge reuse;
  auth timeout; renewal on the same socket; bound-account relay refusing other accounts; before `ready` frames over
  64 KiB close 4413 and sockets beyond `unauthSockets` get 503, and authenticated ones do not count.
- Revocation: cut-off by document push and by poll; sockets closed on cut-off; `gone` purges data; old tickets rejected,
  new tickets accepted after a suspension is lifted.
- Envelopes: peers enforcement, `*` fan-out, queue order, TTL expiry and `expired` notice, acks and redelivery,
  limits (`too-large`, `rate`, `full`), presence events.
- Objects: owner-only writes, version conflicts, header cross-check, list with `since`/`inline`, heads, range with
  `prefer=lite`, `skip`, byte caps and `X-Pocket-More`, change notifications and `resync`.
- Blobs: reservation, direct upload with header check, presigned upload + commit size check (against a fake S3),
  302 downloads without forwarding Authorization, ranges, quotas per day/month with the configured timezone,
  the small-file allowance (small blobs go on after the day and the month, large ones wait, a large blob read in
  ranges is not small, the allowance is bounded and comes back the next day, none for stored bytes), caps from the
  account's newest ticket whichever device presents it (older tickets change nothing, kept across a restart,
  forgotten on purge), retention sweeps.
- Storage: stored bytes count objects and blobs together (default and ticket cap, a smaller new version passes,
  deletes and purges make room, accounts apart); the disk minimum (objects, reservations and direct uploads 503,
  queueing `full`, reads, deletes, live delivery and bucket uploads go on, logged once each way); with a bucket no
  direct upload without a direct-mode reservation; tiny ranges and cut-off downloads do not renew a blob; a direct
  upload under way keeps its reservation through a sweep and loses its bytes when the reservation goes; presigned PUTs
  valid 15 minutes, late uploads after a delete or an expired reservation swept, committed blobs never touched.
- Purge orders: wrong label, wrong relay, older than 7 days, replayed. Control documents signed by a key not allowed
  to sign them, under another label (a ticket), or with another document's signature; unknown key ids fetch keys at
  most once a minute; bodies over the limit are not read.
- Public endpoints give `version` as major.minor.
- Logs contain none of: seal bytes, tickets, tokens, nonces, presigned URLs, claim codes.
- Without a domain (§12.1): the self-signed certificate's fields (also read back by `openssl`), TLS with a correct and
  a wrong pin, files and modes in the data directory, the line in connect.txt and on standard output, only three
  endpoints while unclaimed (WebSocket too), claim tries per IP, malformed claims leave the code valid, the binding
  survives a restart with the same certificate, `reset-claim` from another process unbinds the running relay and a new
  owner does not see the previous account's data, whoami failing then answering, `publicUrl` with a DNS name and a base
  path, certificate files (pinned unless from a public CA), the official configuration unchanged (no lookup, no files,
  plain HTTP, every account), the relay as a process with an environment-only configuration (`--health`,
  `connect-string`, claim, `reset-claim`, SIGTERM).
