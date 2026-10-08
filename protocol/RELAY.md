# Pocket relay — protocol and behaviour v1

Status: implementation spec, phase 1 (2026-10-08). License of the relay implementation: **AGPL-3.0**.
Crypto, identifiers and verification rules come from [E2EE.md](E2EE.md); this document defines what a relay stores,
which requests it accepts and how it answers. Paths below are relative to the relay's **base URL**
(official relay: `https://pocket.pocketcli.net/relay`; a self-hosted relay: whatever URL its owner registered).

> **中文摘要**　中继只搬运和暂存密文:实时转发信封、短时排队、保存会话记录的加密对象、保存加密附件(本机磁盘或任意
> S3 兼容对象存储)。它凭协调服务器签的短期票据放行(离线校验,不需要我们的任何秘密),并要求设备当场用私钥签一次
> 挑战;只在同一账号、ACL 允许的设备之间转发;自建中继只服务绑定的那个账号。它看得到大小、时间、谁和谁通信,看不到内容。

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
  "relayId": "hk1",                         // must equal the `aud` of tickets; given by coordination at registration
  "account": "*",                           // "*" = any account (official); otherwise the one account this relay serves
  "publicUrl": "https://relay.example.com", // base URL as devices reach it (used in /v1/info and redirects)
  "listen": { "host": "0.0.0.0", "port": 8443 },
  "tls": { "cert": "/etc/relay/fullchain.pem", "key": "/etc/relay/privkey.pem" },   // or null behind a TLS proxy
  "trustProxy": false,                      // true only behind a reverse proxy that sets X-Forwarded-For
  "coord": {
    "url": "https://pocket.pocketcli.net",  // keys: <url>/.well-known/pocket/keys.json; feed: <url>/v2/relay/revocations
    "pinnedKeys": [ { "kid": "c1", "pub": "<b64u 65 B>", "use": ["keys","ticket","revocations","purge"], "nbf": 0, "exp": 0 } ]
  },
  "dataDir": "/var/lib/pocket-relay",
  "blobs": { "store": "disk" },             // or { "store": "s3", "backends": [ … ] } — §9
  "timezone": "Asia/Shanghai",              // day/month boundaries for traffic quotas
  "quota": { "dayMB": null, "monthMB": null, "storeMB": null, "useTicketQuota": true },
  "retention": { "objectDays": 30, "blobDays": 30, "queueMaxSeconds": 604800 },
  "limits": { }                             // overrides of §10
}
```

Startup MUST fail if `relayId` or `account` is missing, or if no coordination key is pinned. The pinned keys bootstrap
trust; the relay then refreshes `keys.json` (every 6 h and when it meets an unknown `kid`) and adopts new keys only
when signed by a key it already trusts (E2EE §12.1).

## 3. Authentication

### 3.1 WebSocket
`GET /v1/ws` upgrades without credentials. The relay immediately sends a challenge; the device has 10 s to answer.

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

Frames are JSON text, at most 2 MiB each. After `ready`, either side may send at any time.

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
`too-large`, `rate`, `full` (recipient queue full) or `quota`.

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
expired, 4403 revoked or not allowed, 4408 no `auth` within 10 s, 4409 replaced by a newer socket, 4413 frame too
large, 4429 rate limited. Other errors on a live socket are frames: `{"t":"error","code":…,"id"?:…}`. Frames the relay
sends before closing: `replaced` (4409), `expired` (4401), `revoked` (4403). A `sub` naming realms the ticket cannot
read is answered `{"t":"error","code":"denied","realms":[…]}` and the readable rest is subscribed.

## 6. HTTP API

JSON responses use `application/json`; errors are `{"error": "<code>", "message"?: "<English text for logs>"}` with the
HTTP status of §14. Clients translate codes into their own sentences.

### 6.1 Public
- `GET /v1/info` → `{ "service": "pocket-relay", "version", "relayId", "account", "time", "features": ["ws","objects","blobs","presign"], "limits": {"envelope": 1048576, "object": {…}, "blob": 104857600} }`
- `GET /.well-known/pocket-relay` → `{ "relayId", "account", "version" }` (coordination checks a self-hosted relay with it).

### 6.2 Auth
§3.2.

### 6.3 Objects
Objects are binary seals (`application/x-pocket-seal`, E2EE §3.5). `{realm}` is an address; `{kind}` ∈ `info`, `usage`,
`sess`, `msg`, `lite`; `{key}` matches `[A-Za-z0-9_-]{1,64}`; `{seq}` is a positive integer (only for `msg`, `lite`).

| Request | Who | Behaviour |
|---|---|---|
| `PUT /v1/o/{realm}/{kind}/{key}[/{seq}]` + `X-Pocket-Ver: <int>` | owner | Store if `ver` is greater than the stored version (else `409 {"error":"ver","ver":<stored>}`). Size ≤ the kind's limit + 4096 + 88 bytes (header, tag and framing). The relay parses the seal header and rejects (`400 mismatch`) a header whose `realm` or `by` is not the ticket's did, or whose `kind`, `key`, `seq` or `ver` (= `X-Pocket-Ver`) disagree with the request. Answer `{ "ver", "rev" }`; bump the realm `rev`; notify (§5.4). |
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
| `POST /v1/b/{realm}/{blobId}/upload` `{ "bytes": n }` | writer | Reserve. `bytes` is the length of the encrypted `PKB1` stream (22 + plaintext + 16·⌈plaintext/65536⌉). `409 {"error":"exists"}` if present. Quota checked against `bytes` now (`429 quota`). Answer `{ "mode": "presigned", "url", "method": "PUT", "headers": {"Content-Length": "<n>"}, "expires" }` (S3 store; the length is signed into the URL, send the header as given) or `{ "mode": "direct" }`. |
| `PUT /v1/b/{realm}/{blobId}` | writer | Direct upload; `Content-Length` required and equal to the reserved `bytes`; ≤ 100 MiB + 22 + 16·⌈n/65536⌉. A PUT without a reservation is accepted and reserved on the spot (disk store). The relay checks the 22-byte header (magic, version, chunk size, blob id) and the length formula. |
| `POST /v1/b/{realm}/{blobId}/commit` `{ "bytes": n }` | writer | Presigned mode: the relay HEADs the bucket object; size must equal the reservation (else it deletes the object, `409 size`). Charges traffic. |
| `GET /v1/b/{realm}/{blobId}` | reader | Disk: 200 with the bytes, `Range` supported (single range), charged by the bytes sent. S3: `302` to a presigned GET valid 2 minutes (the client follows **without** its `Authorization` header, at once; a download that started keeps going after the expiry); charged the **stored size** whatever `Range` was asked — the URL serves the whole object and can be replayed until it expires. |
| `HEAD /v1/b/{realm}/{blobId}` | reader | Size only; free. |
| `DELETE /v1/b/{realm}/{blobId}` | owner or uploader | Delete. |

Unfinished reservations expire after 1 hour (their bucket objects are deleted).

### 6.5 Control
| Request | Body | Behaviour |
|---|---|---|
| `POST /v1/revocations` | signed revocation document (E2EE §12.4) | Verify, apply (§3.3); `{ "applied": n }`. No token needed. |
| `POST /v1/purge` | signed purge order (E2EE §12.5) | Verify; if `relay` is this relay or `"*"` and `at` within 7 days and not seen before, delete everything for the account (or the listed realms); `{ "deleted": {objects, blobs, queued} }`. An order already applied answers `200 {"already": true}` (so the sender's retry queue stops). No token needed. |
| `GET /v1/me/quota` | — | `{ "day": {used, cap}, "month": {used, cap}, "store": {used, cap} }` for the caller's account (bytes; `cap` 0 = unlimited). |

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
  (`realm, blobId, bytes, store, backend, uploader, createdAt, lastRead`), traffic counters (`acct, day, bytes`).
- Object bodies: files under `dataDir/o/…` written atomically (temp + rename), or rows in the database.
- Blob bodies: `dataDir/b/<realm>/<blobId>` or the bucket key `<prefix><realm>/<blobId>`; nothing else (no names, no
  account ids in plain, no content types).

### 8.2 Retention (defaults; configurable)
- Objects: deleted when neither written nor read for `objectDays` (30). `sess`, `info` and `usage` objects of a computer
  that is still connected at least weekly are kept.
- Blobs: deleted `blobDays` (30) after the last download, or after upload if never downloaded (today's policy).
- Queue: by `ttl`; at most `queueMaxSeconds`.
- `gone` cut-offs and purge orders delete at once.
- Deleted data is gone: no trash, no backups of ciphertext beyond what the operator's disk snapshots keep.

### 8.3 Quotas
Per account: blob traffic per day and per month (uploads and downloads count, `HEAD` does not), and optionally
stored bytes. Values come from the config or, when `useTicketQuota` is true, from the ticket's `quota`
(`dayMB`, `monthMB`, `storeMB`; 0 = unlimited). Day and month follow `timezone`. Over quota:
`429 {"error":"quota","quota":{"day":{used,cap},"month":{used,cap}},"retryAfter":<s>}` with `Retry-After`.
Envelope and object traffic is not counted against the blob quota (limits of §10 still apply).

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
- If the bucket is unreachable at reservation time the relay answers `{mode: "direct"}` and stores on disk instead.
- The relay deletes bucket objects on retention, purge and `gone`.

## 10. Limits (defaults)
| What | Default |
|---|---|
| WebSocket frame | 2 MiB |
| Envelope ciphertext / header | 1 MiB / 4 KiB |
| Frames per connection | burst 50, sustained 20 per second |
| Sockets per device | 2 |
| Queue per recipient | 1000 envelopes, 32 MiB, TTL ≤ 7 days |
| Object sizes | `info` 256 KiB, `usage` 16 KiB, `sess` 64 KiB, `msg` 4 MiB, `lite` 1 MiB (+ 4096 + 88 bytes for header, tag and framing) |
| Object writes | 30 per second per owner |
| Blob size | 100 MiB of plaintext |
| Concurrent blob uploads per device | 4 |
| JSON request bodies | 64 KiB, 30 s |
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
1. A server with a public IP and a domain; 1 vCPU / 1 GB RAM is enough for one person. HTTPS certificate from any CA
   (ACME through a reverse proxy, or `tls.cert`/`tls.key`).
2. In the Pocket App: Settings → Relay → Add your own relay → enter the URL. Coordination answers with a `relayId` and
   your account id; put both into the config. (Nothing secret is exchanged: the relay only learns public values.)
3. Start the container (`docker run … -v /srv/pocket-relay:/var/lib/pocket-relay -e RELAY_RELAY_ID=… -e RELAY_ACCOUNT=…`),
   then tap "Verify" in the App (coordination fetches `/.well-known/pocket-relay`), then "Use this relay".
4. Switching relays: computers re-upload their sessions to the new relay automatically; phones re-download. The old
   relay's data can be deleted by its owner.
5. If your relay is unreachable, the App offers to switch back to the official relay.

## 13. Official relay
`relayId` = `hk1`, base URL `https://pocket.pocketcli.net/relay` (WebSocket `wss://pocket.pocketcli.net/relay/v1/ws`),
`account` = `*`, hosted in Hong Kong next to the coordination server. Blob backends: Tencent COS Shanghai for clients in
mainland China, Tencent COS Hong Kong for everyone else (`cn-ip` rule), quotas from tickets (today 200 MB/day,
2 GB/month per account). Coordination pushes revocations to it over loopback.

## 14. Errors
| HTTP | `error` codes |
|---|---|
| 400 | `bad-request`, `mismatch`, `bad-blob` |
| 401 | `token`, `bad-ticket`, `expired`, `bad-proof`, `bad-nonce`, `bad-sig`, `stale`, `unknown-key`, `key-not-valid`, `wrong-aud` |
| 403 | `denied`, `revoked`, `wrong-account` |
| 404 | `not-found` |
| 409 | `ver`, `exists`, `size` |
| 413 | `too-large` |
| 429 | `rate`, `quota`, `full` |
| 503 | `storage` |

## 15. Conformance tests (the relay's own suite)
- Ticket and proof verification: every case in `vectors.json` `coord.ticket` and `coord.relayAuth`; challenge reuse;
  auth timeout; renewal on the same socket; bound-account relay refusing other accounts.
- Revocation: cut-off by document push and by poll; sockets closed on cut-off; `gone` purges data; old tickets rejected,
  new tickets accepted after a suspension is lifted.
- Envelopes: peers enforcement, `*` fan-out, queue order, TTL expiry and `expired` notice, acks and redelivery,
  limits (`too-large`, `rate`, `full`), presence events.
- Objects: owner-only writes, version conflicts, header cross-check, list with `since`/`inline`, heads, range with
  `prefer=lite`, `skip`, byte caps and `X-Pocket-More`, change notifications and `resync`.
- Blobs: reservation, direct upload with header check, presigned upload + commit size check (against a fake S3),
  302 downloads without forwarding Authorization, ranges, quotas per day/month with the configured timezone,
  retention sweeps.
- Purge orders: wrong label, wrong relay, older than 7 days, replayed.
- Logs contain none of: seal bytes, tickets, tokens, nonces, presigned URLs.
