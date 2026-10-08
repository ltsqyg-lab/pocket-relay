# Pocket coordination server — API v2

Status: implementation spec, phase 1 (2026-10-08). The coordination server is closed source; this document is its
public interface. It extends today's server (`https://pocket.pocketcli.net`, docs/PROTOCOL.md, "v1") with `/v2`.
Crypto and data formats: [E2EE.md](E2EE.md). Relays: [RELAY.md](RELAY.md). Old → new map: [MAPPING.md](MAPPING.md).

> **中文摘要**　协调服务器管「谁是谁、谁能连谁」:账号与登录(照旧)、每台设备的公钥与虚拟地址、设备锁日志(只存、只校验、
> 只转发,签不出)、包好的内容钥匙(打不开)、短期中继票据、设备表(netmap)、控制推送、中继登记、撤销名单、清除令。
> 它不再存、不再转任何对话内容;双跑期内老接口照旧给老版本用(MAPPING.md)。

---

## 1. Scope

Keeps (unchanged from v1): accounts, password sign-in, email codes, OAuth sign-in for computers, phone tokens and
computer tokens, preferences (`listDays`), language, sign-in notifications, the website, downloads and the update
manifest, the review/demo account, admin tooling.

Adds:
- a device registry: each device's two public keys, kind, platform, name, virtual address, state;
- the account's **lock log** (E2EE §5): stored, validated, ordered (compare-and-swap), served, pushed;
- **grants** (E2EE §8.4) as opaque sealed blobs, routed to their recipients;
- **tickets** for relays and ASR gateways (E2EE §12.2), and the **netmap** (E2EE §12.3);
- a **control WebSocket** per device;
- the **relay registry** (official + self-hosted) and each account's chosen relay;
- the **revocation feed** and **purge orders** (E2EE §12.4–12.5);
- lock **reset** with password + email code (E2EE §5.6).

Never sees after the dual run: messages, session titles, project paths, model lists, approval cards, commands,
attachments, usage figures, search queries, audio (except through the official ASR gateway, which is a separate
open-source service — ASR.md).

## 2. Authentication
- Bearer tokens exactly as v1: phones use the `userToken` from `/v1/auth/login|register`; computers use the
  `agentToken` from `/v1/agents/login`, `/v1/agents/claim` or `/v1/oauth/token`.
- `POST /v2/devices/enroll` binds the calling token to one device id (`did`). From then on every `/v2` call with that
  token acts as that device. A token is bound to at most one device; a device to exactly one token at a time.
- Token kind decides device kind: user token → `phone`, agent token → `computer`.
- A valid token that is not bound to a device yet gets `409 {code: "not-bound"}` on every `/v2` call except enroll
  (never 401, which clients treat as "logged out").
- Revoking or suspending a device revokes its token (and v1 tokens of the same row). Logging in again issues a new
  token that can re-bind to the same `did` only by enrolling with the same public keys (§4.1).
- Responses keep the v1 convention: errors are `{ "error": "<sentence for the user>", "code": "<machine code>" }`
  with `Accept-Language` deciding the sentence (zh/en).

## 3. Coordination signing keys
- P-256 keys, `kid` `c1`, `c2`, …; uses: `keys`, `ticket`, `netmap`, `revocations`, `purge`.
- Private keys live only on the coordination host (`/etc/pocket/coord-keys/<kid>.pem`, root 0600, never in the repo,
  never logged) plus an **offline backup kept by the owner**. Losing them means re-issuing keys through a release
  (clients pin keys); leaking them lets an attacker mint tickets and netmaps — not lock statements, grants or content.
- `GET /.well-known/pocket/keys.json` and `GET /v2/keys` (public, cacheable 1 h): the keys document (E2EE §12.1),
  signed by every currently valid key.
- `node cli.mjs keys init` (create `c1`), `keys rotate` (create the next key, publish it signed by the current one,
  start signing with it after a grace period), `keys show`. The App, agent, relay and ASR gateway ship the current public
  key pinned (kid + point); test labs generate their own keys and never use the test keys in vectors.json outside tests.

## 4. Devices

### 4.1 Enroll
`POST /v2/devices/enroll` (Bearer)
```json
{ "name": "iPhone 18 Pro", "platform": "ios", "sig": "<b64u 65 B>", "kx": "<b64u 65 B>", "sasLang": "zh" | "en",
  "proof": { "a": "<b64u enroll-auth JSON>", "s": "<b64u signature>" } }
```
Server:
1. Validate keys (E2EE §3.3) and name; verify `proof` (E2EE §13, `enroll-auth`: bound to these two keys and to the
   presented token, `|now − ts| ≤ 5 min`, signed by `sig`; `400 bad-proof` / `stale` / `bad-sig`) — so only a holder of
   the private key can bind a token to a device, and a stolen password cannot take over or suspend another device's
   binding; `did = didOf(sig, kx)`; kind from the token.
2. If the token is already bound to this `did`: return its current state (idempotent). If bound to a different `did`:
   the old device is **suspended** (`replaced`), the binding moves to the new `did` (the App or agent lost its keys).
3. Assign an address (§13) to a new `did`.
4. State:
   - the account has no lock → phone: `genesis` (the client now appends a genesis, §5); computer: `waiting`
     (no genesis by computers, E2EE §6.5; it becomes `pending` when a lock appears);
   - the `did` is live in the lock → `active`; revoked → `revoked` (409, new keys needed: the device generates a new
     pair and enrolls as a new device);
   - otherwise → `pending`: create a pending entry (expires after 24 h), push `enroll_pending` to every live admin device
     of the account (§9) and a sign-in style notification to phones.
5. Answer
```json
{ "did": "…", "addr": "100.64.12.7", "state": "genesis" | "waiting" | "pending" | "active" | "suspended" | "revoked",
  "pendingId": "pd_…"?, "lock": { "seq": 9, "h": "…", "genesis": "…" }?, "demo": true? }
```
`demo: true` only on the review demo account (§15): its new phones are approved by the demo computer, which has no screen,
so the app's waiting screen tells the user to just tap "They match".
Rate limit: 10 enrollments per account per hour, 3 pending entries per account at a time.

`active` here means "in the lock", not "turned on": a new device turns on only after its own user confirmed the words on
it (E2EE §6.1). A computer that is in the lock but has no realm yet, or a phone that has not confirmed, is a normal
state (the user has not compared on that device yet), not a fault; coordination does not track it.

### 4.2 Lists
- `GET /v2/devices` → `{ "devices": [ { did, kind, platform, name, addr, sig, kx, state, sas?, online, lastSeen, createdAt,
  v1: { agentId? }, current } ] }` — `state` ∈ `waiting`, `pending`, `active`, `suspended`, `revoked`;
  `sas` copied from the lock's `add`. Devices treat this as display data; trust comes from the lock.
- `GET /v2/devices/pending` → `{ "pending": [ { pendingId, did, kind, platform, name, addr, sig, kx, sasLang, at, expiresAt } ] }`
  (any live device of the account; only admins can act on it).
- `POST /v2/devices/pending/{pendingId}/reject` → removes it, pushes `enroll_result {state: "rejected"}` to the requester.
  (Coordination-level; no signature needed — rejecting can only reduce access.)

### 4.3 Suspend and remove
- `POST /v2/devices/{did}/suspend` (any live phone of the account, or the device itself) → coordination suspension
  (E2EE §5.7): token revoked, new revocation item with `nbf = now`, control socket closed, netmap pushed. Used by
  "log out this phone", "log out all devices" (all devices), password change (other phones).
- A suspended device that signs in again and enrolls with the same keys returns to `active` (a new cut-off is not
  needed; its new tickets have `iat` after the old `nbf`). Suspension is "sign out", not removal: whoever has the
  password and the device's private key can come back this way. Removing a device for good is a lock `revoke`, which only
  an admin device can sign.
- Removing a computer (`DELETE /v1/agents/{id}` or the device page) suspends it and issues a purge order for its realm
  (§11); the App also signs a lock `revoke` when it is an admin.

### 4.4 Leaving the v1 path
`POST /v2/devices/v1-off` (computer) — "my first full sync to the relay is done; I no longer report content over v1".
Coordination then answers old Apps acting on this computer with "please update the App", drops it from the v1 session
list, and deletes its plaintext on the server 24 hours later (dry run until the operator enables purging, MAPPING.md
§10). A control-socket `hello` with `"v1": "off"` means the same (§9).
From then on the v1 path is closed for that computer whatever client uses its agent token: `/v1/agent/ws` answers
`410 {code: "v2-only"}` (a v1 link still open at that moment is closed) and so do the attachment uploads
(`/v1/attachments/{sha}/upload-url`, `/uploaded`, `PUT`). An old desktop version installed again on that computer — or a
copy of its token — cannot report transcripts in plaintext any more.

## 5. Lock log
- `GET /v2/lock?since=<seq>` → `{ "acct", "genesis", "head": {seq, h}, "statements": [ {p, s}, … ] }` (statements after `since`).
- `POST /v2/lock` `{ "statement": { "p", "s" } }`
  1. Validate against the stored log with exactly E2EE §5.3 (the server runs the same validator and passes vectors.json).
     A genesis is accepted only from a phone of an account without a lock, or inside a reset window (§12), or from the
     demo computer (§15).
  2. Compare-and-swap: the statement's `prev`/`seq` must extend the current head, else
     `409 { "code": "head", "head": {seq, h} }`.
  3. Store, then side effects:
     - `add`: device `pending`/`waiting` → `active`; push `enroll_result {state: "active"}` to it; push `lock` to all;
       push `notify {kind: "device_added", did, name, platform, title, body}` to the other phones.
     - `revoke`: device → `revoked`; revoke its tokens; revocation item `{nbf: 2^53−1, gone: true}`; push to relays;
       if it was a computer, issue a purge order for its realm.
     - `policy`: recompute peers; issue revocation items `{nbf: now}` for every device whose peers shrank (their relays
       drop old tickets; they fetch new ones automatically); push `netmap`.
     - `realm`: push `lock` (phones fetch grants). The statement must be in the log before grants of that epoch are
       accepted (§6).
  4. Answer `{ "head": {seq, h} }`.
- Statements are never edited or deleted; on account deletion the whole log goes. A reset archives the old log for
  30 days (for the "lock was reset" screens), then deletes it.

## 6. Grants
- `POST /v2/grants` `{ "grants": [ <seal JSON>, … ] }` (≤ 50 per call, ≤ 64 KiB each). The server parses each header
  (`t = grant`, `to`, `by`, `realm` are devices of this account, `by` = the caller, recipient not revoked) and verifies
  the signature with `by`'s key from the lock (cheap; keeps garbage out). It also requires `to` to be the realm itself
  or a device with `read` on it, and every epoch's `kid` in the header to equal the lock's `kid` for that epoch
  (`bad-kid`). It cannot decrypt anything.
  Stored as `(id, acct, to, realm, by, epochs, seal, at)`; a newer grant from the same `by` to the same `to` for the same
  realm whose epochs are a superset replaces older ones.
- `GET /v2/grants?since=<cursor>` → `{ "grants": [ { "cursor", "seal" } ], "next" }` — only grants addressed to the caller.
- Grants to a revoked device are deleted.

## 7. Tickets
`POST /v2/tickets` `{ "aud": "<relayId>" | "asr:<gatewayId>" }` → `{ "ticket": "<compact>", "exp": … }`
- Caller must be `active` in the lock and not suspended.
- Relay tickets only for the account's current relay or another relay registered to the account (so devices can move).
- `peers`: for a phone, addresses of computers it can `read` (E2EE §7.2); for a computer, addresses of phones that can
  `read` it. Revoked and suspended devices never appear.
- `quota`: the account's attachment limits for the official relay (`prefs.quota` or the defaults 200 MB/day,
  2048 MB/month), absent for other relays.
- Lifetime 6 hours; clients renew at half-life. Rate: 60 per device per hour. The server never issues a ticket living
  longer than 24 hours, whatever its configuration says (relays and gateways refuse longer ones).

## 8. Netmap
`GET /v2/netmap` → signed document (label `netmap`):
```json
{ "v": 1, "t": "netmap", "kid": "c1", "acct": "…", "at": …, "ver": 42, "self": "<did>",
  "lock": { "seq", "h", "genesis" },
  "devices": [ { "id", "addr", "kind", "platform", "name", "sig", "kx", "status", "online", "lastSeen", "ver"?, "v1"?: { "agentId" } } ],
  "relay": { "id": "hk1", "url": "https://pocket.pocketcli.net/relay", "region": "hk", "kind": "official" },
  "relays": [ { "id", "url", "region", "kind": "official" | "self", "state": "verified" | "unverified" } ],
  "prefs": { "listDays": 2 }, "lang": "zh",
  "asr": { "official": { "url": "https://pocket.pocketcli.net/asr", "aud": "asr:official" } } }
```
`ver` increases on every change; the control socket announces it. Devices verify the signature (E2EE §12.3) and treat
device keys in it as hints only.

## 9. Control WebSocket
`GET /v2/ws` (Bearer; the token must be bound to a device). One per device. Server → device events:

| Event | Fields | To | Meaning |
|---|---|---|---|
| `hello_ok` | `did`, `state`, `time`, `netmapVer`, `lockHead` | the device | after connect |
| `netmap` | `ver` | all of the account | refetch `/v2/netmap` |
| `lock` | `head` | all | refetch `/v2/lock?since=` |
| `enroll_pending` | `pendingId`, `kind`, `name`, `platform` | live admins | show the approval screen |
| `enroll_result` | `state` (`active`, `rejected`, `expired`) | the enrolling device | |
| `grant` | `cursor` | the recipient | fetch grants |
| `revocations` | `doc` (signed) | all | hand to the relay (`POST /v1/revocations`) |
| `prefs` | `listDays` | computers | as v1 `prefs` |
| `user_lang` | `lang` | computers | as v1 `user_lang` |
| `notify` | v1 shapes (`login`, `device_added`) | phones | local notification |
| `suspended` | `reason` | the device | then close 4401 |
| `relay` | `id` | all | the account switched relays |
| `purge` | `doc` (signed purge order) | all | the account uses a self-hosted relay: hand the order to it (`POST <relay>/v1/purge`) |

`notify` kinds for v2 accounts: `login` (a new sign-in), `device_added` (`did`, `name`, `platform`, `title`, `body`),
and `enroll_pending` arrives as its own event (above).

Device → server: `{"t":"ping"}` (and WebSocket pings); `{"t":"hello","ver":"<client version>","v1"?:"off"|"syncing"|"on"}`
once after connect — computers report whether they still use the v1 path (`off` is the same as §4.4).
Coordination derives "online" for the netmap from this socket (relays have their own presence). Keep-alive 30 s, dead
after 90 s; token revocation closes with 4401.

## 10. Relay registry
- Official relays are server configuration (`hk1` today).
- `POST /v2/relays` `{ "url": "https://…", "name": "…" }` (phone; ≤ 3 per account) → `{ "relayId": "r_<10 chars>", "account": "<acct>",
  "config": { "relayId", "account", "coord": { "url", "pinnedKeys" } } }` — everything the operator pastes into the relay's
  config; nothing secret.
- `POST /v2/relays/{id}/verify` → the server fetches `<url>/.well-known/pocket-relay` and requires `relayId` and
  `account` to match. SSRF rules: `https` only, port 443 or 8443, DNS must resolve to public unicast addresses only
  (checked again on connect), 5 s timeout, ≤ 4 KiB response, no redirects. → `{ "state": "verified" }` or the reason.
  The lab switch that relaxes these rules (`POCKET_RELAY_VERIFY_LAB=1`, loopback and any port) is ignored, with an error
  in the log, when the server runs in production (`NODE_ENV=production`, or its signing keys live under `/etc`).
- `POST /v2/account/relay` `{ "relayId": "hk1" | "r_…" }` (phone) → sets the account's relay (must be official or a
  verified relay of the account); pushes `relay` and `netmap`. Computers then re-upload their realm to the new relay.
- `DELETE /v2/relays/{id}` (not while it is the account's relay).

## 11. Revocation feed and purge orders
- `GET /v2/relay/revocations?acct=<acct>&since=<cursor>` (public, no auth; `acct` required) → signed document
  (label `revocations`): `{ "v":1, "t":"revocations", "kid", "at", "acct", "since", "next", "items": [ { "addr", "dev", "nbf", "gone"?, "at" } ] }`.
  Items are kept 180 days.
- On every new item the server pushes the document to the official relays and the official speech gateway
  (`POST <local>/v1/revocations` over loopback) and to the account's devices (`revocations` event) so they can hand it
  to a self-hosted relay. What a target did not accept is pushed again every minute until it does; after a restart the
  server pushes the last 24 hours (the longest ticket lifetime) again — cut-offs are idempotent. This matters for the
  speech gateway, which serves every account and so does not poll. The gateway's `/v1/revocations` is not reachable
  through the public `/asr` proxy; only coordination posts there.
- The feed is public so self-hosted relays can poll it without credentials. It shows, for an account id, its devices'
  ids and virtual addresses and when they were cut off or removed. Account ids are 64-bit random values that only the
  account's devices and relays learn.
- Purge orders (label `purge`, `{ "v":1, "t":"purge", "kid", "acct", "at", "relay": "hk1" | "*", "addrs"?: [...] }`) are
  sent to the official relay on: account deletion (`relay: "*"`, no `addrs`), computer removal or revocation
  (`addrs: [its address]`), relay switch after 7 days (old relay, if official). Delivery is retried hourly for 30 days
  (persisted queue, like today's COS purge list); each retry is a freshly signed copy (new `at`), and a relay answers an
  order it already applied with `200 {already: true}`, which ends the retries. Self-hosted relays receive purge orders
  through the account's devices (`purge` event, §9) when they are online; otherwise their owner deletes the data.

## 12. Lock reset
`POST /v2/lock/reset` `{ "password": "…", "code": "<email code, purpose reset-lock>" }` (phone token; computers ask the
user through the tray and call it with their agent token the same way). Requests the code with
`POST /v1/auth/email-code {email, purpose: "reset-lock"}`. On success: a 15-minute window in which this device may
append a genesis with `resetOf` = the current head; an email "your device lock was reset" goes to the account address;
at most 3 resets per account per 30 days. The new genesis replaces the log (the old one is archived, §5), all other
devices become `waiting` (not `pending`: nothing is offered for approval until that device's own user confirms the
reset there, E2EE §5.6, and enrolls again) and get `lock` events.

## 13. Address allocation
Random addresses in 100.64.0.0/10, last octet 1–254, unique across all accounts; an address is not reused for 180 days
after its device is revoked or deleted — as long as relays keep `gone` cut-offs (RELAY.md §3.3), so a new device never
inherits an old cut-off.

## 14. Preferences, language, notifications
Same data and rules as v1. For v2 devices they travel on the control socket (`prefs`, `user_lang`, `notify`) instead of
the v1 sockets. "New device signed in" becomes "New device wants to join — approve it on a device you trust" for v2
accounts.

## 15. Review / demo account
The demo computer (`server/demo-agent.mjs`, systemd `pocket-demo`) becomes a v2 computer: it keeps its device keys in
its state directory, creates the demo account's genesis (the only computer allowed to — on the demo account no phone may
create it), **auto-approves** every pending device of the demo account at once (`add` with `sas: false`,
`admin: false`), grants its keyring, writes its sample sessions as objects to the official relay over loopback and
answers commands with the same canned replies as today. A reviewer's phone that enrolls before the demo lock exists
gets `waiting`, turns `pending` when the lock appears and is approved at once. Account deletion and
re-creation work as today; the demo account never gets `reset`.

## 16. ASR tickets
`POST /v2/tickets {aud: "asr:official"}` issues a ticket for the official ASR gateway (ASR.md §3) with `peers: []`.
Rate limit 120 per device per hour (the gateway enforces per-account recognition limits itself).

## 17. Storage
New tables (SQLite, same database as v1):
```
devices   (did PK, acct, kind, platform, name, addr UNIQUE, sig, kx, state, sas_lang, token_hash, agent_id,
           created_at, updated_at, last_seen, suspended_at)
pending   (pending_id PK, did, acct, created_at, expires_at)
lock_log  (acct, seq, payload BLOB, sig BLOB, hash, at, PRIMARY KEY (acct, seq))
lock_archive (acct, archived_at, seq, payload, sig, hash)
grants    (id INTEGER PK, acct, to_did, realm, by_did, epochs TEXT, seal TEXT, at)
relays    (id PK, acct NULL = official, url, name, region, state, created_at, verified_at)
account_relay (acct PK, relay_id, since)
revocations (id INTEGER PK, acct, addr, did, nbf, gone, at)
purge_queue (id INTEGER PK, relay_id, order_doc TEXT, next_try, tries, created_at)
```
`agents` gains `did` (the v2 device of a v1 agent row). Coordination key private parts are files, not rows.

## 18. Limits
| What | Limit |
|---|---|
| Enrollments | 10 per account per hour; 3 pending at once; pending expires after 24 h |
| Lock appends | 60 per account per hour; payload ≤ 16 KiB |
| Grants | 50 per call; 64 KiB each; 500 stored per device |
| Tickets | 60 per device per hour (ASR: 120) |
| Relays | 3 registered per account; 10 verifications per hour |
| Resets | 3 per account per 30 days |
| Control sockets | 1 per device (a new one replaces the old) |

## 19. Dual run
The v1 API keeps working for old clients during the transition (2–4 weeks); its interplay with v2 — which computer
uses which path, what old Apps see, downgrade protection, when plaintext is deleted — is specified in
[MAPPING.md](MAPPING.md) §1.

## 20. Error codes (`code`)
`bad-request`, `bad-key`, `bad-name`, `bad-proof`, `stale`, `not-bound`, `revoked`, `suspended`, `no-lock`,
`genesis-not-allowed`, `head`
(+ `head`), any E2EE validation code (`bad-sig`, `not-admin`, …), `not-found`, `not-admin`, `relay-unverified`,
`relay-unreachable`, `rate`, `reset-window`, `password`, `code`.
