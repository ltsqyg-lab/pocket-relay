# Pocket coordination server — API v2

Status: implementation spec, phase 1 (2026-10-08); pairing with a 6-digit code (§4.5) replaces the 6 words (2026-10-09).
The coordination server is closed source; this document is its
public interface. It extends today's server (`https://pocket.pocketcli.net`, docs/PROTOCOL.md, "v1") with `/v2`.
Crypto and data formats: [E2EE.md](E2EE.md). Relays: [RELAY.md](RELAY.md). Old → new map: [MAPPING.md](MAPPING.md).

> **中文摘要**　协调服务器管「谁是谁、谁能连谁」:账号与登录(照旧)、每台设备的公钥与虚拟地址、设备锁日志(只存、只校验、
> 只转发,签不出)、包好的内容钥匙(打不开)、短期中继票据、设备表(netmap)、控制推送、中继登记、撤销名单、清除令。
> 自建中继可以只有公网 IP、没有域名(照 Tailscale 的 derper):中继自签证书、打印带证书指纹和认领码的连接串,协调钉住指纹去认领,
> 设备从 netmap 拿到指纹,连它时也只认这个指纹(§8、§10)。
> 新设备加入靠 6 位数配对码(§4.5):新设备显示、用户在已批准的管理设备上输入,两边跑 SPAKE2;协调只转发四个看不懂的字段、管顺序和次数,
> 没走完配对的 `add` 一律不收。
> 它不再存、不再转任何对话内容;双跑期内老接口照旧给老版本用(MAPPING.md),双跑结束后 v1 的内容接口一律 410(§19)。

---

## 1. Scope

Keeps (unchanged from v1): accounts, password sign-in, email codes, OAuth sign-in for computers, phone tokens and
computer tokens, preferences (`listDays`), language, sign-in notifications, the website, downloads and the update
manifest, the review/demo account, admin tooling.

Adds:
- a device registry: each device's two public keys, kind, platform, name, virtual address, state;
- **pairing** of a new device with a 6-digit code (§4.5): relays the SPAKE2 messages, enforces order and attempt limits;
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
{ "name": "iPhone 18 Pro", "platform": "ios", "sig": "<b64u 65 B>", "kx": "<b64u 65 B>",
  "proof": { "a": "<b64u enroll-auth JSON>", "s": "<b64u signature>" } }
```
(`sasLang`, sent by versions that compared 6 words, is ignored.)
Server:
1. Validate keys (E2EE §3.3) and name (1–64 characters, no control or bidi characters, else `400 bad-name`); verify `proof` (E2EE §13, `enroll-auth`: bound to these two keys and to the
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
     of the account (§9), `enroll_result {state: "pending", pendingId}` to the device itself (a `waiting` device that
     becomes `pending` when a lock appears gets the same event) and a sign-in style notification to phones. The device
     then pairs (§4.5).
5. Answer
```json
{ "did": "…", "addr": "100.64.12.7", "name": "iPhone 18 Pro", "state": "genesis" | "waiting" | "pending" | "active" | "suspended" | "revoked",
  "pendingId": "pd_…"?, "pair": { "attempt", "stage", "left", … }?, "lock": { "seq": 9, "h": "…", "genesis": "…" }?, "demo": true? }
```
`name` is the name as registered (see "Device names" below); a device that writes its own genesis should use it.

**Device names** (2026-10-09). A new device's name is shown to the user right next to "enter the 6-digit code shown on
it" (`enroll_pending`, the pending list, the `device_pending` notification), so a name like "pairing code 482913" could
talk a user into typing the attacker's code. Coordination therefore registers every device name — here, and the device
labels of `/v1/auth/login|register` (`deviceName`), `/v1/agents/login|claim` (`host`), the OAuth `device` and a v1
computer's `hello.host` — rewritten by one rule (the same function everywhere):
- kept: letters (any script), digits, spaces and `. - _ ' ’ ‘ ( )` plus the full-width `．－＿＇（）`; other symbols become
  a space, invisible characters (controls, format characters, zero-width) are dropped, runs of spaces collapse;
- a run of three or more digits — digits separated only by spaces or the punctuation above count as one run; any
  script's decimal digits and Chinese numerals count — keeps its first two digits followed by `…`
  ("Xiaomi 23049RAD8C" → "Xiaomi 23…RAD8C", "pairing code 48 29 13" → "pairing code 48…");
- at most 40 characters; if no letter or digit is left, the platform's name ("iPhone", "Android", "Mac", "Windows",
  "Linux"; v1 labels: "手机" / "computer").

The rule rewrites instead of refusing: phone models and default computer names often contain digit runs and users cannot
change them. It is idempotent. Names stored before this rule are not migrated; the pending list, `enroll_pending` and the
`device_pending` / `device_added` notifications show them rewritten too. For `genesis` and `add` (§5) the entry's name
must equal the registered name after this rewrite (an older client that writes its genesis with its own unrewritten name
is accepted).
`pair` (only while `pending` and after the first offer): the device's own pairing progress, as in `GET /v2/pair/{pendingId}`
(§4.5), so a restarted device continues without first hitting `409 stale`.
`demo: true` only on the review demo account (§15): its only admin is the demo computer, which has no screen and nobody to
type the code into it, so the device adds the code it shows to its offer (`demoCode`, §4.5) and the demo computer pairs
with that.
Rate limit: 10 enrollments per account per hour, 3 pending entries per account at a time.

`active` here means "in the lock", not "turned on": a new device turns on only after the pairing it took part in
succeeded on its side (E2EE §6). Coordination does not track that.

### 4.2 Lists
- `GET /v2/devices` → `{ "devices": [ { did, kind, platform, name, addr, sig, kx, state, sas?, online, lastSeen, createdAt,
  v1: { agentId? }, current } ] }` — `state` ∈ `waiting`, `pending`, `active`, `suspended`, `revoked`;
  `sas` copied from the lock's `add`. Devices treat this as display data; trust comes from the lock.
- `GET /v2/devices/pending` → `{ "pending": [ { pendingId, did, kind, platform, name, addr, sig, kx, at, expiresAt, pair? } ] }`
  (any device of the account; only admins can act on it). `pair` (§4.5): present for callers that are live admins (the admin
  view: `pB`, `cB` for the admin that answered, `demoCode` on the demo account) and on the caller's own entry (the
  new-device view); `null` until the first offer. Other callers get the entries without `pair`.
- `POST /v2/devices/pending/{pendingId}/reject` → removes it (with its pairing), pushes `enroll_result {state: "rejected"}`
  to the requester. (Coordination-level; no signature needed — rejecting can only reduce access.)

### 4.3 Suspend and remove
- `POST /v2/devices/{did}/suspend` (any live phone of the account, or the device itself; on the demo account only the
  device itself, §15) → coordination suspension
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

### 4.5 Pairing (6-digit code)

> **中文摘要**　新设备 B 屏幕上显示 6 位数配对码,用户在已批准的管理设备 A 上**输入**(不是点「一样」,免得误触);两边拿这个码跑 SPAKE2
> (E2EE §6,参考实现 `docs/protocol/pake.mjs`)。协调只转发、只存它看不懂的四样(`pB`、`pA`、`cA`、`cB`),管顺序、次数和谁能做什么;
> A 核对过 B 的确认值才签 `add`,协调也只收走完过一次配对的 `add`(`pair-required`)。每个待批准条目最多 5 轮,第 5 轮也没对上就作废、
> B 要重新登录。演示账号的演示电脑没有屏幕,审核员手机在 offer 里把码一起交上来(`demoCode`,只有演示账号收)。

Roles: **B** = the new device (the device of a pending entry; it shows the code); **A** = the approver: a device that is live
and admin in the lock and not suspended (§4.3), where the user types the code shown on B. The code is the SPAKE2 password;
the messages and confirmation values are defined in E2EE §6 and computed by `docs/protocol/pake.mjs` (coordination ships
an identical copy as `server/pake.mjs` for the demo computer). Coordination checks only their format — a SPAKE2 message is
a P-256 point (65 bytes, uncompressed, on the curve), a confirmation value is 32 bytes — and never learns the code.

**Flow** (one *attempt*; attempts are numbered 1–5 per pending entry):
```
B (new device, shows the code)        coordination                          A (live admin, user types the code)
enroll → pending (§4.1)
POST /v2/pair/offer {pendingId, attempt, pB}  ── push pair_offer ─────────▶  (or GET /v2/devices/pending)
                                      ◀──────────────────────────────────  POST /v2/pair/answer {pendingId, attempt, pA, cA}
push pair_answer (or GET /v2/pair/{id}) ◀──
check cA:
  ok    → POST /v2/pair/confirm {pendingId, attempt, cB}  ── push pair_confirm to that A ──▶ check cB; ok → sign `add` (sas: true)
  wrong → POST /v2/pair/fail {pendingId, attempt}         ── push pair_fail to the admins ─▶ ask for the code again
          then POST /v2/pair/offer {attempt + 1, …}
```

**Endpoints** (Bearer, token bound to a device, §2; bodies are JSON; `pendingId` is `pd_` + 16 letters and digits):

| Call | Who | Body | Answer |
|---|---|---|---|
| `POST /v2/pair/offer` | B | `{ pendingId, attempt, pB, demoCode? }` | `{ ok, attempt, stage: "offered", left }` |
| `POST /v2/pair/answer` | A | `{ pendingId, attempt, pA, cA }` | `{ ok, attempt, stage: "answered" }` |
| `POST /v2/pair/confirm` | B | `{ pendingId, attempt, cB }` | `{ ok, attempt, stage: "confirmed" }` |
| `POST /v2/pair/fail` | B | `{ pendingId, attempt }` | `{ ok, attempt, stage: "failed", left, final?, voided? }` |
| `GET /v2/pair/{pendingId}` | B or A | — | the pending entry (as in `GET /v2/devices/pending`) with `pair` in the caller's view |

Rules:
- **offer** starts attempt `attempt` = the previous attempt + 1 (the first is 1). It may start while the previous attempt is
  in any stage (a device that restarted lost its SPAKE2 secret and simply starts the next attempt; an earlier confirmed
  attempt stays recorded). Coordination stores `pB` and pushes `pair_offer` to every live admin of the account.
  Re-sending the current attempt with the same `pB` (a lost answer) returns the current state and pushes nothing.
- **answer**: only the current attempt while it is `offered`; the first admin to answer owns the attempt (another admin
  then gets `409 stale`); the same admin re-sending the same `pA`/`cA` gets `200`. A cannot answer its own entry
  (`403 not-admin`). Pushes `pair_answer` to B.
- **confirm**: B, only for the current attempt while it is `answered`, after `cA` checked out. Records the pending entry
  as *paired by A* (A = the admin that answered that attempt) and pushes `pair_confirm` to that A.
- **fail**: B, for the current attempt while it is `offered` or `answered` (`cA` was wrong — the code was mistyped — or B
  gives the attempt up). Pushes `pair_fail {pendingId, did, attempt, left}` to the live admins; B then offers `attempt + 1`.
- **`add`** (§5): accepted only when the device has a live pending entry that is paired by the statement's signer (`by`)
  and the statement says `sas: true`; otherwise `403 pair-required`. Approving without comparing (`sas: false`) is no longer
  accepted — for any account, the demo account included. (A signs only after checking `cB`; this check is coordination's
  second line, the devices' own checks are the first, E2EE §6.)

`pair` object (caller's view; `null` before the first offer):
- common: `attempt`, `stage` (`offered` → `answered` → `confirmed`; or `failed`), `left` (attempts B may still start after
  this one = 5 − attempt), `fails` (attempts B reported as failed), `at` (last change, ms), `paired: true` once an attempt
  of this entry was confirmed;
- new device (B, its own entry): `pA`, `cA` and `by` (the did of the admin that answered; B takes that admin's `sig`/`kx`
  from the lock it validated, E2EE §6) once answered;
- live admins: `pB` (not after `failed`), `by` (the admin that answered), `cB` (only for that admin, once confirmed),
  `demoCode` (demo account, while `offered`).

Pushes (§9): `pair_offer` = a pending entry with the admin view of `pair` (to live admins); `pair_answer {pendingId,
attempt, by, pA, cA}` (to B); `pair_confirm {pendingId, did, attempt, cB}` (to the admin that answered); `pair_fail
{pendingId, did, attempt, left, final?}` (to live admins); `enroll_result {state: "pending" | "failed", pendingId, …}` (to B).
Every push can be lost: B pulls `GET /v2/pair/{pendingId}` (or enrolls again, §4.1), A pulls `GET /v2/devices/pending`.

**Limits**:
- 5 attempts per pending entry. When attempt 5 fails, or B offers attempt 6, coordination voids the entry: deletes it,
  pushes `enroll_result {state: "failed", reason: "pair-limit", pendingId, error: "配对失败次数太多,重新登录" / "Too many
  wrong codes. Sign in again"}` to B and `pair_fail {final: true, left: 0}` to the admins, **revokes B's token** and closes
  its control socket (4401). The offer of attempt 6 is answered `429 pair-limit {voided: true}`; the failing call of
  attempt 5 gets `200 {final: true, voided: true, reason: "pair-limit"}`. B signs in again and enrolls: a new pending
  entry with 5 new attempts (the enrollment limits of §4.1 and the sign-in limits apply), so the code cannot be guessed
  faster by restarting.
- `offer`, `answer`, `confirm`, `fail`: 10 each per device per minute; `GET /v2/pair/…`: 120 per device per minute (`429 rate`).
- A pending entry still expires after 24 h (`enroll_result {state: "expired"}`), and rejecting it ends its pairing.

**Errors**: a malformed field (`pendingId`, `attempt`, `pB`/`pA` not a 65-byte point on P-256, `cA`/`cB` not 32 bytes,
`demoCode` not 6 digits or sent by another account) → `400 bad-pair`; an unknown or expired `pendingId`, another account's,
an offer / confirm / fail for an entry that is not the caller's, or a pull by a device that is neither B nor a live admin →
`404 not-found`; an attempt or stage that does not fit → `409 stale` with the current `{attempt, stage}`; an answer by a
device that is not a live admin, or by B itself → `403 not-admin`.

**Demo account** (§15): when enroll answered `demo: true`, B adds `demoCode` — the 6 digits it shows — to its offers.
Coordination accepts the field only on the demo account (`400 bad-pair` elsewhere), keeps it with the attempt until it is
answered or failed, and passes it to the admins (`pair_offer` and the admin view of `pair`). The demo computer, the
account's only admin, runs A with it: answer → (B confirms) → check `cB` → `add` with `sas: true`. Nothing else differs; the
`add` check has no exception. (Only phones send `demoCode`, and only when enroll says `demo: true` **and** the account the
user typed is the review account built into the app, E2EE §6.6; computers never send it, and the demo account cannot bind
computers at all, §15. A lying coordination server must not be able to collect a real code this way.) After
a restart between its answer and B's confirmation the demo computer cannot check `cB`; it rejects that pending entry and B
enrolls again.

**Security notes.** Coordination sees `pB`, `pA`, `cA`, `cB` and, except on the demo account, never the code. The SPAKE2
messages reveal nothing about it; whoever runs one side of an attempt with a guessed code gets exactly one online guess
(1 in 10^6) and is detected by the other side's check. The per-entry limit and the forced sign-in bound how often that can
be tried, and every attempt needs the user to type a code on an admin device.

## 5. Lock log
- `GET /v2/lock?since=<seq>` → `{ "acct", "genesis", "head": {seq, h}, "statements": [ {p, s}, … ] }` (statements after `since`).
- `POST /v2/lock` `{ "statement": { "p", "s" } }`
  1. Validate against the stored log with exactly E2EE §5.3 (the server runs the same validator and passes vectors.json).
     A genesis is accepted only from a phone of an account without a lock, or inside a reset window (§12), or from the
     demo computer (§15).
  2. Compare-and-swap: the statement's `prev`/`seq` must extend the current head, else
     `409 { "code": "head", "head": {seq, h} }`.
     For `genesis` and `add` the device entry must equal the device's registration (`400 bad-device`); an `add` also needs
     a confirmed pairing by its signer and `sas: true` (§4.5, else `403 pair-required`).
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
- `quota`: the account's attachment limits for the official relay, `{dayMB, monthMB, smallMB, storeMB}` (`prefs.quota` or
  the defaults 200 MB/day, 2048 MB/month, a 50 MB/day small-file allowance and 5120 MB stored — `POCKET_QUOTA_STORE_MB`,
  per account `cli user quota <name> store <MB>`, 0 = unlimited; the demo account: 1024 MB/day, 10240 MB/month, 200 MB
  stored; RELAY.md §8.3), absent for other relays.
  The relay holds every device of the account to the caps of the account's newest ticket. When the limits change
  (`cli user quota`, or any other way), coordination notices within one tick (a minute) for accounts with a device on
  the control socket and announces a netmap change (§9); devices renew their relay ticket on every netmap
  announcement, so the new caps apply within a minute or so. Each change is announced once (`acct_v2.quota_sig` keeps
  the limits last put in a ticket or announced).
- Lifetime 6 hours; clients renew at half-life. Rate: 60 per device per hour. The server never issues a ticket living
  longer than 24 hours, whatever its configuration says (relays and gateways refuse longer ones).

## 8. Netmap
`GET /v2/netmap` → signed document (label `netmap`):
```json
{ "v": 1, "t": "netmap", "kid": "c1", "acct": "…", "at": …, "ver": 42, "self": "<did>",
  "lock": { "seq", "h", "genesis" },
  "devices": [ { "id", "addr", "kind", "platform", "name", "sig", "kx", "status", "online", "lastSeen", "ver"?, "v1"?: { "agentId" } } ],
  "relay": { "id": "hk1", "url": "https://pocket.pocketcli.net/relay", "region": "hk", "kind": "official" },
  "relays": [ { "id", "url", "region", "kind": "official" | "self", "state": "verified" | "unverified", "name"?, "pin"? } ],
  "prefs": { "listDays": 2 }, "lang": "zh",
  "asr": { "official": { "url": "https://pocket.pocketcli.net/asr", "aud": "asr:official" } } }
```
`ver` increases on every change; the control socket announces it. Devices verify the signature (E2EE §12.3) and treat
device keys in it as hints only.

`pin` (optional, on `relay` and on entries of `relays`; only self-hosted relays registered with one, §10): the relay's
certificate fingerprint, `"sha256:"` + the lowercase hex SHA-256 of its leaf certificate (DER). When the current relay has
a `pin`, devices connecting to it — WebSocket and HTTP, directly or through an HTTP proxy tunnel — use **no root store at
all** (neither system roots nor the Pocket root, so a public certificate somebody obtains for that IP does not help) and
accept the connection only if the SHA-256 of the leaf certificate equals the pin; they compare after the TLS handshake and
before writing a single byte, and on a mismatch close the connection and report "the relay's certificate fingerprint
doesn't match" (then retry with back-off; a new netmap with another pin or URL makes them reconnect at once). Certificate
expiry and names are not checked for a pinned relay (like Tailscale's derper in IP mode). Addresses the relay hands out
that point elsewhere (presigned object-storage URLs, RELAY.md §6.4) are not pinned: they use public CAs and the usual
address checks; an address on the relay's own host and port keeps the pin. A relay without `pin` is reached as before
(public CAs). A `pin` field that is present but malformed is still enforced (the connection fails), never ignored.

## 9. Control WebSocket
`GET /v2/ws` (Bearer in the `Authorization` header — a `?token=` query parameter is not accepted; the token must be bound
to a device). One per device. Server → device events:

| Event | Fields | To | Meaning |
|---|---|---|---|
| `hello_ok` | `did`, `state`, `time`, `netmapVer`, `lockHead` | the device | after connect |
| `netmap` | `ver` | all of the account | refetch `/v2/netmap` |
| `lock` | `head` | all | refetch `/v2/lock?since=` |
| `enroll_pending` | `pendingId`, `kind`, `name`, `platform` | live admins | a device wants to join (its offer follows) |
| `enroll_result` | `state` (`pending`, `active`, `rejected`, `expired`, `failed`), `pendingId`, `reason`?, `error`? | the enrolling device | `pending`: make your offer (§4.5); `failed` + `reason: "pair-limit"`: 5 attempts used, the token is revoked, sign in again |
| `pair_offer` | a pending entry (§4.2) with the admin view of `pair` (`attempt`, `pB`, `demoCode`?) | live admins | ask the user for the code shown on that device |
| `pair_answer` | `pendingId`, `attempt`, `by`, `pA`, `cA` | the new device | check `cA` (with `by`'s keys from the lock), then confirm or fail |
| `pair_confirm` | `pendingId`, `did`, `attempt`, `cB` | the admin that answered | check `cB`, then sign `add` |
| `pair_fail` | `pendingId`, `did`, `attempt`, `left`, `final`? | live admins | the code did not match (`final`: the entry is void) |
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
- Self-hosted relays come in two shapes:
  - **with a domain** and a certificate from a public CA (port 443 or 8443): the operator writes `relayId` / `account`
    into the relay's config, then the App verifies it (below);
  - **with only a public IP**, no domain (like Tailscale's derper in IP mode): the relay starts unclaimed, makes a
    self-signed certificate and prints a connection string `pocket-relay://<host>:<port>?pin=sha256:<hex>&claim=<code>`
    (RELAY.md). The App splits it and registers with `pin` and `claim`; coordination claims the relay over a TLS
    connection pinned to that fingerprint, and the relay is registered and verified in one step. Devices get the `pin`
    in the netmap and pin it too (§8).
- `POST /v2/relays` (approved phone; ≤ 3 per account)
  ```json
  { "url": "https://<host>:<port>", "name"?: "…", "pin"?: "sha256:<64 hex>", "claim"?: "<code>" }
  ```
  Address rules (else `400 relay-url`): `https` only; no user info, query or fragment; ≤ 300 characters. A host that is an
  **IP literal** must be a public unicast address (SSRF rules below) **and must carry `pin`** (a self-signed relay is the
  only kind reachable by IP). Port: without `pin` 443 or 8443 (public-CA certificates, unchanged); with `pin` 443 or
  1024–65535. A domain may carry a `pin` too (self-signed certificate on a domain); its port then follows the `pin` rule.
  The URL may end in a path prefix, with or without `pin` (a relay behind a reverse proxy, e.g. `https://<ip>:443/relay`):
  only `/[A-Za-z0-9._~/-]*`, at most 200 characters; and since URL parsers silently rewrite some spellings (`/a/../b`,
  `%2e%2e`, `\`, tabs and newlines), the address as written may not contain `..`, `%`, `\`, white space or control
  characters at all (leading and trailing white space is trimmed first). Trailing slashes are dropped. `/v1/claim`,
  `/.well-known/pocket-relay` and everything devices use (`/v1/ws`, …) are appended to the prefix.
  `pin` is `"sha256:"` + 64 hex digits (upper case is accepted and stored lower case; malformed → `400 relay-url`).
  `claim` is printable ASCII without spaces, 4–256 characters (malformed → `400 relay-claim-rejected`); coordination passes
  it to the relay and neither stores nor logs it.
  - **Without `claim`** (the operator configures the relay by hand) → stored as `unverified` (with its `pin`, if any) →
    `{ "relayId": "r_<10 chars>", "account": "<acct>", "state": "unverified", "pin"?: "…",
    "config": { "relayId", "account", "coord": { "url", "pinnedKeys" } } }` — everything the operator pastes into the
    relay's config; nothing secret. Then `POST /v2/relays/{id}/verify`.
  - **With `claim`**: coordination derives `relayId` = `r_` + 10 characters from (account, claim code) and sends
    `POST <url>/v1/claim { "claim", "relayId", "account", "edition" }`(`edition` = 这台协调是 `cn` 还是 `intl`,2026-10-10) through the client below (with `pin`: pinned TLS).
    The relay answers `200 { "ok": true, "relayId", "account" }` (the same values) → the relay is stored as
    `{ id, url, name, pin, state: "verified" }`, the netmap changes, and the answer is
    `{ "relayId", "account", "state": "verified", "pin": "sha256:…" | null }`. Because the same code gives the same
    `relayId`, an App that retries after losing that answer gets `409` (already claimed) from the relay; coordination then
    reads `<url>/.well-known/pocket-relay` (same pinned connection rules) and, when it shows exactly this `relayId` and
    account — which nobody without the claim code can arrange — treats the claim as done. Anything else registers nothing:
    | Answer | When |
    |---|---|
    | `409 relay-pin-mismatch` | the relay's leaf certificate does not hash to `pin` (the request — and the claim code — was never sent) |
    | `409 relay-wrong-edition` | the relay answered 403 `wrong-edition`: it was installed for the other edition (RELAY.md §2.1). The message carries this coordination server's install command. |
    | `409 relay-claim-rejected` | the relay answered 403 (wrong code), or 409 (already claimed) while its `/.well-known/pocket-relay` shows another `relayId` / account, or a 200 that does not echo this `relayId` and account |
    | `502 relay-unreachable` | no connection or no answer within 5 s ("Couldn't reach `<host>:<port>`: check that the server's firewall / security group allows this port"); unknown host; resolves to a non-public address; certificate not valid (no `pin`); a redirect, more than 4 KiB, or another status (e.g. 404 — not a Pocket relay, or too old) |
    | `400 relay-url` | the address rules above |
    | `429 rate` | 3 relays already; 10 verifications and claims per account per hour together; another claim of the account still running; the relay itself answered 429 (too many claim attempts there) |
- `POST /v2/relays/{id}/verify` → the server fetches `<url>/.well-known/pocket-relay` (pinned TLS when the relay has a
  `pin`) and requires `relayId` and `account` to match → `{ "state": "verified" }`; `409 relay-unverified` when they do
  not match, `409 relay-pin-mismatch`, or `502 relay-unreachable` with the reason (as in the table). A failed verification
  does not demote a relay that is already verified.
- **SSRF rules** for every connection coordination makes to a self-hosted relay (verify, claim): `https` only; the port
  rules above; an IP literal must be public unicast, and every address a host name resolves to must be public unicast —
  checked in the resolver before connecting and again on the socket's actual peer address after connecting; one fresh
  connection per request (no pooling); 5 s for the whole exchange; response ≤ 4 KiB; redirects are not followed. With
  `pin`, no root store is used: the leaf certificate's SHA-256 must equal `pin`, checked after the handshake and before the
  request is written. The lab switch that relaxes these rules (`POCKET_RELAY_VERIFY_LAB=1`: loopback / private addresses
  and any port; loopback / private IP literals may then omit `pin`) is ignored, with an error in the log, when the server
  runs in production (`NODE_ENV=production`, or its signing keys live under `/etc`).
- `POST /v2/account/relay` `{ "relayId": "hk1" | "r_…" }` (phone) → sets the account's relay (must be official or a
  verified relay of the account); pushes `relay` and `netmap`. Computers then re-upload their realm to the new relay.
- `DELETE /v2/relays/{id}` (not while it is the account's relay).

### 10.1 Who am I
`GET /v2/whoami` (no authentication) → `{ "ip": "<the caller's address>" }` with `Cache-Control: no-store` — the address
coordination sees, by the same rule as its rate limits (the TCP peer; `CF-Connecting-IP` only when the server is deployed
behind Cloudflare; IPv4-mapped IPv6 is shown as IPv4). A self-hosted relay or speech gateway asks once at startup to learn
its public IP for the connection string it prints. 30 requests per IP per minute (`429 rate`). Answers even while the v2
signing keys are unavailable.

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
the v1 sockets. "New device signed in" becomes "New device wants to join — enter the 6-digit code shown on it" for v2
accounts (`notify {kind: "device_pending"}`).

## 15. Review / demo account
The demo computer (`server/demo-agent.mjs`, systemd `pocket-demo`) becomes a v2 computer: it keeps its device keys in
its state directory, creates the demo account's genesis (the only computer allowed to — on the demo account no phone may
create it), **pairs with every new device of the demo account at once** — it answers each offer with the `demoCode` the
device sent (§4.5), checks `cB` and signs `add` with `sas: true`, `admin: false` — grants its keyring, writes its sample
sessions as objects to the official relay over loopback and answers commands with the same canned replies as today. A
reviewer's phone that enrolls before the demo lock exists gets `waiting`, turns `pending` when the lock appears and pairs
then. Account deletion and re-creation work as today; the demo account never gets `reset`.

Its password is given to reviewers, so treat it as semi-public (2026-10-09):
- **phones only**: the demo computer pairs with and adds phones only, and rejects any other pending computer; coordination
  refuses an `add` of a computer on the demo account (`403 not-allowed`), and no other computer can get a token for it —
  `/v1/agents/login`, `/v1/agents/pair-code`, `/v1/agents/claim` and the OAuth `authorize` / `token` answer `403` for the
  demo account (the demo computer gets its token from the loopback admin interface);
- **at most 20 live devices** in the demo lock (`POCKET_DEMO_DEVICE_MAX`): before adding a phone to a full lock the demo
  computer revokes the phone seen longest ago (offline phones first); coordination refuses an `add` to a full lock
  (`409 device-limit`);
- a phone can sign out only itself (`POST /v2/devices/{did}/suspend` for another device → `403 not-allowed`);
- no relay changes: `POST /v2/relays`, `…/verify`, `DELETE /v2/relays/{id}` and `POST /v2/account/relay` answer
  `403 not-allowed`;
- small limits: official relay quota above (200 MB stored), speech recognition 5 minutes a day and 60 a month (§16).

## 16. ASR tickets
`POST /v2/tickets {aud: "asr:official"}` issues a ticket for the official ASR gateway (ASR.md §3) with `peers: []` and the
account's recognition limits:
```json
"asrQuota": { "dayMin": 120, "monthMin": 1500 }
```
minutes of audio per day and per month, 0 = unlimited. Defaults 120 and 1500 (`POCKET_ASR_DAY_MIN`, `POCKET_ASR_MONTH_MIN`),
per account `cli user quota <name> asr <day> <month>` (`prefs.asrQuota`); the demo account gets `{dayMin: 5, monthMin: 60}`.
The gateway adds up recognized seconds per account (`acct`) and refuses more once a limit is reached; when a ticket carries
no `asrQuota` it applies the same defaults. A change applies from the device's next speech ticket (at most 6 hours).
Rate limit 120 tickets per device per hour.

## 17. Storage
New tables (SQLite, same database as v1):
```
devices   (did PK, acct, kind, platform, name, addr UNIQUE, sig, kx, state, sas_lang, token_hash, agent_id,
           created_at, updated_at, last_seen, suspended_at)
pending   (pending_id PK, did, acct, created_at, expires_at,
           pair_attempt, pair_stage, pair_pb, pair_pa, pair_ca, pair_cb, pair_by, pair_at, pair_fails,
           pair_ok_by, pair_ok_attempt, pair_ok_at, demo_code)          -- §4.5; the pairing goes with its entry
lock_log  (acct, seq, payload BLOB, sig BLOB, hash, at, PRIMARY KEY (acct, seq))
lock_archive (acct, archived_at, seq, payload, sig, hash)
grants    (id INTEGER PK, acct, to_did, realm, by_did, epochs TEXT, seal TEXT, at)
relays    (id PK, acct NULL = official, url, name, region, state, reason, created_at, verified_at, pin)
account_relay (acct PK, relay_id, since)
revocations (id INTEGER PK, acct, addr, did, nbf, gone, at)
purge_queue (id INTEGER PK, relay_id, order_doc TEXT, next_try, tries, created_at)
```
`agents` gains `did` (the v2 device of a v1 agent row). Coordination key private parts are files, not rows.

## 18. Limits
| What | Limit |
|---|---|
| Enrollments | 10 per account per hour; 3 pending at once; pending expires after 24 h |
| Pairing | 5 attempts per pending entry (then void + sign in again); offer / answer / confirm / fail 10 each per device per minute; pulls 120 per device per minute |
| Lock appends | 60 per account per hour; payload ≤ 16 KiB |
| Grants | 50 per call; 64 KiB each; 500 stored per device |
| Tickets | 60 per device per hour (ASR: 120) |
| Relays | 3 registered per account; 10 verifications and claims per account per hour; one claim at a time |
| `/v2/whoami` | 30 per IP per minute |
| Resets | 3 per account per 30 days |
| Control sockets | 1 per device (a new one replaces the old) |
| Attachments on the official relay | 200 MB/day, 2048 MB/month, 5120 MB stored per account (§7) |
| Speech recognition (official gateway) | 120 minutes/day, 1500 minutes/month per account (§16) |
| Demo account | 20 live devices; phones only; 200 MB stored; 5 minutes of speech a day (§15) |

## 19. Dual run
The v1 API keeps working for old clients during the transition (2–4 weeks); its interplay with v2 — which computer
uses which path, what old Apps see, downgrade protection, when plaintext is deleted — is specified in
[MAPPING.md](MAPPING.md) §1.

When the transition ends the server runs with `POCKET_V1_CONTENT=off`: every v1 content entry answers
`410 {code: "v1-off", error: "先更新 Pocket" / "Update Pocket first"}` — sessions (`/v1/sessions`, `…/messages`,
`…/dispatch`, `…/answer`, `…/stop`, `…/handoff`), `/v1/search`, `/v1/dispatch`, `/v1/voice/dispatch`, attachments
(`/v1/attachments/…`: GET / HEAD / upload-url / uploaded / PUT), `/v1/agents/{id}/usage/refresh`, `/v1/agents/{id}/folders`,
and the computer socket `/v1/agent/ws` (410 at the upgrade). `GET /v1/agents` still lists the computers (name, online from
the control socket, `v2 {did, addr, state}`) but without content (`projects: []`, `models: {}`, `engines`, `permissions`,
`usage` null, …). Accounts, sign-in, email codes, the website, downloads, OAuth and `/v1/app/ws` (sign-in
notifications) keep working. A computer already on v2 that an old version tries to use over v1 gets the same
`410` wording with `code: "v2-only"`.

## 20. Error codes (`code`)
`bad-request`, `bad-key`, `bad-name`, `bad-proof`, `stale`, `not-bound`, `revoked`, `suspended`, `no-lock`,
`genesis-not-allowed`, `head`, `bad-pair`, `pair-required`, `pair-limit`
(+ `head`), any E2EE validation code (`bad-sig`, `not-admin`, …), `not-found`, `not-admin`, `relay-unverified`,
`relay-unreachable`, `relay-url`, `relay-pin-mismatch`, `relay-claim-rejected`, `relay-wrong-edition`, `rate`, `reset-window`, `password`, `code`,
`not-allowed` (the demo account, §15), `device-limit` (the demo account's lock is full, §15).
