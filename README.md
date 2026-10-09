English | [简体中文](README.zh-CN.md)

# Pocket relay

The relay of [Pocket](https://pocket.pocketcli.net), the phone remote control for AI coding sessions (Claude Code,
Codex and friends) running on your computer. It moves and stores **ciphertext only**:

- routes end-to-end encrypted **envelopes** (commands, replies, events) between the devices of one account, with a
  short offline queue;
- stores the computer's **objects** (session list, messages, usage — sealed and signed by the computer) so phones can
  read history while the computer sleeps;
- stores **attachments** (chunked AES-GCM streams) on local disk or in any S3-compatible bucket, with presigned
  direct transfers;
- tells devices when their peers come and go and when objects change.

It never decrypts anything and holds no Pocket secret: devices prove who they are with short-lived tickets signed by
the Pocket coordination server, which the relay checks offline with the coordination **public** key, plus a signature
over a one-time challenge made with the device's own private key. Anyone can run one; the official relay runs the
same code.

| The relay sees | The relay does not see |
|---|---|
| account id, device addresses, who talks to whom and when, sizes, how many sessions and messages, client IPs | message text, tool output, approval cards, titles, project paths, attachment names or contents, thumbnails, search queries, usage figures |

Protocol: [RELAY.md](protocol/RELAY.md) (this server) and [E2EE.md](protocol/E2EE.md) (the cryptography),
with shared test vectors in [vectors.json](protocol/vectors.json).

## Deploy without a domain (recommended)

All you need is a server with a public IP address (1 vCPU / 1 GB RAM is plenty for one person) and Docker — like
Tailscale's DERP servers, no domain name and no certificate authority are involved.

```sh
docker build -t pocket-relay .
docker run -d --name pocket-relay --restart unless-stopped -p 8443:8443 -v pocket-relay:/var/lib/pocket-relay pocket-relay
docker logs pocket-relay
```

The log shows one line:

```
pocket-relay://203.0.113.7:8443?pin=sha256:3f1c…&claim=Qm9x…
```

1. **Open TCP port 8443** to the internet in the server's firewall and in your cloud provider's security group.
2. **In the Pocket App: Devices → Relay → Add your own relay, paste this line.** The Pocket coordination server
   connects to your relay — checking its certificate against the `pin` in the line — and claims it for your account
   with the one-time `claim` code. From then on the relay serves your account only.
3. Switch to it in the App. Your computers upload their sessions to it; your phones read from it.

What happens on the first start: the relay asks the coordination server which IP address its requests come from
(`GET https://pocket.pocketcli.net/v2/whoami`), makes a self-signed certificate for that address (ECDSA P-256, valid 10
years) and prints the line. The `pin` is the SHA-256 of that certificate: devices check that exact certificate and
nothing else, so no certificate authority can impersonate your relay. The certificate, the claim and all data stay in
the `pocket-relay` volume across restarts and upgrades; the line does not change.

**Keep the line to yourself until you have pasted it.** Its claim code lets whoever has it first claim the relay.
It only exists in the relay's output and in its data directory, works once, and the relay accepts at most 5 tries a
minute from one address. If it leaked before you used it, make a new one with `reset-claim` (below).

**When the detected address is wrong** (the server reaches the internet through another IP than the one devices
should use, or you map another outside port such as `-p 443:8443`), say it yourself:

```sh
docker run -d --name pocket-relay --restart unless-stopped -p 443:8443 -v pocket-relay:/var/lib/pocket-relay \
  -e RELAY_PUBLIC_URL=https://203.0.113.7:443 pocket-relay
```

**Without Docker** (Node.js 22.13 or newer; no npm packages at all):

```sh
RELAY_DATA_DIR=$HOME/pocket-relay node src/main.mjs                       # port 8443
RELAY_DATA_DIR=$HOME/pocket-relay RELAY_LISTEN_PORT=9443 node src/main.mjs
```

On IPv6-only servers also set `RELAY_LISTEN_HOST=::`.

## Deploy with a domain

**Behind a reverse proxy** (nginx, Caddy…) that already has a certificate for your domain: terminate HTTPS in the
proxy, pass WebSocket upgrades for `/v1/ws`, append the client address to `X-Forwarded-For`, and run the relay on
loopback with plain HTTP:

```sh
docker run -d --name pocket-relay --restart unless-stopped -p 127.0.0.1:8443:8443 -v pocket-relay:/var/lib/pocket-relay \
  -e RELAY_TRUST_PROXY=true -e RELAY_PUBLIC_URL=https://relay.example.com pocket-relay
```

```nginx
location / {
    proxy_pass http://127.0.0.1:8443;
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection $connection_upgrade;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_request_buffering off;
    proxy_read_timeout 120s;
    client_max_body_size 110m;
}
```

The printed line then has no `pin` (devices check your proxy's certificate like any website):
`pocket-relay://relay.example.com:443?claim=…`. Serve the relay at the root of its own host name (or port): the App
does not add relays under a path such as `https://example.com/relay`.

**With your own certificate files**: mount them and set `RELAY_TLS='{"cert":"/etc/pocket-relay/fullchain.pem","key":"/etc/pocket-relay/privkey.pem"}'`
(they are reloaded when they change). A certificate from a public CA for the domain name in `publicUrl` is not pinned,
so renewals keep working; any other certificate — and any certificate when devices connect by IP address — is pinned
like the self-signed one.

**A domain without a CA certificate** also works: `RELAY_PUBLIC_URL=https://relay.example.com:8443` with the default
self-signed certificate (made for that name, pinned).

## Configuration

Environment variables and/or a JSON file (comments allowed; [relay.example.json](relay.example.json) lists everything).
Every key has an environment variable `RELAY_<PATH IN UPPER SNAKE CASE>`: `publicUrl` → `RELAY_PUBLIC_URL`,
`listen.port` → `RELAY_LISTEN_PORT`, `coord.pinnedKeys` → `RELAY_COORD_PINNED_KEYS` (JSON), `blobs` → `RELAY_BLOBS`
(JSON). The file path comes from `--config`, `RELAY_CONFIG` or `/etc/pocket-relay/relay.json`.

| Key | Default | Meaning |
|---|---|---|
| `publicUrl` | `null` | The `https://` address devices use. `null`: the IP the coordination server sees, on `listen.port`. |
| `listen.host`, `listen.port` | `0.0.0.0`, `8443` | Where to listen. |
| `tls` | `"auto"` | `"auto"`: own self-signed certificate (plain HTTP when `trustProxy` is true). `"self"`: always self-signed. `null`: plain HTTP behind a TLS proxy. `{"cert", "key"}`: PEM files. |
| `trustProxy` | `false` | Take the client IP from the last `X-Forwarded-For` entry (only behind your own proxy). |
| `relayId`, `account` | `null` | Leave both out: the relay is claimed from the App. Give both to bind it by hand (the official relay: `hk1`, `"*"`). |
| `coord.url` | `https://pocket.pocketcli.net` | Public address lookup, coordination keys, revocations. |
| `coord.pinnedKeys` | the official key | Coordination public keys to trust initially: `[{kid, pub, use, nbf, exp}]`. Newer keys signed by these are adopted. |
| `coord.pollSeconds` | `60` | Revocation polling interval for accounts with live connections. |
| `dataDir` | `/var/lib/pocket-relay` | Certificate, claim, index database, objects, attachments. |
| `blobs` | `{"store": "disk"}` | Attachments on disk, or `{"store": "s3", "backends": [...]}` (below). |
| `timezone` | `Asia/Shanghai` | Day and month boundaries of traffic quotas. |
| `quota.dayMB`, `quota.monthMB`, `quota.storeMB` | unlimited | Per-account attachment traffic and storage caps. |
| `quota.useTicketQuota` | `true` | Use the caps that coordination puts in tickets when present. |
| `retention.objectDays` | `30` | Delete objects neither written nor read for this long (the session list of a computer seen in the last week is kept). |
| `retention.blobDays` | `30` | Delete attachments not downloaded for this long (or since upload). |
| `retention.queueMaxSeconds` | `604800` | Longest time an envelope waits for an offline device. |
| `limits` | see `src/config.mjs` | Sizes and rates (frame 2 MiB, envelope 1 MiB, 2 sockets per device, …). |

### S3-compatible storage

```json
"blobs": { "store": "s3", "cnIpFile": "/var/lib/pocket-relay/cn-ip.txt", "backends": [
  { "name": "main", "when": "default", "endpoint": "https://s3.example.com", "region": "us-east-1",
    "bucket": "my-pocket", "accessKeyEnv": "RELAY_S3_KEY", "secretKeyEnv": "RELAY_S3_SECRET",
    "pathStyle": false, "prefix": "pocket/" } ] }
```

Works with AWS S3, Cloudflare R2, MinIO, Tencent COS and Aliyun OSS (S3-compatible endpoints; AWS Signature V4 presigned
URLs). Keys are read from the environment variables you name, never from the file. Each new attachment goes to the first
backend whose `when` matches the uploader: `cn-ip` matches IPs inside the CIDR list in `cnIpFile` (one CIDR per line, a
JSON array of CIDRs, or `{v4:[[start,end]…], v6:[…]}`), `default` matches everyone. If the bucket is unreachable the
relay keeps the attachment on its own disk. Objects are named `<prefix><address>/<blob id>` — no names, no account ids,
no content types. The bucket needs no public access: uploads and downloads use presigned URLs valid for an hour and
ten minutes.

## Operations

- **Print the line again**: `docker exec pocket-relay node src/main.mjs connect-string` (or `node src/main.mjs
  connect-string` with the same environment). It is also in `connect.txt` in the data directory. Once the relay is
  claimed the line has no claim code.
- **Unbind and claim again** (you removed the relay in the App, or want to give it to another account):
  `docker exec pocket-relay node src/main.mjs reset-claim`. It prints a new line with a new claim code; the running
  relay closes its connections within a few seconds and waits to be claimed. When another account claims it, what the
  previous account stored is deleted.
- **A new IP address** makes a new certificate (and pin): run `reset-claim` and add the relay again. To avoid that, use
  a static IP (an elastic IP on cloud servers), or a domain in `publicUrl`. To replace the certificate on purpose, delete
  `tls/` in the data directory, restart, then `reset-claim`.
- **Upgrade**: rebuild the image and start a new container with the same volume —
  `docker build -t pocket-relay . && docker rm -f pocket-relay && docker run …` (same command as above). The certificate,
  the claim and the data stay.
- **Logs** go to standard output: time, relay id, account, device address, operation, sizes, status, latency and client
  IP. Never message bytes, tickets, tokens, challenges, claim codes, presigned URLs or `Authorization` headers.
- **Health**: `node src/main.mjs --health` (the container's health check) asks `/v1/info`; `GET /v1/health` answers 200
  once the relay is claimed (503 `unclaimed` before). `GET /v1/metrics` (loopback only): connection, queue, object and
  attachment counts.
- **Data** is a cache of ciphertext. Losing it loses nothing that the computers cannot upload again — except the
  certificate (`tls/`) and the claim (`binding.json`): without them, add the relay again. Deleted data is gone at once
  (no trash). Disk use is bounded by the retention settings.
- **Restarts** forget the in-memory session tokens; devices simply authenticate again.
- Revocations arrive pushed by coordination (`POST /v1/revocations`), forwarded by devices, or by polling; a revoked
  device is disconnected at once and a deleted one's data removed. Purge orders (`POST /v1/purge`, signed by
  coordination) delete an account's or a computer's data.

## Development and tests

```sh
node --test                   # or npm test: protocol vectors, WebSocket, objects, blobs (with a fake S3), control, config,
                              # the self-signed certificate, the claim flow and the relay as a process
node test/fake-s3.mjs --port 18650 --keys-file keys.json     # the fake S3 used by the tests
```

Tests read the protocol vectors from `POCKET_PROTOCOL_DIR`, `./protocol`.

## License

GNU Affero General Public License v3.0 or later — see [LICENSE](LICENSE). If you run a modified relay as a network
service, its users are entitled to your modified source.
