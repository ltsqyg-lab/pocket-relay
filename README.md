English | [简体中文](README.zh-CN.md)

# Pocket relay

The relay for [Pocket](https://pocket.pocketcli.net), the phone app for the AI coding tools on your computer (Claude
Code, Codex and others). It carries your devices' end-to-end encrypted data and cannot read it. The official relay
runs this same code, and you can run your own.

## Deploy without a domain (recommended)

You need a server with a public IP and Docker. 1 vCPU and 1 GB of memory is enough for one person. As with Tailscale's
DERP servers, you don't need a domain or a certificate: the relay makes its own certificate and the app pins it.

```sh
git clone https://github.com/ltsqyg-lab/pocket-relay && cd pocket-relay
docker build -t pocket-relay .
docker run -d --name pocket-relay --restart unless-stopped -p 8443:8443 -v pocket-relay:/var/lib/pocket-relay pocket-relay
docker logs pocket-relay
```

The log contains a line like this:

```
pocket-relay://203.0.113.7:8443?pin=sha256:3f1c…&claim=Qm9x…
```

1. Open TCP port 8443 in the server's firewall and in your cloud provider's security group.
2. In the Pocket app, go to **Settings → Relay → Add your own relay** and paste the line. Pocket checks the relay's
   certificate against `pin` and uses the one-time `claim` code to tie the relay to your account. After that it
   serves only you.
3. Switch to the relay in the app. Your computers upload their sessions to it and your phones read from it.

**Keep the line private until you have pasted it.** Whoever uses the claim code first gets the relay. The code works
once and only appears in the relay's output and data directory, and the relay allows 5 tries a minute per address. If
it leaks, run `reset-claim` (see [Operations](#operations)).

The relay learns its public IP from the coordination server (`GET https://pocket.pocketcli.net/v2/whoami`) and makes a
self-signed certificate for it (ECDSA P-256, valid for 10 years). `pin` is that certificate's SHA-256, and devices
accept no other certificate, so no certificate authority can impersonate your relay. Everything is kept in the
`pocket-relay` volume, so the line doesn't change when you restart or upgrade.

**If the detected address is wrong** (the server goes out through another IP, or you publish another port such as
`-p 443:8443`), set it:

```sh
docker run -d --name pocket-relay --restart unless-stopped -p 443:8443 -v pocket-relay:/var/lib/pocket-relay \
  -e RELAY_PUBLIC_URL=https://203.0.113.7:443 pocket-relay
```

**Without Docker** (Node.js 22.13 or later, no npm packages):

```sh
RELAY_DATA_DIR=$HOME/pocket-relay node src/main.mjs                       # port 8443
RELAY_DATA_DIR=$HOME/pocket-relay RELAY_LISTEN_PORT=9443 node src/main.mjs
```

On IPv6-only servers, also set `RELAY_LISTEN_HOST=::`.

## Deploy with a domain

**Behind a reverse proxy** (nginx, Caddy, …) that already has a certificate for your domain: the proxy terminates
HTTPS, passes WebSocket upgrades for `/v1/ws` and appends the client address to `X-Forwarded-For`, and the relay
listens on loopback with plain HTTP.

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

The line then has no `pin`, since devices check the proxy's certificate like any website's:
`pocket-relay://relay.example.com:443?claim=…`. Put the relay at the root of its own host name or port. The app can't
add a relay under a path such as `https://example.com/relay`.

**Your own certificate files:** mount them and set
`RELAY_TLS='{"cert":"/etc/pocket-relay/fullchain.pem","key":"/etc/pocket-relay/privkey.pem"}'`. They are reloaded when
they change. A public CA certificate for the domain in `publicUrl` is not pinned, so renewals keep working. Any other
certificate, and any certificate used over an IP address, is pinned.

**A domain without a CA certificate:** set `RELAY_PUBLIC_URL=https://relay.example.com:8443`. The relay makes a
self-signed certificate for that name and pins it.

## What the relay sees

It passes messages between your devices (queued for a while if one is offline) and keeps your computer's encrypted
session list, history and attachments, so your phone can read them while the computer sleeps. It never decrypts
anything and holds no Pocket secret. A device proves who it is with a short-lived ticket signed by the Pocket
coordination server, which the relay checks offline with the coordination public key, and with a signature over a
one-time challenge made with the device's own key.

| The relay sees | The relay doesn't see |
|---|---|
| account id, device addresses, who talks to whom and when, sizes, how many sessions and messages, client IPs | message text, tool output, approval cards, titles, project paths, attachment names or contents, thumbnails, search queries, usage figures |

Protocol: [RELAY.md](protocol/RELAY.md) (this server), [E2EE.md](protocol/E2EE.md) (the cryptography),
test vectors in [vectors.json](protocol/vectors.json).

## Configuration

Most relays need none. Settings come from environment variables and/or a JSON file (comments allowed;
[relay.example.json](relay.example.json) lists them with their defaults). Each key has a variable `RELAY_<PATH IN UPPER SNAKE CASE>`:
`publicUrl` → `RELAY_PUBLIC_URL`, `listen.port` → `RELAY_LISTEN_PORT`, `coord.pinnedKeys` → `RELAY_COORD_PINNED_KEYS`
(JSON), `blobs` → `RELAY_BLOBS` (JSON). The file is read from `--config`, `RELAY_CONFIG` or
`/etc/pocket-relay/relay.json`.

| Key | Default | Meaning |
|---|---|---|
| `publicUrl` | `null` | The `https://` address devices use. `null`: the IP the coordination server sees, on `listen.port`. |
| `listen.host`, `listen.port` | `0.0.0.0`, `8443` | Where to listen. |
| `tls` | `"auto"` | `"auto"`: own self-signed certificate (plain HTTP when `trustProxy` is true). `"self"`: always self-signed. `null`: plain HTTP behind a TLS proxy. `{"cert", "key"}`: PEM files. |
| `trustProxy` | `false` | Take the client IP from the last `X-Forwarded-For` entry. Only behind your own proxy. |
| `relayId`, `account` | `null` | Leave both out to claim the relay from the app. Set both to bind it by hand (the official relay: `hk1`, `"*"`). |
| `coord.url` | `https://pocket.pocketcli.net` | Public address lookup, coordination keys, revocations. |
| `coord.pinnedKeys` | the official key | Coordination public keys trusted at first: `[{kid, pub, use, nbf, exp}]`. Newer keys signed by these are adopted. |
| `coord.pollSeconds` | `60` | How often to poll revocations for accounts with live connections. |
| `dataDir` | `/var/lib/pocket-relay` | Certificate, claim, index database, objects, attachments. |
| `blobs` | `{"store": "disk"}` | Attachments on disk, or `{"store": "s3", "backends": [...]}` (below). |
| `timezone` | `Asia/Shanghai` | Where days and months start for traffic quotas. |
| `quota.dayMB`, `quota.monthMB` | unlimited | Per-account caps on attachment traffic. |
| `quota.storeMB` | `5120` | What one account may keep here: sessions and attachments together. `null` or `0`: no cap. |
| `quota.smallMB`, `quota.smallFileMB` | `50`, `2` | When the day or month is used up, files up to `smallFileMB` (thumbnails, voice) still go through, up to `smallMB` a day. `0` turns this off. |
| `quota.useTicketQuota` | `true` | Use the caps in the account's newest coordination ticket, when present. |
| `disk.minFreeMB` | `5120` | Free space to leave on the data directory's disk. Below it the relay stores nothing new there (`503 full`); everything else keeps working. `0` turns this off. |
| `retention.objectDays` | `30` | Delete objects not written or read for this long. A computer seen in the last week keeps its session list. |
| `retention.blobDays` | `30` | Delete attachments not downloaded for this long (counted from upload if never downloaded). Reading a few bytes doesn't count. |
| `retention.queueMaxSeconds` | `604800` | Longest an envelope waits for an offline device. |
| `limits` | see `src/config.mjs` | Sizes and rates (frame 2 MiB, 64 KiB before sign-in, envelope 1 MiB, 2 sockets per device, …). |

### S3-compatible storage

```json
"blobs": { "store": "s3", "cnIpFile": "/var/lib/pocket-relay/cn-ip.txt", "backends": [
  { "name": "main", "when": "default", "endpoint": "https://s3.example.com", "region": "us-east-1",
    "bucket": "my-pocket", "accessKeyEnv": "RELAY_S3_KEY", "secretKeyEnv": "RELAY_S3_SECRET",
    "pathStyle": false, "prefix": "pocket/" } ] }
```

Works with AWS S3, Cloudflare R2, MinIO, Tencent COS and Aliyun OSS (S3-compatible endpoints, AWS Signature V4
presigned URLs). Keys come from the environment variables you name, never from the file. A new attachment goes to the
first backend whose `when` matches the uploader: `cn-ip` matches IPs in the CIDR list in `cnIpFile` (one CIDR per
line, a JSON array, or `{v4:[[start,end]…], v6:[…]}`), `default` matches everyone. If the bucket is unreachable, the
attachment stays on the relay's disk; otherwise nothing goes there. Objects are named `<prefix><address>/<blob id>`,
with no file names, account ids or content types. The bucket needs no public access: upload links last 15 minutes,
download links two minutes. The relay deletes what an upload link leaves behind after its attachment is gone. Give
each relay its own bucket or `prefix`.

## Operations

- **Print the line again:** `docker exec pocket-relay node src/main.mjs connect-string` (without Docker, run
  `node src/main.mjs connect-string` with the same environment). It is also in `connect.txt` in the data directory.
  Once the relay is claimed, the line has no claim code.
- **Claim it again** (you removed it in the app, or want to give it to another account):
  `docker exec pocket-relay node src/main.mjs reset-claim` prints a line with a new claim code. A running relay drops
  its connections within seconds and waits to be claimed. If another account claims it, the old account's data is
  deleted.
- **New IP address:** the relay makes a new certificate and pin. Run `reset-claim` and add the relay in the app again.
  A static IP (an elastic IP on cloud servers) or a domain in `publicUrl` avoids this. To replace the certificate on
  purpose, delete `tls/` in the data directory, restart, then run `reset-claim`.
- **Upgrade:** `git pull && docker build -t pocket-relay . && docker rm -f pocket-relay`, then the same `docker run`.
  The volume keeps the certificate, the claim and the data.
- **Logs** go to standard output: time, relay id, account, device address, operation, sizes, status, latency, client
  IP. Never message bytes, tickets, tokens, challenges, claim codes, presigned URLs or `Authorization` headers.
- **Health:** `node src/main.mjs --health` (the container health check) asks `/v1/info`. `GET /v1/health` returns 200
  once the relay is claimed (503 `unclaimed` before). `GET /v1/metrics` (loopback only) gives connection, queue,
  object and attachment counts.
- **Data** is a cache of ciphertext that the computers can upload again. Only the certificate (`tls/`) and the claim
  (`binding.json`) can't be rebuilt: lose them and you add the relay in the app again. Deletes are immediate (no
  trash). Disk use is capped by retention, by `quota.storeMB` per account and by `disk.minFreeMB`: when the disk gets
  that full, the log says `disk-low` and the relay stops taking new data until there is room again.
- **Restarts** drop the in-memory session tokens, and devices sign in to the relay again by themselves.
- **Revocations** come from coordination (`POST /v1/revocations`), through devices, or by polling. A revoked device is
  disconnected at once and a deleted device's data is removed. Purge orders signed by coordination (`POST /v1/purge`)
  delete an account's or a computer's data.

## Development and tests

```sh
node --test                   # or npm test: protocol vectors, WebSocket, objects, blobs (with a fake S3), control, config,
                              # the self-signed certificate, the claim flow and the relay as a process
node test/fake-s3.mjs --port 18650 --keys-file keys.json     # the fake S3 used by the tests
```

Tests read the protocol vectors from `POCKET_PROTOCOL_DIR` if set, else from `./protocol`.

## License

GNU Affero General Public License v3.0 or later (see [LICENSE](LICENSE)). If you run a modified relay as a network
service, its users are entitled to your modified source.
