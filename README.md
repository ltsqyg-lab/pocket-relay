English | [简体中文](README.zh-CN.md)

# Pocket relay

The relay for [Pocket](https://pocket.pocketcli.net), the phone app for the AI coding tools on your computer (Claude
Code, Codex and others). It carries your devices' end-to-end encrypted data and cannot read it. The official relay
runs this same code, and you can run your own.

## One-command install (recommended)

You need a server with a public IP running Ubuntu or Debian (x86_64 or arm64, systemd). 1 vCPU and 1 GB of memory is
enough for one person. You don't need a domain or a certificate. One command installs the relay and the
[speech service](https://github.com/pocketcli-app/pocket-asr) together:

```sh
# international edition
curl -fsSL https://pocket.pocketcli.net/dl/selfhost/install.sh | sudo bash

# mainland China edition (for the mainland China edition of the app)
curl -fsSL https://api.pocketcli.cn/dl/selfhost/install.sh | sudo bash
```

It ends with two lines (the script talks in Chinese; these lines are what you need):

```
 中继:在 Pocket App「我的 → 服务器 → 添加自建服务器」粘贴这一行
   pocket-relay://203.0.113.7:8443?pin=sha256:3f1c…&claim=Qm9x…

 语音服务:在 Pocket App「我的 → 语音识别方式 → 自建语音服务」粘贴这一行
   pocket-asr://203.0.113.7:8444?pin=sha256:068a…&token=eJLA…
```

1. Open TCP ports 8443 and 8444 in your cloud provider's firewall / security group (the script opens them in ufw when
   ufw is on).
2. In the Pocket app, paste the first line in **Settings → Server → Add self-hosted server** and the second in
   **Settings → Voice transcription → Self-hosted speech service**. The second line carries an access key and is shown
   only once.

| Option (after `bash -s --`) | What it does |
|---|---|
| `--relay-only` / `--asr-only` | Install, upgrade or uninstall only one of them |
| `--uninstall` | Stop the services and remove the programs, data, settings and system users (asks first; `--yes` doesn't ask) |
| `--docker <dir>` | Install no services: put the verified programs and a `docker-compose.yml` into `<dir>` (see Docker below) |

For example, only the relay: `curl -fsSL https://pocket.pocketcli.net/dl/selfhost/install.sh | sudo bash -s -- --relay-only`.

**Upgrade:** run the same command again. The certificate, the claim, the access keys and the speech model are kept, so
the lines don't change. A relay installed by hand as described below (code in `/opt/pocket-relay`, service
`pocket-relay`, data in `/var/lib/pocket-relay`) is taken over with its data; its old code moves to
`/opt/pocket-relay.bak-<time>`.

**What the script does:** checks the system; when there is no Node.js 22.13 or later, downloads Node.js 22 from
nodejs.org (international) or npmmirror (mainland China) into `/opt/pocket-selfhost/node` and checks its SHA-256,
leaving any system Node.js alone; downloads the relay and speech service packages (the same files as the open-source
repositories) from `/dl/selfhost/` on the same server and checks them against the SHA-256 written in the script;
creates the system users `pocket-relay` and `pocket-asr`, installs the code to `/opt/pocket-relay` and `/opt/pocket-asr`
and the data to `/var/lib/pocket-relay` and `/var/lib/pocket-asr`, and writes and starts systemd services. Afterwards,
`sudo pocket-relay connect-string` prints the relay's line again and `sudo pocket-asr new-token` makes a new speech
service line. Your own settings (such as `RELAY_PUBLIC_URL`) go in `/etc/pocket-relay/env`; then
`systemctl restart pocket-relay`.

### Two editions

Pocket runs two separate services: the international edition (`pocket.pocketcli.net`) and the mainland China edition
(`api.pocketcli.cn`). They share no accounts, keys or servers. Install the relay of the edition your app uses:

- **International** (`RELAY_EDITION=intl`, the default): talks to `https://pocket.pocketcli.net`.
- **Mainland China** (`RELAY_EDITION=cn`): looks up its public IP, fetches the coordination keys and polls revocations
  only at `https://api.pocketcli.cn`, trusts only that edition's coordination key and connects to nothing outside
  mainland China. Its install script, Node.js and packages are downloaded from mainland China too.

If you install the wrong one, adding it in the other edition's app fails: the relay refuses the claim and its log says
which command to reinstall with. The claim code keeps working.

### Before you paste

**Keep the relay's line private until you have pasted it.** Whoever uses the claim code first gets the relay. The code
works once and only appears in the relay's output and data directory, and the relay allows 5 tries a minute per
address. If it leaks, run `sudo pocket-relay reset-claim` (see [Operations](#operations)).

The app checks the relay's certificate against `pin` and uses the one-time `claim` code to tie the relay to your
account. After that it serves only you. Switch to it in the app: your computers upload their sessions to it and your
phones read from it.

The relay learns its public IP from the coordination server (`GET <coordination>/v2/whoami`) and makes a self-signed
certificate for it (ECDSA P-256, valid for 10 years). `pin` is that certificate's SHA-256, and devices accept no other
certificate, so no certificate authority can impersonate your relay. Restarts and upgrades keep the line. If the
detected address is wrong (the server goes out through another IP, or you publish another port), put
`RELAY_PUBLIC_URL=https://203.0.113.7:8443` in `/etc/pocket-relay/env` and `systemctl restart pocket-relay`.

## Other ways to deploy

### Docker

Let the install script fetch and verify the programs, then start the relay and the speech service with Docker Compose:

```sh
curl -fsSL https://pocket.pocketcli.net/dl/selfhost/install.sh | sudo bash -s -- --docker /opt/pocket-docker   # or api.pocketcli.cn
cd /opt/pocket-docker && docker compose up -d --build
docker compose logs          # the two lines are in the log
```

`.env` in that directory holds the edition (`POCKET_EDITION=cn` or `intl`). From mainland China, pulling the base
images (`node:22-alpine`, `node:22-bookworm-slim`) from Docker Hub is slow or fails: configure a registry mirror for
Docker first. The mainland China `.env` also points the speech image's apt at `mirrors.aliyun.com`. Without a registry
mirror, use the one-command install (no Docker needed).

Only the relay, from the repository:

```sh
git clone https://github.com/pocketcli-app/pocket-relay && cd pocket-relay
docker build -t pocket-relay .                                     # mainland China: --build-arg RELAY_EDITION=cn
docker run -d --name pocket-relay --restart unless-stopped -p 8443:8443 -v pocket-relay:/var/lib/pocket-relay pocket-relay
docker logs pocket-relay
```

With another published port (`-p 443:8443`), add `-e RELAY_PUBLIC_URL=https://203.0.113.7:443`.

### Without Docker or the script

Node.js 22.13 or later, no npm packages:

```sh
RELAY_DATA_DIR=$HOME/pocket-relay node src/main.mjs                       # international, port 8443
RELAY_EDITION=cn RELAY_DATA_DIR=$HOME/pocket-relay node src/main.mjs      # mainland China
RELAY_DATA_DIR=$HOME/pocket-relay RELAY_LISTEN_PORT=9443 node src/main.mjs
```

On IPv6-only servers, also set `RELAY_LISTEN_HOST=::`.

### With a domain

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
| `edition` | `intl` | `intl` or `cn` (see [Two editions](#two-editions)); sets the defaults of the next two. Variable `RELAY_EDITION`. |
| `relayId`, `account` | `null` | Leave both out to claim the relay from the app. Set both to bind it by hand (the official relay: `hk1`, `"*"`). |
| `coord.url` | the edition's: `https://pocket.pocketcli.net` / `https://api.pocketcli.cn` | Public address lookup, coordination keys, revocations. Startup fails if it names the other edition's server. |
| `coord.pinnedKeys` | the edition's official key | Coordination public keys trusted at first: `[{kid, pub, use, nbf, exp}]`. Newer keys signed by these are adopted. Startup fails if it holds the other edition's key. |
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

- **Print the line again:** `sudo pocket-relay connect-string` (one-command install), `docker exec pocket-relay node
  src/main.mjs connect-string` (Docker), or `node src/main.mjs connect-string` with the same environment. It is also in `connect.txt` in the data directory.
  Once the relay is claimed, the line has no claim code.
- **Claim it again** (you removed it in the app, or want to give it to another account):
  `sudo pocket-relay reset-claim` (Docker: `docker exec pocket-relay node src/main.mjs reset-claim`) prints a line
  with a new claim code. A running relay drops
  its connections within seconds and waits to be claimed. If another account claims it, the old account's data is
  deleted.
- **New IP address:** the relay makes a new certificate and pin. Run `reset-claim` and add the relay in the app again.
  A static IP (an elastic IP on cloud servers) or a domain in `publicUrl` avoids this. To replace the certificate on
  purpose, delete `tls/` in the data directory, restart, then run `reset-claim`.
- **Upgrade:** run the install command again; with Docker, rebuild with the new code (`docker compose up -d --build`,
  or `git pull && docker build …` and the same `docker run`). The certificate, the claim and the data are kept.
- **Logs** go to standard output (`journalctl -u pocket-relay`, `docker logs pocket-relay`): time, relay id, account, device address, operation, sizes, status, latency, client
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
