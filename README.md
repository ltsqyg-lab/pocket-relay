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

## Requirements

- Node.js **22.13 or newer** (uses the built-in `node:sqlite`; no npm packages at all), or Docker.
- A server reachable from the internet over HTTPS (port 443 or 8443). 1 vCPU / 1 GB RAM is plenty for one person.
- A TLS certificate for its domain — either files the relay reads itself, or a reverse proxy in front of it.

## Run it

**1. Register the relay in the Pocket App** — Settings → Relay → Add your own relay → enter its URL. The App shows the
values for the configuration: `relayId`, `account` and the coordination keys. None of them is secret.

**2a. With Docker**

```sh
docker build -t pocket-relay .
mkdir -p /srv/pocket-relay/data /etc/pocket-relay
cp relay.example.json /etc/pocket-relay/relay.json      # fill in relayId, account, coord.pinnedKeys, tls
docker run -d --name pocket-relay --restart unless-stopped -p 443:8443 \
  -v /srv/pocket-relay/data:/var/lib/pocket-relay \
  -v /etc/pocket-relay:/etc/pocket-relay:ro \
  pocket-relay
```

**2b. With Node directly**

```sh
node src/main.mjs --config /etc/pocket-relay/relay.json
```

**3.** Back in the App, tap **Verify** (the coordination server fetches `https://<your relay>/.well-known/pocket-relay`),
then **Use this relay**. Your computers re-upload their sessions to it; your phones download from it from then on.
If it becomes unreachable, the App offers to switch back to the official relay.

## Configuration

A JSON file (comments allowed) and/or environment variables. Every key has an environment variable
`RELAY_<PATH IN UPPER SNAKE CASE>`: `relayId` → `RELAY_RELAY_ID`, `listen.port` → `RELAY_LISTEN_PORT`,
`coord.pinnedKeys` → `RELAY_COORD_PINNED_KEYS` (JSON), `blobs` → `RELAY_BLOBS` (JSON). The file path comes from
`--config`, `RELAY_CONFIG` or `/etc/pocket-relay/relay.json`.

| Key | Default | Meaning |
|---|---|---|
| `relayId` | — (required) | The id the coordination server gave this relay; tickets must be addressed to it. |
| `account` | — (required) | `"*"` serves every account (the official relay); otherwise the one account this relay serves. |
| `publicUrl` | `null` | How devices reach it (informational). |
| `listen.host`, `listen.port` | `0.0.0.0`, `8443` | Where to listen. |
| `tls.cert`, `tls.key` | `null` | PEM files; reloaded automatically when they change. `null` = plain HTTP behind a TLS proxy. |
| `trustProxy` | `false` | Take the client IP from the last `X-Forwarded-For` entry (only behind your own proxy). |
| `coord.url` | `https://pocket.pocketcli.net` | Where to refresh coordination keys and poll revocations. |
| `coord.pinnedKeys` | — (required) | Coordination public keys to trust initially: `[{kid, pub, use, nbf, exp}]`. |
| `coord.pollSeconds` | `60` | Revocation polling interval for accounts with live connections. |
| `dataDir` | `/var/lib/pocket-relay` | Index database, objects, attachments. |
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

### Behind a reverse proxy

Terminate HTTPS in the proxy, pass WebSocket upgrades for `/v1/ws`, append the client address to `X-Forwarded-For`,
set `"tls": null`, `"trustProxy": true` and listen on `127.0.0.1`. Example (nginx):

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

## Operations

- **Logs** go to standard output: time, relay id, account, device address, operation, sizes, status, latency and client
  IP. Never message bytes, tickets, tokens, challenges, presigned URLs or `Authorization` headers.
- `GET /v1/health` for probes (`node src/main.mjs --health` in the container); `GET /v1/metrics` (loopback only):
  connection, queue, object and attachment counts.
- **Data** is a cache of ciphertext. Losing it loses nothing that the computers cannot upload again; there is nothing
  to back up. Deleted data is gone at once (no trash). Disk use is bounded by the retention settings.
- **Restarts** forget the in-memory session tokens; devices simply authenticate again.
- Revocations arrive pushed by coordination (`POST /v1/revocations`), forwarded by devices, or by polling; a revoked
  device is disconnected at once and a deleted one's data removed. Purge orders (`POST /v1/purge`, signed by
  coordination) delete an account's or a computer's data.

## Development

```sh
npm test                      # node --test test/*.test.mjs — the protocol vectors, WebSocket, objects, blobs (with a fake S3), control, config
node test/fake-s3.mjs --port 18650 --keys-file keys.json     # the fake S3 used by the tests
```

Tests read the protocol vectors from `POCKET_PROTOCOL_DIR`, `./protocol`.

## License

GNU Affero General Public License v3.0 or later — see [LICENSE](LICENSE). If you run a modified relay as a network
service, its users are entitled to your modified source.

---

## 自建中继(中文)

**中继是什么**:Pocket 手机和电脑之间的「邮局」—— 转发两边的加密信封,替不在线的一方暂存,保存电脑上传的加密会话记录和附件。
它**只经手密文**,看得到「哪台设备、什么时候、多大」,看不到任何内容;不需要 Pocket 的任何秘密,靠协调服务器签的短期票据和设备当场签名认人。

**需要什么**
1. 一台有公网地址的服务器(1 核 1G 足够一个人用)和一个域名 + HTTPS 证书(可以交给 nginx / Caddy 反代,也可以把证书文件直接配给中继)。
2. Node.js 22.13 以上,或者 Docker。**不需要对象存储**:附件默认存这台服务器自己的硬盘;想要大容量再接任意 S3 兼容的桶
   (腾讯云 COS、阿里云 OSS、AWS S3、Cloudflare R2、MinIO,用你自己的账号和钥匙)。

**步骤**
1. 手机 App:设置 → 中继 → 添加自建中继 → 填中继的网址。App 给出 `relayId`、`account`、协调公钥 —— 这些都不是秘密,原样填进
   `/etc/pocket-relay/relay.json`(照 `relay.example.json`)。
2. 启动:`docker run …`(见上文 Run it),或 `node src/main.mjs --config /etc/pocket-relay/relay.json`。
3. 回到 App 点「验证」(协调服务器会访问 `https://你的中继/.well-known/pocket-relay` 核对),再点「使用这个中继」。电脑会把会话重新加密上传到你的中继。
4. 中继连不上时 App 会提示切回官方中继。

**安全**:中继里只有密文,附件按随机编号存,不用文件哈希当名字;只服务绑定的那个账号;每台设备凭协调签发、几小时就过期的票据 + 自己私钥的当场签名才能连上;
撤销的设备立刻断开、数据删除。中继坏了最多是不送 / 晚送,拿不到内容,也造不了假(每个信封都有发件设备的签名)。

**日志**:只记时间、账号、设备地址、操作、大小、状态、耗时、客户端 IP,不记内容、票据、令牌、预签名地址。保留多久由你决定。

**许可**:AGPL-3.0。你改了中继并作为网络服务给别人用,就要把改动开源。
