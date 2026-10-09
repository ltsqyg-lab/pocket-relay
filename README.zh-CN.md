[English](README.md) | 简体中文

# Pocket 中继

[Pocket](https://pocket.pocketcli.net) 的中继。Pocket 是用手机遥控电脑上 AI 编程会话(Claude Code、Codex 等)的工具。
中继**只经手密文**:

- 在同一账号的设备之间转发端到端加密的**信封**(指令、回复、事件),对方不在线时短暂排队;
- 保存电脑上传的**对象**(会话列表、消息、用量,由电脑加密并签名),电脑睡着时手机照样能看历史;
- 保存**附件**(分块 AES-GCM 加密流),放本机硬盘或任意 S3 兼容的对象存储,支持预签名直传;
- 告诉设备对方何时上线、下线,对象何时有变化。

它不解密任何东西,也不持有 Pocket 的任何秘密:设备凭 Pocket 协调服务器签发的短期票据(中继用协调服务器的**公钥**离线核对)
加上用自己私钥对一次性挑战的签名证明身份。谁都可以自己跑一个;官方中继跑的也是这份代码。

| 中继看得到 | 中继看不到 |
|---|---|
| 账号编号、设备地址、谁和谁在什么时候通信、大小、会话和消息的数量、客户端 IP | 消息内容、工具输出、审批卡片、标题、项目路径、附件名字或内容、缩略图、搜索词、用量数字 |

协议:[RELAY.md](protocol/RELAY.md)(本服务)与 [E2EE.md](protocol/E2EE.md)(密码学),
共用的测试向量在 [vectors.json](protocol/vectors.json)。

## 免域名一键部署(推荐)

只要一台有公网 IP 的服务器(一个人用,1 核 1G 足够)和 Docker —— 和 Tailscale 的 DERP 中继一样,不需要域名,也不需要证书机构。

```sh
docker build -t pocket-relay .
docker run -d --name pocket-relay --restart unless-stopped -p 8443:8443 -v pocket-relay:/var/lib/pocket-relay pocket-relay
docker logs pocket-relay
```

日志里有这样一行:

```
pocket-relay://203.0.113.7:8443?pin=sha256:3f1c…&claim=Qm9x…
```

1. 在服务器防火墙和云服务器的安全组里**放行 TCP 8443 端口**。
2. **在 Pocket App:设备 → 中继 → 添加自建中继,粘贴这一行。** Pocket 协调服务器会连上你的中继(用这一行里的 `pin` 核对它的证书),
   凭一次性的认领码 `claim` 把它认领到你的账号下。从此这个中继只服务你的账号。
3. 在 App 里切换到它。你的电脑会把会话上传到它,手机从它读取。

第一次启动时发生了什么:中继问协调服务器「我的请求是从哪个 IP 来的」(`GET https://pocket.pocketcli.net/v2/whoami`),
给这个地址生成一张自签证书(ECDSA P-256,有效 10 年),然后打印这一行。`pin` 是这张证书的 SHA-256:设备只认这一张证书,
不看任何证书机构,所以谁也冒充不了你的中继。证书、认领关系和所有数据都在 `pocket-relay` 卷里,重启、升级都还在,这一行不会变。

**粘贴之前别把这一行给别人看。** 里面的认领码谁先拿到谁就能认领这个中继。它只出现在中继的输出和数据目录里,只能用一次,
同一个地址每分钟最多试 5 次。用之前泄露了,就用 `reset-claim`(见下文)换一个。

**自动探测的地址不对时**(服务器出网用的 IP 和设备该连的不是同一个,或者对外映射了别的端口,比如 `-p 443:8443`),自己指定:

```sh
docker run -d --name pocket-relay --restart unless-stopped -p 443:8443 -v pocket-relay:/var/lib/pocket-relay \
  -e RELAY_PUBLIC_URL=https://203.0.113.7:443 pocket-relay
```

**不用 Docker**(Node.js 22.13 以上,不需要任何 npm 包):

```sh
RELAY_DATA_DIR=$HOME/pocket-relay node src/main.mjs                       # 端口 8443
RELAY_DATA_DIR=$HOME/pocket-relay RELAY_LISTEN_PORT=9443 node src/main.mjs
```

只有 IPv6 的服务器再加上 `RELAY_LISTEN_HOST=::`。

## 有域名时的部署

**放在反向代理后面**(nginx、Caddy 等,已经有这个域名的证书):HTTPS 在代理上终结,`/v1/ws` 的 WebSocket 升级要转过来,
客户端地址追加到 `X-Forwarded-For`,中继在本机回环上跑明文 HTTP:

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

这时打印的那一行不带 `pin`(设备像访问普通网站一样核对代理的证书):`pocket-relay://relay.example.com:443?claim=…`。
中继要挂在自己的域名(或端口)的根路径上:App 不能添加 `https://example.com/relay` 这种带路径的中继。

**用自己的证书文件**:把文件挂进容器,设 `RELAY_TLS='{"cert":"/etc/pocket-relay/fullchain.pem","key":"/etc/pocket-relay/privkey.pem"}'`
(文件变了会自动重新加载)。公共证书机构给 `publicUrl` 里那个域名签发的证书不钉 pin,续期照常;其他证书 —— 以及设备按 IP 地址连接时的任何证书 —— 都和自签证书一样钉住。

**有域名但没有证书机构的证书**也行:`RELAY_PUBLIC_URL=https://relay.example.com:8443`,用默认的自签证书(给这个域名生成,钉 pin)。

## 配置

环境变量和/或 JSON 文件(可以写注释;[relay.example.json](relay.example.json) 列出了全部选项)。每个配置项都有对应的环境变量
`RELAY_<路径的大写蛇形>`:`publicUrl` → `RELAY_PUBLIC_URL`,`listen.port` → `RELAY_LISTEN_PORT`,
`coord.pinnedKeys` → `RELAY_COORD_PINNED_KEYS`(JSON),`blobs` → `RELAY_BLOBS`(JSON)。配置文件路径取自 `--config`、`RELAY_CONFIG`
或 `/etc/pocket-relay/relay.json`。

| 配置项 | 默认 | 含义 |
|---|---|---|
| `publicUrl` | `null` | 设备连接用的 `https://` 地址。`null`:协调服务器看到的 IP,端口用 `listen.port`。 |
| `listen.host`、`listen.port` | `0.0.0.0`、`8443` | 监听的地址和端口。 |
| `tls` | `"auto"` | `"auto"`:自己的自签证书(`trustProxy` 为 true 时改为明文 HTTP)。`"self"`:总用自签证书。`null`:明文 HTTP,TLS 由前面的代理终结。`{"cert", "key"}`:PEM 文件。 |
| `trustProxy` | `false` | 客户端 IP 取 `X-Forwarded-For` 的最后一项(只在你自己的代理后面打开)。 |
| `relayId`、`account` | `null` | 两个都不写:在 App 里认领。两个都写:手动绑定(官方中继是 `hk1`、`"*"`)。 |
| `coord.url` | `https://pocket.pocketcli.net` | 查公网地址、取协调公钥、拉撤销名单的地方。 |
| `coord.pinnedKeys` | 官方公钥 | 初始信任的协调公钥:`[{kid, pub, use, nbf, exp}]`。由它们签过的新公钥会自动采用。 |
| `coord.pollSeconds` | `60` | 有在线连接的账号多久拉一次撤销名单。 |
| `dataDir` | `/var/lib/pocket-relay` | 证书、认领关系、索引数据库、对象、附件。 |
| `blobs` | `{"store": "disk"}` | 附件放硬盘,或 `{"store": "s3", "backends": [...]}`(见下)。 |
| `timezone` | `Asia/Shanghai` | 流量配额按哪个时区算日、月。 |
| `quota.dayMB`、`quota.monthMB`、`quota.storeMB` | 不限 | 每个账号的附件流量和存储上限。 |
| `quota.useTicketQuota` | `true` | 票据里带了上限就用票据里的。 |
| `retention.objectDays` | `30` | 多久没写也没读的对象删掉(最近一周连过的电脑,会话列表保留)。 |
| `retention.blobDays` | `30` | 多久没下载的附件删掉(从没下载过就从上传时算)。 |
| `retention.queueMaxSeconds` | `604800` | 信封最多等离线设备多久。 |
| `limits` | 见 `src/config.mjs` | 大小和速率(帧 2 MiB、信封 1 MiB、每台设备 2 条连接……)。 |

### S3 兼容的对象存储

```json
"blobs": { "store": "s3", "cnIpFile": "/var/lib/pocket-relay/cn-ip.txt", "backends": [
  { "name": "main", "when": "default", "endpoint": "https://s3.example.com", "region": "us-east-1",
    "bucket": "my-pocket", "accessKeyEnv": "RELAY_S3_KEY", "secretKeyEnv": "RELAY_S3_SECRET",
    "pathStyle": false, "prefix": "pocket/" } ] }
```

支持 AWS S3、Cloudflare R2、MinIO、腾讯云 COS、阿里云 OSS(S3 兼容接口;AWS Signature V4 预签名)。钥匙从你指定的环境变量里读,
绝不写在文件里。每个新附件放到第一个 `when` 匹配上传者的后端:`cn-ip` 匹配 `cnIpFile` 里 CIDR 列表内的 IP(每行一个 CIDR、
CIDR 的 JSON 数组,或 `{v4:[[start,end]…], v6:[…]}`),`default` 匹配所有人。桶连不上时附件先放中继自己的硬盘。
对象名是 `<prefix><地址>/<附件编号>` —— 没有文件名、没有账号编号、没有内容类型。桶不需要公开访问:上传和下载都用一小时十分钟内有效的预签名地址。

## 运维

- **再打印一遍那一行**:`docker exec pocket-relay node src/main.mjs connect-string`(不用 Docker 就在同样的环境变量下跑
  `node src/main.mjs connect-string`)。数据目录里的 `connect.txt` 也是这一行。认领之后的这一行不带认领码。
- **解绑、重新认领**(在 App 里删掉了这个中继,或者要给另一个账号用):`docker exec pocket-relay node src/main.mjs reset-claim`。
  它打印带新认领码的一行;正在运行的中继几秒内断开所有连接,等着被认领。被另一个账号认领时,上一个账号存的东西会删掉。
- **公网 IP 变了**会生成新证书(pin 也变):跑 `reset-claim`,在 App 里重新添加。想避免的话用固定 IP(云服务器的弹性公网 IP),
  或者在 `publicUrl` 里用域名。故意要换证书:删掉数据目录里的 `tls/`,重启,再 `reset-claim`。
- **升级**:重新构建镜像,用同一个卷起新容器 ——
  `docker build -t pocket-relay . && docker rm -f pocket-relay && docker run …`(和上面同一条命令)。证书、认领关系和数据都还在。
- **日志**输出到标准输出:时间、中继编号、账号、设备地址、操作、大小、状态、耗时、客户端 IP。绝不记消息内容、票据、令牌、挑战、
  认领码、预签名地址、`Authorization` 头。
- **健康检查**:`node src/main.mjs --health`(容器的健康检查)问的是 `/v1/info`;`GET /v1/health` 认领之后回 200(之前回 503 `unclaimed`)。
  `GET /v1/metrics`(只限本机回环):连接、队列、对象、附件的数量。
- **数据**是密文缓存。丢了也没关系,电脑会重新上传 —— 除了证书(`tls/`)和认领关系(`binding.json`):没了它们就要在 App 里重新添加。
  删除的数据立即消失(没有回收站)。硬盘占用受保留期限制。
- **重启**会忘掉内存里的会话令牌;设备重新认证一次就好。
- 撤销名单由协调服务器推来(`POST /v1/revocations`)、设备转交,或者中继自己去拉;被撤销的设备立即断开,被删除的设备的数据立即删掉。
  清除指令(`POST /v1/purge`,协调服务器签名)删掉一个账号或一台电脑的数据。

## 开发与测试

```sh
node --test                   # 或 npm test:协议向量、WebSocket、对象、附件(带假 S3)、控制、配置、
                              # 自签证书、认领流程、以进程方式运行的中继
node test/fake-s3.mjs --port 18650 --keys-file keys.json     # 测试用的假 S3
```

测试从 `POCKET_PROTOCOL_DIR`、`./protocol` 读协议向量。

## 许可

GNU Affero General Public License v3.0 或更新版本 —— 见 [LICENSE](LICENSE)。你修改了中继并作为网络服务给别人用,用户有权拿到你修改后的源代码。
