[English](README.md) | 简体中文

# Pocket 中继

[Pocket](https://pocket.pocketcli.net) 的中继。Pocket 是用手机遥控电脑上 AI 编程工具(Claude Code、Codex 等)的 App。中继替你的设备转发、保存端到端加密的数据,自己看不到内容。官方中继跑的就是这份代码,你也可以自己跑一个。

## 不用域名部署(推荐)

要一台有公网 IP 的服务器和 Docker,一个人用 1 核 1G 就够。和 Tailscale 的 DERP 中继一样,不需要域名,也不需要买证书:中继自己生成证书,App 钉住它。

```sh
git clone https://github.com/ltsqyg-lab/pocket-relay && cd pocket-relay
docker build -t pocket-relay .
docker run -d --name pocket-relay --restart unless-stopped -p 8443:8443 -v pocket-relay:/var/lib/pocket-relay pocket-relay
docker logs pocket-relay
```

日志里有这样一行:

```
pocket-relay://203.0.113.7:8443?pin=sha256:3f1c…&claim=Qm9x…
```

1. 在服务器防火墙和云服务器的安全组里放行 TCP 8443 端口。
2. 在 Pocket App 里打开 **我的 → 中继 → 添加自建中继**,粘贴这一行。Pocket 用 `pin` 核对中继的证书,凭一次性的认领码 `claim` 把中继认领到你的账号下。从此它只服务你一个人。
3. 在 App 里切换到这个中继。电脑会把会话上传到它,手机从它读取。

**粘贴之前别把这一行给别人。** 认领码谁先用谁就拿到这个中继。它只能用一次,只出现在中继的输出和数据目录里,同一个地址每分钟最多试 5 次。泄露了就用 `reset-claim` 换一个(见[运维](#运维))。

中继问协调服务器自己的公网 IP 是多少(`GET https://pocket.pocketcli.net/v2/whoami`),给这个地址生成一张自签证书(ECDSA P-256,有效 10 年)。`pin` 是这张证书的 SHA-256,设备只认这一张,所以证书机构也冒充不了你的中继。所有东西都在 `pocket-relay` 卷里,重启、升级之后这一行不变。

**探测到的地址不对时**(服务器出网走的是另一个 IP,或者对外映射了别的端口,比如 `-p 443:8443`),自己指定:

```sh
docker run -d --name pocket-relay --restart unless-stopped -p 443:8443 -v pocket-relay:/var/lib/pocket-relay \
  -e RELAY_PUBLIC_URL=https://203.0.113.7:443 pocket-relay
```

**不用 Docker**(Node.js 22.13 以上,不需要 npm 包):

```sh
RELAY_DATA_DIR=$HOME/pocket-relay node src/main.mjs                       # 端口 8443
RELAY_DATA_DIR=$HOME/pocket-relay RELAY_LISTEN_PORT=9443 node src/main.mjs
```

只有 IPv6 的服务器再加 `RELAY_LISTEN_HOST=::`。

## 有域名时

**放在反向代理后面**(nginx、Caddy 等,已经有这个域名的证书):HTTPS 在代理上终结,`/v1/ws` 的 WebSocket 升级要转过来,客户端地址追加到 `X-Forwarded-For`,中继在本机回环上跑明文 HTTP。

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

这时打印的那一行不带 `pin`,设备像访问普通网站一样核对代理的证书:`pocket-relay://relay.example.com:443?claim=…`。中继要挂在自己的域名(或端口)的根路径上,App 加不了 `https://example.com/relay` 这种带路径的中继。

**用自己的证书文件**:把文件挂进容器,设 `RELAY_TLS='{"cert":"/etc/pocket-relay/fullchain.pem","key":"/etc/pocket-relay/privkey.pem"}'`,文件变了会自动重新加载。公共证书机构给 `publicUrl` 里的域名签的证书不钉,续期照常;其他证书,以及按 IP 连接时的任何证书,都钉住。

**有域名但没有证书机构的证书**:设 `RELAY_PUBLIC_URL=https://relay.example.com:8443`,中继给这个域名生成自签证书并钉住。

## 中继看得到什么

中继在你的设备之间转发消息(对方不在线时先排着),保存电脑加密后的会话列表、历史记录和附件,电脑睡着时手机照样能看。它不解密任何东西,也不持有 Pocket 的任何秘密。设备证明身份靠两样:Pocket 协调服务器签发的短期票据(中继用协调服务器的公钥离线核对),加上用设备自己的私钥对一次性挑战的签名。

| 中继看得到 | 中继看不到 |
|---|---|
| 账号编号、设备地址、谁和谁在什么时候通信、大小、会话和消息的数量、客户端 IP | 消息内容、工具输出、审批卡片、标题、项目路径、附件名字或内容、缩略图、搜索词、用量数字 |

协议:[RELAY.md](protocol/RELAY.md)(本服务)、[E2EE.md](protocol/E2EE.md)(密码学),测试向量在 [vectors.json](protocol/vectors.json)。

## 配置

大多数情况不用配置。设置来自环境变量和/或 JSON 文件(可以写注释;[relay.example.json](relay.example.json) 列出了各项和默认值)。每个配置项都有对应的环境变量 `RELAY_<路径的大写蛇形>`:`publicUrl` → `RELAY_PUBLIC_URL`,`listen.port` → `RELAY_LISTEN_PORT`,`coord.pinnedKeys` → `RELAY_COORD_PINNED_KEYS`(JSON),`blobs` → `RELAY_BLOBS`(JSON)。配置文件依次取自 `--config`、`RELAY_CONFIG`、`/etc/pocket-relay/relay.json`。

| 配置项 | 默认 | 含义 |
|---|---|---|
| `publicUrl` | `null` | 设备连接用的 `https://` 地址。`null`:协调服务器看到的 IP,端口用 `listen.port`。 |
| `listen.host`、`listen.port` | `0.0.0.0`、`8443` | 监听的地址和端口。 |
| `tls` | `"auto"` | `"auto"`:自己的自签证书(`trustProxy` 为 true 时改为明文 HTTP)。`"self"`:总用自签证书。`null`:明文 HTTP,TLS 由前面的代理终结。`{"cert", "key"}`:PEM 文件。 |
| `trustProxy` | `false` | 客户端 IP 取 `X-Forwarded-For` 的最后一项。只在你自己的代理后面打开。 |
| `relayId`、`account` | `null` | 两个都不写:在 App 里认领。两个都写:手动绑定(官方中继是 `hk1`、`"*"`)。 |
| `coord.url` | `https://pocket.pocketcli.net` | 查公网地址、取协调公钥、拉撤销名单。 |
| `coord.pinnedKeys` | 官方公钥 | 一开始信任的协调公钥:`[{kid, pub, use, nbf, exp}]`。由它们签过的新公钥会自动采用。 |
| `coord.pollSeconds` | `60` | 有在线连接的账号多久拉一次撤销名单。 |
| `dataDir` | `/var/lib/pocket-relay` | 证书、认领关系、索引数据库、对象、附件。 |
| `blobs` | `{"store": "disk"}` | 附件放硬盘,或 `{"store": "s3", "backends": [...]}`(见下)。 |
| `timezone` | `Asia/Shanghai` | 流量配额按哪个时区算日、月。 |
| `quota.dayMB`、`quota.monthMB`、`quota.storeMB` | 不限 | 每个账号的附件流量和存储上限。 |
| `quota.useTicketQuota` | `true` | 票据里带了上限就用票据里的。 |
| `retention.objectDays` | `30` | 这么久没写也没读的对象删掉。最近一周连过的电脑,会话列表保留。 |
| `retention.blobDays` | `30` | 这么久没下载的附件删掉(从没下载过就从上传时算)。 |
| `retention.queueMaxSeconds` | `604800` | 信封最多等离线设备多久。 |
| `limits` | 见 `src/config.mjs` | 大小和速率(帧 2 MiB、信封 1 MiB、每台设备 2 条连接……)。 |

### S3 兼容的对象存储

```json
"blobs": { "store": "s3", "cnIpFile": "/var/lib/pocket-relay/cn-ip.txt", "backends": [
  { "name": "main", "when": "default", "endpoint": "https://s3.example.com", "region": "us-east-1",
    "bucket": "my-pocket", "accessKeyEnv": "RELAY_S3_KEY", "secretKeyEnv": "RELAY_S3_SECRET",
    "pathStyle": false, "prefix": "pocket/" } ] }
```

支持 AWS S3、Cloudflare R2、MinIO、腾讯云 COS、阿里云 OSS(S3 兼容接口,AWS Signature V4 预签名)。钥匙从你指定的环境变量里读,不写在文件里。新附件放到第一个 `when` 匹配上传者的后端:`cn-ip` 匹配 `cnIpFile` 里 CIDR 列表内的 IP(每行一个 CIDR、CIDR 的 JSON 数组,或 `{v4:[[start,end]…], v6:[…]}`),`default` 匹配所有人。桶连不上时附件先放在中继自己的硬盘上。对象名是 `<prefix><地址>/<附件编号>`,没有文件名、账号编号、内容类型。桶不用公开访问:上传链接一小时内有效,下载链接两分钟内有效。

## 运维

- **再打印一遍那一行**:`docker exec pocket-relay node src/main.mjs connect-string`(不用 Docker 就在同样的环境变量下跑 `node src/main.mjs connect-string`)。数据目录里的 `connect.txt` 也是这一行。认领之后这一行不带认领码。
- **重新认领**(在 App 里删掉了这个中继,或者要给另一个账号用):`docker exec pocket-relay node src/main.mjs reset-claim`,打印带新认领码的一行。正在跑的中继几秒内断开所有连接,等着被认领。被另一个账号认领时,上一个账号存的东西会删掉。
- **公网 IP 变了**:中继生成新证书,`pin` 也跟着变。跑 `reset-claim`,在 App 里重新添加。用固定 IP(云服务器的弹性公网 IP),或者在 `publicUrl` 里用域名,就不会这样。故意要换证书:删掉数据目录里的 `tls/`,重启,再跑 `reset-claim`。
- **升级**:`git pull && docker build -t pocket-relay . && docker rm -f pocket-relay`,再跑同样的 `docker run`。证书、认领关系和数据都在卷里,不受影响。
- **日志**输出到标准输出:时间、中继编号、账号、设备地址、操作、大小、状态、耗时、客户端 IP。不记消息内容、票据、令牌、挑战、认领码、预签名地址、`Authorization` 头。
- **健康检查**:`node src/main.mjs --health`(容器的健康检查)问的是 `/v1/info`;`GET /v1/health` 认领之后回 200(之前回 503 `unclaimed`)。`GET /v1/metrics`(只限本机回环):连接、队列、对象、附件的数量。
- **数据**是密文缓存,丢了电脑会重新上传。只有证书(`tls/`)和认领关系(`binding.json`)补不回来,丢了就要在 App 里重新添加。删除立即生效(没有回收站)。硬盘占用受保留期限制。
- **重启**会忘掉内存里的会话令牌,设备会自己重新登录中继。
- **撤销名单**由协调服务器推来(`POST /v1/revocations`)、设备转交,或者中继自己去拉。被撤销的设备立即断开,被删除的设备的数据立即删掉。协调服务器签名的清除指令(`POST /v1/purge`)删掉一个账号或一台电脑的数据。

## 开发与测试

```sh
node --test                   # 或 npm test:协议向量、WebSocket、对象、附件(带假 S3)、控制、配置、
                              # 自签证书、认领流程、以进程方式运行的中继
node test/fake-s3.mjs --port 18650 --keys-file keys.json     # 测试用的假 S3
```

测试读协议向量:设了 `POCKET_PROTOCOL_DIR` 就用它,否则找 `./protocol`。

## 许可

GNU Affero General Public License v3.0 或更新版本,见 [LICENSE](LICENSE)。如果你把修改过的中继作为网络服务给别人用,用户有权拿到你修改后的源代码。
