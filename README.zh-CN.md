[English](README.md) | 简体中文

# Pocket 中继

[Pocket](https://pocket.pocketcli.net) 的中继。Pocket 是用手机遥控电脑上 AI 编程工具(Claude Code、Codex 等)的 App。中继替你的设备转发、保存端到端加密的数据,自己看不到内容。官方中继跑的就是这份代码,你也可以自己跑一个。

## 一条命令部署(推荐)

要一台有公网 IP 的 Ubuntu 或 Debian 服务器(x86_64 或 arm64,systemd),一个人用 1 核 1G 就够。不需要域名,也不需要买证书。这条命令同时装好中继和[语音服务](https://github.com/pocketcli-app/pocket-asr):

```sh
# 国内版(用国内版 Pocket App 的,一般选这个)
curl -fsSL https://api.pocketcli.cn/dl/selfhost/install.sh | sudo bash

# 国际版
curl -fsSL https://pocket.pocketcli.net/dl/selfhost/install.sh | sudo bash
```

装完会打印两行连接串:

```
 中继:在 Pocket App「我的 → 服务器 → 添加自建服务器」粘贴这一行
   pocket-relay://203.0.113.7:8443?pin=sha256:3f1c…&claim=Qm9x…

 语音服务:在 Pocket App「我的 → 语音识别方式 → 自建语音服务」粘贴这一行
   pocket-asr://203.0.113.7:8444?pin=sha256:068a…&token=eJLA…
```

1. 在云服务器控制台的防火墙 / 安全组里放行 TCP 8443 和 8444(机器上开着 ufw 时脚本已经放行)。
2. 按上面说的位置把两行分别粘贴到 App 里。语音服务那一行带着访问密钥,只显示这一次。

| 选项(写在 `bash -s --` 后面) | 作用 |
|---|---|
| `--relay-only` / `--asr-only` | 只装、升级或卸载其中一个 |
| `--uninstall` | 停止服务,删除程序、数据、设置和系统用户(会先问;加 `--yes` 不问) |
| `--docker <目录>` | 不装服务,只把核对过的程序和 `docker-compose.yml` 放进这个目录(见下面的 Docker) |

例如只装中继:`curl -fsSL https://api.pocketcli.cn/dl/selfhost/install.sh | sudo bash -s -- --relay-only`。

**升级**:重新运行同一条命令。证书、认领状态、访问密钥和语音模型都保留,连接串不变。之前照下面的办法手动装过的(程序在 `/opt/pocket-relay`、服务名 `pocket-relay`、数据在 `/var/lib/pocket-relay`),脚本会接管,数据不丢,原来的程序目录挪到 `/opt/pocket-relay.bak-<时间>`。

**脚本做了什么**:检查系统;没有 Node.js 22.13 以上时,从 npmmirror(国内版)或 nodejs.org(国际版)下载 Node.js 22 放进 `/opt/pocket-selfhost/node`,核对 SHA-256,不影响系统里原有的 Node.js;从同一台服务器的 `/dl/selfhost/` 下载中继和语音服务的程序包(内容与开源仓库相同),按写在脚本里的 SHA-256 核对;建系统用户 `pocket-relay`、`pocket-asr`,程序装到 `/opt/pocket-relay`、`/opt/pocket-asr`,数据放 `/var/lib/pocket-relay`、`/var/lib/pocket-asr`,写 systemd 服务并启动。之后可以用 `sudo pocket-relay connect-string` 再看一遍连接串,`sudo pocket-asr new-token` 生成新的语音服务连接串。自己的设置(比如 `RELAY_PUBLIC_URL`)写在 `/etc/pocket-relay/env`,改完 `systemctl restart pocket-relay`。

### 国内版和国际版

Pocket 分国内版(`api.pocketcli.cn`)和国际版(`pocket.pocketcli.net`)两套服务,账号、钥匙和服务器都不互通。中继也分两版,用哪个版本的 App 就装哪个版本:

- **国内版**(`RELAY_EDITION=cn`):查公网 IP、取协调公钥、拉撤销名单都只连 `https://api.pocketcli.cn`,只认国内版的协调公钥,不连任何境外地址。安装脚本、Node.js 和程序包也都从国内下载。
- **国际版**(`RELAY_EDITION=intl`,默认):连 `https://pocket.pocketcli.net`。

装错了也不要紧:在另一版 App 里添加时,中继会拒绝,并在日志里说明该用哪条安装命令重装;认领码仍然有效。

### 粘贴之前

**粘贴之前别把中继那一行给别人。** 认领码谁先用谁就拿到这个中继。它只能用一次,只出现在中继的输出和数据目录里,同一个地址每分钟最多试 5 次。泄露了就运行 `sudo pocket-relay reset-claim` 换一个(见[运维](#运维))。

App 用 `pin` 核对中继的证书,凭一次性的认领码 `claim` 把中继认领到你的账号下,从此它只服务你一个人。在 App 里切换到这个中继后,电脑把会话上传到它,手机从它读取。

中继问协调服务器自己的公网 IP 是多少(`GET <协调服务器>/v2/whoami`),给这个地址生成一张自签证书(ECDSA P-256,有效 10 年)。`pin` 是这张证书的 SHA-256,设备只认这一张,所以证书机构也冒充不了你的中继。重启、升级之后这一行不变。探测到的地址不对时(服务器出网走的是另一个 IP,或者对外映射了别的端口),在 `/etc/pocket-relay/env` 里写一行 `RELAY_PUBLIC_URL=https://203.0.113.7:8443`,然后 `systemctl restart pocket-relay`。

## 其他部署方式

### Docker

用安装脚本准备文件(程序按 SHA-256 核对过),再用 Docker Compose 一起起中继和语音服务:

```sh
curl -fsSL https://api.pocketcli.cn/dl/selfhost/install.sh | sudo bash -s -- --docker /opt/pocket-docker   # 国际版换成 pocket.pocketcli.net
cd /opt/pocket-docker && docker compose up -d --build
docker compose logs          # 两行连接串在日志里
```

目录里的 `.env` 写着版本(`POCKET_EDITION=cn` 或 `intl`)。国内拉 Docker Hub 的基础镜像(`node:22-alpine`、`node:22-bookworm-slim`)很慢甚至拉不下来,要先给 Docker 配好镜像加速器;国内版的 `.env` 还让语音服务镜像构建时的 apt 走 `mirrors.aliyun.com`。没有加速器就用上面的一条命令部署(不需要 Docker)。

只要中继、能访问 GitHub 时也可以直接构建:

```sh
git clone https://github.com/pocketcli-app/pocket-relay && cd pocket-relay
docker build -t pocket-relay .                                     # 国内版:--build-arg RELAY_EDITION=cn
docker run -d --name pocket-relay --restart unless-stopped -p 8443:8443 -v pocket-relay:/var/lib/pocket-relay pocket-relay
docker logs pocket-relay
```

对外映射了别的端口时(`-p 443:8443`)加 `-e RELAY_PUBLIC_URL=https://203.0.113.7:443`。

### 不用 Docker、不用脚本

Node.js 22.13 以上,不需要 npm 包:

```sh
RELAY_DATA_DIR=$HOME/pocket-relay node src/main.mjs                       # 国际版,端口 8443
RELAY_EDITION=cn RELAY_DATA_DIR=$HOME/pocket-relay node src/main.mjs      # 国内版
RELAY_DATA_DIR=$HOME/pocket-relay RELAY_LISTEN_PORT=9443 node src/main.mjs
```

只有 IPv6 的服务器再加 `RELAY_LISTEN_HOST=::`。

### 有域名时

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
| `edition` | `intl` | `cn`:国内版,`intl`:国际版(见[国内版和国际版](#国内版和国际版))。决定下面两项的默认值。环境变量 `RELAY_EDITION`。 |
| `relayId`、`account` | `null` | 两个都不写:在 App 里认领。两个都写:手动绑定(官方中继是 `hk1`、`"*"`)。 |
| `coord.url` | 按版本:`https://api.pocketcli.cn` / `https://pocket.pocketcli.net` | 查公网地址、取协调公钥、拉撤销名单。和 `edition` 不一致时启动报错。 |
| `coord.pinnedKeys` | 按版本:该版的官方公钥 | 一开始信任的协调公钥:`[{kid, pub, use, nbf, exp}]`。由它们签过的新公钥会自动采用。写成另一版的公钥时启动报错。 |
| `coord.pollSeconds` | `60` | 有在线连接的账号多久拉一次撤销名单。 |
| `dataDir` | `/var/lib/pocket-relay` | 证书、认领关系、索引数据库、对象、附件。 |
| `blobs` | `{"store": "disk"}` | 附件放硬盘,或 `{"store": "s3", "backends": [...]}`(见下)。 |
| `timezone` | `Asia/Shanghai` | 流量配额按哪个时区算日、月。 |
| `quota.dayMB`、`quota.monthMB` | 不限 | 每个账号的附件流量上限。 |
| `quota.storeMB` | `5120` | 每个账号在这里最多存多少:会话和附件一起算。`null` 或 `0`:不限。 |
| `quota.smallMB`、`quota.smallFileMB` | `50`、`2` | 当天或当月的流量用完后,不超过 `smallFileMB` 的文件(缩略图、语音)照样能传,每天最多 `smallMB`。设成 `0` 就不放行。 |
| `quota.useTicketQuota` | `true` | 这个账号最新的票据里带了上限就用它的。 |
| `disk.minFreeMB` | `5120` | 数据目录所在的硬盘至少留这么多空间。剩得比这少,中继就不再往这块盘上存新东西(回 `503 full`),别的照常。`0` 就是不管。 |
| `retention.objectDays` | `30` | 这么久没写也没读的对象删掉。最近一周连过的电脑,会话列表保留。 |
| `retention.blobDays` | `30` | 这么久没下载的附件删掉(从没下载过就从上传时算)。只读几个字节不算下载。 |
| `retention.queueMaxSeconds` | `604800` | 信封最多等离线设备多久。 |
| `limits` | 见 `src/config.mjs` | 大小和速率(帧 2 MiB、登录前 64 KiB,信封 1 MiB、每台设备 2 条连接……)。 |

### S3 兼容的对象存储

```json
"blobs": { "store": "s3", "cnIpFile": "/var/lib/pocket-relay/cn-ip.txt", "backends": [
  { "name": "main", "when": "default", "endpoint": "https://s3.example.com", "region": "us-east-1",
    "bucket": "my-pocket", "accessKeyEnv": "RELAY_S3_KEY", "secretKeyEnv": "RELAY_S3_SECRET",
    "pathStyle": false, "prefix": "pocket/" } ] }
```

支持 AWS S3、Cloudflare R2、MinIO、腾讯云 COS、阿里云 OSS(S3 兼容接口,AWS Signature V4 预签名)。钥匙从你指定的环境变量里读,不写在文件里。新附件放到第一个 `when` 匹配上传者的后端:`cn-ip` 匹配 `cnIpFile` 里 CIDR 列表内的 IP(每行一个 CIDR、CIDR 的 JSON 数组,或 `{v4:[[start,end]…], v6:[…]}`),`default` 匹配所有人。桶连不上时附件先放在中继自己的硬盘上,桶正常时一个也不放。对象名是 `<prefix><地址>/<附件编号>`,没有文件名、账号编号、内容类型。桶不用公开访问:上传链接 15 分钟内有效,下载链接两分钟内有效。附件删掉之后上传链接留下的东西,中继会清掉。每个中继用自己的桶或 `prefix`。

## 运维

- **再打印一遍那一行**:`sudo pocket-relay connect-string`(一条命令部署的);Docker:`docker exec pocket-relay node src/main.mjs connect-string`;自己跑的,在同样的环境变量下跑 `node src/main.mjs connect-string`。数据目录里的 `connect.txt` 也是这一行。认领之后这一行不带认领码。
- **重新认领**(在 App 里删掉了这个中继,或者要给另一个账号用):`sudo pocket-relay reset-claim`(Docker:`docker exec pocket-relay node src/main.mjs reset-claim`),打印带新认领码的一行。正在跑的中继几秒内断开所有连接,等着被认领。被另一个账号认领时,上一个账号存的东西会删掉。
- **公网 IP 变了**:中继生成新证书,`pin` 也跟着变。跑 `reset-claim`,在 App 里重新添加。用固定 IP(云服务器的弹性公网 IP),或者在 `publicUrl` 里用域名,就不会这样。故意要换证书:删掉数据目录里的 `tls/`,重启,再跑 `reset-claim`。
- **升级**:一条命令部署的,重新运行安装命令;Docker,换上新程序后 `docker compose up -d --build`(或 `git pull && docker build …` 再 `docker run`)。证书、认领关系和数据都保留。
- **日志**输出到标准输出(`journalctl -u pocket-relay`、`docker logs pocket-relay`):时间、中继编号、账号、设备地址、操作、大小、状态、耗时、客户端 IP。不记消息内容、票据、令牌、挑战、认领码、预签名地址、`Authorization` 头。
- **健康检查**:`node src/main.mjs --health`(容器的健康检查)问的是 `/v1/info`;`GET /v1/health` 认领之后回 200(之前回 503 `unclaimed`)。`GET /v1/metrics`(只限本机回环):连接、队列、对象、附件的数量。
- **数据**是密文缓存,丢了电脑会重新上传。只有证书(`tls/`)和认领关系(`binding.json`)补不回来,丢了就要在 App 里重新添加。删除立即生效(没有回收站)。硬盘占用受保留期、每个账号的 `quota.storeMB` 和 `disk.minFreeMB` 限制:硬盘剩得太少时日志里出现 `disk-low`,中继先不收新数据,腾出空间后自己恢复。
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
