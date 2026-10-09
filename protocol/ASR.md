# Pocket speech recognition — modes and gateway API v1

Status: implementation spec, phase 1 (2026-10-08). License of the gateway implementation: **AGPL-3.0**.
Related: [E2EE.md](E2EE.md) (tickets, blobs, envelopes), [COORD.md](COORD.md) §16 (ASR tickets).

> **中文摘要**　「按住说话」有四种识别方式,第一次用时让用户选(官方云端排第一):
> ① 官方云端(录音经我们的网关交给云端识别服务);② 我的电脑(录音加密传给自己的电脑,电脑上的本地模型识别,谁也听不到);
> ③ 自建网关(用户自己部署这个开源网关,接自己选的云服务或本地模型);④ 手机本机(系统自带的离线识别)。
> 网关只回文字、不存录音、日志里没有识别出的字。云端引擎:火山、阿里云、腾讯云、讯飞、OpenAI、Deepgram、Azure;
> 本地引擎:sherpa-onnx、whisper.cpp、Vosk。
> 自建网关不需要域名(§11):只要一台有公网 IP 的服务器,网关自己生成自签证书,启动时打印一行
> `pocket-asr://<IP>:8444?pin=sha256:<证书指纹>&token=<令牌>`;App 钉住这个指纹,不看系统根证书。

---

## 1. Modes

| Mode | Where the audio goes | Who can hear it | Needs | Label in the App |
|---|---|---|---|---|
| `official` | phone → official gateway (Hong Kong) → a cloud speech service | the official gateway process (memory only) and that service | nothing | zh「官方云端识别」 en "Pocket cloud" |
| `computer` | phone → relay (encrypted blob) → the user's computer → local model | nobody else | a computer online with a local model installed (§8) | 「我的电脑识别」 "My computer" |
| `gateway` | phone → the user's own gateway → the engine they configured | their gateway and, for cloud engines, that provider | a deployed gateway (§11) + a token | 「自建语音网关」 "My own gateway" |
| `device` | stays on the phone | nobody | iOS on-device recognition / Android 13+ on-device recognizer for the language (§9) | 「手机本机识别」 "On this phone" |

- **First use**: the first time the user holds the mic button, the App shows the four modes — `official` first and
  preselected, each with one line on where the audio goes; unavailable modes greyed out with the
  reason ("no computer has a speech model yet", "this phone can't recognise Chinese offline"). The choice is per phone,
  changeable under Settings → Voice. The voice-consent text applies to `official` only. The App names neither the
  cloud service behind `official` nor labels modes "(not) end-to-end"; the privacy policy lists the service as a processor.
- Recording stays as today: WAV, 16 kHz, mono, signed 16-bit PCM, ≤ 8 MiB.
- After recognition the phone (or, in `computer` mode, the computer) sends the text as a normal `dispatch` (E2EE §9.5).

## 2. Gateway HTTP API

Base URL: official `https://pocket.pocketcli.net/asr`; self-hosted: `https://<host>:<port><path>` from the connection
line the gateway prints (§11.2).

### `GET /v1/info` (public)
```json
{ "service": "pocket-asr", "version": "1.0.0", "gatewayId": "official",
  "engines": [ { "id": "volcano", "kind": "cloud", "langs": ["zh", "en"], "maxSeconds": 240, "default": true } ],
  "auth": ["ticket"] | ["token"] | ["ticket", "token"],
  "limits": { "maxBytes": 8388608, "maxSeconds": 240 } }
```

### `POST /v1/recognize?lang=zh|en|auto&engine=<id>`
Body: the WAV file (`Content-Type: audio/wav`). `engine` optional (gateway default for the language).
```json
200 { "ok": true, "text": "把 README 翻译成英文", "lang": "zh", "engine": "volcano", "seconds": 3.2, "ms": 910 }
4xx/5xx { "ok": false, "code": "<code>", "message": "<English, for logs>" }
```
Codes and HTTP statuses:

| `code` | Status | Meaning |
|---|---|---|
| `bad-audio` | 400 | not 16 kHz mono s16 WAV |
| `no-engine` | 400 | no engine for this language (or the named engine does not exist) |
| `unauthorized` | 401 | missing or invalid token / ticket / proof |
| `too-large`, `too-long` | 413 | over `maxBytes` / over `maxSeconds` (or the engine's own limit) |
| `empty` | 422 | no speech (the gateway answers this without calling an engine when the loudest sample is below 64) |
| `rate` | 429 + `Retry-After` | this caller is over its limit (more than 2 requests at once, or over its per-minute count; 12 per minute on the official gateway) |
| `engine-error` | 502 | the provider or program failed |
| `busy` | 503 + `Retry-After` | the whole gateway is at its concurrency limit |
| `engine-timeout` | 504 | the provider or program took too long |

The App writes its own sentences for each code. A self-hosted gateway's "test" button can call `GET /v1/info` (does
`auth` include `token`? do `engines[].langs` include the phone's language?) and then send half a second of audio that
is not silent (silence answers `empty`).

Timeouts: the gateway answers within `30 s + audio length`; clients wait that long plus 15 s.

## 3. Authentication
A gateway accepts one or both:
- **Static tokens** (self-hosted): `Authorization: Bearer <token>`. The config stores only SHA-256 hashes of tokens and
  a label for each (for logs). The App stores the token in the platform keystore.
- **Pocket tickets** (official; optional for self-hosted): `Authorization: PocketTicket <ticket>` plus
  `X-Pocket-Proof: <b64u(a)>.<b64u(s)>` where (E2EE §13, label `asr-auth`)
  `a = {"v":1,"t":"asr-auth","aud":"asr:<gatewayId>","ts":<ms>,"nonce":"<b64u 16 B>","bodySha":"<b64u SHA-256 of the body>"}`
  and `s` is signed by the device key named in the ticket. The gateway verifies the ticket offline with coordination keys
  (`aud` = `asr:<gatewayId>`, E2EE §12.2), the proof (`|now − ts| ≤ 5 min`, nonce not seen in the last 10 minutes,
  `bodySha` matches the received body), and may restrict to an account list (`*` for official).
  The proof binds the audio, so a captured request cannot be replayed with other audio. Vectors: `coord.asrAuth`.
  The gateway checks the ticket and everything in the proof except `bodySha` from the headers, before it reads the body
  and before the request counts against the account's rate and concurrency; only `bodySha` waits for the body. A stolen
  ticket without the device key therefore cannot use up its owner's voice limits.
- **Revocations** work as on relays (RELAY.md §3.3): a gateway that accepts tickets takes signed revocation documents
  at `POST /v1/revocations` (coordination pushes them to the official gateway over loopback and pushes again every
  minute until one is accepted, COORD §11; answer `{ok, applied}`; at most 120 documents per minute for the whole
  gateway, then `429`), and a gateway bound to one account also polls coordination every 60 s. A ticket cut off this way
  is refused as `unauthorized` (logged as `revoked`). A gateway with a `dataDir` keeps its cut-offs there, so a restart
  does not lift them; the official gateway has one.

## 4. Audio rules
The gateway parses the RIFF header and accepts only PCM format 1, 1 channel, 16000 Hz, 16 bits, data size consistent
with the body. Size ≤ `maxBytes` (`too-large`), duration ≤ `maxSeconds` (`too-long`). Adapters convert as their engine
needs (raw PCM, base64 frames, WAV passthrough).

## 5. Engines

### 5.1 Adapter interface (JavaScript, zero dependencies)
```js
// asr/src/engines/<id>.mjs
export default {
  type: 'volcano',                       // matches config "type"
  kind: 'cloud',                         // 'cloud' | 'local'
  langs: ['zh', 'en'],
  langsOf(config) { return ['zh'] },     // optional: the languages this configuration really serves (an Alibaba appkey serves one)
  maxSeconds: 60,                        // optional: the provider's own limit (longer audio → too-long)
  validate(config) {},                   // throw on bad config at startup
  async recognize({ pcm, wav, sampleRate, seconds, lang, uid, signal, config, note }) { return { text: '…' } },
  // pcm = Int16 little-endian bytes; wav = the same audio with a standard 44-byte header; uid = an anonymous id for the
  // provider (gateway id + a hash of the caller), never the account; note(id) records the provider's request id in the log
}
```
Adapters MUST honour `signal` (abort on client disconnect or timeout), never log audio or text, and map provider errors to
the codes of §2 (provider codes go to the log only).

### 5.2 Cloud engines (users bring their own keys)
Verify request details against each provider's current documentation when implementing; the gateway hides all of this
behind §2.

| `type` | Service | Interface | Credentials |
|---|---|---|---|
| `volcano` | 火山引擎 豆包大模型语音识别 | WebSocket binary protocol `wss://openspeech.bytedance.com/api/v3/sauc/bigmodel_nostream` (headers `X-Api-App-Key`, `X-Api-Access-Key`, `X-Api-Resource-Id`); today's `server/volc-asr.mjs` is the reference client | app id, access token, resource id |
| `alibaba` | 阿里云 智能语音交互 一句话识别 | HTTPS `…/stream/v1/asr?appkey=…&format=pcm&sample_rate=16000` with `X-NLS-Token`; token from CreateToken (AccessKey signature), cached until expiry; ≤ 60 s | AccessKey ID/secret, appkey, region |
| `tencent` | 腾讯云 语音识别 一句话识别 | API 3.0 `SentenceRecognition` at `asr.tencentcloudapi.com` (TC3-HMAC-SHA256), `EngSerViceType` `16k_zh` / `16k_en`, base64 data; ≤ 60 s | SecretId/SecretKey, region |
| `iflytek` | 讯飞开放平台 语音听写 | WebSocket `wss://iat-api.xfyun.cn/v2/iat` with an HMAC-SHA256 signed URL, base64 PCM frames; ≤ 60 s | APPID, APIKey, APISecret |
| `openai` | OpenAI (or any compatible endpoint) | `POST <baseUrl>/audio/transcriptions` multipart, model `gpt-4o-transcribe` (default) / `gpt-4o-mini-transcribe` / `whisper-1`; `baseUrl` includes `/v1` as in the official SDKs (default `https://api.openai.com/v1`) | API key, optional base URL |
| `deepgram` | Deepgram | `POST https://api.deepgram.com/v1/listen?model=…&language=…` with `Authorization: Token …`, WAV body | API key, model per language |
| `azure` | Azure AI Speech | REST for short audio `https://<region>.stt.speech.microsoft.com/speech/recognition/conversation/cognitiveservices/v1?language=zh-CN`, or a resource endpoint `https://<name>.cognitiveservices.azure.com/stt/…`; header `Ocp-Apim-Subscription-Key`; ≤ 60 s | key, region or endpoint |

Audio longer than an engine's limit is answered `too-long` for that engine (no silent truncation).

### 5.3 Local engines
Run as external programs per request (no native addons in the gateway, so the same code runs in Docker, on a desktop
and inside the Pocket agent):

| `type` | Program | Suggested models (download size, approximate) | Notes |
|---|---|---|---|
| `sherpa-onnx` | `sherpa-onnx-offline` (prebuilt for macOS arm64/x64, Windows x64, Linux) | SenseVoice zh/en/ja/ko/yue int8 (~230 MB); Paraformer-zh small int8 (~80 MB) | best Chinese accuracy per CPU second; recommended default |
| `whisper.cpp` | `whisper-cli -m <model> -f <wav> -l <lang> -nt` | ggml base (~150 MB), small (~490 MB) | multilingual; slower on CPU; no prebuilt macOS program upstream (build it, or use sherpa-onnx on macOS) |
| `vosk` | `vosk-transcriber` (needs ffmpeg) or `asr/scripts/vosk-wav.py` (only `pip install vosk`, same arguments) | vosk-model-small-cn (~40 MB), vosk-model-small-en-us (~40 MB) | smallest, least accurate |

Contract (`asr/src/engines/local.mjs`, also embedded by the desktop agent):
```js
export async function transcribeLocal({ engine /* 'sherpa-onnx' | 'whisper.cpp' | 'vosk' */, bin, model, wav, lang,
                                        threads, timeoutMs, tmpDir, signal, env, silencePeak }) → { text, ms, lang? }
```
`env` adds variables for the program (library paths); `silencePeak` overrides the "no speech" threshold; `lang` is
returned when the engine reports one (SenseVoice reports Cantonese as `zh`). Errors are `LocalAsrError` with `code` ∈
`no-engine`, `bad-audio`, `empty`, `engine-timeout`, `engine-error`, `aborted`. This one file is licensed MIT (the rest of
the gateway is AGPL-3.0), because the closed-source desktop agent embeds it verbatim.
It writes the WAV to a private temporary file (directory 0700, random name), runs the program with an argument array
(no shell), reads stdout, deletes the file in `finally`, kills the process on timeout or abort, and returns plain text
(trimmed, engine markers removed). Models are files the operator installs; the module only checks they exist.
SenseVoice is told `zh` only for `zh`, otherwise `auto` (never `en`: Chinese speech then comes out as nonsense).
**Windows** (revision 3, 2026-10-09): the program is started through `cmd.exe /d /v:off /s /c` with every argument
quoted — a bun-compiled parent (the desktop agent) that starts it directly waits ~3.4 s before it runs and it then
decodes ~2.5× slower (5.1–5.5 s instead of 1.3 s for a 7.6 s clip). An argument cmd.exe would still interpret (`"`, `%`),
a trailing backslash, a control character or a UNC working directory means a direct start instead. If the cmd.exe
start fails, or ends non-zero without a result, the program is started once more directly (same arguments, directory
and time limit; never after a timeout or an abort); a timeout kills the whole tree (`taskkill /T /F`). When a path has
non-ASCII characters (sherpa-onnx 1.13.8 cannot open those, 8.3 short names included — e.g. `C:\Users\张三`), the program
runs in the deepest directory holding all its files and gets ASCII relative paths.

## 6. Configuration
Optional: every key has a default, and with no file at all the gateway runs as in §11.1.
```json
{
  "gatewayId": "my-asr",
  "listen": { "host": null, "port": 8444 },
  "tls": "auto",
  "publicUrl": null,
  "dataDir": "/var/lib/pocket-asr",
  "auth": {
    "tokens": [ { "label": "my phone", "sha256": "<hex>" } ],
    "ticket": { "enabled": false, "coordUrl": "https://pocket.pocketcli.net", "pinnedKeys": [ … ], "accounts": ["*"] }
  },
  "engines": [
    { "id": "volcano", "type": "volcano", "appId": "env:VOLC_APP_ID", "accessToken": "env:VOLC_ACCESS_TOKEN" },
    { "id": "local", "type": "sherpa-onnx", "bin": "/opt/sherpa/bin/sherpa-onnx-offline", "model": "/var/lib/pocket-asr/models/sense-voice-int8", "threads": 2 }
  ],
  "default": { "zh": "local", "en": "local" },
  "limits": { "maxBytes": 8388608, "maxSeconds": 240, "perMinute": 12, "concurrentPerCaller": 2, "concurrent": 8 }
}
```
Values of the form `env:NAME` are read from the environment at startup (secrets never sit in the file).
Limits are per caller (token label or ticket account).
Defaults: `gatewayId` `my-asr` (required when ticket auth is on: tickets are addressed to `asr:<gatewayId>`);
`listen` every address (`host: null`), port 8444; `tls` `"auto"` (§11.1); `publicUrl` `null` (§11.1); `coordUrl`
`https://pocket.pocketcli.net`; `dataDir` `/var/lib/pocket-asr` when started from the command line; no `engines` = the
local engine of §11.1. Environment variables override the file: `ASR_DATA_DIR`, `ASR_PORT`, `ASR_PUBLIC_URL`, `ASR_TLS`
(`auto` | `self` | `off`), `ASR_COORD_URL`; the file itself comes from `--config`, `ASR_CONFIG` or
`/etc/pocket-asr/asr.json`.

## 7. Privacy rules (all modes, all gateways)
- Audio and text live in memory for one request; local engines use one temp file that is deleted before the response.
- Logs: time, gateway id, caller (token label or account id), engine, audio seconds, number of characters, latency,
  result code. **Never** audio, text, tokens, tickets or proofs.
- No analytics, no third-party calls other than the configured engine (and, on a self-hosted gateway, the downloads
  its owner asks for and — without `publicUrl` — one `GET /v2/whoami` to coordination per start, §11.1).
- The official gateway keeps the same 7-month log retention as the coordination server; it does not keep audio or
  text at all. The privacy policy names the speech service that receives the audio in `official` mode (as a processor).

## 8. `computer` mode
1. The App offers this mode only when a computer's `info` object (E2EE §10.1) reports
   `asr: { "local": { "ready": true, "engine": "sherpa-onnx", "langs": ["zh","en"], "model": "sense-voice-int8" } }`
   and the computer is online. If several qualify, the user picks one (default: the target computer of the session).
2. The phone uploads the WAV as a blob into that computer's realm (E2EE §11.6) and sends `cmd` `voice`
   `{ audio: BlobRef, speechLang, dispatchId, sessionId | null, target?, model?, effort?, mode?, cwd?, team?, lang }`
   (E2EE §9.5). The audio never touches the official gateway.
3. The computer verifies the envelope, downloads and decrypts the blob, checks `bytes`/`sha`, runs
   `transcribeLocal`, deletes the audio, then dispatches the text exactly like a `dispatch` command for that session
   (or a new session), and replies `res { ok, text, stage: "asr" | "dispatch" | "done", delivered, queued?, note?, sessionId?, error? }`.
   The recognised text is part of the session like any typed message.
4. The phone shows the text in the outgoing bubble when the reply arrives; timeout = 120 s + the audio length.
5. Model management on the computer: the tray (and the App's computer page) offers "Install speech model". The agent
   downloads a pinned model (URL list + SHA-256 + size in the agent; files mirrored on `https://pocket.pocketcli.net/dl/`
   because GitHub is unreachable from mainland China), verifies the hash, unpacks under `~/.pocket/asr/`, and reports
   `ready` in `info`. The engine binary comes the same way (macOS arm64/x64, Windows x64). Removing the model deletes
   the directory.

## 9. `device` mode (App only, no gateway)
- **iOS**: `SFSpeechRecognizer(locale: zh-CN | en-US)` with `supportsOnDeviceRecognition == true`, an
  `SFSpeechURLRecognitionRequest` on the recorded WAV and `requiresOnDeviceRecognition = true`, so audio never leaves
  the device. Needs `NSSpeechRecognitionUsageDescription` and the speech-recognition permission, requested only after the
  user picked this mode. If on-device support for the language is missing the mode is not offered.
- **Android**: offered on API 33+ when `SpeechRecognizer.isOnDeviceRecognitionAvailable()` is true:
  `createOnDeviceSpeechRecognizer()` with the recorded audio passed through `EXTRA_AUDIO_SOURCE`. Not offered below
  API 33 (the ordinary recognizer may send audio to a server).
- Implemented in `AppDelegate.swift` / `MainActivity.kt` behind the existing `pocket/native` channel (no pub plugins).

## 10. Official deployment
`gatewayId` `official` (ticket `aud` `asr:official`), base URL `https://pocket.pocketcli.net/asr` (served behind the
coordination server's TLS listener; the proxy does not forward `/asr/v1/revocations`, which only coordination uses over
loopback), one cloud engine with today's credentials file, ticket auth only, `dataDir` `/var/lib/pocket-asr` (cut-offs
and adopted coordination keys survive restarts), limits as today: 12 recognitions per account per minute, 2 at once per
account, 8 at once in total.

## 11. Self-hosting
Most people who self-host have one server with a public IP address and no domain. Like Tailscale's DERP servers, the
gateway therefore brings its own certificate and the App pins it: no domain, no certificate authority, nothing to renew.

### 11.1 Without a domain (the default)
```
docker run -d --name pocket-asr --restart unless-stopped -p 8444:8444 -v pocket-asr:/var/lib/pocket-asr pocket-asr
docker logs pocket-asr        # → the connection line
```
(or `node src/main.mjs` with Node 22). With no configuration the gateway, on first start:

1. **Engine**: local recognition, sherpa-onnx + SenseVoice small int8 (`zh`, `en`, `auto`): the program from the image
   (or installed into `<dataDir>/sherpa-onnx`), the model downloaded into `<dataDir>/models/sense-voice-int8`; every file
   checked against the size and SHA-256 pinned in `models.json`. Engine calls at once: 1 below 1.8 GB of memory, else 2.
2. **Public address**: `publicUrl` (`ASR_PUBLIC_URL`) when set; else the coordination server's `GET /v2/whoami` →
   `{"ip": "<address the request came from>"}` (direct connection, IPv4 first, 5 s; an IPv4-mapped IPv6 answer is
   unwrapped, anything that is not an IP address ignored); else a public IPv4 address of a network interface; else
   unknown — the line then carries the placeholder `<this-server-public-IP>` and says how to set the address. A gateway
   listening only on loopback (behind a proxy on the same machine) uses `publicUrl` only.
3. **Certificate** (`tls` `"auto"`): ECDSA P-256, self-signed, SAN = the public address (none while unknown), valid
   10 years; key and certificate in `<dataDir>/self-key.pem` and `self-cert.pem` (0600). Kept across restarts, so the
   pin never changes by itself. Replaced only when missing, broken, within 30 days of its end, or made for another public
   address (the line changes then anyway); a certificate made while the address was unknown is kept once it becomes
   known, because phones may already pin it. The same code makes the relay's certificate (RELAY.md §12.1).
4. **Token**: when no way to authenticate is configured (no `auth.tokens`, no stored token, no ticket auth), one token is
   made: 32 random bytes, base64url (43 characters). Only its SHA-256 and a label (`token-1`) are stored, in
   `<dataDir>/tokens.json` (0600; same shape as `auth.tokens`). The token itself appears once, in the printed line.
5. **Listen** on every address, port 8444, HTTPS with that certificate.
6. **Print** the connection line (§11.2) to stdout, with the App path and the firewall port in English and Chinese, and
   write it without the token to `<dataDir>/connect.txt`. Later starts print the line without a token.

`tls` modes: `"auto"` (default) = own certificate, except plain HTTP when listening on loopback only; `"self"` = own
certificate; `"off"` / `null` = plain HTTP behind the owner's HTTPS reverse proxy; `{"cert", "key"}` = PEM files
(read at start; the pin of the leaf certificate is printed too). A ticket-only gateway behind a proxy (the official
one, §10) prints no line and never asks for its address.

Commands (in Docker: `docker exec pocket-asr …`): `node src/main.mjs new-token [label]` makes another token and prints a
complete line; `connect-string` prints the line without a token (tokens cannot be shown again: only hashes are kept);
`tokens` lists labels; `revoke-token <label>` removes a stored token. A running gateway re-reads `tokens.json` when it
changes (at most once a second), so new and revoked tokens take effect without a restart. The commands never replace
the certificate (only make it when it does not exist yet).

### 11.2 The connection line
```
pocket-asr://<host>:<port>[/<path>]?pin=sha256:<hex>&token=<token>
```
- `host`: an IPv4 address, `[IPv6]` in brackets, or a DNS name. `port`: always written, even 443. `path`: only when
  `publicUrl` has one (a reverse proxy serving the gateway under a prefix).
- `pin`: `sha256:` + 64 lowercase hex digits = SHA-256 of the leaf certificate's DER encoding. Present for the gateway's
  own certificate, for any self-signed certificate and for any certificate on an IP address; absent for a DNS name with
  a certificate from a public authority (so renewals keep working) and when a reverse proxy terminates TLS.
- `token`: the static token for `Authorization: Bearer`. Absent from `connect-string` and `connect.txt`.
- Base URL for §2: `https://<host>:<port><path>`. Unknown query parameters are ignored (room for later additions).
- In the App: Settings → Voice transcription → My own gateway → paste the line (zh「我的 → 语音识别方式 → 自建语音网关」).
  The App keeps the token in the platform keystore.

### 11.3 Pin check in the App
With `pin`, the App accepts the TLS connection when, and only when, the SHA-256 of the server's leaf certificate (DER)
equals the pin. It does not consult the system's trusted roots and does not check the host name (an IP address has no
certificate from an authority). The check happens on the handshake, before anything — token or audio — is sent; a
different certificate is refused as "the gateway's certificate changed: paste its new line". Without `pin`, the App
validates the certificate the usual way (system roots and host name). The App's "test" button then calls
`GET /v1/info` and sends half a second of audio (§2).

### 11.4 With a domain, other engines
- A reverse proxy with its own certificate (e.g. Caddy) in front: the gateway on loopback or with `tls` `"off"`, and
  `publicUrl` = the proxy's `https://` address; the line has no pin.
- Certificate files: `tls: {cert, key}` and `publicUrl`; restart after renewals.
- Cloud engines or other models need a config file (§6); the `slim` image has no local program.
- One server can run the relay (port 8443) and the speech gateway (port 8444) side by side.
- Self-hosters may also enable ticket auth for their own account instead of a static token.

## 12. Conformance tests
WAV validation (rates, channels, truncated headers, size and duration limits); token auth (hash only); ticket auth with
every `vectors.json` `coord.ticket`/`coord.asrAuth` case plus nonce replay and body mismatch; per-caller rate and
concurrency limits; each cloud adapter against a local mock of its protocol (request shape, auth header or signature,
error mapping, abort); each local engine with a fake program (argument array, timeout kill, temp file deleted on
success, error and abort); logs and error bodies contain no text or audio; `computer` mode end to end through a local
relay with the agent's embedded module; self-hosting (§11): the certificate kept across starts and never replaced by
the commands, tokens stored as hashes and picked up / dropped while running, whoami answers and fallbacks, the line's
format and pin rules, and `node src/main.mjs` end to end with a client that pins the certificate.
