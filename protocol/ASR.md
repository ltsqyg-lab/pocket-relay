# Pocket speech recognition — modes and gateway API v1

Status: implementation spec, phase 1 (2026-10-08). License of the gateway implementation: **AGPL-3.0**.
Related: [E2EE.md](E2EE.md) (tickets, blobs, envelopes), [COORD.md](COORD.md) §16 (ASR tickets).

> **中文摘要**　「按住说话」有四种识别方式,第一次用时让用户选(官方云端排第一,写明「不是端到端加密」):
> ① 官方云端(录音经我们的网关交给火山引擎);② 我的电脑(录音加密传给自己的电脑,电脑上的本地模型识别,谁也听不到);
> ③ 自建网关(用户自己部署这个开源网关,接自己选的云服务或本地模型);④ 手机本机(系统自带的离线识别)。
> 网关只回文字、不存录音、日志里没有识别出的字。云端引擎:火山、阿里云、腾讯云、讯飞、OpenAI、Deepgram、Azure;
> 本地引擎:sherpa-onnx、whisper.cpp、Vosk。

---

## 1. Modes

| Mode | Where the audio goes | Who can hear it | Needs | Label in the App |
|---|---|---|---|---|
| `official` | phone → official gateway (Hong Kong) → Volcano Engine | the official gateway process (memory only) and Volcano Engine | nothing | zh「官方云端识别(不是端到端加密)」 en "Pocket cloud (not end-to-end encrypted)" |
| `computer` | phone → relay (encrypted blob) → the user's computer → local model | nobody else | a computer online with a local model installed (§8) | 「我的电脑识别(端到端加密)」 "My computer (end-to-end encrypted)" |
| `gateway` | phone → the user's own gateway → the engine they configured | their gateway and, for cloud engines, that provider | a deployed gateway (§11) + a token | 「自建语音网关」 "My own gateway" |
| `device` | stays on the phone | nobody | iOS on-device recognition / Android 13+ on-device recognizer for the language (§9) | 「手机本机识别」 "On this phone" |

- **First use**: the first time the user holds the mic button, the App shows the four modes — `official` first and
  preselected, its "not end-to-end encrypted" note visible without tapping; unavailable modes greyed out with the
  reason ("no computer has a speech model yet", "this phone can't recognise Chinese offline"). The choice is per phone,
  changeable under Settings → Voice. The existing voice-consent text (Volcano Engine) applies to `official` only.
- Recording stays as today: WAV, 16 kHz, mono, signed 16-bit PCM, ≤ 8 MiB.
- After recognition the phone (or, in `computer` mode, the computer) sends the text as a normal `dispatch` (E2EE §9.5).

## 2. Gateway HTTP API

Base URL: official `https://pocket.pocketcli.net/asr`; self-hosted: whatever the owner configured.

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

## 6. Configuration
```json
{
  "gatewayId": "my-asr",
  "listen": { "host": "0.0.0.0", "port": 8080 },
  "tls": null,
  "auth": {
    "tokens": [ { "label": "my phone", "sha256": "<hex>" } ],
    "ticket": { "enabled": false, "coordUrl": "https://pocket.pocketcli.net", "pinnedKeys": [ … ], "accounts": ["*"] }
  },
  "engines": [
    { "id": "volcano", "type": "volcano", "appId": "env:VOLC_APP_ID", "accessToken": "env:VOLC_ACCESS_TOKEN" },
    { "id": "local", "type": "sherpa-onnx", "bin": "/opt/sherpa/bin/sherpa-onnx-offline", "model": "/models/sense-voice", "threads": 2 }
  ],
  "default": { "zh": "local", "en": "local" },
  "limits": { "maxBytes": 8388608, "maxSeconds": 240, "perMinute": 12, "concurrentPerCaller": 2, "concurrent": 8 }
}
```
Values of the form `env:NAME` are read from the environment at startup (secrets never sit in the file).
Limits are per caller (token label or ticket account).

## 7. Privacy rules (all modes, all gateways)
- Audio and text live in memory for one request; local engines use one temp file that is deleted before the response.
- Logs: time, gateway id, caller (token label or account id), engine, audio seconds, number of characters, latency,
  result code. **Never** audio, text, tokens, tickets or proofs.
- No analytics, no third-party calls other than the configured engine.
- The official gateway keeps the same 7-month log retention as the coordination server; it does not keep audio or
  text at all. The privacy policy states that Volcano Engine receives the audio in `official` mode.

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
loopback), engine `volcano` with today's credentials file, ticket auth only, `dataDir` `/var/lib/pocket-asr` (cut-offs
and adopted coordination keys survive restarts), limits as today: 12 recognitions per account per minute, 2 at once per
account, 8 at once in total.

## 11. Self-hosting
`docker run` the gateway image (`slim`: cloud engines only; `local`: adds sherpa-onnx and downloads the configured
model on first start), put the HTTPS URL and a token into the App (Settings → Voice → My own gateway → Test), done.
Self-hosters may also enable ticket auth for their own account instead of a static token.

## 12. Conformance tests
WAV validation (rates, channels, truncated headers, size and duration limits); token auth (hash only); ticket auth with
every `vectors.json` `coord.ticket`/`coord.asrAuth` case plus nonce replay and body mismatch; per-caller rate and
concurrency limits; each cloud adapter against a local mock of its protocol (request shape, auth header or signature,
error mapping, abort); each local engine with a fake program (argument array, timeout kill, temp file deleted on
success, error and abort); logs and error bodies contain no text or audio; `computer` mode end to end through a local
relay with the agent's embedded module.
