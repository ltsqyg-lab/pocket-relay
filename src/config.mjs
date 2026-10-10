// Relay configuration: a JSON file (comments allowed) whose every value may be overridden by an environment
// variable RELAY_<UPPER_SNAKE_PATH> (RELAY.md §2). Secrets (S3 keys) are read from the environment variables the
// configuration names, never from the file.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
import fs from 'node:fs'
import { validKeyRecord } from './proto.mjs'

export const DEFAULT_LIMITS = {
  frame: 2 * 1024 * 1024,              // WebSocket message, once the socket is authenticated
  authFrame: 64 * 1024,                // WebSocket message before that (an auth frame is ~15 KB)
  unauthSockets: 1000,                 // sockets not authenticated yet, all clients together (then 503)
  envelope: 1024 * 1024,               // envelope ciphertext (plus the 16-byte tag)
  header: 4096,                        // seal header
  frameBurst: 50,                      // frames per connection: burst
  frameRate: 20,                       // frames per connection: sustained per second
  socketsPerDevice: 2,
  queueEnvelopes: 1000,                // per recipient
  queueBytes: 32 * 1024 * 1024,        // per recipient
  objects: { info: 262144, usage: 16384, sess: 65536, msg: 4194304, lite: 1048576 },
  objectWritesPerSecond: 30,           // per owner
  blob: 100 * 1024 * 1024,             // plaintext bytes
  blobUploadsPerDevice: 4,
  jsonBody: 64 * 1024,
  bodySeconds: 30,
  connectionsPerIp: 100,
  authSeconds: 10,
  pingSeconds: 30,
  idleSeconds: 90,
  challengesPerIp: 120,                // HTTP challenges per IP per minute
  nonces: 200000,                      // outstanding HTTP challenges, all clients together (then 429)
  listInline: 4 * 1024 * 1024,         // total inline seal bytes in one list response
  presenceDebounceMs: 5000,
}

/** The official coordination public key of the international edition (also pinned in the App and the desktop agent;
 *  not a secret). Newer keys are adopted when keys.json is signed by one already trusted (E2EE.md §12.1), so this list
 *  only grows with releases. */
export const OFFICIAL_COORD_KEYS = [
  { kid: 'c1', pub: 'BLv9ISMLeI3tx3arobNAhCeYOFlF7DWmPGHh5zky1v0V2vLMLdeQIoFnJAmRkj_oU9i6Ml0Qoe2-v-xdEeRhqJ0',
    use: ['keys', 'ticket', 'netmap', 'revocations', 'purge'], nbf: 1791478203268, exp: 1886086503268 },
]
/** The coordination public key of the mainland China edition (api.pocketcli.cn). */
export const CN_COORD_KEYS = [
  { kid: 'c1', pub: 'BKhhniVXB9NNhTXSRxobx4SWsho4vLGYCAcU32s9zP9mr-5Fj6_rScKjKmf7Kout2Un2nG1edVuFLngEsgtKUtI',
    use: ['keys', 'ticket', 'netmap', 'revocations', 'purge'], nbf: 1791598605724, exp: 1886206905724 },
]

/**
 * The two Pocket services (RELAY.md §2.1). They share no accounts, keys or servers: a relay serves the accounts of one
 * of them, and the App of one edition can add only relays of that edition. `edition` picks the coordination server and
 * its pinned key; the mainland China edition talks to nothing outside mainland China. `coordIps` are where that
 * edition's coordination server sends its claims from: a claim arriving from the other edition's is refused
 * (`wrong-edition`), so a relay installed with the wrong command says so instead of being bound to an account whose
 * devices it can never let in.
 */
export const EDITIONS = {
  intl: { coordUrl: 'https://pocket.pocketcli.net', keys: OFFICIAL_COORD_KEYS, coordIps: ['43.129.75.199'],
    install: 'curl -fsSL https://pocket.pocketcli.net/dl/selfhost/install.sh | sudo bash', zh: '国际版', en: 'international edition' },
  cn: { coordUrl: 'https://api.pocketcli.cn', keys: CN_COORD_KEYS, coordIps: ['110.42.231.153'],
    install: 'curl -fsSL https://api.pocketcli.cn/dl/selfhost/install.sh | sudo bash', zh: '国内版', en: 'mainland China edition' },
}
export const EDITION_NAMES = Object.keys(EDITIONS)
/** The edition whose official coordination server is at this URL (same origin), or null. */
export function editionOfUrl(url) {
  let o
  try { o = new URL(String(url)).origin } catch { return null }
  return EDITION_NAMES.find((e) => new URL(EDITIONS[e].coordUrl).origin === o) ?? null
}

export const DEFAULTS = {
  // "intl" (pocket.pocketcli.net) or "cn" (api.pocketcli.cn, mainland China): which coordination server and key
  // coord.url and coord.pinnedKeys default to (RELAY.md §2.1). null = "intl", or "cn" when coord.url is the cn server.
  edition: null,
  relayId: null,                        // both null: the relay is claimed from the Pocket App (RELAY.md §12.1)
  account: null,
  publicUrl: null,                      // null: ask coordination for this server's IP and use https://<ip>:<listen.port>
  listen: { host: '0.0.0.0', port: 8443 },
  tls: 'auto',                          // "auto": own self-signed certificate, or plain HTTP when trustProxy is true
  trustProxy: false,
  // url and pinnedKeys left out (undefined): the edition's coordination server and key (EDITIONS); url null = none (labs)
  coord: { url: undefined, pinnedKeys: undefined, refreshHours: 6, pollSeconds: 60, idlePollHours: 6 },
  dataDir: '/var/lib/pocket-relay',
  blobs: { store: 'disk' },
  timezone: 'Asia/Shanghai',
  // storeMB: what one account may keep here, session data and attachments together (null / 0 = unlimited).
  // smallMB: once the day or month is used up, blobs of at most smallFileMB of plaintext (thumbnails, voice clips)
  // still go through, up to this many MB a day (0 = no allowance). Tickets may carry their own caps (RELAY.md §8.3).
  quota: { dayMB: null, monthMB: null, storeMB: 5120, smallMB: 50, smallFileMB: 2, useTicketQuota: true },
  // below this much free space on the data directory's disk nothing new is stored there (503 full, RELAY.md §8.4)
  disk: { minFreeMB: 5120 },
  retention: { objectDays: 30, blobDays: 30, queueMaxSeconds: 604800, tombstoneDays: 30, sweepMinutes: 60 },
  limits: {},
  log: { format: 'text' },
}

/** Remove // and /* *\/ comments outside JSON strings so the documented example can be pasted as is. */
export function stripJsonComments(text) {
  let out = '', i = 0, inStr = false
  while (i < text.length) {
    const ch = text[i], nx = text[i + 1]
    if (inStr) {
      out += ch
      if (ch === '\\') { out += nx ?? ''; i += 2; continue }
      if (ch === '"') inStr = false
      i++
      continue
    }
    if (ch === '"') { inStr = true; out += ch; i++; continue }
    if (ch === '/' && nx === '/') { while (i < text.length && text[i] !== '\n') i++; continue }
    if (ch === '/' && nx === '*') { i += 2; while (i < text.length && !(text[i] === '*' && text[i + 1] === '/')) i++; i += 2; continue }
    out += ch
    i++
  }
  // trailing commas before } or ] (common when pasting), again only outside strings
  let res = ''
  inStr = false
  for (let j = 0; j < out.length; j++) {
    const ch = out[j]
    if (inStr) {
      res += ch
      if (ch === '\\') { res += out[j + 1] ?? ''; j++ } else if (ch === '"') inStr = false
      continue
    }
    if (ch === '"') inStr = true
    if (ch === ',') {
      let k = j + 1
      while (k < out.length && /\s/.test(out[k])) k++
      if (out[k] === '}' || out[k] === ']') continue
    }
    res += ch
  }
  return res
}

const isObj = (v) => v && typeof v === 'object' && !Array.isArray(v)
function merge(base, over) {
  if (!isObj(over)) return over === undefined ? base : over
  const out = isObj(base) ? { ...base } : {}
  for (const [k, v] of Object.entries(over)) out[k] = isObj(v) && isObj(base?.[k]) ? merge(base[k], v) : v
  return out
}
const snake = (s) => s.replace(/([a-z0-9])([A-Z])/g, '$1_$2').toUpperCase()

/** Every leaf path of the defaults (objects listed here are whole values set from JSON in the environment). */
const WHOLE = new Set(['tls', 'blobs', 'limits', 'coord.pinnedKeys'])
function paths(obj, prefix = []) {
  const out = []
  for (const [k, v] of Object.entries(obj)) {
    const p = [...prefix, k]
    if (isObj(v) && !WHOLE.has(p.join('.'))) out.push(...paths(v, p))
    else out.push(p)
  }
  return out
}
function parseEnvValue(s) {
  const t = s.trim()
  if (t === '') return null
  try { return JSON.parse(t) } catch { return s }
}
function setPath(obj, p, v) {
  let o = obj
  for (const k of p.slice(0, -1)) { if (!isObj(o[k])) o[k] = {}; o = o[k] }
  o[p.at(-1)] = v
}

export class ConfigError extends Error {}

/** Load configuration: defaults ← file ← environment. */
export function loadConfig({ file = null, env = process.env } = {}) {
  let cfg = structuredClone(DEFAULTS)
  if (file) {
    let text
    try { text = fs.readFileSync(file, 'utf8') } catch (e) { throw new ConfigError(`cannot read config file ${file}: ${e.code || e.message}`) }
    let j
    try { j = JSON.parse(stripJsonComments(text)) } catch (e) { throw new ConfigError(`config file ${file} is not valid JSON: ${e.message}`) }
    if (!isObj(j)) throw new ConfigError('config file must contain a JSON object')
    cfg = merge(cfg, j)
  }
  for (const p of paths(DEFAULTS)) {
    const name = 'RELAY_' + p.map(snake).join('_')
    if (env[name] !== undefined) setPath(cfg, p, parseEnvValue(env[name]))
  }
  return finalize(cfg)
}

/** Validate and normalise a configuration object (also used by tests that build one in memory). */
export function finalize(input) {
  const cfg = merge(structuredClone(DEFAULTS), input)
  const bad = (m) => { throw new ConfigError(m) }
  // relayId and account: both given = bound by this configuration (the official relay, or a relay set up the old way);
  // both left out = bound later by a claim from the Pocket App (binding.json in the data directory)
  const given = (v) => v !== null && v !== undefined && v !== ''
  if (given(cfg.relayId) !== given(cfg.account)) {
    bad('relayId and account go together: give both, or leave both out to claim the relay from the Pocket App (RELAY.md §12.1)')
  }
  if (given(cfg.relayId)) {
    if (typeof cfg.relayId !== 'string' || !/^[A-Za-z0-9_:.-]{1,64}$/.test(cfg.relayId)) bad('relayId must be the id coordination gave this relay, e.g. "hk1" or "r_…"')
    if (typeof cfg.account !== 'string' || cfg.account.length > 128) bad('account must be "*" for any account, otherwise the one account this relay serves')
  } else { cfg.relayId = null; cfg.account = null }
  // the edition (RELAY.md §2.1): given, or the one whose coordination server coord.url names, else international
  let edition = cfg.edition
  if (edition === null || edition === undefined || edition === '') edition = editionOfUrl(cfg.coord?.url) ?? 'intl'
  if (typeof edition !== 'string' || !EDITIONS[edition]) bad(`edition must be ${EDITION_NAMES.map((e) => `"${e}"`).join(' or ')} (RELAY_EDITION)`)
  const urlEdition = cfg.coord?.url ? editionOfUrl(cfg.coord.url) : null
  if (urlEdition && urlEdition !== edition) {
    bad(`edition "${edition}" and coord.url ${cfg.coord.url} (the coordination server of the "${urlEdition}" edition) disagree: remove coord.url, or set edition "${urlEdition}"`)
  }
  cfg.edition = edition
  if (cfg.coord.url === undefined) cfg.coord.url = EDITIONS[edition].coordUrl
  let pinned = cfg.coord?.pinnedKeys
  if (pinned === undefined) pinned = structuredClone(EDITIONS[edition].keys)
  if (typeof pinned === 'string') { try { pinned = JSON.parse(pinned) } catch { bad('coord.pinnedKeys must be a JSON array') } }
  if (!Array.isArray(pinned) || !pinned.length) bad('coord.pinnedKeys must list at least one coordination public key')
  for (const k of pinned) if (!validKeyRecord(k)) bad(`coord.pinnedKeys has an invalid entry (${JSON.stringify(k?.kid ?? k)}); each needs kid, pub, use, nbf, exp`)
  for (const other of EDITION_NAMES.filter((e) => e !== edition)) {
    if (pinned.some((k) => EDITIONS[other].keys.some((o) => o.pub === k.pub))) {
      bad(`coord.pinnedKeys holds the key of the "${other}" edition, but this relay is the "${edition}" edition: remove coord.pinnedKeys, or set edition "${other}"`)
    }
  }
  cfg.coord.pinnedKeys = pinned
  if (cfg.coord.url != null) {
    try { const u = new URL(cfg.coord.url); if (!/^https?:$/.test(u.protocol)) throw 0 } catch { bad('coord.url must be an http(s) URL') }
    cfg.coord.url = String(cfg.coord.url).replace(/\/+$/, '')
  }
  if (typeof cfg.dataDir !== 'string' || !cfg.dataDir) bad('dataDir is required')
  const port = Number(cfg.listen?.port)
  if (!Number.isInteger(port) || port < 0 || port > 65535) bad('listen.port must be a port number')
  cfg.listen = { host: cfg.listen?.host || '0.0.0.0', port }
  cfg.trustProxy = cfg.trustProxy === true || cfg.trustProxy === 'true' || cfg.trustProxy === 1
  // tls: "auto" (default) = the relay's own self-signed certificate, unless trustProxy says a proxy terminates TLS;
  // "self" = always the self-signed certificate; null / false / "off" = plain HTTP (TLS at a proxy in front);
  // {"cert", "key"} = these PEM files
  const t = cfg.tls
  if (t === undefined || t === 'auto') cfg.tlsMode = cfg.trustProxy ? 'off' : 'self'
  else if (t === 'self') cfg.tlsMode = 'self'
  else if (t === null || t === false || t === 'off') cfg.tlsMode = 'off'
  else if (isObj(t) && typeof t.cert === 'string' && t.cert && typeof t.key === 'string' && t.key) cfg.tlsMode = 'files'
  else bad('tls must be "auto", "self", null (plain HTTP behind a TLS proxy) or {"cert": "<file>", "key": "<file>"}')
  // kept in a form that finalize() reads back the same way (tests and tools may finalize a finalized object again)
  cfg.tls = cfg.tlsMode === 'files' ? { cert: t.cert, key: t.key } : cfg.tlsMode === 'self' ? 'self' : null
  try { new Intl.DateTimeFormat('en-CA', { timeZone: cfg.timezone }) } catch { bad(`timezone ${JSON.stringify(cfg.timezone)} is not a valid IANA time zone`) }
  if (!cfg.publicUrl) cfg.publicUrl = null
  else {
    let u = null
    try { u = new URL(String(cfg.publicUrl)) } catch { /* reported below */ }
    if (!u || u.protocol !== 'https:' || u.username || u.password || u.search || u.hash) bad('publicUrl must be the https:// address devices use, e.g. https://203.0.113.7:8443 or https://relay.example.com')
    cfg.publicUrl = u.href.replace(/\/+$/, '')
  }
  cfg.limits = merge(structuredClone(DEFAULT_LIMITS), isObj(cfg.limits) ? cfg.limits : {})
  const minFree = isObj(cfg.disk) ? cfg.disk.minFreeMB : undefined
  if (minFree !== null && minFree !== undefined && !(typeof minFree === 'number' && Number.isFinite(minFree) && minFree >= 0)) {
    bad('disk.minFreeMB must be a number of megabytes (0 = no minimum)')
  }
  cfg.disk = { minFreeMB: minFree ?? 0 }
  const blobs = isObj(cfg.blobs) ? cfg.blobs : { store: 'disk' }
  if (blobs.store === 's3') {
    if (!Array.isArray(blobs.backends) || !blobs.backends.length) bad('blobs.backends must list at least one S3 backend')
    const names = new Set()
    for (const b of blobs.backends) {
      if (!isObj(b) || typeof b.name !== 'string' || !b.name || names.has(b.name)) bad('every S3 backend needs a unique "name"')
      names.add(b.name)
      if (!['cn-ip', 'default'].includes(b.when ?? 'default')) bad(`backend ${b.name}: "when" must be "cn-ip" or "default"`)
      try { new URL(b.endpoint) } catch { bad(`backend ${b.name}: endpoint must be a URL`) }
      if (!b.region || !b.bucket) bad(`backend ${b.name}: region and bucket are required`)
      if (!b.accessKeyEnv || !b.secretKeyEnv) bad(`backend ${b.name}: accessKeyEnv and secretKeyEnv name the environment variables holding the keys`)
    }
  } else if (blobs.store !== 'disk') bad('blobs.store must be "disk" or "s3"')
  cfg.blobs = blobs
  return cfg
}
