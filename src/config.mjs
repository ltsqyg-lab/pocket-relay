// Relay configuration: a JSON file (comments allowed) whose every value may be overridden by an environment
// variable RELAY_<UPPER_SNAKE_PATH> (RELAY.md §2). Secrets (S3 keys) are read from the environment variables the
// configuration names, never from the file.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
import fs from 'node:fs'
import { validKeyRecord } from './proto.mjs'

export const DEFAULT_LIMITS = {
  frame: 2 * 1024 * 1024,              // WebSocket message
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

export const DEFAULTS = {
  relayId: null,
  account: null,
  publicUrl: null,
  listen: { host: '0.0.0.0', port: 8443 },
  tls: null,
  trustProxy: false,
  coord: { url: 'https://pocket.pocketcli.net', pinnedKeys: [], refreshHours: 6, pollSeconds: 60, idlePollHours: 6 },
  dataDir: '/var/lib/pocket-relay',
  blobs: { store: 'disk' },
  timezone: 'Asia/Shanghai',
  quota: { dayMB: null, monthMB: null, storeMB: null, useTicketQuota: true },
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
  if (typeof cfg.relayId !== 'string' || !/^[A-Za-z0-9_:.-]{1,64}$/.test(cfg.relayId)) bad('relayId is required (the id coordination gave this relay, e.g. "hk1" or "r_…")')
  if (typeof cfg.account !== 'string' || !cfg.account || cfg.account.length > 128) bad('account is required ("*" for any account, otherwise the one account this relay serves)')
  let pinned = cfg.coord?.pinnedKeys
  if (typeof pinned === 'string') { try { pinned = JSON.parse(pinned) } catch { bad('coord.pinnedKeys must be a JSON array') } }
  if (!Array.isArray(pinned) || !pinned.length) bad('coord.pinnedKeys must list at least one coordination public key')
  for (const k of pinned) if (!validKeyRecord(k)) bad(`coord.pinnedKeys has an invalid entry (${JSON.stringify(k?.kid ?? k)}); each needs kid, pub, use, nbf, exp`)
  cfg.coord.pinnedKeys = pinned
  if (cfg.coord.url != null) {
    try { const u = new URL(cfg.coord.url); if (!/^https?:$/.test(u.protocol)) throw 0 } catch { bad('coord.url must be an http(s) URL') }
    cfg.coord.url = String(cfg.coord.url).replace(/\/+$/, '')
  }
  if (typeof cfg.dataDir !== 'string' || !cfg.dataDir) bad('dataDir is required')
  const port = Number(cfg.listen?.port)
  if (!Number.isInteger(port) || port < 0 || port > 65535) bad('listen.port must be a port number')
  cfg.listen = { host: cfg.listen?.host || '0.0.0.0', port }
  if (cfg.tls && (typeof cfg.tls !== 'object' || !cfg.tls.cert || !cfg.tls.key)) bad('tls must be null or {"cert": "<file>", "key": "<file>"}')
  if (!cfg.tls) cfg.tls = null
  cfg.trustProxy = cfg.trustProxy === true || cfg.trustProxy === 'true' || cfg.trustProxy === 1
  try { new Intl.DateTimeFormat('en-CA', { timeZone: cfg.timezone }) } catch { bad(`timezone ${JSON.stringify(cfg.timezone)} is not a valid IANA time zone`) }
  if (!cfg.publicUrl) cfg.publicUrl = null
  cfg.limits = merge(structuredClone(DEFAULT_LIMITS), isObj(cfg.limits) ? cfg.limits : {})
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
