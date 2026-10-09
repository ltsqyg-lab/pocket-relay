// Test helpers: protocol reference (gen-vectors.mjs) as a device simulator, a fresh coordination key per run,
// a relay on an ephemeral port with a temporary data directory, a minimal WebSocket client.
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import http from 'node:http'
import net from 'node:net'
import tls from 'node:tls'
import crypto from 'node:crypto'
import { fileURLToPath, pathToFileURL } from 'node:url'
import { finalize } from '../src/config.mjs'
import { createRelay } from '../src/relay.mjs'
import { pinOf } from '../src/selfcert.mjs'

const HERE = path.dirname(fileURLToPath(import.meta.url))
/** Protocol documents: POCKET_PROTOCOL_DIR, else the monorepo layout (../docs/protocol), else ./protocol in a split repo. */
export const PROTOCOL_DIR = [process.env.POCKET_PROTOCOL_DIR, path.join(HERE, '..', '..', 'docs', 'protocol'), path.join(HERE, '..', 'protocol')]
  .find((d) => d && fs.existsSync(path.join(d, 'vectors.json')))
if (!PROTOCOL_DIR) throw new Error('protocol vectors not found; set POCKET_PROTOCOL_DIR')
export const vectors = JSON.parse(fs.readFileSync(path.join(PROTOCOL_DIR, 'vectors.json'), 'utf8'))
export const ref = await import(pathToFileURL(path.join(PROTOCOL_DIR, 'gen-vectors.mjs')).href)

export const b64u = (b) => Buffer.from(b).toString('base64url')
export const sleep = (ms) => new Promise((r) => setTimeout(r, ms))

/** A P-256 key pair as {priv (32 B), pub (65 B)}. */
export function p256() {
  const { privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' })
  const j = privateKey.export({ format: 'jwk' })
  const priv = Buffer.from(j.d, 'base64url')
  return { priv, pub: ref.pubOf(priv) }
}

/** Coordination for tests: a fresh signing key, tickets, revocation documents, purge orders, keys.json. */
export class Coord {
  constructor({ kid = 'lab-c1', iss = 'lab' } = {}) {
    this.kid = kid
    this.iss = iss
    this.key = p256()
    this.revSeq = 0
    this.items = new Map()  // acct -> [{addr, dev, nbf, gone, at}]
  }
  get pinned() { return [{ kid: this.kid, pub: b64u(this.key.pub), use: ['keys', 'ticket', 'netmap', 'revocations', 'purge'], nbf: 0, exp: Date.now() + 365 * 86400000 }] }
  ticket(dev, { aud = 'hk1', peers = [], iat = Date.now(), exp = iat + 6 * 3600000, quota, kid = this.kid, key = this.key.priv, acct = dev.acct } = {}) {
    const p = { v: 1, t: 'ticket', kid, iss: this.iss, aud, acct, dev: dev.id, addr: dev.addr, kind: dev.kind, sig: b64u(dev.sigPub), peers, iat, exp }
    if (quota) p.quota = quota
    return ref.ticketOf(ref.makeSigned('ticket', key, p))
  }
  revocations(acct, items, { at = Date.now() } = {}) {
    const list = this.items.get(acct) ?? []
    list.push(...items.map((x) => ({ at, ...x })))
    this.items.set(acct, list)
    return ref.makeSigned('revocations', this.key.priv, { v: 1, t: 'revocations', kid: this.kid, at, acct, since: 0, next: list.length, items })
  }
  feed(acct, since = 0) {
    const list = this.items.get(acct) ?? []
    return ref.makeSigned('revocations', this.key.priv, { v: 1, t: 'revocations', kid: this.kid, at: Date.now(), acct, since, next: list.length, items: list.slice(since) })
  }
  purge(acct, { relay = 'hk1', at = Date.now(), addrs } = {}) {
    const p = { v: 1, t: 'purge', kid: this.kid, acct, at, relay }
    if (addrs) p.addrs = addrs
    return ref.makeSigned('purge', this.key.priv, p)
  }
  keysDoc(keys, signers = [this]) {
    const p = Buffer.from(JSON.stringify({ v: 1, t: 'keys', at: Date.now(), keys }))
    return { p: b64u(p), sigs: signers.map((c) => ({ kid: c.kid, s: b64u(ref.ecdsaSign(c.key.priv, ref.sigInput('keys', p))) })) }
  }
}

let ADDR = 10
/** A device with its own keys; addresses are unique per test process. */
export function device(kind = 'phone', acct = 'u_lab1', addr) {
  const s = p256(), k = p256()
  ADDR++
  const a = addr ?? `100.64.${Math.floor(ADDR / 250)}.${(ADDR % 250) + 1}`
  return { kind, acct, addr: a, sigPriv: s.priv, sigPub: s.pub, kxPriv: k.priv, kxPub: k.pub, id: ref.didOf(s.pub, k.pub) }
}

export function proof(dev, ticket, nonce, { relay = 'hk1', ts = Date.now() } = {}) {
  return ref.makeProof('relay-auth', dev.sigPriv, { relay, nonce, th: b64u(ref.sha256(Buffer.from(ticket, 'utf8'))), ts })
}

/**
 * Start a relay on 127.0.0.1:0 with a temp data dir (or `dir`). Plain HTTP unless `tls` is given (the default
 * configuration would make a self-signed certificate). Returns {relay, base, pin, logs, printed, dir, cfg, stop}; with
 * TLS, `base` is https:// and requests must go through pinnedRequest / wsConnect with `pin`. The free-space minimum
 * (disk.minFreeMB) is off unless a test sets it, so the suite does not depend on the machine's disk; `statfs` fakes
 * the disk for the tests that do.
 */
export async function startRelay(coord, overIn = {}, { fetchImpl, env, dir: dirIn, keep = false, bindingPollMs, whoamiRetryMs, statfs } = {}) {
  const { now: nowFn, ...over } = overIn
  const dir = dirIn ?? fs.mkdtempSync(path.join(os.tmpdir(), 'pocket-relay-test-'))
  const logs = [], printed = []
  const cfg = finalize({
    relayId: 'hk1', account: '*', dataDir: dir, listen: { host: '127.0.0.1', port: 0 },
    coord: { url: null, pinnedKeys: coord.pinned },
    tls: null,
    ...over,
    disk: { minFreeMB: 0, ...(over.disk ?? {}) },
    limits: { presenceDebounceMs: 150, ...(over.limits ?? {}) },
  })
  const log = { info: (op, f) => logs.push(JSON.stringify({ op, ...f })), warn: (op, f) => logs.push(JSON.stringify({ op, ...f })), error: (op, f) => logs.push(JSON.stringify({ op, ...f })) }
  const relay = await createRelay(cfg, { log, fetchImpl, env, now: nowFn, print: (text) => printed.push(text), bindingPollMs, whoamiRetryMs, statfs })
  const a = await relay.listen(0, '127.0.0.1')
  const base = `${cfg.tlsMode === 'off' ? 'http' : 'https'}://127.0.0.1:${a.port}`
  return {
    relay, base, port: a.port, logs, printed, dir, cfg, now: nowFn ?? Date.now,
    get pin() { return relay.state.pin },
    async stop() { await relay.close(); if (!keep) fs.rmSync(dir, { recursive: true, force: true }) },
  }
}

/**
 * A TLS socket to `url` that is used only after the server's certificate matched `pin` (SHA-256 of its DER): no CA,
 * no host name check — how devices and coordination talk to a relay with a self-signed certificate (RELAY.md §12.1).
 */
export function pinnedSocket(url, pin) {
  return new Promise((resolve, reject) => {
    const u = new URL(url)
    const host = u.hostname.replace(/^\[|\]$/g, '')
    const sock = tls.connect({ host, port: Number(u.port || 443), servername: net.isIP(host) ? undefined : host, rejectUnauthorized: false })
    sock.once('error', reject)
    sock.once('secureConnect', () => {
      const got = pinOf(sock.getPeerCertificate().raw)
      if (got !== pin) { sock.destroy(); return reject(Object.assign(new Error('certificate does not match the pin'), { code: 'PIN_MISMATCH', got })) }
      sock.off('error', reject)
      resolve(sock)
    })
  })
}

/** One HTTPS request over a pinned socket: {status, headers, text, json()}. */
export async function pinnedRequest(url, { pin, method = 'GET', headers = {}, body = null, timeout = 20_000 } = {}) {
  const sock = await pinnedSocket(url, pin)
  const u = new URL(url)
  return new Promise((resolve, reject) => {
    const req = http.request({ createConnection: () => sock, method, path: u.pathname + u.search, timeout,
      headers: { host: u.host, connection: 'close', ...(body !== null ? { 'content-type': 'application/json', 'content-length': Buffer.byteLength(body) } : {}), ...headers } }, (res) => {
      const chunks = []
      res.on('data', (c) => chunks.push(c))
      res.on('end', () => { sock.destroy(); const text = Buffer.concat(chunks).toString('utf8'); resolve({ status: res.statusCode, headers: res.headers, text, json: () => JSON.parse(text) }) })
      res.on('error', reject)
    })
    req.on('timeout', () => req.destroy(new Error('timeout')))
    req.on('error', reject)
    req.end(body ?? undefined)
  })
}

// ---- minimal WebSocket client ---------------------------------------------------------------------------------------
export async function wsConnect(base, pathname = '/v1/ws', { pin = null } = {}) {
  const u = new URL(base)
  const sock = u.protocol === 'https:' ? await pinnedSocket(base, pin) : null
  return new Promise((resolve, reject) => {
    const key = crypto.randomBytes(16).toString('base64')
    const headers = { Connection: 'Upgrade', Upgrade: 'websocket', 'Sec-WebSocket-Key': key, 'Sec-WebSocket-Version': '13' }
    const req = http.request(sock ? { createConnection: () => sock, path: pathname, headers: { host: u.host, ...headers } } : { host: u.hostname, port: u.port, path: pathname, headers })
    req.on('upgrade', (res, socket, head) => resolve(new WsClient(socket, head)))
    req.on('response', (res) => { const e = new Error(`HTTP ${res.statusCode}`); e.status = res.statusCode; reject(e) })
    req.on('error', reject)
    req.end()
  })
}

export class WsClient {
  constructor(socket, head) {
    this.socket = socket
    this.frames = []
    this.waiters = []
    this.closeCode = null
    const closed = new Promise((r) => { this._closed = r })
    // a close that never comes fails the test after 10 s instead of hanging it
    Object.defineProperty(this, 'closed', { get: () => Promise.race([closed, sleep(10_000).then(() => { throw new Error('socket not closed within 10 s') })]) })
    let buf = Buffer.alloc(0)
    const onData = (d) => {
      buf = Buffer.concat([buf, d])
      for (;;) {
        if (buf.length < 2) break
        const op = buf[0] & 0x0f
        let len = buf[1] & 0x7f, off = 2
        if (len === 126) { if (buf.length < 4) break; len = buf.readUInt16BE(2); off = 4 }
        else if (len === 127) { if (buf.length < 10) break; len = Number(buf.readBigUInt64BE(2)); off = 10 }
        if (buf.length < off + len) break
        const payload = buf.subarray(off, off + len)
        buf = buf.subarray(off + len)
        if (op === 0x1) this.push(JSON.parse(payload.toString('utf8')))
        else if (op === 0x8) { this.closeCode = payload.length >= 2 ? payload.readUInt16BE(0) : 1005; this.closeReason = payload.subarray(2).toString('utf8'); this._closed(this.closeCode) }
        else if (op === 0x9) this.raw(0xa, payload)
      }
    }
    socket.on('data', onData)
    if (head?.length) queueMicrotask(() => onData(head))
    socket.on('close', () => { if (this.closeCode === null) this.closeCode = 1006; this._closed(this.closeCode) })
    socket.on('error', () => {})
  }
  push(f) {
    const i = this.waiters.findIndex((w) => w.pred(f))
    if (i >= 0) { const [w] = this.waiters.splice(i, 1); clearTimeout(w.t); w.resolve(f) } else this.frames.push(f)
  }
  /** Wait for the next frame matching `t` (string type or predicate). */
  next(t, ms = 3000) {
    const pred = typeof t === 'function' ? t : (f) => f.t === t
    const i = this.frames.findIndex(pred)
    if (i >= 0) return Promise.resolve(this.frames.splice(i, 1)[0])
    return new Promise((resolve, reject) => {
      const w = { pred, resolve, t: setTimeout(() => { this.waiters.splice(this.waiters.indexOf(w), 1); reject(new Error(`timeout waiting for ${typeof t === 'string' ? t : 'frame'}; have ${JSON.stringify(this.frames.map((f) => f.t))}`)) }, ms) }
      this.waiters.push(w)
    })
  }
  /** Frames of a type that arrive within `ms`. */
  async collect(t, ms = 300) { await sleep(ms); const out = this.frames.filter((f) => f.t === t); this.frames = this.frames.filter((f) => f.t !== t); return out }
  raw(op, payload, { mask = true, fin = true } = {}) {
    const len = payload.length
    let hdr
    if (len < 126) hdr = Buffer.from([(fin ? 0x80 : 0) | op, (mask ? 0x80 : 0) | len])
    else if (len < 65536) { hdr = Buffer.alloc(4); hdr[0] = (fin ? 0x80 : 0) | op; hdr[1] = (mask ? 0x80 : 0) | 126; hdr.writeUInt16BE(len, 2) }
    else { hdr = Buffer.alloc(10); hdr[0] = (fin ? 0x80 : 0) | op; hdr[1] = (mask ? 0x80 : 0) | 127; hdr.writeBigUInt64BE(BigInt(len), 2) }
    if (!mask) return this.socket.write(Buffer.concat([hdr, payload]))
    const m = crypto.randomBytes(4)
    const out = Buffer.alloc(len)
    for (let i = 0; i < len; i++) out[i] = payload[i] ^ m[i & 3]
    this.socket.write(Buffer.concat([hdr, m, out]))
  }
  send(obj) { this.raw(0x1, Buffer.from(typeof obj === 'string' ? obj : JSON.stringify(obj))) }
  close(code = 1000) { const b = Buffer.alloc(2); b.writeUInt16BE(code); this.raw(0x8, b); setTimeout(() => this.socket.destroy(), 100) }
}

/** Connect and authenticate a device; returns {ws, ready, token}. */
export async function connect(t, coord, dev, ticketOpts = {}, proofOpts = {}) {
  const ws = await wsConnect(t.base, '/v1/ws', { pin: t.pin })
  const ch = await ws.next('challenge')
  const ticket = coord.ticket(dev, { aud: t.cfg.relayId, ...ticketOpts })
  ws.send({ t: 'auth', ticket, ...proof(dev, ticket, ch.nonce, { relay: t.cfg.relayId, ts: t.now(), ...proofOpts }) })
  const f = await ws.next((x) => x.t === 'ready' || x.t === 'error')
  if (f.t === 'error') { const e = new Error(`auth failed: ${f.code}`); e.code = f.code; e.ws = ws; throw e }
  return { ws, ready: f, token: f.token, ticket }
}

/** HTTP token through /v1/auth/challenge + /v1/auth. */
export async function httpToken(t, coord, dev, ticketOpts = {}) {
  const ch = await (await tfetch(`${t.base}/v1/auth/challenge`, { method: 'POST' })).json()
  const ticket = coord.ticket(dev, { aud: t.cfg.relayId, ...ticketOpts })
  const r = await tfetch(`${t.base}/v1/auth`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ ticket, ...proof(dev, ticket, ch.nonce, { relay: t.cfg.relayId, ts: t.now() }) }) })
  const j = await r.json()
  if (!r.ok) { const e = new Error(`http auth failed: ${j.error}`); e.code = j.error; throw e }
  return j.token
}

/** An envelope sealed by `from` (the relay only reads the header; the key is any 32 bytes). */
export function envelope(from, { to, realm, kind = 'cmd', payload = { op: 'dispatch', text: 'hello' }, seq = Date.now() * 1024, key = crypto.randomBytes(32), re } = {}) {
  const header = { v: 1, t: 'env', id: b64u(crypto.randomBytes(16)), nonce: b64u(crypto.randomBytes(12)), from: from.id, to, realm, epoch: 1, seq, ts: Date.now(), kind }
  if (kind === 'res') header.re = re ?? b64u(crypto.randomBytes(16))
  return ref.sealToJson(ref.makeEnvelope({ sender: from, header, payload, key }))
}

/** A binary object seal written by computer `c`. */
export function objectSeal(c, { kind = 'sess', key = 'k1', seq, ver = Date.now(), plaintext = { title: 'x' }, realmKey = crypto.randomBytes(32), over = {} } = {}) {
  const header = { v: 1, t: 'obj', id: b64u(crypto.randomBytes(16)), nonce: b64u(crypto.randomBytes(12)), realm: c.id, kind, key, ...(seq !== undefined ? { seq } : {}), ver, epoch: 1, by: c.id, ts: Date.now(), ...over }
  return ref.sealToBin(ref.makeObject({ owner: c, header, plaintext, key: realmKey }))
}

/** fetch with a deadline, so a request the relay never answers fails the test with a message instead of hanging it. */
export const tfetch = (url, opts = {}) => fetch(url, { signal: AbortSignal.timeout(20_000), ...opts })

export function api(t, token) {
  const h = (extra = {}) => ({ authorization: `Bearer ${token}`, ...extra })
  return {
    get: (p, extra) => tfetch(t.base + p, { headers: h(extra), redirect: 'manual' }),
    head: (p) => tfetch(t.base + p, { method: 'HEAD', headers: h() }),
    del: (p) => tfetch(t.base + p, { method: 'DELETE', headers: h() }),
    put: (p, body, extra) => tfetch(t.base + p, { method: 'PUT', headers: h(extra), body }),
    post: (p, j) => tfetch(t.base + p, { method: 'POST', headers: h({ 'content-type': 'application/json' }), body: JSON.stringify(j) }),
  }
}
