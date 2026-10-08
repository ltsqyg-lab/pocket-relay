// Pocket relay: HTTP + WebSocket server tying together authentication, envelopes, objects, blobs, revocations,
// purge orders, quotas and retention (RELAY.md).
//
// SPDX-License-Identifier: AGPL-3.0-or-later
import http from 'node:http'
import https from 'node:https'
import fs from 'node:fs'
import crypto from 'node:crypto'
import { Store } from './db.mjs'
import { createLogger } from './log.mjs'
import { CoordKeys, ticketKid } from './coordkeys.mjs'
import { Cutoffs } from './cutoffs.mjs'
import { Quota } from './quota.mjs'
import { CnIp } from './cnip.mjs'
import { Objects, OBJ_KINDS } from './objects.mjs'
import { Blobs } from './blobs.mjs'
import { Hub } from './hub.mjs'
import { RelayError, fail, statusOf, verifyRelayAuth, verifyCoordDoc, b64u, sha256hex, isInt, checkAddr, SKEW_MS, unb64u, blobSizeFor } from './proto.mjs'

export const VERSION = '0.1.0'
const DAY = 86_400_000
const NONCE_TTL = 60_000
// An address whose device stayed silent this long may go to a new device even when this relay never saw the `gone`
// cut-off (it was offline when coordination published it): coordination holds a released address for 180 days
// (COORD.md §13), so a live device is never this silent and still holding its address. Kept equal to that hold.
const REASSIGN_SILENCE = 180 * DAY

export async function createRelay(cfg, { now = Date.now, log = null, fetchImpl = globalThis.fetch, env = process.env } = {}) {
  const logger = log ?? createLogger({ relayId: cfg.relayId, format: cfg.log?.format })
  const store = new Store(cfg.dataDir)
  const keys = new CoordKeys({ pinned: cfg.coord.pinnedKeys, url: cfg.coord.url, store, now, log: logger, fetchImpl, refreshHours: cfg.coord.refreshHours })
  const cutoffs = new Cutoffs({ store, now })
  const quota = new Quota({ store, timezone: cfg.timezone, quota: cfg.quota, now })
  const cnip = new CnIp({ file: cfg.blobs.cnIpFile ?? null, unknownMatches: cfg.blobs.cnIpUnknown !== 'nomatch' })

  // ---- tokens (RELAY.md §3.2): 32 random bytes, only their SHA-256 kept, in memory, until the ticket's exp ----------
  const tokens = new Map()
  const byDevice = new Map()          // dev -> token hashes, newest last (at most 16 live tokens per device)
  const issueToken = (ident) => {
    const raw = crypto.randomBytes(32)
    const tok = 'rt_' + b64u(raw)
    const k = sha256hex(tok)
    tokens.set(k, ident)
    const list = (byDevice.get(ident.dev) ?? []).filter((x) => tokens.has(x))
    list.push(k)
    while (list.length > 16) tokens.delete(list.shift())
    byDevice.set(ident.dev, list)
    return tok
  }
  const identOfToken = (req) => {
    const h = String(req.headers.authorization || '')
    const m = /^Bearer (rt_[A-Za-z0-9_-]{43})$/.exec(h)
    if (!m) fail('token')
    const k = sha256hex(m[1])
    const ident = tokens.get(k)
    if (!ident) fail('token')
    if (now() > ident.exp + SKEW_MS) { tokens.delete(k); fail('token') }
    return ident
  }

  // ---- access control (RELAY.md §4) -------------------------------------------------------------------------------
  const acctOfAddr = (addr) => store.get('identGet', addr)?.acct ?? store.get('realmGet', addr)?.acct ?? null
  const access = {
    canRead(ident, realm) {
      if (ident.addr !== realm && !ident.peers.has(realm)) return false
      const a = acctOfAddr(realm)
      return !a || a === ident.acct
    },
    read(ident, realm) { if (!checkAddr(realm) || !access.canRead(ident, realm)) fail('denied') },
    owner(ident, realm) {
      if (!checkAddr(realm) || ident.kind !== 'computer' || ident.addr !== realm) fail('denied')
      const r = store.get('realmGet', realm)
      if (r && r.acct !== ident.acct) fail('wrong-account')
    },
    claimRealm(ident, realm) {
      store.run('realmAdd', realm, ident.acct)
      if (store.get('realmGet', realm).acct !== ident.acct) fail('wrong-account')
    },
    writeBlob(ident, realm) {
      if (!checkAddr(realm) || (ident.addr !== realm && !ident.peers.has(realm))) fail('denied')
      const a = acctOfAddr(realm)
      if (a && a !== ident.acct) fail('wrong-account')
    },
    realmAcct(ident, realm) { return acctOfAddr(realm) ?? ident.acct },
    deleteBlob(ident, realm, row) {
      const owner = ident.kind === 'computer' && ident.addr === realm
      if (!(owner || ident.addr === row.uploader) || row.acct !== ident.acct) fail('denied')
    },
    sameAccount(ident, addr) { const a = acctOfAddr(addr); return !a || a === ident.acct },
  }

  let hub
  const objects = new Objects({ store, limits: cfg.limits, retention: cfg.retention, now, access, notify: (realm, o) => hub?.notify(realm, o) })
  const blobs = new Blobs({ cfg, store, quota, now, log: logger, env, fetchImpl, cnip, access })

  /** Delete everything stored under an address (as a realm) and every envelope queued for it. */
  async function purgeAddr(addr) {
    const o = objects.purgeRealm(addr)
    const b = await blobs.purgeRealm(addr)
    const q = store.run('qDelFor', addr).changes
    return { objects: o, blobs: b, queued: q }
  }

  // ---- authentication shared by WS and HTTP -------------------------------------------------------------------------
  const auth = {
    async verify(msg, nonce) {
      if (!msg || typeof msg.ticket !== 'string' || typeof msg.a !== 'string' || typeof msg.s !== 'string') fail('bad-proof')
      const attempt = () => verifyRelayAuth(msg, { keys: keys.list, relayId: cfg.relayId, acct: cfg.account, nonce, now: now() })
      let T
      try { T = attempt() } catch (e) {
        if (!(e instanceof RelayError) || e.code !== 'unknown-key') throw e
        const kid = ticketKid(msg.ticket)
        if (!kid || !(await keys.ensure(kid))) throw e
        T = attempt()
      }
      if (cutoffs.check(T)) fail('revoked')
      const known = store.get('identGet', T.addr)
      if (known && known.dev !== T.dev) {
        // Coordination gives an address to a new device only 180 days after the previous one was revoked or deleted
        // (COORD.md §13). Anything else is refused: a second live device must not take over an address and its data.
        const free = cutoffs.isGone(T.addr, known.dev) || now() - known.last_seen > REASSIGN_SILENCE
        if (!free) fail(known.acct !== T.acct ? 'wrong-account' : 'denied')
        cutoffs.reassigned(T.addr, T.dev)
        const stale = (id) => id.addr === T.addr && id.dev !== T.dev
        hub.kick(stale, 4403, 'revoked')
        for (const [k, id] of tokens) if (stale(id)) tokens.delete(k)
        const d = await purgeAddr(T.addr)
        store.run('realmDel', T.addr)
        logger.info('addr-reassigned', { addr: T.addr, acct: T.acct, objects: d.objects, blobs: d.blobs })
      } else if (known && known.acct !== T.acct) fail('wrong-account')
      store.run('identPut', T.addr, T.acct, T.dev, T.kind, now())
      return { acct: T.acct, dev: T.dev, addr: T.addr, kind: T.kind, sig: T.sig, peers: new Set(T.peers), quota: T.quota ?? null, iat: T.iat, exp: T.exp }
    },
    token: issueToken,
  }

  hub = new Hub({ cfg, store, now, log: logger, auth, access, cutoffs })

  // HTTP challenges: nonce → expiry, single use
  const nonces = new Map()
  const challengeHits = new Map()

  /** Apply a verified revocation document: close sockets, drop tokens, delete data of gone addresses. */
  async function applyRevocations(doc) {
    let r
    try { r = cutoffs.apply(doc, { keys: keys.list, account: cfg.account }) } catch (e) {
      if (!(e instanceof RelayError) || e.code !== 'unknown-key') throw e
      const kid = (() => { try { return JSON.parse(unb64u(doc.p).toString('utf8')).kid } catch { return null } })()
      if (!kid || !(await keys.ensure(kid))) throw e
      r = cutoffs.apply(doc, { keys: keys.list, account: cfg.account })
    }
    for (const c of r.changes) {
      const hit = (id) => id.addr === c.addr && (!c.dev || c.dev === id.dev) && id.iat < c.nbf
      hub.kick(hit, 4403, 'revoked')
      for (const [k, id] of tokens) if (hit(id)) tokens.delete(k)
      if (c.newlyGone) {
        const d = await purgeAddr(c.addr)
        logger.info('addr-gone', { acct: r.acct, addr: c.addr, objects: d.objects, blobs: d.blobs, queued: d.queued })
      }
    }
    if (r.applied) logger.info('revocations', { acct: r.acct, applied: r.applied })
    return r
  }

  /** Purge order (RELAY.md §6.5, E2EE.md §12.5). */
  async function applyPurge(doc) {
    let D
    try { D = verifyCoordDoc('purge', doc, keys.list, now()) } catch (e) {
      if (!(e instanceof RelayError) || e.code !== 'unknown-key') throw e
      const kid = (() => { try { return JSON.parse(unb64u(doc.p).toString('utf8')).kid } catch { return null } })()
      if (!kid || !(await keys.ensure(kid))) throw e
      D = verifyCoordDoc('purge', doc, keys.list, now())
    }
    if (typeof D.acct !== 'string' || !D.acct || !isInt(D.at, 1) || typeof D.relay !== 'string') fail('bad-format')
    if (D.relay !== cfg.relayId && D.relay !== '*') fail('denied', 'order for another relay')
    if (cfg.account !== '*' && D.acct !== cfg.account) fail('wrong-account')
    const t = now()
    if (D.at < t - 7 * DAY || D.at > t + SKEW_MS) fail('stale', 'order older than 7 days')
    if (D.addrs !== undefined && (!Array.isArray(D.addrs) || !D.addrs.every(checkAddr))) fail('bad-format')
    const id = sha256hex(Buffer.from(String(doc.p), 'utf8'))
    if (store.get('purgeSeen', id)) return { deleted: { objects: 0, blobs: 0, queued: 0 }, already: true }
    const deleted = { objects: 0, blobs: 0, queued: 0 }
    const add = (d) => { deleted.objects += d.objects; deleted.blobs += d.blobs; deleted.queued += d.queued }
    if (D.addrs) {
      for (const a of D.addrs) { const owner = acctOfAddr(a); if (!owner || owner === D.acct) add(await purgeAddr(a)) }
    } else {
      const realms = new Set([...store.all('realmsOfAcct', D.acct).map((r) => r.realm), ...store.all('identsOfAcct', D.acct).map((r) => r.addr)])
      for (const a of realms) add(await purgeAddr(a))
      deleted.blobs += await blobs.purgeAcct(D.acct)
      deleted.queued += store.run('qDelAcct', D.acct).changes
      store.run('trafDelAcct', D.acct)
      for (const a of realms) { store.run('realmDel', a) }
    }
    store.run('purgeAdd', id, t)
    logger.info('purge', { acct: D.acct, relayTarget: D.relay, objects: deleted.objects, blobs: deleted.blobs, queued: deleted.queued })
    return { deleted }
  }

  // ---- revocation polling (RELAY.md §3.3) --------------------------------------------------------------------------
  const lastPoll = new Map()
  let pollTimer = null
  async function pollAccount(acct) {
    if (!cfg.coord.url || !fetchImpl) return
    lastPoll.set(acct, now())
    const cursor = store.get('curGet', acct)?.cursor ?? 0
    try {
      const r = await fetchImpl(`${cfg.coord.url}/v2/relay/revocations?acct=${encodeURIComponent(acct)}&since=${cursor}`, { signal: AbortSignal.timeout(10_000), redirect: 'error' })
      if (!r.ok) throw new Error(`HTTP ${r.status}`)
      const text = await r.text()
      if (text.length > 4 * 1024 * 1024) throw new Error('document too large')
      const res = await applyRevocations(JSON.parse(text))
      if (res.acct !== acct) throw new Error('document for another account')
      if (res.next !== null && res.next !== cursor) store.run('curSet', acct, res.next, now())
    } catch (e) {
      logger.warn('revocation-poll-failed', { acct, error: String(e?.code || e?.message || e).slice(0, 120) })
    }
  }
  function schedulePoll() {
    const base = Math.max(5, Number(cfg.coord.pollSeconds) || 60) * 1000
    pollTimer = setTimeout(async () => {
      try {
        const t = now()
        const idleGap = Math.max(1, Number(cfg.coord.idlePollHours) || 6) * 3_600_000
        const live = new Set(cfg.account === '*' ? hub.liveAccounts() : [cfg.account])
        const idle = cfg.account === '*' ? store.all('acctsWithData').map((r) => r.acct).filter((a) => !live.has(a) && t - (lastPoll.get(a) ?? 0) > idleGap) : []
        for (const a of [...live, ...idle.slice(0, 50)]) await pollAccount(a)
      } finally { schedulePoll() }
    }, base * (0.8 + Math.random() * 0.4))
    pollTimer.unref?.()
  }

  // ---- housekeeping ------------------------------------------------------------------------------------------------
  let sweepTimer = null, tokenTimer = null, probeTimer = null, certTimer = null
  async function sweep() {
    try {
      const o = objects.sweep()
      const b = await blobs.sweep()
      cutoffs.sweep()
      quota.sweep()
      store.run('purgeOld', now() - 8 * DAY)
      store.run('identsOld', now() - 180 * DAY)
      if (o || b) logger.info('retention', { objects: o, blobs: b })
    } catch (e) { logger.error('sweep-failed', { error: String(e?.message || e).slice(0, 160) }) }
  }

  // ---- HTTP --------------------------------------------------------------------------------------------------------
  const ipOf = (req) => {
    if (cfg.trustProxy) {
      const xf = String(req.headers['x-forwarded-for'] || '').split(',').map((s) => s.trim()).filter(Boolean)
      if (xf.length) return xf[xf.length - 1]
    }
    return req.socket.remoteAddress || ''
  }
  const COMMON = { 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer' }
  function sendJson(res, status, obj, headers = {}) {
    const body = Buffer.from(JSON.stringify(obj))
    res.writeHead(status, { 'Content-Type': 'application/json', 'Content-Length': String(body.length), 'Cache-Control': 'no-store', ...COMMON, ...headers })
    res.end(body)
  }
  function sendError(res, e) {
    const code = e instanceof RelayError ? e.code : 'storage'
    const status = statusOf(code)
    const body = { error: code, ...(e?.extra ?? {}) }
    const headers = {}
    if (code === 'quota' && e.extra?.retryAfter) headers['Retry-After'] = String(e.extra.retryAfter)
    if (status === 401 && code === 'token') headers['WWW-Authenticate'] = 'Bearer'
    if (!res.headersSent) sendJson(res, status, body, headers)
    else res.destroy()
    return status
  }
  function readBody(req, max, { seconds = cfg.limits.bodySeconds } = {}) {
    return new Promise((resolve, reject) => {
      const len = req.headers['content-length']
      if (len !== undefined && Number(len) > max) return reject(new RelayError('too-large'))
      const parts = []
      let got = 0
      const t = setTimeout(() => { reject(new RelayError('bad-request', 'body timeout')); req.destroy() }, seconds * 1000)
      req.on('data', (c) => { got += c.length; if (got > max) { clearTimeout(t); reject(new RelayError('too-large')); req.destroy() } else parts.push(c) })
      req.on('end', () => { clearTimeout(t); resolve(Buffer.concat(parts, got)) })
      req.on('error', (e) => { clearTimeout(t); reject(new RelayError('bad-request', String(e?.message || e))) })
    })
  }
  async function readJson(req, max = cfg.limits.jsonBody) {
    const b = await readBody(req, max)
    try { const j = JSON.parse(b.toString('utf8')); if (!j || typeof j !== 'object' || Array.isArray(j)) throw 0; return j } catch { fail('bad-request', 'JSON body') }
  }
  const info = () => ({
    service: 'pocket-relay', version: VERSION, relayId: cfg.relayId, account: cfg.account, time: now(),
    features: ['ws', 'objects', 'blobs', ...(blobs.presign ? ['presign'] : [])],
    limits: { envelope: cfg.limits.envelope, object: { ...cfg.limits.objects }, blob: cfg.limits.blob },
  })
  // metrics only for direct loopback requests: behind a proxy every request arrives from loopback, but carries X-Forwarded-For
  const isLoopback = (req) => {
    const a = req.socket.remoteAddress || ''
    return (a === '127.0.0.1' || a === '::1' || a === '::ffff:127.0.0.1') && !(cfg.trustProxy && req.headers['x-forwarded-for'])
  }

  /** At most `limit` requests of one kind per client IP per minute. */
  function limitIp(ctx, kind, limit) {
    const t = now(), key = `${kind} ${ctx.ip}`
    const hits = (challengeHits.get(key) ?? []).filter((x) => t - x < 60_000)
    if (hits.length >= limit) fail('rate')
    hits.push(t); challengeHits.set(key, hits)
  }

  async function route(req, res, ctx) {
    const url = new URL(req.url, 'http://relay')
    const p = url.pathname.split('/').filter(Boolean).map((s) => { try { return decodeURIComponent(s) } catch { return '\u0000' } })
    const m = req.method
    ctx.op = `${m} /${p.slice(0, 2).join('/')}`
    if (m === 'GET' && url.pathname === '/v1/info') { ctx.quiet = true; return sendJson(res, 200, info()) }
    if (m === 'GET' && url.pathname === '/.well-known/pocket-relay') { ctx.quiet = true; return sendJson(res, 200, { relayId: cfg.relayId, account: cfg.account, version: VERSION }) }
    if (m === 'GET' && url.pathname === '/v1/health') { ctx.quiet = true; return sendJson(res, 200, { ok: true, version: VERSION }) }
    if (m === 'GET' && url.pathname === '/v1/metrics') {
      if (!isLoopback(req)) fail('not-found')
      const count = (sql) => store.db.prepare(sql).get().n
      return sendJson(res, 200, { ...hub.stats(), tokens: tokens.size, queue: count('SELECT COUNT(*) AS n FROM queue'),
        objects: count('SELECT COUNT(*) AS n FROM objects WHERE del = 0'), blobs: count("SELECT COUNT(*) AS n FROM blobs WHERE state = 'ready'"),
        blobBytes: store.db.prepare("SELECT COALESCE(SUM(bytes), 0) AS n FROM blobs WHERE state = 'ready'").get().n })
    }
    if (m === 'POST' && url.pathname === '/v1/auth/challenge') {
      const t = now()
      limitIp(ctx, 'challenge', cfg.limits.challengesPerIp)
      const cap = cfg.limits.nonces ?? 200_000
      if (nonces.size >= cap) {
        for (const [k, exp] of nonces) if (exp < t) nonces.delete(k)
        // still full: many addresses each staying under the per-IP limit; refuse instead of growing without bound
        if (nonces.size >= cap) fail('rate')
      }
      const nonce = b64u(crypto.randomBytes(16))
      nonces.set(nonce, t + NONCE_TTL)
      return sendJson(res, 200, { relay: cfg.relayId, nonce, ts: t, exp: t + NONCE_TTL })
    }
    if (m === 'POST' && url.pathname === '/v1/auth') {
      limitIp(ctx, 'auth', cfg.limits.challengesPerIp)
      const j = await readJson(req)
      let nonce = null
      try { const A = JSON.parse(unb64u(String(j.a)).toString('utf8')); nonce = typeof A.nonce === 'string' ? A.nonce : null } catch { /* reported below */ }
      const exp = nonce ? nonces.get(nonce) : undefined
      if (nonce) nonces.delete(nonce)                         // single use
      const ident = await auth.verify(j, exp && exp >= now() ? nonce : null)
      ctx.acct = ident.acct; ctx.addr = ident.addr
      return sendJson(res, 200, { token: issueToken(ident), exp: ident.exp, addr: ident.addr, dev: ident.dev })
    }
    if (m === 'POST' && url.pathname === '/v1/revocations') {
      if (!isLoopback(req)) limitIp(ctx, 'control', 60)          // unauthenticated signature checks: bounded per IP
      const doc = await readJson(req, 4 * 1024 * 1024)
      const r = await applyRevocations(doc)
      return sendJson(res, 200, { applied: r.applied })
    }
    if (m === 'POST' && url.pathname === '/v1/purge') {
      if (!isLoopback(req)) limitIp(ctx, 'control', 60)
      const doc = await readJson(req)
      return sendJson(res, 200, await applyPurge(doc))
    }
    if (m === 'GET' && url.pathname === '/v1/me/quota') {
      const ident = identOfToken(req); ctx.acct = ident.acct; ctx.addr = ident.addr
      return sendJson(res, 200, quota.usage(ident.acct, ident))
    }
    if (p[0] === 'v1' && p[1] === 'o' && p.length >= 3) return routeObjects(req, res, ctx, url, p)
    if (p[0] === 'v1' && p[1] === 'b' && p.length >= 4) return routeBlobs(req, res, ctx, url, p)
    fail('not-found')
  }

  async function routeObjects(req, res, ctx, url, p) {
    const ident = identOfToken(req); ctx.acct = ident.acct; ctx.addr = ident.addr
    const realm = p[2], m = req.method
    if (!checkAddr(realm)) fail('not-found')
    const q = url.searchParams
    const intParam = (name, def, min, max) => {
      const v = q.get(name)
      if (v === null || v === '') return def
      if (!/^\d{1,16}$/.test(v)) fail('bad-request', name)
      const n = Number(v)
      if (n < min || n > max) fail('bad-request', name)
      return n
    }
    if (p.length === 3 && m === 'GET') {
      ctx.op = 'list'
      const kinds = (q.get('kinds') || 'info,usage,sess').split(',').filter(Boolean)
      if (!kinds.length || !kinds.every((k) => OBJ_KINDS.includes(k))) fail('bad-request', 'kinds')
      return sendJson(res, 200, objects.list(ident, realm, { since: intParam('since', 0, 0, Number.MAX_SAFE_INTEGER), kinds: [...new Set(kinds)],
        limit: intParam('limit', 500, 1, 500), inline: intParam('inline', 0, 0, cfg.limits.objects.info + 4096 + 88) }))
    }
    if (p.length === 4 && p[3] === 'heads' && m === 'GET') { ctx.op = 'heads'; return sendJson(res, 200, objects.heads(ident, realm, q.get('kind') || 'msg')) }
    if (p.length === 6 && p[3] === 'msg' && p[5] === 'range' && m === 'GET') {
      ctx.op = 'range'
      const skip = new Map()
      for (const s of q.getAll('skip').flatMap((x) => x.split(','))) {
        const mm = /^(\d{1,16}):(\d{1,16})$/.exec(s)
        if (!mm) fail('bad-request', 'skip')
        skip.set(Number(mm[1]), Number(mm[2]))
      }
      const maxV = q.get('max')
      const r = objects.range(ident, realm, p[4], { after: intParam('after', 0, 0, Number.MAX_SAFE_INTEGER), limit: intParam('limit', 500, 1, 500),
        max: maxV === null ? null : intParam('max', null, 1, 64 * 1024 * 1024), preferLite: q.get('prefer') === 'lite', skip })
      ctx.bytes = r.buf.length
      res.writeHead(200, { 'Content-Type': 'application/x-pocket-seal-stream', 'Content-Length': String(r.buf.length), 'Cache-Control': 'no-store',
        'X-Pocket-Last': String(r.last), ...(r.more ? { 'X-Pocket-More': '1' } : {}), ...COMMON })
      return res.end(r.buf)
    }
    if (p.length === 5 || p.length === 6) {
      const n = objects.name(p[3], p[4], p[5])
      if (m === 'PUT') {
        ctx.op = 'obj-put'
        const max = cfg.limits.objects[n.kind] + 4096 + 16 + 72
        const body = await readBody(req, max)
        const r = objects.put(ident, realm, n, req.headers['x-pocket-ver'], body)
        ctx.bytes = body.length
        return sendJson(res, 200, { ver: r.ver, rev: r.rev })
      }
      if (m === 'GET') {
        ctx.op = 'obj-get'
        const r = objects.get(ident, realm, n)
        const etag = `"${r.ver}"`
        if (String(req.headers['if-none-match'] || '').split(',').map((s) => s.trim().replace(/^W\//, '')).includes(etag)) {
          res.writeHead(304, { ETag: etag, 'X-Pocket-Ver': String(r.ver), 'Cache-Control': 'no-cache', ...COMMON }); return res.end()
        }
        ctx.bytes = r.buf.length
        res.writeHead(200, { 'Content-Type': 'application/x-pocket-seal', 'Content-Length': String(r.buf.length), ETag: etag, 'X-Pocket-Ver': String(r.ver), 'Cache-Control': 'no-cache', ...COMMON })
        return res.end(r.buf)
      }
      if (m === 'DELETE') { ctx.op = 'obj-del'; return sendJson(res, 200, objects.del(ident, realm, n)) }
    }
    fail('not-found')
  }

  async function routeBlobs(req, res, ctx, url, p) {
    const ident = identOfToken(req); ctx.acct = ident.acct; ctx.addr = ident.addr
    const realm = p[2], id = p[3], m = req.method
    if (!checkAddr(realm)) fail('not-found')
    if (p.length === 5 && p[4] === 'upload' && m === 'POST') {
      ctx.op = 'blob-reserve'
      const j = await readJson(req)
      ctx.bytes = j.bytes
      return sendJson(res, 200, blobs.reserve(ident, realm, id, j.bytes, ctx.ip))
    }
    if (p.length === 5 && p[4] === 'commit' && m === 'POST') {
      ctx.op = 'blob-commit'
      const j = await readJson(req)
      return sendJson(res, 200, await blobs.commit(ident, realm, id, j.bytes))
    }
    if (p.length === 4) {
      if (m === 'PUT') { ctx.op = 'blob-put'; const r = await blobs.putDirect(ident, realm, id, req, ctx.ip); ctx.bytes = r.bytes; return sendJson(res, 200, r) }
      if (m === 'GET') { ctx.op = 'blob-get'; return blobs.send(ident, realm, id, req, res) }
      if (m === 'HEAD') { ctx.op = 'blob-head'; return blobs.send(ident, realm, id, req, res, { head: true }) }
      if (m === 'DELETE') { ctx.op = 'blob-del'; return sendJson(res, 200, await blobs.del(ident, realm, id)) }
    }
    fail('not-found')
  }

  async function onRequest(req, res) {
    const t0 = Date.now()
    const ctx = { ip: ipOf(req), op: req.method, acct: null, addr: null, bytes: undefined, quiet: false }
    let status = 200
    try {
      await route(req, res, ctx)
      status = res.statusCode
    } catch (e) {
      if (!(e instanceof RelayError)) logger.error('http-error', { op: ctx.op, error: String(e?.message || e).slice(0, 200) })
      status = sendError(res, e)
      // a body we did not read must not be parsed as the next request on this connection. The socket is taken now:
      // when the client already went away (an upload cut off halfway) req.socket is null by the time the answer
      // finishes, and a throw in this listener used to take the whole relay down (red team 2026-10-08).
      if (!req.complete) { const sock = req.socket; res.once('finish', () => { try { sock?.destroy() } catch { /* gone */ } }); req.resume() }
    }
    if (!ctx.quiet || status >= 400) logger.info(ctx.op, { acct: ctx.acct, addr: ctx.addr, status, bytes: ctx.bytes, ms: Date.now() - t0, ip: ctx.ip })
  }

  // ---- server ---------------------------------------------------------------------------------------------------
  let server
  const tlsCtx = () => ({ cert: fs.readFileSync(cfg.tls.cert), key: fs.readFileSync(cfg.tls.key) })
  let certStamp = ''
  const stampOf = () => { try { return [fs.statSync(cfg.tls.cert).mtimeMs, fs.statSync(cfg.tls.key).mtimeMs].join('/') } catch { return '' } }
  if (cfg.tls) { server = https.createServer({ ...tlsCtx() }); certStamp = stampOf() } else server = http.createServer()
  server.requestTimeout = 0               // big uploads over slow links; idle sockets are timed out below
  server.headersTimeout = 30_000
  server.keepAliveTimeout = 65_000
  const perIp = new Map()
  server.on('connection', (socket) => {
    const ip = socket.remoteAddress || ''
    const n = (perIp.get(ip) ?? 0) + 1
    perIp.set(ip, n)
    socket.once('close', () => { const k = (perIp.get(ip) ?? 1) - 1; if (k > 0) perIp.set(ip, k); else perIp.delete(ip) })
    if (n > cfg.limits.connectionsPerIp && !cfg.trustProxy) { socket.destroy(); return }
    socket.setTimeout(120_000, () => socket.destroy())
  })
  server.on('request', (req, res) => { onRequest(req, res).catch((e) => { try { sendError(res, e) } catch { /* gone */ } }) })
  server.on('upgrade', (req, socket, head) => {
    const url = new URL(req.url, 'http://relay')
    if (url.pathname !== '/v1/ws') { socket.end('HTTP/1.1 404 Not Found\r\nConnection: close\r\nContent-Length: 0\r\n\r\n'); return }
    const ip = ipOf(req)
    if (cfg.trustProxy && [...hub.conns].filter((c) => c.ip === ip).length >= cfg.limits.connectionsPerIp) {
      socket.end('HTTP/1.1 429 Too Many Requests\r\nConnection: close\r\nContent-Length: 0\r\n\r\n'); return
    }
    hub.onUpgrade(req, socket, head, ip)
  })
  server.on('clientError', (err, socket) => { try { socket.end('HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n') } catch { /* gone */ } })

  function start() {
    keys.start()
    schedulePoll()
    sweepTimer = setTimeout(function run() { sweep().finally(() => { sweepTimer = setTimeout(run, cfg.retention.sweepMinutes * 60_000); sweepTimer.unref?.() }) }, 60_000)
    sweepTimer.unref?.()
    tokenTimer = setInterval(() => {
      const t = now()
      for (const [k, id] of tokens) if (t > id.exp + SKEW_MS) tokens.delete(k)
      for (const [d, list] of byDevice) { const live = list.filter((x) => tokens.has(x)); if (live.length) byDevice.set(d, live); else byDevice.delete(d) }
      for (const [k, e] of nonces) if (e < t) nonces.delete(k)
      challengeHits.clear()
    }, 60_000)
    tokenTimer.unref?.()
    if (blobs.backends.length) {
      blobs.probe()
      probeTimer = setInterval(() => blobs.probe(), 10 * 60_000)
      probeTimer.unref?.()
    }
    if (cfg.tls) {
      certTimer = setInterval(() => {
        const s = stampOf()
        if (s && s !== certStamp) { try { server.setSecureContext(tlsCtx()); certStamp = s; logger.info('tls-reloaded', {}) } catch (e) { logger.warn('tls-reload-failed', { error: String(e?.message || e).slice(0, 80) }) } }
      }, 3_600_000)
      certTimer.unref?.()
    }
  }

  return {
    cfg, store, keys, cutoffs, quota, objects, blobs, hub, tokens, server, log: logger,
    sweep, pollAccount, applyRevocations, applyPurge, purgeAddr,
    listen(port = cfg.listen.port, host = cfg.listen.host) {
      return new Promise((resolve, reject) => {
        server.once('error', reject)
        server.listen(port, host, () => { server.off('error', reject); start(); resolve(server.address()) })
      })
    },
    async close() {
      keys.stop(); clearTimeout(pollTimer); clearTimeout(sweepTimer); clearInterval(tokenTimer); clearInterval(probeTimer); clearInterval(certTimer)
      hub.close()
      await new Promise((r) => { server.close(() => r()); setTimeout(r, 2000).unref?.(); server.closeAllConnections?.() })
      store.close()
    },
  }
}

export { blobSizeFor }
