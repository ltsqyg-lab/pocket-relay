// WebSocket side of the relay (RELAY.md §3.1, §5): challenge → auth → ready; envelope routing between the
// devices of an account (peers only), the short offline queue with acks, presence, and object-change notifications.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
import crypto from 'node:crypto'
import { upgrade } from './ws.mjs'
import { RelayError, b64u, checkAddr, checkEnvelopeJson, isInt, parseObj, SKEW_MS } from './proto.mjs'

const REPLAY_MAX = 1000

let CONN_SEQ = 0

export class Hub {
  constructor({ cfg, store, now = Date.now, log, auth, access, cutoffs, disk = null }) {
    this.cfg = cfg
    this.limits = cfg.limits
    this.store = store
    this.now = now
    this.log = log
    this.auth = auth                  // async (msg, nonce) → ident; issues tokens via auth.token(ident)
    this.access = access
    this.cutoffs = cutoffs
    this.disk = disk                  // queueing stops while the disk is nearly full (RELAY.md §8.4)
    this.conns = new Set()
    this.unauth = 0                   // sockets that have not authenticated yet
    this.byAddr = new Map()           // addr → Set<conn> (authenticated)
    this.byAcct = new Map()           // acct → Set<conn>
    this.subs = new Map()             // realm → Set<conn>
    this.pendingOffline = new Map()   // addr → timer
    this.timer = setInterval(() => this.keepalive(), this.limits.pingSeconds * 1000)
    this.timer.unref?.()
    this.qTimer = setInterval(() => this.expireQueue(), 5_000)
    this.qTimer.unref?.()
  }

  // ---- connections ------------------------------------------------------------------------------------------
  // Before authentication a socket may only answer the challenge: its frames are capped at limits.authFrame (64 KiB,
  // an auth frame is ~15 KB), it has limits.authSeconds to do it, and at most limits.unauthSockets such sockets are
  // open at once, all clients together. The full frame size comes with `ready` (red team 2026-10-09: 2 MiB buffered
  // per unauthenticated socket, without a total).
  onUpgrade(req, socket, head, ip) {
    if (this.unauth >= this.limits.unauthSockets) {
      socket.end('HTTP/1.1 503 Service Unavailable\r\nConnection: close\r\nRetry-After: 5\r\nContent-Length: 0\r\n\r\n')
      return
    }
    const ws = upgrade(req, socket, head, { maxMessage: Math.min(this.limits.authFrame, this.limits.frame) })
    if (!ws) return
    const conn = { id: ++CONN_SEQ, ws, ip, ident: null, nonce: null, authing: false, subs: new Set(), openedAt: this.now(),
      bucket: { t: this.limits.frameBurst, at: Date.now() }, over: 0, expTimer: null, authTimer: null, pending: true }
    this.conns.add(conn)
    this.unauth++
    ws.onMessage = (m) => this.onFrame(conn, m)
    ws.onClose = (code) => this.onClose(conn, code)
    this.challenge(conn)
    conn.authTimer = setTimeout(() => { if (!conn.ident) { this.error(conn, 'expired'); ws.close(4408, 'auth timeout') } }, this.limits.authSeconds * 1000)
    conn.authTimer.unref?.()
  }

  /** The socket authenticated (or went away before): it no longer counts as pending. */
  settled(conn) {
    if (!conn.pending) return
    conn.pending = false
    this.unauth = Math.max(0, this.unauth - 1)
  }

  challenge(conn) {
    conn.nonce = b64u(crypto.randomBytes(16))
    conn.ws.send({ t: 'challenge', relay: this.cfg.relayId, nonce: conn.nonce, ts: this.now() })
  }

  error(conn, code, extra = {}) { conn.ws.send({ t: 'error', code, ...extra }) }

  ackOk(conn) {
    const now = Date.now()
    const b = conn.ackBucket ?? (conn.ackBucket = { t: 1000, at: now })
    b.t = Math.min(1000, b.t + ((now - b.at) / 1000) * 200); b.at = now
    if (b.t < 1) return false
    b.t -= 1
    return true
  }

  rateOk(conn) {
    const now = Date.now(), b = conn.bucket, rate = this.limits.frameRate
    b.t = Math.min(this.limits.frameBurst, b.t + ((now - b.at) / 1000) * rate); b.at = now
    if (b.t >= 1) { b.t -= 1; conn.over = 0; return true }
    if (++conn.over > 4 * this.limits.frameBurst) conn.ws.close(4429, 'rate')
    return false
  }

  onFrame(conn, m) {
    const t = m.t
    if (t === 'auth') return this.onAuth(conn, m).catch((e) => { this.log?.error('ws-auth-error', { error: String(e?.message || e).slice(0, 160) }); conn.ws.close(1011, 'error') })
    if (!conn.ident) { this.error(conn, 'token'); return conn.ws.close(4401, 'not authenticated') }
    // acks have their own, larger allowance: a phone working through a long queue acks every envelope
    if (t === 'ack') return this.ackOk(conn) ? this.onAck(conn, m) : this.error(conn, 'rate')
    if (!this.rateOk(conn)) {
      if (t === 'send') conn.ws.send({ t: 'sent', id: typeof m.id === 'string' ? m.id.slice(0, 64) : null, status: 'rate', n: 0, queued: 0 })
      else this.error(conn, 'rate')
      return
    }
    switch (t) {
      case 'send': return this.onSend(conn, m)
      case 'sub': return this.onSub(conn, m)
      case 'ping': return conn.ws.send({ t: 'pong', ts: isInt(m.ts) ? m.ts : this.now() })
      case 'renew': return this.challenge(conn)
      default: return this.error(conn, 'bad-request', { what: 'unknown frame type' })
    }
  }

  async onAuth(conn, m) {
    if (conn.authing) return
    const nonce = conn.nonce
    conn.nonce = null                  // single use, whatever happens
    if (!nonce) { this.error(conn, 'bad-nonce'); return conn.ws.close(4401, 'no challenge') }
    conn.authing = true
    let ident
    try {
      ident = await this.auth.verify({ ticket: m.ticket, a: m.a, s: m.s }, nonce)
    } catch (e) {
      conn.authing = false
      const code = e instanceof RelayError ? e.code : 'bad-proof'
      this.log?.info('ws-auth-failed', { ip: conn.ip, status: code })
      this.error(conn, code)
      return conn.ws.close(code === 'revoked' || code === 'wrong-account' || code === 'denied' ? 4403 : 4401, code)
    }
    conn.authing = false
    if (!conn.ws.alive) return
    const prev = conn.ident
    if (prev && (prev.dev !== ident.dev || prev.addr !== ident.addr || prev.acct !== ident.acct)) {
      this.error(conn, 'denied', { what: 'renewal for another device' })
      return conn.ws.close(4401, 'renewal for another device')
    }
    clearTimeout(conn.authTimer)
    conn.ident = ident
    if (!prev) {
      this.settled(conn)
      conn.ws.maxMessage = this.limits.frame
      this.register(conn)
    }
    else for (const realm of [...conn.subs]) if (!this.access.canRead(ident, realm)) this.unsub(conn, realm)
    clearTimeout(conn.expTimer)
    conn.expTimer = setTimeout(() => { this.error(conn, 'expired'); conn.ws.close(4401, 'expired') }, Math.max(1000, ident.exp + SKEW_MS - this.now()))
    conn.expTimer.unref?.()
    const token = this.auth.token(ident)
    const queued = this.store.get('qStats', ident.addr).n
    conn.ws.send({ t: 'ready', addr: ident.addr, dev: ident.dev, acct: ident.acct, exp: ident.exp, token, tokenExp: ident.exp, queued,
      peers: [...ident.peers].map((a) => ({ addr: a, online: this.online(a) })) })
    this.log?.info(prev ? 'ws-renew' : 'ws-ready', { acct: ident.acct, addr: ident.addr, kind: ident.kind, ip: conn.ip, queued })
    if (!prev) this.flushQueue(conn)
  }

  register(conn) {
    const { addr, acct } = conn.ident
    let set = this.byAddr.get(addr)
    const first = !set || set.size === 0
    if (!set) { set = new Set(); this.byAddr.set(addr, set) }
    // at most N sockets per device: the oldest goes
    while (set.size >= this.limits.socketsPerDevice) {
      const oldest = [...set].sort((a, b) => a.openedAt - b.openedAt || a.id - b.id)[0]
      set.delete(oldest)
      oldest.replaced = true
      this.error(oldest, 'replaced')
      oldest.ws.close(4409, 'replaced')
    }
    set.add(conn)
    let as = this.byAcct.get(acct)
    if (!as) { as = new Set(); this.byAcct.set(acct, as) }
    as.add(conn)
    if (first) {
      const pend = this.pendingOffline.get(addr)
      if (pend) { clearTimeout(pend); this.pendingOffline.delete(addr) } else this.presence(addr, acct, true)
    }
  }

  onClose(conn) {
    this.conns.delete(conn)
    this.settled(conn)
    clearTimeout(conn.authTimer); clearTimeout(conn.expTimer)
    for (const realm of [...conn.subs]) this.unsub(conn, realm)
    if (!conn.ident) return
    const { addr, acct } = conn.ident
    this.byAcct.get(acct)?.delete(conn)
    if (this.byAcct.get(acct)?.size === 0) this.byAcct.delete(acct)
    const set = this.byAddr.get(addr)
    if (!set) return
    set.delete(conn)
    if (set.size === 0) {
      this.byAddr.delete(addr)
      if (!this.pendingOffline.has(addr)) {
        const t = setTimeout(() => { this.pendingOffline.delete(addr); if (!this.byAddr.get(addr)?.size) this.presence(addr, acct, false) }, this.limits.presenceDebounceMs ?? 5_000)
        t.unref?.()
        this.pendingOffline.set(addr, t)
      }
    }
  }

  online(addr) { return (this.byAddr.get(addr)?.size ?? 0) > 0 || this.pendingOffline.has(addr) }

  /** Tell the connected devices that may see `addr` (it is in their peers) that it came or went. */
  presence(addr, acct, online) {
    const frame = { t: 'presence', addr, online, at: this.now() }
    for (const c of this.byAcct.get(acct) ?? []) if (c.ident.peers.has(addr)) c.ws.send(frame)
  }

  keepalive() {
    const now = Date.now(), idle = this.limits.idleSeconds * 1000
    for (const c of this.conns) {
      if (now - c.ws.lastSeen > idle) c.ws.close(1001, 'idle')
      else c.ws.ping()
    }
  }

  // ---- envelopes ---------------------------------------------------------------------------------------------
  onSend(conn, m) {
    const id = m.id
    if (typeof id !== 'string' || !id || id.length > 64) return this.error(conn, 'bad-request', { what: 'id' })
    const reply = (status, n = 0, queued = 0) => conn.ws.send({ t: 'sent', id, status, n, queued })
    const ttl = m.ttl === undefined ? 0 : m.ttl
    if (!isInt(ttl) || ttl > 604800) return this.error(conn, 'bad-request', { id, what: 'ttl' })
    if (typeof m.to !== 'string' || (m.to !== '*' && !checkAddr(m.to))) return this.error(conn, 'bad-request', { id, what: 'to' })
    let env
    try { env = checkEnvelopeJson(m.env, { maxC: this.limits.envelope + 16, maxH: this.limits.header }) } catch (e) {
      if (e instanceof RelayError && e.code === 'too-large') return reply('too-large')
      return this.error(conn, 'bad-request', { id, what: 'env' })
    }
    const me = conn.ident
    // cross-check routing fields of the plaintext header (honest-mistake and spoofing guard; content stays opaque)
    let H
    try { H = parseObj(env.h, this.limits.header) } catch { return reply('denied') }
    if (H.from !== me.dev) return reply('denied')
    let rcpts
    if (m.to === '*') {
      if (H.to !== '*') return reply('denied')
      rcpts = [...me.peers]
    } else {
      if (!me.peers.has(m.to)) return reply('denied')
      if (typeof H.to === 'string' && H.to !== '*') {
        const known = this.store.get('identGet', m.to)
        if (known && known.dev !== H.to) return reply('denied')
      }
      rcpts = [m.to]
    }
    const frame = { t: 'msg', from: me.addr, env: { h: m.env.h, c: m.env.c, s: m.env.s }, at: this.now() }
    let text = null
    let delivered = 0, queued = 0, full = 0
    const ttlMs = Math.min(ttl, this.cfg.retention.queueMaxSeconds) * 1000
    for (const r of rcpts) {
      if (!this.access.sameAccount(me, r)) continue
      if (this.cutoffs.isGone(r, this.store.get('identGet', r)?.dev)) continue
      const socks = this.byAddr.get(r)
      if (socks?.size) {
        text ??= JSON.stringify(frame)
        for (const s of socks) s.ws.send(text)
        delivered++
        continue
      }
      if (ttlMs <= 0) continue
      const envText = JSON.stringify(frame.env)
      const st = this.store.get('qStats', r)
      if (st.n >= this.limits.queueEnvelopes || st.b + envText.length > this.limits.queueBytes) { full++; continue }
      if (this.disk && !this.disk.ok(envText.length)) { full++; continue }       // the relay's disk is nearly full
      const now = this.now()
      this.store.run('qAdd', r, me.acct, me.addr, id, envText, envText.length, now, now + ttlMs)
      queued++
    }
    let status
    if (delivered && delivered === rcpts.length) status = 'delivered'
    else if (delivered) status = 'partial'
    else if (queued) status = 'queued'
    else if (full) status = 'full'
    else status = 'offline'
    if (delivered && (queued || full) && status === 'partial') status = 'partial'
    reply(status, delivered, queued)
    this.log?.info('env', { acct: me.acct, addr: me.addr, to: m.to, status, bytes: env.bytes, n: delivered, queued })
  }

  /** Send the queue in order, a slice at a time so a large backlog does not swamp the socket buffer. */
  flushQueue(conn) {
    const addr = conn.ident.addr
    let after = 0
    const step = () => {
      if (!conn.ws.alive || conn.ident?.addr !== addr) return
      if (conn.ws.buffered > 4 * 1024 * 1024) { setTimeout(step, 50).unref?.(); return }
      const rows = this.store.db.prepare('SELECT q, sender, env, at FROM queue WHERE rcpt = ? AND q > ? AND expires > ? ORDER BY q LIMIT 100').all(addr, after, this.now())
      for (const r of rows) {
        conn.ws.send(`{"t":"msg","q":${r.q},"from":${JSON.stringify(r.sender)},"env":${r.env},"at":${r.at}}`)
        after = r.q
      }
      if (rows.length === 100) setImmediate(step)
    }
    step()
  }

  /** {t:"ack", q} — q may also be an array of up to 1000 queue ids (one frame for a batch). */
  onAck(conn, m) {
    const list = Array.isArray(m.q) ? m.q : [m.q]
    if (!list.length || list.length > 1000 || !list.every((q) => isInt(q, 1))) return this.error(conn, 'bad-request', { what: 'q' })
    if (list.length === 1) return void this.store.run('qAck', list[0], conn.ident.addr)
    this.store.tx(() => { for (const q of list) this.store.run('qAck', q, conn.ident.addr) })
  }

  expireQueue() {
    const now = this.now()
    for (;;) {
      const rows = this.store.all('qExpired', now)
      if (!rows.length) break
      for (const r of rows) {
        this.store.run('qDel', r.q)
        for (const c of this.byAddr.get(r.sender) ?? []) c.ws.send({ t: 'expired', id: r.fid, to: r.rcpt })
      }
      if (rows.length < 1000) break
    }
  }

  // ---- object-change notifications ---------------------------------------------------------------------------------
  onSub(conn, m) {
    if (!Array.isArray(m.realms) || m.realms.length > 256 || !m.realms.every(checkAddr)) return this.error(conn, 'bad-request', { what: 'realms' })
    const want = new Set(m.realms)
    const denied = []
    for (const realm of [...conn.subs]) if (!want.has(realm)) this.unsub(conn, realm)
    for (const realm of want) {
      if (!this.access.canRead(conn.ident, realm)) { denied.push(realm); continue }
      conn.subs.add(realm)
      let set = this.subs.get(realm)
      if (!set) { set = new Set(); this.subs.set(realm, set) }
      set.add(conn)
    }
    if (denied.length) this.error(conn, 'denied', { realms: denied })
    const since = m.since && typeof m.since === 'object' ? m.since : {}
    for (const realm of conn.subs) {
      const rev = since[realm]
      if (rev === undefined) continue
      if (!isInt(rev)) { this.error(conn, 'bad-request', { what: 'since' }); continue }
      this.replay(conn, realm, rev)
    }
  }

  unsub(conn, realm) {
    conn.subs.delete(realm)
    const set = this.subs.get(realm)
    if (set) { set.delete(conn); if (!set.size) this.subs.delete(realm) }
  }

  replay(conn, realm, rev) {
    const r = this.store.get('realmGet', realm)
    if (!r) { if (rev > 0) conn.ws.send({ t: 'resync', realm }); return }
    if (rev < r.purged_rev || rev > r.rev) { conn.ws.send({ t: 'resync', realm }); return }
    const rows = this.store.all('objChanges', realm, rev, REPLAY_MAX + 1)
    if (rows.length > REPLAY_MAX) { conn.ws.send({ t: 'resync', realm }); return }
    for (const o of rows) conn.ws.send(objFrame(realm, o))
  }

  /** Called by the object store after a write or delete. */
  notify(realm, o) {
    const set = this.subs.get(realm)
    if (!set?.size) return
    const text = JSON.stringify(objFrame(realm, o))
    for (const c of set) c.ws.send(text)
  }

  // ---- control -------------------------------------------------------------------------------------------------
  /** Close sockets whose identity matches (revocation). */
  kick(pred, code = 4403, reason = 'revoked') {
    for (const c of [...this.conns]) if (c.ident && pred(c.ident)) { this.error(c, reason); c.ws.close(code, reason) }
  }
  /** Close every socket, authenticated or not (the relay was unbound: RELAY.md §12.1 reset-claim). */
  closeAll(code = 4403, reason = 'unclaimed') {
    for (const c of [...this.conns]) { try { this.error(c, reason); c.ws.close(code, reason) } catch { /* already gone */ } }
  }

  liveAccounts() { return [...this.byAcct.keys()] }

  stats() {
    return { connections: this.conns.size, devices: this.byAddr.size, accounts: this.byAcct.size, subscriptions: this.subs.size }
  }

  close() {
    clearInterval(this.timer); clearInterval(this.qTimer)
    for (const t of this.pendingOffline.values()) clearTimeout(t)
    for (const c of [...this.conns]) c.ws.close(1001, 'shutting down')
  }
}

function objFrame(realm, o) {
  const f = { t: 'obj', realm, kind: o.kind, key: o.key }
  if (o.seq) f.seq = o.seq
  f.ver = o.ver; f.rev = o.rev; f.bytes = o.bytes
  if (o.del) f.del = true
  return f
}
