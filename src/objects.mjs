// Stored objects (RELAY.md §6.3, E2EE.md §10): binary seals written by a realm's computer, read by its phones.
// Index rows in SQLite (one row per object, deleted objects kept as tombstones for `tombstoneDays` so readers can
// list "changes since rev"); bodies in files named by a hash of (kind, key, seq) — safe on case-insensitive disks.
// Writes count against the account's stored bytes (§8.3) and stop while the disk is nearly full (§8.4).
//
// SPDX-License-Identifier: AGPL-3.0-or-later
import fs from 'node:fs'
import path from 'node:path'
import crypto from 'node:crypto'
import { fail, isInt, parseSealBin, parseObj, b64u } from './proto.mjs'

export const OBJ_KINDS = ['info', 'usage', 'sess', 'msg', 'lite']
const SEQ_KINDS = new Set(['msg', 'lite'])
export const KEY_RE = /^[A-Za-z0-9_-]{1,64}$/
const DAY = 86_400_000
const TOUCH_GAP = 3_600_000

export class Objects {
  constructor({ store, limits, retention, now = Date.now, notify = () => {}, access, quota = null, disk = null }) {
    this.store = store
    this.limits = limits
    this.retention = retention
    this.now = now
    this.notify = notify
    this.access = access
    this.quota = quota
    this.disk = disk
    this.buckets = new Map()          // per-owner write rate
  }

  fileOf(realm, kind, key, seq) {
    const h = crypto.createHash('sha256').update(`${kind}\0${key}\0${seq}`).digest('hex').slice(0, 40)
    return path.join(this.store.dir, 'o', realm, h.slice(0, 2), h)
  }

  /** Validate the (kind, key, seq) part of a path; seq is a string from the URL or undefined. */
  name(kind, key, seqStr) {
    if (!OBJ_KINDS.includes(kind) || !KEY_RE.test(key ?? '')) fail('not-found')
    if (SEQ_KINDS.has(kind)) {
      if (seqStr === undefined) return { kind, key, seq: null }
      if (!/^[1-9][0-9]{0,15}$/.test(seqStr)) fail('bad-request', 'seq')
      const seq = Number(seqStr)
      if (!isInt(seq, 1)) fail('bad-request', 'seq')
      return { kind, key, seq }
    }
    if (seqStr !== undefined) fail('not-found')
    return { kind, key, seq: 0 }
  }

  rate(addr) {
    const now = this.now(), cap = this.limits.objectWritesPerSecond
    let b = this.buckets.get(addr)
    if (!b) { b = { t: cap, at: now }; this.buckets.set(addr, b) }
    b.t = Math.min(cap, b.t + ((now - b.at) / 1000) * cap); b.at = now
    if (b.t < 1) fail('rate', 'object writes', { retryAfter: 1 })   // 让写的一方等 1 秒再来,不是长时间停下(2026-10-09)
    b.t -= 1
    if (this.buckets.size > 10000) for (const [k, v] of this.buckets) if (now - v.at > 60_000) this.buckets.delete(k)
  }

  writeFile(file, buf) {
    fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 })
    const tmp = path.join(this.store.dir, 'tmp', `o-${crypto.randomBytes(9).toString('hex')}`)
    fs.writeFileSync(tmp, buf, { mode: 0o600 })
    fs.renameSync(tmp, file)
  }
  unlink(file) { try { fs.unlinkSync(file) } catch { /* already gone */ } }

  /**
   * Before the body of a PUT is read: refuse what could not be stored anyway — no room left for the account (§8.3) or
   * on the disk (§8.4) — so that a refused write does not cost its upload. put() checks again with the real body.
   */
  precheck(ident, realm, n, len) {
    this.access.owner(ident, realm)
    if (n.seq === null) return
    const prev = this.store.get('objGet', realm, n.kind, n.key, n.seq)
    this.quota?.checkStore(ident.acct, ident, len - (prev && !prev.del ? prev.bytes : 0))
    this.disk?.check(len)
  }

  /** PUT: owner only; version must grow; header must agree with the request. */
  put(ident, realm, n, verHeader, body) {
    this.access.owner(ident, realm)
    if (n.seq === null) fail('bad-request', 'seq required')
    const ver = Number(verHeader)
    if (!/^[1-9][0-9]{0,15}$/.test(String(verHeader ?? '')) || !isInt(ver, 1)) fail('bad-request', 'X-Pocket-Ver')
    const max = this.limits.objects[n.kind]
    if (body.length > max + 4096 + 16 + 72) fail('too-large')
    const seal = parseSealBin(body)
    if (seal.c.length > max + 16) fail('too-large')
    let H
    try { H = parseObj(seal.h, 4096) } catch { fail('mismatch', 'header') }
    const seqOk = SEQ_KINDS.has(n.kind) ? H.seq === n.seq : H.seq === undefined
    if (H.v !== 1 || H.t !== 'obj' || H.kind !== n.kind || H.key !== n.key || !seqOk || H.ver !== ver || H.realm !== ident.dev || H.by !== ident.dev) fail('mismatch')
    this.rate(ident.addr)
    const now = this.now()
    const prev = this.store.get('objGet', realm, n.kind, n.key, n.seq)
    if (prev && ver <= prev.ver) fail('ver', 'stale version', { ver: prev.ver })
    // what the account keeps grows by the difference to the version it replaces (§8.3); the file is written in full
    const delta = body.length - (prev && !prev.del ? prev.bytes : 0)
    this.quota?.checkStore(ident.acct, ident, delta)
    this.disk?.check(body.length)
    this.access.claimRealm(ident, realm)
    this.writeFile(this.fileOf(realm, n.kind, n.key, n.seq), body)
    const rev = this.store.tx(() => {
      const r = this.store.get('realmBump', realm).rev
      this.store.run('objPut', realm, n.kind, n.key, n.seq, ver, body.length, now, now, r)
      return r
    })
    this.quota?.noteObjects(ident.acct, delta)
    this.notify(realm, { kind: n.kind, key: n.key, ...(n.seq ? { seq: n.seq } : {}), ver, rev, bytes: body.length })
    return { ver, rev, bytes: body.length }
  }

  get(ident, realm, n) {
    this.access.read(ident, realm)
    if (n.seq === null) fail('not-found')
    const row = this.store.get('objGet', realm, n.kind, n.key, n.seq)
    if (!row || row.del) fail('not-found')
    let buf
    try { buf = fs.readFileSync(this.fileOf(realm, n.kind, n.key, n.seq)) } catch { fail('not-found') }
    this.touch(row, realm, n)
    return { buf, ver: row.ver }
  }

  touch(row, realm, n) {
    const now = this.now()
    if (now - row.last_read > TOUCH_GAP) this.store.run('objTouch', now, realm, n.kind, n.key, n.seq)
  }

  /** DELETE: owner only. Without seq on msg/lite: every seq of that key. */
  del(ident, realm, n) {
    this.access.owner(ident, realm)
    const now = this.now()
    if (n.seq === null) {
      const seqs = this.store.all('objSeqs', realm, n.kind, n.key)
      if (!seqs.length) fail('not-found')
      const rev = this.store.tx(() => {
        const r = this.store.get('realmBump', realm).rev
        this.store.db.prepare('DELETE FROM objects WHERE realm = ? AND kind = ? AND key = ? AND seq > 0').run(realm, n.kind, n.key)
        this.store.run('objTomb', realm, n.kind, n.key, 0, 0, now, now, r)
        return r
      })
      for (const s of seqs) this.unlink(this.fileOf(realm, n.kind, n.key, s.seq))
      this.quota?.dropObjects(ident.acct)
      this.notify(realm, { kind: n.kind, key: n.key, ver: 0, rev, bytes: 0, del: true })
      return { rev, deleted: seqs.length }
    }
    const row = this.store.get('objGet', realm, n.kind, n.key, n.seq)
    if (!row || row.del) fail('not-found')
    const rev = this.store.tx(() => {
      const r = this.store.get('realmBump', realm).rev
      this.store.run('objTomb', realm, n.kind, n.key, n.seq, row.ver, now, now, r)
      return r
    })
    this.unlink(this.fileOf(realm, n.kind, n.key, n.seq))
    this.quota?.noteObjects(ident.acct, -row.bytes)
    this.notify(realm, { kind: n.kind, key: n.key, ...(n.seq ? { seq: n.seq } : {}), ver: row.ver, rev, bytes: 0, del: true })
    return { rev, deleted: 1 }
  }

  /** Changes after `since`, ordered by rev (since = 0: everything that exists). */
  list(ident, realm, { since = 0, kinds = ['info', 'usage', 'sess'], limit = 500, inline = 0 }) {
    this.access.read(ident, realm)
    const r = this.store.get('realmGet', realm)
    if (!r) return { rev: 0, more: false, items: [] }
    let reset = false
    if (since > 0 && since < r.purged_rev) { since = 0; reset = true }
    const marks = kinds.map(() => '?').join(',')
    const sql = since === 0
      ? `SELECT kind, key, seq, ver, bytes, at, rev, del FROM objects WHERE realm = ? AND del = 0 AND kind IN (${marks}) ORDER BY rev LIMIT ?`
      : `SELECT kind, key, seq, ver, bytes, at, rev, del FROM objects WHERE realm = ? AND rev > ? AND kind IN (${marks}) ORDER BY rev LIMIT ?`
    const rows = since === 0
      ? this.store.db.prepare(sql).all(realm, ...kinds, limit + 1)
      : this.store.db.prepare(sql).all(realm, since, ...kinds, limit + 1)
    const more = rows.length > limit
    let budget = this.limits.listInline
    const items = rows.slice(0, limit).map((o) => {
      const it = { kind: o.kind, key: o.key, ...(o.seq ? { seq: o.seq } : {}), ver: o.ver, bytes: o.bytes, at: o.at, rev: o.rev }
      if (o.del) it.del = true
      else if (inline > 0 && o.bytes <= inline && o.bytes <= budget) {
        try { it.seal = b64u(fs.readFileSync(this.fileOf(realm, o.kind, o.key, o.seq))); budget -= o.bytes } catch { /* raced with a delete */ }
      }
      return it
    })
    return { rev: r.rev, more, items, ...(reset || since === 0 ? { full: true } : {}) }
  }

  heads(ident, realm, kind = 'msg') {
    this.access.read(ident, realm)
    if (!SEQ_KINDS.has(kind)) fail('bad-request', 'kind')
    const heads = this.store.all('objHeads', realm, kind).map((h) => {
      const top = this.store.get('objGet', realm, kind, h.key, h.last)
      return { key: h.key, last: h.last, ver: top?.ver ?? 0, count: h.count }
    })
    return { heads }
  }

  /** Seal stream of msg (or lite, when preferred and present) objects with seq > after. */
  range(ident, realm, key, { after = 0, limit = 500, max = null, preferLite = false, skip = new Map() }) {
    this.access.read(ident, realm)
    if (!KEY_RE.test(key)) fail('not-found')
    const rows = this.store.all('objRange', realm, key, after, limit)
    const last = this.store.get('objLast', realm, 'msg', key)?.last ?? 0
    const cap = max ?? (rows.length && rows[rows.length - 1].seq === last ? 2 * 1024 * 1024 : 16 * 1024 * 1024)
    const parts = []
    let total = 0, more = false
    for (const row of rows) {
      let kind = 'msg', ver = row.ver
      let lite = null
      if (preferLite) {
        lite = this.store.get('objGet', realm, 'lite', key, row.seq)
        if (lite && !lite.del) { kind = 'lite'; ver = lite.ver } else lite = null
      }
      const sk = skip.get(row.seq)
      if (sk !== undefined && (sk === row.ver || (lite && sk === lite.ver))) continue
      let buf
      try { buf = fs.readFileSync(this.fileOf(realm, kind, key, row.seq)) } catch { continue }
      if (parts.length && total + buf.length > cap) { more = true; break }
      parts.push(buf)
      total += buf.length
      this.touch(kind === 'lite' ? lite : row, realm, { kind, key, seq: row.seq })
    }
    return { buf: Buffer.concat(parts, total), more, last, count: parts.length }
  }

  /** Delete every object of a realm (gone address, purge order, address reassigned). */
  purgeRealm(realm) {
    const rows = this.store.all('objOfRealm', realm)
    const r = this.store.get('realmGet', realm)
    this.store.tx(() => {
      this.store.run('objDelRealm', realm)
      if (r) this.store.run('realmPurged', r.rev, realm)
    })
    try { fs.rmSync(path.join(this.store.dir, 'o', realm), { recursive: true, force: true }) } catch { /* nothing there */ }
    if (r) this.quota?.dropObjects(r.acct)
    return rows.filter((x) => !x.del).length
  }

  /** Retention: objects neither written nor read for objectDays; tombstones after tombstoneDays. */
  sweep() {
    const now = this.now()
    const old = now - this.retention.objectDays * DAY
    const week = now - 7 * DAY
    let removed = 0
    for (;;) {
      const rows = this.store.all('objStale', old, old, week)
      if (!rows.length) break
      for (const o of rows) {
        this.store.tx(() => {
          const r = this.store.get('realmBump', o.realm)?.rev
          if (r) this.store.run('objTomb', o.realm, o.kind, o.key, o.seq, 0, now, now, r)
          else this.store.run('objDelRow', o.realm, o.kind, o.key, o.seq)
        })
        this.unlink(this.fileOf(o.realm, o.kind, o.key, o.seq))
        removed++
      }
      if (rows.length < 2000) break
    }
    if (removed) this.quota?.dropObjects()
    const tombOld = now - this.retention.tombstoneDays * DAY
    for (;;) {
      const rows = this.store.all('objOldTombs', tombOld)
      if (!rows.length) break
      this.store.tx(() => {
        for (const t of rows) {
          this.store.run('objDelRow', t.realm, t.kind, t.key, t.seq)
          this.store.run('realmPurged', t.rev, t.realm)
        }
      })
      if (rows.length < 5000) break
    }
    return removed
  }
}
