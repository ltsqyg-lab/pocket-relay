// Quotas per account (RELAY.md §8.3): blob traffic (uploads and downloads) per day and per month in the configured
// time zone, a small-file allowance that keeps small blobs (thumbnails, voice clips) moving after the day or month is
// used up, and stored bytes — objects and blobs together, so one account cannot fill the relay's disk or bucket.
// Caps come from the configuration or, when useTicketQuota is set, from the account's newest ticket
// (`quota: {dayMB, monthMB, storeMB, smallMB}`; 0 = unlimited, except smallMB where 0 = no allowance): every device of
// the account gets the same caps, whichever ticket it holds itself.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
import { fail, blobSizeFor } from './proto.mjs'

const MB = 1024 * 1024
const QUOTA_FIELDS = ['dayMB', 'monthMB', 'storeMB', 'smallMB']
const num = (v) => (typeof v === 'number' && Number.isFinite(v) && v >= 0 ? v : null)
// an account's object bytes are summed from the index at most once a minute and kept up to date in between by the
// writes themselves; deletes and sweeps just drop the figure (the next check sums again)
const OBJ_SUM_MS = 60_000

/** The quota fields of a ticket that the relay uses; anything else is dropped. */
function quotaOfTicket(q) {
  if (!q || typeof q !== 'object' || Array.isArray(q)) return null
  const out = {}
  for (const k of QUOTA_FIELDS) if (num(q[k]) !== null) out[k] = q[k]
  return out
}

export class Quota {
  constructor({ store, timezone, quota, now = Date.now }) {
    this.store = store
    this.now = now
    this.cfg = quota || {}
    this.fmt = new Intl.DateTimeFormat('en-CA', { timeZone: timezone, year: 'numeric', month: '2-digit', day: '2-digit' })
    const fileMB = num(this.cfg.smallFileMB) || 2
    this.smallFile = blobSizeFor(Math.round(fileMB * MB))      // a blob this size or smaller counts as small (2 MiB of plaintext)
    this.latest = new Map()                                     // acct -> {iat, quota} (cache of acct_quota)
    this.objBytes = new Map()                                   // acct -> {b, at}: bytes of live objects
  }

  /** Bytes of the account's live objects (session lists, messages, info, usage). */
  objectsUsed(acct) {
    const t = this.now()
    const c = this.objBytes.get(acct)
    if (c && t - c.at >= 0 && t - c.at < OBJ_SUM_MS) return c.b
    const b = this.store.get('objBytesOfAcct', acct)?.b ?? 0
    if (this.objBytes.size > 50_000) this.objBytes.clear()
    this.objBytes.set(acct, { b, at: t })
    return b
  }
  /** An object write changed the account's bytes by `delta` (a new object, or a new version of one). */
  noteObjects(acct, delta) { const c = this.objBytes.get(acct); if (c) c.b = Math.max(0, c.b + delta) }
  /** Objects were deleted (one account, or any after a sweep): sum again at the next check. */
  dropObjects(acct = null) { if (acct === null) this.objBytes.clear(); else this.objBytes.delete(acct) }

  dayKey(t) { return this.fmt.format(new Date(t)) }            // YYYY-MM-DD in the relay's time zone
  monthKey(t) { return this.dayKey(t).slice(0, 7) }             // YYYY-MM

  /** First instant after `t` whose key differs (binary search; handles DST and odd offsets). */
  nextBoundary(t, keyOf, span) {
    const k = keyOf(t)
    let lo = t, hi = t + span
    if (keyOf(hi) === k) return hi
    while (hi - lo > 1) { const mid = Math.floor((lo + hi) / 2); if (keyOf(mid) === k) lo = mid; else hi = mid }
    return hi
  }

  /** The newest ticket seen for an account: {iat, quota} or null. */
  record(acct) {
    if (this.latest.has(acct)) return this.latest.get(acct)
    const row = this.store.get('acctQuotaGet', acct)
    let rec = null
    if (row) { let q = null; try { q = quotaOfTicket(JSON.parse(row.quota ?? 'null')) } catch { /* unreadable: as if absent */ } rec = { iat: row.iat, quota: q } }
    if (this.latest.size > 50_000) this.latest.clear()
    this.latest.set(acct, rec)
    return rec
  }

  /**
   * A ticket was accepted (WebSocket or HTTP auth). If it is the newest ticket seen for its account, its caps become
   * the account's caps for every device: a quota change takes effect as soon as any device of the account renews.
   */
  observe(ident) {
    if (!ident?.acct || !Number.isSafeInteger(ident.iat)) return
    const cur = this.record(ident.acct)
    if (cur && cur.iat >= ident.iat) return
    const q = quotaOfTicket(ident.quota)
    this.store.run('acctQuotaPut', ident.acct, ident.iat, q ? JSON.stringify(q) : null)
    this.latest.set(ident.acct, { iat: ident.iat, quota: q })
  }

  /** The account is gone from this relay (purge): forget its newest ticket too. */
  forget(acct) {
    this.store.run('acctQuotaDel', acct)
    this.latest.delete(acct)
    this.objBytes.delete(acct)
  }

  /** Caps in bytes for an account (day, month, store: 0 = unlimited; small: 0 = no allowance), plus the small-file size. */
  caps(acct, ident = null) {
    const c = this.cfg
    let t = null
    if (c.useTicketQuota !== false) {
      const rec = this.record(acct)
      t = rec ? rec.quota : ident?.acct === acct ? quotaOfTicket(ident.quota) : null
    }
    const pick = (name) => {
      const v = t && num(t[name]) !== null ? t[name] : num(c[name])
      return v ? Math.round(v * MB) : 0
    }
    return { day: pick('dayMB'), month: pick('monthMB'), store: pick('storeMB'), small: pick('smallMB'), smallFile: this.smallFile }
  }

  usage(acct, ident = null, caps = this.caps(acct, ident)) {
    const now = this.now()
    const used = (p) => this.store.get('trafGet', acct, p)?.bytes ?? 0
    return {
      day: { used: used(`d:${this.dayKey(now)}`), cap: caps.day },
      month: { used: used(`m:${this.monthKey(now)}`), cap: caps.month },
      small: { used: used(`s:${this.dayKey(now)}`), cap: caps.small, file: caps.smallFile },
      // objects and blobs (reservations included) together
      store: { used: (this.store.get('blobStoreUsed', acct)?.b ?? 0) + this.objectsUsed(acct), cap: caps.store },
    }
  }

  /** Throw `quota` if keeping `bytes` more for the account would pass its stored-bytes cap (object writes). */
  checkStore(acct, ident, bytes) {
    if (!(bytes > 0)) return
    const caps = this.caps(acct, ident)
    if (!caps.store) return
    const u = this.usage(acct, ident, caps)
    if (u.store.used + bytes > u.store.cap) fail('quota', 'stored bytes', { quota: { day: u.day, month: u.month, small: u.small, store: u.store }, retryAfter: 3600 })
  }

  /** Whether `bytes` more fit the day and month caps. */
  static fits(u, bytes) {
    return !(u.day.cap && u.day.used + bytes > u.day.cap) && !(u.month.cap && u.month.used + bytes > u.month.cap)
  }

  /**
   * Throw `quota` unless moving `bytes` of a blob whose stored size is `blobBytes` fits. Day and month first; when
   * they are used up, a small blob may still go on the small-file allowance. Stored bytes have no allowance.
   * Answers which counter the transfer will go to: 'main' or 'small'.
   */
  check(acct, ident, bytes, { storing = false, blobBytes = bytes } = {}) {
    const caps = this.caps(acct, ident)
    const u = this.usage(acct, ident, caps)
    const now = this.now()
    const overStore = storing && u.store.cap && u.store.used + bytes > u.store.cap
    const report = (what, retryAfter) => fail('quota', what,
      { quota: { day: u.day, month: u.month, small: u.small, ...(storing ? { store: u.store } : {}) }, retryAfter: Math.max(1, retryAfter) })
    if (overStore) report('stored bytes', 3600)
    if (Quota.fits(u, bytes)) return 'main'
    const small = blobBytes <= caps.smallFile && caps.small > 0
    if (small && u.small.used + bytes <= caps.small) return 'small'
    const overMonth = u.month.cap && u.month.used + bytes > u.month.cap
    const tomorrow = () => Math.ceil((this.nextBoundary(now, (x) => this.dayKey(x), 27 * 3_600_000) - now) / 1000)
    // small blobs come back with tomorrow's allowance even when the month is used up
    if (small && bytes <= caps.small) report('daily traffic and small-file allowance', tomorrow())
    if (overMonth) report('monthly traffic', Math.ceil((this.nextBoundary(now, (x) => this.monthKey(x), 32 * 86_400_000) - now) / 1000))
    report('daily traffic', tomorrow())
  }

  /** Count a transfer that happened: day and month while they have room, otherwise the small-file allowance. */
  charge(acct, bytes, { blobBytes = bytes, ident = null } = {}) {
    if (!(bytes > 0)) return
    const now = this.now()
    const caps = this.caps(acct, ident)
    if (!Quota.fits(this.usage(acct, ident, caps), bytes) && blobBytes <= caps.smallFile && caps.small > 0) {
      this.store.run('trafAdd', acct, `s:${this.dayKey(now)}`, bytes)
      return
    }
    this.store.run('trafAdd', acct, `d:${this.dayKey(now)}`, bytes)
    this.store.run('trafAdd', acct, `m:${this.monthKey(now)}`, bytes)
  }

  /** Drop counters older than about three months, and the newest-ticket records of accounts silent for 90 days. */
  sweep() {
    const now = this.now()
    const old = this.monthKey(now - 95 * 86_400_000)
    // keys are "d:YYYY-MM-DD", "s:YYYY-MM-DD" and "m:YYYY-MM"; each sorts lexically by date within its prefix
    this.store.db.prepare("DELETE FROM traffic WHERE ((period LIKE 'd:%' OR period LIKE 's:%') AND substr(period, 3) < ?) OR (period LIKE 'm:%' AND substr(period, 3) < ?)").run(old + '-01', old)
    // tickets live at most a day: an account whose newest ticket is this old has not connected for months
    if (this.store.db.prepare('DELETE FROM acct_quota WHERE iat < ?').run(now - 90 * 86_400_000).changes) this.latest.clear()
  }
}
