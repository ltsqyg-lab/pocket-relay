// Blob traffic quotas per account (RELAY.md §8.3): uploads and downloads per day and per month in the configured
// time zone, and optionally stored bytes. Caps come from the configuration or, when useTicketQuota is set, from the
// caller's ticket (`quota: {dayMB, monthMB, storeMB}`, 0 = unlimited).
//
// SPDX-License-Identifier: AGPL-3.0-or-later
import { fail } from './proto.mjs'

const MB = 1024 * 1024

export class Quota {
  constructor({ store, timezone, quota, now = Date.now }) {
    this.store = store
    this.now = now
    this.cfg = quota || {}
    this.fmt = new Intl.DateTimeFormat('en-CA', { timeZone: timezone, year: 'numeric', month: '2-digit', day: '2-digit' })
  }

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

  /** Caps in bytes (0 = unlimited) for a caller identity. */
  caps(ident) {
    const c = this.cfg
    const t = c.useTicketQuota !== false && ident?.quota && typeof ident.quota === 'object' ? ident.quota : null
    const pick = (name) => {
      const v = t && Number.isFinite(t[name]) ? t[name] : c[name]
      return Number.isFinite(v) && v > 0 ? Math.round(v * MB) : 0
    }
    return { day: pick('dayMB'), month: pick('monthMB'), store: pick('storeMB') }
  }

  usage(acct, ident) {
    const now = this.now()
    const caps = this.caps(ident)
    const used = (p) => this.store.get('trafGet', acct, p)?.bytes ?? 0
    return {
      day: { used: used(`d:${this.dayKey(now)}`), cap: caps.day },
      month: { used: used(`m:${this.monthKey(now)}`), cap: caps.month },
      store: { used: this.store.get('blobStoreUsed', acct)?.b ?? 0, cap: caps.store },
    }
  }

  /** Throw `quota` if moving `bytes` (and, for uploads, storing them) would exceed a cap. */
  check(acct, ident, bytes, { storing = false } = {}) {
    const u = this.usage(acct, ident)
    const now = this.now()
    const overDay = u.day.cap && u.day.used + bytes > u.day.cap
    const overMonth = u.month.cap && u.month.used + bytes > u.month.cap
    const overStore = storing && u.store.cap && u.store.used + bytes > u.store.cap
    if (!overDay && !overMonth && !overStore) return u
    let retryAfter = 3600
    if (overMonth) retryAfter = Math.ceil((this.nextBoundary(now, (x) => this.monthKey(x), 32 * 86_400_000) - now) / 1000)
    else if (overDay) retryAfter = Math.ceil((this.nextBoundary(now, (x) => this.dayKey(x), 27 * 3_600_000) - now) / 1000)
    fail('quota', overStore ? 'stored bytes' : overMonth ? 'monthly traffic' : 'daily traffic',
      { quota: { day: u.day, month: u.month, ...(storing ? { store: u.store } : {}) }, retryAfter: Math.max(1, retryAfter) })
  }

  charge(acct, bytes) {
    if (!(bytes > 0)) return
    const now = this.now()
    this.store.run('trafAdd', acct, `d:${this.dayKey(now)}`, bytes)
    this.store.run('trafAdd', acct, `m:${this.monthKey(now)}`, bytes)
  }

  /** Drop counters older than about three months. */
  sweep() {
    const now = this.now()
    const old = this.monthKey(now - 95 * 86_400_000)
    // keys are "d:YYYY-MM-DD" and "m:YYYY-MM"; both sort lexically by date within their prefix
    this.store.db.prepare("DELETE FROM traffic WHERE (period LIKE 'd:%' AND substr(period, 3) < ?) OR (period LIKE 'm:%' AND substr(period, 3) < ?)").run(old + '-01', old)
  }
}
