// Revocation cut-offs (RELAY.md §3.3, E2EE.md §12.4): "tickets for this address issued before nbf are void";
// gone = the device was revoked or deleted, so everything stored for its address goes too.
//
// Entries remember the device id they were issued for. Coordination gives an address to a new device only 180 days
// after the old one was revoked or deleted (COORD.md §13), the same time relays keep `gone` entries; a cut-off applies
// only to tickets of the same device (or to every ticket of the address when the item names no device).
//
// SPDX-License-Identifier: AGPL-3.0-or-later
import { checkAddr, isInt, DID_RE, verifyCoordDoc, fail } from './proto.mjs'

const DAY = 86_400_000
export const GONE_NBF = Number.MAX_SAFE_INTEGER

export class Cutoffs {
  constructor({ store, now = Date.now }) {
    this.store = store
    this.now = now
    this.map = new Map()
    for (const r of store.all('cutAll')) this.map.set(r.addr, { addr: r.addr, dev: r.dev, acct: r.acct, nbf: r.nbf, gone: !!r.gone, at: r.at, keepUntil: r.keep_until })
  }

  /** null if the ticket may be used, else 'revoked'. */
  check(T) {
    const c = this.map.get(T.addr)
    if (!c) return null
    if (c.dev && c.dev !== T.dev) return null
    return T.iat < c.nbf ? 'revoked' : null
  }

  /** Is the device currently at `addr` (dev, if known) gone? */
  isGone(addr, dev) {
    const c = this.map.get(addr)
    if (!c || !c.gone) return false
    return !c.dev || !dev || c.dev === dev
  }

  /** A new device holds an address that carried a cut-off for another device: forget the old entry. */
  reassigned(addr, dev) {
    const c = this.map.get(addr)
    if (c && c.dev && c.dev !== dev) { this.map.delete(addr); this.store.run('cutDel', addr); return true }
    return false
  }

  /**
   * Verify a signed revocation document and record its items. Returns { acct, applied, changes, next } where
   * changes lists the entries that became stricter (callers close sockets and delete data for them).
   */
  apply(doc, { keys, account }) {
    const now = this.now()
    const D = verifyCoordDoc('revocations', doc, keys, now)
    if (typeof D.acct !== 'string' || !D.acct || !Array.isArray(D.items)) fail('bad-format')
    if (account !== '*' && D.acct !== account) fail('wrong-account')
    const changes = []
    this.store.tx(() => {
      for (const it of D.items) {
        if (!it || !checkAddr(it.addr) || !isInt(it.nbf) || !isInt(it.at ?? 0)) continue
        const dev = typeof it.dev === 'string' && DID_RE.test(it.dev) ? it.dev : null
        const gone = it.gone === true
        const prev = this.map.get(it.addr)
        let next
        if (prev && prev.dev && dev && prev.dev !== dev) {
          if ((it.at ?? 0) < prev.at) continue          // older news about the address's previous device
          next = { addr: it.addr, dev, acct: D.acct, nbf: it.nbf, gone, at: it.at ?? now }
        } else if (prev) {
          next = { addr: it.addr, dev: dev ?? prev.dev, acct: D.acct, nbf: Math.max(prev.nbf, it.nbf), gone: prev.gone || gone, at: Math.max(prev.at, it.at ?? 0) }
          if (next.nbf === prev.nbf && next.gone === prev.gone && next.dev === prev.dev) continue
        } else {
          next = { addr: it.addr, dev, acct: D.acct, nbf: it.nbf, gone, at: it.at ?? now }
        }
        // Tickets live at most 24 h: a plain cut-off matters for 24 h after nbf, kept 48 h more; gone: 180 days.
        next.keepUntil = next.gone ? now + 180 * DAY : Math.min(GONE_NBF, Math.max(next.nbf, now) + 72 * 3_600_000)
        this.map.set(it.addr, next)
        this.store.run('cutPut', next.addr, next.dev, next.acct, next.nbf, next.gone ? 1 : 0, next.at, next.keepUntil)
        changes.push({ ...next, newlyGone: next.gone && !prev?.gone })
      }
    })
    return { acct: D.acct, applied: changes.length, changes, next: isInt(D.next) ? D.next : null }
  }

  sweep() {
    const now = this.now()
    for (const r of this.store.all('cutOld', now)) { this.map.delete(r.addr); this.store.run('cutDel', r.addr) }
  }
}
