// Coordination public keys (E2EE.md §12.1): pinned keys from the configuration bootstrap trust; the relay then
// refreshes <coord.url>/.well-known/pocket/keys.json every few hours (and when a ticket names an unknown key id) and
// adopts a new set only if it is signed by a key it already trusts for `keys`.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
import { verifyKeysDoc, validKeyRecord } from './proto.mjs'

const MIN_REFRESH_GAP = 60_000

export class CoordKeys {
  constructor({ pinned, url, store, now = Date.now, log, fetchImpl = globalThis.fetch, refreshHours = 6 }) {
    this.pinned = pinned.filter(validKeyRecord)
    this.url = url
    this.store = store
    this.now = now
    this.log = log
    this.fetch = fetchImpl
    this.refreshMs = Math.max(1, refreshHours) * 3_600_000
    this.adopted = []
    this.lastTry = 0
    this.inflight = null
    this.timer = null
    try {
      const saved = JSON.parse(store.meta('coordKeys') || '[]')
      if (Array.isArray(saved)) this.adopted = saved.filter(validKeyRecord)
    } catch { /* nothing saved */ }
  }

  /** Trusted keys: pinned first (authoritative for their kid), then adopted ones with other kids. */
  get list() {
    const kids = new Set(this.pinned.map((k) => k.kid))
    return [...this.pinned, ...this.adopted.filter((k) => !kids.has(k.kid))]
  }

  has(kid) { return this.list.some((k) => k.kid === kid) }

  /** Fetch and adopt keys.json. Never throws; returns true when the key set changed. */
  refresh(reason = 'timer') {
    if (!this.url || !this.fetch) return Promise.resolve(false)
    if (this.inflight) return this.inflight
    this.lastTry = this.now()
    this.inflight = (async () => {
      try {
        const r = await this.fetch(`${this.url}/.well-known/pocket/keys.json`, { signal: AbortSignal.timeout(10_000), redirect: 'error' })
        if (!r.ok) throw new Error(`HTTP ${r.status}`)
        const text = await r.text()
        if (text.length > 262144) throw new Error('keys document too large')
        const keys = verifyKeysDoc(JSON.parse(text), this.list, this.now())
        const before = JSON.stringify(this.adopted)
        this.adopted = keys
        const changed = JSON.stringify(keys) !== before
        if (changed) {
          this.store.meta('coordKeys', JSON.stringify(keys))
          this.log?.info('coord-keys', { reason, keys: keys.length })
        }
        return changed
      } catch (e) {
        this.log?.warn('coord-keys-failed', { reason, error: String(e?.code || e?.message || e).slice(0, 120) })
        return false
      } finally {
        this.inflight = null
      }
    })()
    return this.inflight
  }

  /** A ticket named a key id we do not know: refresh unless we just did. */
  async ensure(kid) {
    if (this.has(kid)) return true
    if (this.now() - this.lastTry < MIN_REFRESH_GAP) return false
    await this.refresh('unknown-kid')
    return this.has(kid)
  }

  start() {
    const tick = () => { this.refresh('timer').finally(() => { this.timer = setTimeout(tick, this.refreshMs); this.timer.unref?.() }) }
    this.timer = setTimeout(tick, 5_000)
    this.timer.unref?.()
  }
  stop() { clearTimeout(this.timer) }
}

/** kid of a compact ticket's payload without verifying it (used only to decide whether to refresh keys). */
export function ticketKid(ticket) {
  try {
    const p = String(ticket).split('.')[0]
    const j = JSON.parse(Buffer.from(p, 'base64url').toString('utf8'))
    return typeof j.kid === 'string' ? j.kid : null
  } catch { return null }
}
