// Free space on the data directory's disk (RELAY.md §8.4). Below `disk.minFreeMB` the relay stores nothing new on that
// disk — objects, attachments kept on disk, envelopes queued for offline devices — and answers 503 `full`. Reads,
// deletes, live delivery and attachments that go to a bucket carry on: a relay on the system disk must not fill it.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
import fs from 'node:fs'
import { fail } from './proto.mjs'

const MB = 1024 * 1024
const CACHE_MS = 2000        // statfs at most every 2 s; the margin (GBs) absorbs what is written meanwhile

export class DiskGuard {
  /** statfs: (dir) → {bavail, bsize} (tests pass a fake one). */
  constructor({ dir, minFreeMB, log = null, statfs = (d) => fs.statfsSync(d) }) {
    this.dir = dir
    this.min = typeof minFreeMB === 'number' && Number.isFinite(minFreeMB) && minFreeMB > 0 ? Math.round(minFreeMB * MB) : 0
    this.log = log
    this.statfs = statfs
    this.at = 0
    this.value = null        // bytes free for this process; null = the system cannot tell
    this.low = false         // last state logged
  }

  /** Bytes free on the data directory's disk, or null when unknown. */
  free() {
    const t = Date.now()
    if (t - this.at < CACHE_MS) return this.value
    this.at = t
    try {
      const s = this.statfs(this.dir)
      const v = Number(s.bavail) * Number(s.bsize)
      this.value = Number.isFinite(v) && v >= 0 ? v : null
    } catch { this.value = null }
    if (this.value !== null && this.min) {
      const low = this.value < this.min
      if (low !== this.low) {
        this.low = low
        this.log?.[low ? 'warn' : 'info'](low ? 'disk-low' : 'disk-ok', { freeMB: Math.floor(this.value / MB), minMB: Math.round(this.min / MB) })
      }
    }
    return this.value
  }

  /** Throw `full` (503) unless `bytes` more still leave the minimum free. Unknown free space never blocks. */
  check(bytes = 0) {
    if (!this.min) return
    const f = this.free()
    if (f !== null && f - bytes < this.min) fail('full', 'disk nearly full', { retryAfter: 600 })
  }

  /** check() as a boolean (envelope queueing answers `full` in its `sent` frame instead of an HTTP error). */
  ok(bytes = 0) {
    try { this.check(bytes); return true } catch { return false }
  }

  /** Forget the cached figure (the next check asks the system again). */
  refresh() { this.at = 0 }
}
