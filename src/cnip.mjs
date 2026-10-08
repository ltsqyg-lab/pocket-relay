// The `cn-ip` rule for choosing a blob backend (RELAY.md §9): is the uploading client's IP inside the CIDR list in
// `cnIpFile`? Accepted file formats:
//   - JSON {"v4": [[start, end], …], "v6": [["start", "end"], …]}  (numeric ranges, IPv6 as decimal strings)
//   - JSON ["1.0.1.0/24", "2001:250::/35", …]
//   - plain text, one CIDR per line (# comments allowed)
// The operator refreshes the file (weekly is plenty); the relay re-reads it when its modification time changes.
// Without a usable table every client counts as matching (unknown → the first backend), configurable.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
import fs from 'node:fs'

export function v4num(s) {
  const p = String(s).split('.')
  if (p.length !== 4) return null
  let n = 0
  for (const x of p) {
    if (!/^\d{1,3}$/.test(x)) return null
    const v = Number(x)
    if (v > 255) return null
    n = n * 256 + v
  }
  return n
}
export function v6big(s) {
  s = String(s).split('%')[0]
  if (!s.includes(':')) return null
  const halves = s.split('::')
  if (halves.length > 2) return null
  const parts = (x) => (x ? x.split(':') : [])
  const v4tail = (arr) => {
    const last = arr[arr.length - 1]
    if (!last || !last.includes('.')) return arr
    const n = v4num(last)
    if (n == null) return null
    return [...arr.slice(0, -1), Math.floor(n / 65536).toString(16), (n % 65536).toString(16)]
  }
  let groups
  if (halves.length === 2) {
    const h = parts(halves[0]), t = v4tail(parts(halves[1]))
    if (!t || h.length + t.length > 7) return null
    groups = [...h, ...Array(8 - h.length - t.length).fill('0'), ...t]
  } else {
    groups = v4tail(parts(halves[0]))
    if (!groups) return null
  }
  if (groups.length !== 8) return null
  let n = 0n
  for (const g of groups) {
    if (!/^[0-9a-f]{1,4}$/i.test(g)) return null
    n = (n << 16n) | BigInt(parseInt(g, 16))
  }
  return n
}
function cidr(s) {
  const [a, bitsS] = String(s).trim().split('/')
  const bits = Number(bitsS)
  const n4 = v4num(a)
  if (n4 != null && Number.isInteger(bits) && bits >= 0 && bits <= 32) {
    const size = 2 ** (32 - bits)
    const start = Math.floor(n4 / size) * size
    return { v: 4, r: [start, start + size - 1] }
  }
  const n6 = v6big(a)
  if (n6 != null && Number.isInteger(bits) && bits >= 0 && bits <= 128) {
    const size = 1n << BigInt(128 - bits)
    const start = (n6 / size) * size
    return { v: 6, r: [start, start + size - 1n] }
  }
  return null
}
function inRanges(list, x) {
  let lo = 0, hi = list.length - 1
  while (lo <= hi) {
    const mid = (lo + hi) >> 1
    if (x < list[mid][0]) hi = mid - 1
    else if (x > list[mid][1]) lo = mid + 1
    else return true
  }
  return false
}
const byStart = (a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0)

export function parseTable(text) {
  const v4 = [], v6 = []
  const add = (c) => { if (c) (c.v === 4 ? v4 : v6).push(c.r) }
  let j = null
  try { j = JSON.parse(text) } catch { /* not JSON */ }
  if (j && Array.isArray(j.v4)) {
    for (const r of j.v4) if (Array.isArray(r) && r.length === 2) v4.push([Number(r[0]), Number(r[1])])
    for (const r of j.v6 ?? []) if (Array.isArray(r) && r.length === 2) { try { v6.push([BigInt(r[0]), BigInt(r[1])]) } catch { /* skip */ } }
  } else if (Array.isArray(j)) {
    for (const s of j) add(cidr(s))
  } else {
    for (const line of String(text).split('\n')) { const s = line.replace(/#.*/, '').trim(); if (s) add(cidr(s)) }
  }
  v4.sort(byStart); v6.sort(byStart)
  return { v4, v6 }
}

export class CnIp {
  constructor({ file = null, unknownMatches = true } = {}) {
    this.file = file
    this.unknownMatches = unknownMatches
    this.v4 = []; this.v6 = []
    this.mtime = 0
    this.checked = 0
    this.load()
  }
  load() {
    if (!this.file) return
    try {
      const st = fs.statSync(this.file)
      if (st.mtimeMs === this.mtime) return
      const t = parseTable(fs.readFileSync(this.file, 'utf8'))
      this.v4 = t.v4; this.v6 = t.v6; this.mtime = st.mtimeMs
    } catch { /* keep what we have */ }
  }
  get ready() { return this.v4.length + this.v6.length > 0 }
  /** true / false; when the table is missing or the address unreadable: `unknownMatches`. */
  matches(ip) {
    if (Date.now() - this.checked > 60_000) { this.checked = Date.now(); this.load() }
    if (!this.ready) return this.unknownMatches
    let s = String(ip || '').trim()
    const mapped = s.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/i)
    if (mapped) s = mapped[1]
    const n4 = v4num(s)
    if (n4 != null) return inRanges(this.v4, n4)
    const n6 = v6big(s)
    if (n6 != null) return inRanges(this.v6, n6)
    return this.unknownMatches
  }
}
