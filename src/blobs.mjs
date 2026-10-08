// Blobs (RELAY.md §6.4, §8, §9): PKB1 ciphertext streams on local disk or in an S3-compatible bucket, uploaded
// directly or through presigned PUTs, downloaded directly (Range supported) or through 302s to presigned GETs.
// Disk names are the hex of the blob id (base64url differs only by letter case, unsafe on case-insensitive disks).
//
// SPDX-License-Identifier: AGPL-3.0-or-later
import fs from 'node:fs'
import path from 'node:path'
import crypto from 'node:crypto'
import { pipeline } from 'node:stream/promises'
import { Transform } from 'node:stream'
import { fail, isInt, parseBlobId, blobBytesValid, blobSizeFor, checkBlobHeader, BLOB_HEADER, RelayError } from './proto.mjs'
import { S3Backend } from './s3.mjs'

const HOUR = 3_600_000, DAY = 86_400_000
const RESERVATION_MS = HOUR
const PRESIGN_PUT_S = 3600
// A presigned GET can be replayed until it expires and serves the whole object whatever Range the client asked the
// relay for, so each 302 charges the stored size and the URL lives just long enough to be followed (clients follow
// at once; a download that started keeps going after the expiry).
const PRESIGN_GET_S = 120

export class Blobs {
  constructor({ cfg, store, quota, now = Date.now, log, env = process.env, fetchImpl = globalThis.fetch, cnip, access }) {
    this.store = store
    this.quota = quota
    this.now = now
    this.log = log
    this.access = access
    this.cnip = cnip
    this.limits = cfg.limits
    this.retention = cfg.retention
    this.maxBytes = blobSizeFor(cfg.limits.blob)
    this.backends = cfg.blobs.store === 's3' ? cfg.blobs.backends.map((b) => new S3Backend(b, { env, now, fetchImpl })) : []
    this.inflight = new Map()        // uploader addr -> direct uploads in progress
  }

  get presign() { return this.backends.length > 0 }

  diskPath(realm, blobId) { return path.join(this.store.dir, 'b', realm, blobId.toString('hex')) }

  /** The backend for a new blob from this client IP, or null for local disk (no S3, or bucket unreachable). */
  pick(ip) {
    for (const b of this.backends) {
      if ((b.when === 'cn-ip' && this.cnip.matches(ip)) || b.when === 'default') return b.healthy ? b : null
    }
    return null
  }
  backend(name) { return this.backends.find((b) => b.name === name) ?? null }

  async probe() { for (const b of this.backends) { const was = b.healthy; await b.probe(); if (was !== b.healthy) this.log?.warn('s3-health', { backend: b.name, healthy: b.healthy }) } }

  parse(realm, id) {
    const blobId = parseBlobId(id)
    if (!blobId) fail('not-found')
    return blobId
  }

  /** POST …/upload {bytes}: reserve. */
  reserve(ident, realm, id, bytes, ip, { forceDisk = false } = {}) {
    this.access.writeBlob(ident, realm)
    const blobId = this.parse(realm, id)
    if (!isInt(bytes, 1) || bytes > this.maxBytes || !blobBytesValid(bytes)) fail('bad-blob', 'size is not a PKB1 stream size within the limit')
    const now = this.now()
    const prev = this.store.get('blobGet', realm, id)
    if (prev && prev.state !== 'reserved') fail('exists')
    if (prev && prev.uploader !== ident.addr && prev.expires > now) fail('exists')
    if ((this.store.get('blobActiveRes', ident.addr, now - 10 * 60_000)?.n ?? 0) >= this.limits.blobUploadsPerDevice && !prev) fail('rate', 'too many uploads at once')
    const acct = this.access.realmAcct(ident, realm)
    this.quota.check(acct, ident, bytes, { storing: true })
    const be = forceDisk ? null : this.pick(ip)
    if (prev) this.store.run('blobReplaceReservation', bytes, be ? 's3' : 'disk', be?.name ?? null, ident.addr, now, now + RESERVATION_MS, realm, id)
    else this.store.run('blobReserve', realm, id, acct, bytes, be ? 's3' : 'disk', be?.name ?? null, ident.addr, now, now + RESERVATION_MS)
    if (!be) return { mode: 'direct' }
    const p = be.presignPut(be.keyOf(realm, id), bytes, PRESIGN_PUT_S)
    return { mode: 'presigned', url: p.url, method: 'PUT', headers: p.headers, expires: now + PRESIGN_PUT_S * 1000 }
  }

  /** PUT …/{blobId}: direct upload, streamed to a temporary file, header and length checked, then moved in place. */
  async putDirect(ident, realm, id, req, ip) {
    this.access.writeBlob(ident, realm)
    const blobId = this.parse(realm, id)
    const len = Number(req.headers['content-length'])
    if (req.headers['transfer-encoding'] || !isInt(len, 1)) fail('bad-request', 'Content-Length required')
    let row = this.store.get('blobGet', realm, id)
    if (row && row.state !== 'reserved') fail('exists')
    if (!row || row.expires <= this.now()) {
      this.reserve(ident, realm, id, len, ip, { forceDisk: true })
      row = this.store.get('blobGet', realm, id)
    }
    if (row.uploader !== ident.addr) fail('denied')
    if (len !== row.bytes) fail('size', 'Content-Length differs from the reservation')
    const n = this.inflight.get(ident.addr) ?? 0
    if (n >= this.limits.blobUploadsPerDevice) fail('rate', 'too many uploads at once')
    this.inflight.set(ident.addr, n + 1)
    const tmp = path.join(this.store.dir, 'tmp', `b-${crypto.randomBytes(9).toString('hex')}`)
    try {
      let got = 0, head = Buffer.alloc(0), headOk = false
      const check = new Transform({
        transform(chunk, _enc, cb) {
          got += chunk.length
          if (got > len) return cb(new RelayError('too-large'))
          if (!headOk) {
            head = Buffer.concat([head, chunk.subarray(0, BLOB_HEADER - head.length)])
            if (head.length >= BLOB_HEADER) {
              if (!checkBlobHeader(head, blobId)) return cb(new RelayError('bad-blob', 'header'))
              headOk = true
            }
          }
          cb(null, chunk)
        },
      })
      await pipeline(req, check, fs.createWriteStream(tmp, { mode: 0o600 }))
      if (got !== len || !headOk) fail('bad-request', 'body shorter than Content-Length')
      const dest = this.diskPath(realm, blobId)
      fs.mkdirSync(path.dirname(dest), { recursive: true, mode: 0o700 })
      fs.renameSync(tmp, dest)
      const old = this.store.get('blobGet', realm, id)
      if (old?.store === 's3' && old.backend) this.delRemote(old.backend, realm, id)   // abandoned presigned upload, if any
      this.store.run('blobCommit', 'disk', null, this.now(), realm, id)
      this.quota.charge(row.acct, len)
      return { bytes: len }
    } catch (e) {
      try { fs.unlinkSync(tmp) } catch { /* not created */ }
      if (e instanceof RelayError) throw e
      fail('bad-request', 'upload interrupted')
    } finally {
      const m = (this.inflight.get(ident.addr) ?? 1) - 1
      if (m > 0) this.inflight.set(ident.addr, m); else this.inflight.delete(ident.addr)
    }
  }

  /** POST …/commit: a presigned upload finished; check the bucket object's size and header. */
  async commit(ident, realm, id, bytes) {
    this.access.writeBlob(ident, realm)
    const blobId = this.parse(realm, id)
    const row = this.store.get('blobGet', realm, id)
    if (!row) fail('not-found')
    if (row.state === 'ready') { if (isInt(bytes) && bytes !== row.bytes) fail('size'); return { bytes: row.bytes } }
    if (row.state !== 'reserved') fail('not-found')
    if (row.uploader !== ident.addr) fail('denied')
    if (isInt(bytes) && bytes !== row.bytes) fail('size')
    if (row.store !== 's3') fail('size', 'nothing uploaded')
    const be = this.backend(row.backend)
    if (!be) fail('storage')
    const key = be.keyOf(realm, id)
    let h
    try { h = await be.head(key) } catch { fail('storage') }
    if (h.status === 404) fail('size', 'nothing uploaded')
    if (h.status !== 200) fail('storage')
    if (h.size !== row.bytes) { await this.delRemote(be.name, realm, id); fail('size') }
    try {
      const r = await be.fetch(be.presignGet(key, 60), { headers: { Range: `bytes=0-${BLOB_HEADER - 1}` }, signal: AbortSignal.timeout(15_000), redirect: 'error' })
      const head = Buffer.from(await r.arrayBuffer())
      if (!(r.status === 206 || r.status === 200) || !checkBlobHeader(head.subarray(0, BLOB_HEADER), blobId)) {
        await this.delRemote(be.name, realm, id)
        fail('bad-blob', 'header')
      }
    } catch (e) { if (e instanceof RelayError) throw e; fail('storage') }
    this.store.run('blobCommit', 's3', be.name, this.now(), realm, id)
    this.quota.charge(row.acct, row.bytes)
    return { bytes: row.bytes }
  }

  ready(ident, realm, id) {
    this.access.read(ident, realm)
    const blobId = this.parse(realm, id)
    const row = this.store.get('blobGet', realm, id)
    if (!row || row.state !== 'ready') fail('not-found')
    return { row, blobId }
  }

  /** GET / HEAD …/{blobId}. Writes the response itself (streams, 206, 302). */
  async send(ident, realm, id, req, res, { head = false } = {}) {
    const { row, blobId } = this.ready(ident, realm, id)
    const size = row.bytes
    let start = 0, end = size - 1, partial = false
    const range = req.headers.range
    if (range && !head) {
      const m = /^bytes=(\d*)-(\d*)$/.exec(String(range).trim())
      if (!m || (m[1] === '' && m[2] === '')) { res.writeHead(416, { 'Content-Range': `bytes */${size}` }); return res.end() }
      if (m[1] === '') { start = Math.max(0, size - Number(m[2])); end = size - 1 }
      else { start = Number(m[1]); end = m[2] === '' ? size - 1 : Math.min(Number(m[2]), size - 1) }
      if (start > end || start >= size) { res.writeHead(416, { 'Content-Range': `bytes */${size}` }); return res.end() }
      partial = true
    }
    const charge = row.store === 's3' ? size : end - start + 1
    if (head) {
      res.writeHead(200, { 'Content-Type': 'application/octet-stream', 'Content-Length': String(size), 'Accept-Ranges': 'bytes', 'Cache-Control': 'private, no-store' })
      return res.end()
    }
    this.quota.check(row.acct, ident, charge)
    this.touch(row, realm, id)
    if (row.store === 's3') {
      const be = this.backend(row.backend)
      if (!be) fail('storage')
      this.quota.charge(row.acct, charge)
      res.writeHead(302, { Location: be.presignGet(be.keyOf(realm, id), PRESIGN_GET_S), 'Cache-Control': 'no-store', 'Content-Length': '0' })
      return res.end()
    }
    const file = this.diskPath(realm, blobId)
    let fd
    try { fd = fs.openSync(file, 'r') } catch { fail('not-found') }
    this.quota.charge(row.acct, charge)
    const headers = { 'Content-Type': 'application/octet-stream', 'Content-Length': String(charge), 'Accept-Ranges': 'bytes', 'Cache-Control': 'private, no-store' }
    if (partial) headers['Content-Range'] = `bytes ${start}-${end}/${size}`
    res.writeHead(partial ? 206 : 200, headers)
    await pipeline(fs.createReadStream(null, { fd, start, end }), res).catch(() => { /* client went away */ })
  }

  touch(row, realm, id) {
    const now = this.now()
    if (!row.last_read || now - row.last_read > HOUR) this.store.run('blobTouch', now, realm, id)
  }

  /** DELETE: the realm's owner or the uploader. */
  async del(ident, realm, id) {
    const blobId = this.parse(realm, id)
    const row = this.store.get('blobGet', realm, id)
    if (!row || row.state === 'dead') fail('not-found')
    this.access.deleteBlob(ident, realm, row)
    await this.drop(row, blobId)
    return { ok: true }
  }

  delRemote(name, realm, id) {
    const be = this.backend(name)
    if (!be) return Promise.resolve()
    return be.del(be.keyOf(realm, id)).catch((e) => this.log?.warn('s3-delete-failed', { backend: name, error: String(e?.message || e).slice(0, 80) }))
  }

  /** Remove the bytes, then the row; S3 failures leave a `dead` row for the sweep to retry. */
  async drop(row, blobId = parseBlobId(row.blob)) {
    if (row.store === 's3' && row.backend) {
      const be = this.backend(row.backend)
      if (be) {
        try { await be.del(be.keyOf(row.realm, row.blob)) } catch { this.store.run('blobMarkDead', row.realm, row.blob); return false }
      }
    }
    if (blobId) { try { fs.unlinkSync(this.diskPath(row.realm, blobId)) } catch { /* not on disk */ } }
    this.store.run('blobDel', row.realm, row.blob)
    return true
  }

  async purgeRealm(realm) {
    const rows = this.store.all('blobsOfRealm', realm)
    for (const r of rows) await this.drop(r)
    try { fs.rmSync(path.join(this.store.dir, 'b', realm), { recursive: true, force: true }) } catch { /* nothing */ }
    return rows.filter((r) => r.state === 'ready').length
  }

  async purgeAcct(acct) {
    const rows = this.store.all('blobsOfAcct', acct)
    for (const r of rows) await this.drop(r)
    return rows.filter((r) => r.state === 'ready').length
  }

  /** Expired reservations, blobs not downloaded for blobDays (or never, since upload), retries of failed deletes. */
  async sweep() {
    const now = this.now()
    let n = 0
    for (const r of this.store.all('blobExpiredRes', now)) { await this.drop(r); n++ }
    for (const r of this.store.all('blobStale', now - this.retention.blobDays * DAY)) { await this.drop(r); n++ }
    for (const r of this.store.all('blobDead')) { if (await this.drop(r)) n++ }
    // temporary files left by crashes
    try {
      const tdir = path.join(this.store.dir, 'tmp')
      for (const f of fs.readdirSync(tdir)) {
        const p = path.join(tdir, f)
        try { if (now - fs.statSync(p).mtimeMs > 6 * HOUR) fs.unlinkSync(p) } catch { /* raced */ }
      }
    } catch { /* no tmp */ }
    return n
  }
}
