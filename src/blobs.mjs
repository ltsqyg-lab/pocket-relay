// Blobs (RELAY.md §6.4, §8, §9): PKB1 ciphertext streams on local disk or in an S3-compatible bucket, uploaded
// directly or through presigned PUTs, downloaded directly (Range supported) or through 302s to presigned GETs.
// Disk names are the hex of the blob id (base64url differs only by letter case, unsafe on case-insensitive disks).
// With a bucket configured the relay's own disk takes a blob only when the bucket was unreachable at reservation time.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
import fs from 'node:fs'
import path from 'node:path'
import crypto from 'node:crypto'
import { pipeline } from 'node:stream/promises'
import { Transform } from 'node:stream'
import { fail, isInt, parseBlobId, blobBytesValid, blobSizeFor, checkBlobHeader, BLOB_HEADER, RelayError } from './proto.mjs'
import { S3Backend } from './s3.mjs'

const MIN = 60_000, HOUR = 3_600_000, DAY = 86_400_000
const RESERVATION_MS = HOUR
// A presigned PUT can be used again for as long as it is valid, so it is short: the upload has to start within
// 15 minutes of the reservation (one that started keeps going after the expiry).
const PRESIGN_PUT_S = 900
// An upload that lands after its blob row is gone (the reservation expired, the blob was deleted, the account purged)
// leaves an object nothing points to. The relay remembers each presigned PUT for a day and deletes such objects (§9).
const PRESIGN_WATCH_MS = DAY
const PRESIGN_SWEEP_MAX = 2000
// A presigned GET can be replayed until it expires and serves the whole object whatever Range the client asked the
// relay for, so each 302 charges the stored size and the URL lives just long enough to be followed (clients follow
// at once; a download that started keeps going after the expiry).
const PRESIGN_GET_S = 120

export class Blobs {
  constructor({ cfg, store, quota, now = Date.now, log, env = process.env, fetchImpl = globalThis.fetch, cnip, access, disk = null }) {
    this.store = store
    this.quota = quota
    this.now = now
    this.log = log
    this.access = access
    this.cnip = cnip
    this.disk = disk
    this.limits = cfg.limits
    this.retention = cfg.retention
    this.maxBytes = blobSizeFor(cfg.limits.blob)
    this.backends = cfg.blobs.store === 's3' ? cfg.blobs.backends.map((b) => new S3Backend(b, { env, now, fetchImpl })) : []
    this.inflight = new Map()        // uploader addr -> direct uploads in progress
    this.uploading = new Set()       // "realm/blobId" of direct uploads in progress: their reservations are not swept
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
  reserve(ident, realm, id, bytes, ip) {
    this.access.writeBlob(ident, realm)
    const blobId = this.parse(realm, id)
    if (!isInt(bytes, 1) || bytes > this.maxBytes || !blobBytesValid(bytes)) fail('bad-blob', 'size is not a PKB1 stream size within the limit')
    const now = this.now()
    const prev = this.store.get('blobGet', realm, id)
    if (prev && prev.state !== 'reserved') fail('exists')
    if (prev && prev.uploader !== ident.addr && prev.expires > now) fail('exists')
    if (this.uploading.has(`${realm}/${id}`)) fail('rate', 'an upload of this blob is under way')
    if ((this.store.get('blobActiveRes', ident.addr, now - 10 * 60_000)?.n ?? 0) >= this.limits.blobUploadsPerDevice && !prev) fail('rate', 'too many uploads at once')
    const acct = this.access.realmAcct(ident, realm)
    this.quota.check(acct, ident, bytes, { storing: true, blobBytes: bytes })
    const be = this.pick(ip)
    if (!be) this.disk?.check(bytes)                 // this one will be kept on the relay's own disk (§8.4)
    if (prev) this.store.run('blobReplaceReservation', bytes, be ? 's3' : 'disk', be?.name ?? null, ident.addr, now, now + RESERVATION_MS, realm, id)
    else this.store.run('blobReserve', realm, id, acct, bytes, be ? 's3' : 'disk', be?.name ?? null, ident.addr, now, now + RESERVATION_MS)
    if (!be) return { mode: 'direct' }
    this.store.run('presignPut', realm, id, be.name, now)
    const p = be.presignPut(be.keyOf(realm, id), bytes, PRESIGN_PUT_S)
    return { mode: 'presigned', url: p.url, method: 'PUT', headers: p.headers, expires: now + PRESIGN_PUT_S * 1000 }
  }

  /**
   * PUT …/{blobId}: direct upload, streamed to a temporary file, header and length checked, then moved in place.
   * With a bucket configured only a reservation in mode "direct" (the bucket was unreachable) may be filled this way:
   * a PUT used to be reserved on the spot and kept on this disk, which let anyone bypass the bucket (red team
   * 2026-10-09). Without a bucket a PUT still reserves on the spot (§6.4).
   */
  async putDirect(ident, realm, id, req, ip) {
    this.access.writeBlob(ident, realm)
    const blobId = this.parse(realm, id)
    const len = Number(req.headers['content-length'])
    if (req.headers['transfer-encoding'] || !isInt(len, 1)) fail('bad-request', 'Content-Length required')
    const key = `${realm}/${id}`
    if (this.uploading.has(key)) fail('rate', 'an upload of this blob is under way')
    let row = this.store.get('blobGet', realm, id)
    if (row && row.state !== 'reserved') fail('exists')
    const live = !!row && row.expires > this.now()
    if (this.backends.length) {
      if (!live || row.store !== 'disk') fail('denied', 'reserve first and upload the way the reservation says')
    } else if (!live) {
      this.reserve(ident, realm, id, len, ip)
      row = this.store.get('blobGet', realm, id)
    }
    if (row.uploader !== ident.addr) fail('denied')
    if (len !== row.bytes) fail('size', 'Content-Length differs from the reservation')
    this.disk?.check(len)
    const n = this.inflight.get(ident.addr) ?? 0
    if (n >= this.limits.blobUploadsPerDevice) fail('rate', 'too many uploads at once')
    this.inflight.set(ident.addr, n + 1)
    this.uploading.add(key)
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
      // the reservation may have gone while the bytes came in (blob deleted, realm or account purged): so does the file
      const cur = this.store.get('blobGet', realm, id)
      if (!cur || cur.state !== 'reserved' || cur.uploader !== ident.addr || cur.bytes !== len) fail('not-found', 'the reservation is gone')
      const dest = this.diskPath(realm, blobId)
      fs.mkdirSync(path.dirname(dest), { recursive: true, mode: 0o700 })
      fs.renameSync(tmp, dest)
      if (cur.store === 's3' && cur.backend) this.delRemote(cur.backend, realm, id)   // left from a bucket no longer configured
      this.store.run('blobCommit', 'disk', null, this.now(), realm, id)
      this.quota.charge(row.acct, len, { blobBytes: len, ident })
      return { bytes: len }
    } catch (e) {
      try { fs.unlinkSync(tmp) } catch { /* not created */ }
      if (e instanceof RelayError) throw e
      fail('bad-request', 'upload interrupted')
    } finally {
      this.uploading.delete(key)
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
    this.quota.charge(row.acct, row.bytes, { blobBytes: row.bytes, ident })
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
    // a small blob may still go on the small-file allowance once the day or month is used up: small by its whole
    // size, so a large blob read in small ranges does not count as small (RELAY.md §8.3)
    this.quota.check(row.acct, ident, charge, { blobBytes: size })
    if (row.store === 's3') {
      const be = this.backend(row.backend)
      if (!be) fail('storage')
      this.quota.charge(row.acct, charge, { blobBytes: size, ident })
      this.touch(row, realm, id)          // the URL serves the whole object, and the whole size was charged
      res.writeHead(302, { Location: be.presignGet(be.keyOf(realm, id), PRESIGN_GET_S), 'Cache-Control': 'no-store', 'Content-Length': '0' })
      return res.end()
    }
    const file = this.diskPath(realm, blobId)
    let fd
    try { fd = fs.openSync(file, 'r') } catch { fail('not-found') }
    this.quota.charge(row.acct, charge, { blobBytes: size, ident })
    const headers = { 'Content-Type': 'application/octet-stream', 'Content-Length': String(charge), 'Accept-Ranges': 'bytes', 'Cache-Control': 'private, no-store' }
    if (partial) headers['Content-Range'] = `bytes ${start}-${end}/${size}`
    res.writeHead(partial ? 206 : 200, headers)
    const done = await pipeline(fs.createReadStream(null, { fd, start, end }), res).then(() => true, () => false)   // false: the client went away
    // retention counts downloads (§8.2): one that delivered at least half of the blob. A few bytes of a range used to
    // keep a blob alive for ever (red team 2026-10-09).
    if (done && 2 * charge >= size) this.touch(row, realm, id)
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

  /**
   * Objects that presigned PUTs left in a bucket with no blob row pointing to them (§9): each presigned PUT is looked
   * at once its URL can no longer start an upload, and again at every sweep for a day (an upload that started in time
   * may land late). An object whose blob is not committed there — and not being uploaded — is deleted.
   */
  async sweepPresigned(now = this.now()) {
    let deleted = 0
    const down = new Set()
    for (const p of this.store.all('presignDue', now - PRESIGN_PUT_S * 1000 - 5 * MIN, PRESIGN_SWEEP_MAX)) {
      const done = () => this.store.run('presignDel', p.realm, p.blob, p.backend)
      const old = p.at < now - PRESIGN_WATCH_MS
      const committed = (r) => r?.state === 'ready' && r.store === 's3' && r.backend === p.backend
      const row = this.store.get('blobGet', p.realm, p.blob)
      if (committed(row)) { done(); continue }                   // the object there is the blob
      if (row?.state === 'reserved') { if (old) done(); continue }   // a new reservation of the same blob is under way
      const be = this.backend(p.backend)
      if (!be) { done(); continue }                              // that bucket is no longer configured
      if (down.has(p.backend)) continue
      const key = be.keyOf(p.realm, p.blob)
      try {
        const h = await be.head(key)
        if (h.status === 200) {
          const again = this.store.get('blobGet', p.realm, p.blob)
          if (!committed(again) && again?.state !== 'reserved') { await be.del(key); deleted++ }
        } else if (h.status !== 404) throw new Error(`HTTP ${h.status}`)
      } catch { down.add(p.backend); continue }                  // try again at the next sweep
      if (old) done()
    }
    if (deleted) this.log?.info('presign-orphans', { deleted })
    return deleted
  }

  /** Expired reservations, blobs not downloaded for blobDays (or never, since upload), retries of failed deletes. */
  async sweep() {
    const now = this.now()
    let n = 0
    for (const r of this.store.all('blobExpiredRes', now)) {
      if (this.uploading.has(`${r.realm}/${r.blob}`)) continue   // its bytes are still coming in
      await this.drop(r); n++
    }
    for (const r of this.store.all('blobStale', now - this.retention.blobDays * DAY)) { await this.drop(r); n++ }
    for (const r of this.store.all('blobDead')) { if (await this.drop(r)) n++ }
    if (this.backends.length) n += await this.sweepPresigned(now)
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
