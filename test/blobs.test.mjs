// Blobs: reservation, direct and presigned uploads, commit checks, downloads (Range, 302), quotas, retention
// (RELAY.md §6.4, §8, §9).
import test from 'node:test'
import assert from 'node:assert/strict'
import crypto from 'node:crypto'
import fs from 'node:fs'
import path from 'node:path'
import { tfetch, Coord, device, startRelay, httpToken, api, ref, b64u, sleep } from './helpers.mjs'
import { startFakeS3 } from './fake-s3.mjs'

const MB = 1024 * 1024
const blob = (n, id = crypto.randomBytes(16)) => {
  const pt = crypto.randomBytes(n)
  return { id, idS: b64u(id), pt, ct: ref.encryptBlob(crypto.randomBytes(32), id, pt) }
}

test('blobs on disk: reserve, direct upload with header check, download with ranges, delete', async (t) => {
  const coord = new Coord()
  const r = await startRelay(coord)
  t.after(() => r.stop())
  const mac = device('computer'), phone = device('phone'), other = device('phone'), stranger = device('phone')
  const M = api(r, await httpToken(r, coord, mac, { peers: [phone.addr, other.addr] }))
  const P = api(r, await httpToken(r, coord, phone, { peers: [mac.addr] }))
  const O = api(r, await httpToken(r, coord, other, { peers: [mac.addr] }))
  const S = api(r, await httpToken(r, coord, stranger, { peers: [] }))
  const base = `/v1/b/${mac.addr}`

  // the phone uploads an attachment into the computer's realm
  const b = blob(200000)
  let res = await P.post(`${base}/${b.idS}/upload`, { bytes: b.ct.length })
  assert.deepEqual(await res.json(), { mode: 'direct' })
  assert.equal((await O.put(`${base}/${b.idS}`, b.ct)).status, 403, 'someone else cannot fill my reservation')
  res = await P.put(`${base}/${b.idS}`, b.ct)
  assert.equal(res.status, 200)
  assert.deepEqual(await res.json(), { bytes: b.ct.length })
  assert.equal((await P.post(`${base}/${b.idS}/upload`, { bytes: b.ct.length })).status, 409, 'exists')
  assert.equal((await S.post(`${base}/${crypto.randomBytes(16).toString('base64url')}/upload`, { bytes: 38 })).status, 403, 'not a peer')

  // download: whole, ranges, HEAD
  res = await M.get(`${base}/${b.idS}`)
  assert.equal(res.status, 200)
  const got = Buffer.from(await res.arrayBuffer())
  assert.deepEqual(got, b.ct)
  res = await M.get(`${base}/${b.idS}`, { range: 'bytes=0-21' })
  assert.equal(res.status, 206)
  assert.equal(res.headers.get('content-range'), `bytes 0-21/${b.ct.length}`)
  assert.deepEqual(Buffer.from(await res.arrayBuffer()), b.ct.subarray(0, 22))
  res = await M.get(`${base}/${b.idS}`, { range: 'bytes=-16' })
  assert.deepEqual(Buffer.from(await res.arrayBuffer()), b.ct.subarray(b.ct.length - 16))
  res = await M.get(`${base}/${b.idS}`, { range: 'bytes=999999999-' })
  assert.equal(res.status, 416)
  res = await M.head(`${base}/${b.idS}`)
  assert.equal(res.status, 200)
  assert.equal(res.headers.get('content-length'), String(b.ct.length))
  assert.equal((await S.get(`${base}/${b.idS}`)).status, 403)

  // header and size checks on direct upload
  const c = blob(10)
  res = await P.post(`${base}/${c.idS}/upload`, { bytes: c.ct.length })
  assert.equal(res.status, 200)
  const wrongId = Buffer.from(c.ct); wrongId[10] ^= 1
  res = await P.put(`${base}/${c.idS}`, wrongId)
  assert.equal(res.status, 400)
  assert.equal((await res.json()).error, 'bad-blob')
  res = await P.put(`${base}/${c.idS}`, Buffer.concat([c.ct, Buffer.alloc(16)]))
  assert.equal(res.status, 409, 'length differs from the reservation')
  assert.equal((await P.post(`${base}/${c.idS}/upload`, { bytes: 37 })).status, 400, 'not a PKB1 size')
  assert.equal((await P.post(`${base}/notanid/upload`, { bytes: 38 })).status, 404)
  // direct PUT without a reservation reserves on the spot
  const d = blob(1000)
  assert.equal((await M.put(`${base}/${d.idS}`, d.ct)).status, 200)

  // delete: the uploader or the realm's owner; not other readers
  assert.equal((await O.del(`${base}/${b.idS}`)).status, 403)
  assert.equal((await P.del(`${base}/${b.idS}`)).status, 200)
  assert.equal((await M.get(`${base}/${b.idS}`)).status, 404)
  assert.equal((await M.del(`${base}/${d.idS}`)).status, 200)
  assert.equal(fs.readdirSync(path.join(r.dir, 'b', mac.addr)).length, 0, 'files removed')
})

test('blobs in S3: presigned upload, commit checks size and header, 302 downloads work without Authorization', async (t) => {
  const keys = { AKLAB: 'secret-lab-key' }
  const s3 = await startFakeS3({ keys })
  t.after(() => s3.stop())
  const coord = new Coord()
  const cnFile = path.join(fs.mkdtempSync(path.join(process.env.TMPDIR || '/tmp', 'cnip-')), 'cn.txt')
  fs.writeFileSync(cnFile, '10.0.0.0/8\n')
  const backend = (name, when, bucket) => ({ name, when, endpoint: s3.url, region: 'lab-1', bucket, accessKeyEnv: 'K', secretKeyEnv: 'S', pathStyle: true, prefix: 'p/' })
  const r = await startRelay(coord, { blobs: { store: 's3', cnIpFile: cnFile, backends: [backend('cn', 'cn-ip', 'cnb'), backend('intl', 'default', 'hkb')] } }, { env: { K: 'AKLAB', S: 'secret-lab-key' } })
  t.after(() => r.stop())
  await r.relay.blobs.probe()
  const mac = device('computer'), phone = device('phone')
  const M = api(r, await httpToken(r, coord, mac, { peers: [phone.addr] }))
  const P = api(r, await httpToken(r, coord, phone, { peers: [mac.addr] }))
  const base = `/v1/b/${mac.addr}`

  const b = blob(70000)
  let res = await P.post(`${base}/${b.idS}/upload`, { bytes: b.ct.length })
  const resv = await res.json()
  assert.equal(resv.mode, 'presigned')
  assert.equal(resv.method, 'PUT')
  assert.equal(resv.headers['Content-Length'], String(b.ct.length))
  assert.ok(resv.url.startsWith(`${s3.url}/hkb/p/${mac.addr}/${b.idS}?`), '127.0.0.1 is not in the cn list → default bucket')
  assert.match(resv.url, /X-Amz-Expires=900(&|$)/, 'the presigned PUT lives 15 minutes')
  assert.ok(resv.expires > Date.now() + 14 * 60_000 && resv.expires <= Date.now() + 15 * 60_000)
  assert.ok(!r.logs.join('\n').includes('X-Amz-Signature'), 'presigned URLs are not logged')
  // commit before uploading
  res = await P.post(`${base}/${b.idS}/commit`, { bytes: b.ct.length })
  assert.equal(res.status, 409)
  // upload to the bucket directly (no relay token involved)
  res = await tfetch(resv.url, { method: 'PUT', body: b.ct, headers: resv.headers })
  assert.equal(res.status, 200)
  // a wrong content length breaks the signature
  assert.equal((await tfetch(resv.url, { method: 'PUT', body: b.ct.subarray(1) })).status, 403)
  res = await P.post(`${base}/${b.idS}/commit`, { bytes: b.ct.length })
  assert.equal(res.status, 200)
  assert.equal((await P.post(`${base}/${b.idS}/commit`, { bytes: b.ct.length })).status, 200, 'commit is idempotent')

  // download: 302 to a presigned GET, followed without Authorization
  res = await M.get(`${base}/${b.idS}`)
  assert.equal(res.status, 302)
  const loc = res.headers.get('location')
  assert.ok(loc.startsWith(s3.url))
  const before = s3.state.requests.length
  const dl = await tfetch(loc)
  assert.equal(dl.status, 200)
  assert.deepEqual(Buffer.from(await dl.arrayBuffer()), b.ct)
  assert.equal(s3.state.requests.slice(before).every((x) => x.auth === null), true)
  assert.equal((await M.head(`${base}/${b.idS}`)).headers.get('content-length'), String(b.ct.length))

  // a bucket object of the wrong size is deleted at commit
  const c = blob(5000)
  res = await P.post(`${base}/${c.idS}/upload`, { bytes: c.ct.length })
  const rc = await res.json()
  const smaller = blob(4000, c.id)
  await tfetch(rc.url.replace(/X-Amz-Expires=\d+/, (m) => m), { method: 'PUT', body: c.ct, headers: rc.headers })
  const key = `hkb/p/${mac.addr}/${c.idS}`
  s3.objects.set(key, smaller.ct)                        // something else ended up there
  res = await P.post(`${base}/${c.idS}/commit`, { bytes: c.ct.length })
  assert.equal(res.status, 409)
  assert.equal(s3.objects.has(key), false, 'deleted from the bucket')
  // a bucket object with another blob's header is rejected at commit
  const e = blob(100)
  const re = await (await P.post(`${base}/${e.idS}/upload`, { bytes: e.ct.length })).json()
  const forged = blob(100)
  await tfetch(re.url, { method: 'PUT', body: forged.ct, headers: re.headers })
  res = await P.post(`${base}/${e.idS}/commit`, { bytes: e.ct.length })
  assert.equal((await res.json()).error, 'bad-blob')
  // with the bucket up, the relay's disk takes nothing: not a direct PUT on a presigned reservation, not one without
  // any reservation (both used to be stored on disk on the spot)
  const f = blob(300)
  await P.post(`${base}/${f.idS}/upload`, { bytes: f.ct.length })
  assert.equal((await P.put(`${base}/${f.idS}`, f.ct)).status, 403)
  const f2 = blob(300)
  assert.equal((await P.put(`${base}/${f2.idS}`, f2.ct)).status, 403)
  assert.equal(r.relay.store.get('blobGet', mac.addr, f2.idS), undefined, 'not reserved on the spot either')
  assert.ok(!fs.existsSync(path.join(r.dir, 'b', mac.addr)) || fs.readdirSync(path.join(r.dir, 'b', mac.addr)).length === 0, 'nothing on disk')

  // the cn-ip rule picks the other bucket for addresses on the list
  assert.equal(r.relay.blobs.pick('10.1.2.3').name, 'cn')
  assert.equal(r.relay.blobs.pick('8.8.8.8').name, 'intl')
  // bucket down at reservation time → direct: that reservation may be filled on disk, and is served from there
  s3.state.down = true
  await r.relay.blobs.probe()
  const g = blob(64)
  assert.deepEqual(await (await P.post(`${base}/${g.idS}/upload`, { bytes: g.ct.length })).json(), { mode: 'direct' })
  s3.state.down = false
  await r.relay.blobs.probe()
  assert.equal((await P.put(`${base}/${g.idS}`, g.ct)).status, 200, 'the bucket is back, the direct reservation still counts')
  res = await M.get(`${base}/${g.idS}`)
  assert.equal(res.status, 200, 'served from disk')
  assert.deepEqual(Buffer.from(await res.arrayBuffer()), g.ct)

  // delete removes the bucket object
  assert.equal((await M.del(`${base}/${b.idS}`)).status, 200)
  assert.equal(s3.objects.has(`hkb/p/${mac.addr}/${b.idS}`), false)
})

test('quotas: per day and per month in the configured time zone, from the ticket; HEAD is free', async (t) => {
  let skew = 0
  // 2026-10-08 23:59:00 in Asia/Shanghai = 15:59:00Z
  const T0 = Date.UTC(2026, 9, 8, 15, 59, 0)
  const now = () => T0 + skew
  const coord = new Coord()
  const r = await startRelay(coord, { now, timezone: 'Asia/Shanghai' })
  t.after(() => r.stop())
  const mac = device('computer'), phone = device('phone')
  const quota = { dayMB: 1, monthMB: 2, smallMB: 0 }      // no small-file allowance (quota.test.mjs covers it)
  const iat = T0 - 1000, exp = T0 + 20 * 3600_000
  const M = api(r, await httpToken(r, coord, mac, { peers: [phone.addr], iat, exp, quota }))
  const base = `/v1/b/${mac.addr}`
  const big = blob(700 * 1024)
  assert.equal((await M.put(`${base}/${big.idS}`, big.ct)).status, 200)
  let q = await (await M.get('/v1/me/quota')).json()
  assert.equal(q.day.used, big.ct.length)
  assert.equal(q.day.cap, 1 * MB)
  assert.equal(q.month.cap, 2 * MB)
  // a second upload would exceed today's MB
  const big2 = blob(400 * 1024)
  let res = await M.post(`${base}/${big2.idS}/upload`, { bytes: big2.ct.length })
  assert.equal(res.status, 429)
  const body = await res.json()
  assert.equal(body.error, 'quota')
  assert.ok(body.retryAfter > 0 && body.retryAfter <= 60, `retry after the local midnight (${body.retryAfter}s)`)
  assert.equal(res.headers.get('retry-after'), String(body.retryAfter))
  // HEAD costs nothing; a download of the stored blob would exceed the day → refused
  assert.equal((await M.head(`${base}/${big.idS}`)).status, 200)
  assert.equal((await M.get(`${base}/${big.idS}`)).status, 429)
  // past midnight in Shanghai: a new day, same month
  skew = 2 * 60_000
  q = await (await M.get('/v1/me/quota')).json()
  assert.equal(q.day.used, 0)
  assert.equal(q.month.used, big.ct.length)
  assert.equal((await M.get(`${base}/${big.idS}`)).status, 200)
  // the month runs out
  const big3 = blob(700 * 1024)
  res = await M.post(`${base}/${big3.idS}/upload`, { bytes: big3.ct.length })
  assert.equal(res.status, 429)
  assert.ok((await res.json()).retryAfter > 20 * 86400, 'until the next month')
})

test('retention: blobs not downloaded for blobDays, never-downloaded blobs after upload, expired reservations', async (t) => {
  let skew = 0
  const now = () => Date.now() + skew
  const coord = new Coord()
  const r = await startRelay(coord, { now, retention: { blobDays: 30, objectDays: 30 } })
  t.after(() => r.stop())
  const mac = device('computer')
  const M = api(r, await httpToken(r, coord, mac, { peers: [], exp: Date.now() + 23 * 3600_000 }))
  const base = `/v1/b/${mac.addr}`
  const a = blob(100), b = blob(100), c = blob(100)
  assert.equal((await M.put(`${base}/${a.idS}`, a.ct)).status, 200)
  assert.equal((await M.put(`${base}/${b.idS}`, b.ct)).status, 200)
  assert.equal((await M.post(`${base}/${c.idS}/upload`, { bytes: c.ct.length })).status, 200)
  skew = 2 * 3600_000
  await r.relay.sweep()
  assert.equal(r.relay.store.get('blobGet', mac.addr, c.idS), undefined, 'reservation expired after an hour')
  // b was downloaded at day 20; a never
  skew = 20 * 86400_000
  r.relay.store.run('blobTouch', now(), mac.addr, b.idS)
  skew = 31 * 86400_000
  await r.relay.sweep()
  assert.equal(r.relay.store.get('blobGet', mac.addr, a.idS), undefined, 'never downloaded: 30 days after upload')
  assert.ok(r.relay.store.get('blobGet', mac.addr, b.idS), 'downloaded 11 days ago: kept')
  skew = 51 * 86400_000
  await r.relay.sweep()
  assert.equal(r.relay.store.get('blobGet', mac.addr, b.idS), undefined)
  assert.deepEqual(fs.readdirSync(path.join(r.dir, 'b', mac.addr)), [])
})
