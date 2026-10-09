// Storage limits and abuse resistance (security review 2026-10-09: M1, low 17, 18, 20): stored bytes per account count
// objects and blobs together; the disk keeps a minimum free; a relay with a bucket takes no direct uploads of its own
// accord; ranged reads do not renew a blob; presigned PUTs are short and what lands after its blob is gone is swept;
// small frames and a cap before authentication; control documents only under coordination signatures; the public
// version without its patch level.
import test from 'node:test'
import assert from 'node:assert/strict'
import crypto from 'node:crypto'
import fs from 'node:fs'
import path from 'node:path'
import http from 'node:http'
import { tfetch, Coord, device, startRelay, connect, wsConnect, httpToken, objectSeal, api, envelope, ref, b64u, sleep } from './helpers.mjs'
import { startFakeS3 } from './fake-s3.mjs'
import { loadConfig } from '../src/config.mjs'
import { DiskGuard } from '../src/disk.mjs'
import { VERSION } from '../src/relay.mjs'

const KB = 1024, MB = 1024 * 1024, DAY = 86_400_000
const SEAL = { 'content-type': 'application/x-pocket-seal' }
const blob = (n, id = crypto.randomBytes(16)) => ({ id, idS: b64u(id), ct: ref.encryptBlob(crypto.randomBytes(32), id, crypto.randomBytes(n)) })
const post = (r, p, j) => tfetch(`${r.base}${p}`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(j) })
async function until(fn, ms = 3000) { const t0 = Date.now(); for (;;) { if (await fn()) return true; if (Date.now() - t0 > ms) return false; await sleep(20) } }
const S3KEYS = { AKLAB: 'secret-lab-key' }
const S3ENV = { K: 'AKLAB', S: 'secret-lab-key' }
const backendOf = (s3) => ({ name: 'intl', when: 'default', endpoint: s3.url, region: 'lab-1', bucket: 'hkb', accessKeyEnv: 'K', secretKeyEnv: 'S', pathStyle: true, prefix: 'p/' })

/**
 * A request that announces `body` but sends only its headers, then waits: an answer that arrives without the body
 * shows the relay refused it before reading anything. Resolves {status, json, headers} or {status: 0} after 3 s.
 */
function headersOnly(r, token, method, p, body, headers = {}) {
  const u = new URL(r.base)
  return new Promise((resolve) => {
    const req = http.request({ host: u.hostname, port: u.port, path: p, method, headers: { authorization: `Bearer ${token}`, 'content-length': body.length, ...headers } }, (res) => {
      const c = []
      res.on('data', (d) => c.push(d))
      res.on('end', () => { clearTimeout(t); let json = null; try { json = JSON.parse(Buffer.concat(c).toString('utf8')) } catch { /* empty */ } resolve({ status: res.statusCode, json, headers: res.headers }); req.destroy() })
    })
    const t = setTimeout(() => { req.destroy(); resolve({ status: 0 }) }, 3000)
    req.on('error', () => {})
    req.flushHeaders()
  })
}

/** A PUT whose body arrives in two halves: finish() sends the rest; result resolves with {status, json}. */
function slowPut(r, token, p, body) {
  const u = new URL(r.base)
  let done
  const result = new Promise((res) => { done = res })
  const req = http.request({ host: u.hostname, port: u.port, path: p, method: 'PUT', headers: { authorization: `Bearer ${token}`, 'content-length': body.length } }, (res) => {
    const c = []
    res.on('data', (d) => c.push(d))
    res.on('end', () => { let json = null; try { json = JSON.parse(Buffer.concat(c).toString('utf8')) } catch { /* empty */ } done({ status: res.statusCode, json }) })
  })
  req.on('error', (e) => done({ status: 0, error: e }))
  req.write(body.subarray(0, body.length >> 1))
  return { finish: () => req.end(body.subarray(body.length >> 1)), result }
}

test('stored bytes: objects and blobs count together against storeMB (from the ticket, else the configured 5120 MB); deletes make room', async (t) => {
  const coord = new Coord()
  const r = await startRelay(coord)
  t.after(() => r.stop())
  const mac = device('computer', 'u_st1'), phone = device('phone', 'u_st1'), other = device('computer', 'u_st2')
  const iat = Date.now() - 60_000
  const M0 = api(r, await httpToken(r, coord, mac, { peers: [phone.addr], iat }))
  assert.equal((await (await M0.get('/v1/me/quota')).json()).store.cap, 5120 * MB, 'no storeMB in the ticket: the configured default')
  // the account's newest ticket says 1 MB: messages and attachments share it
  const tokM = await httpToken(r, coord, mac, { peers: [phone.addr], iat: iat + 1000, quota: { storeMB: 1 } })
  const M = api(r, tokM)
  const P = api(r, await httpToken(r, coord, phone, { peers: [mac.addr], iat: iat + 1000, quota: { storeMB: 1 } }))
  const seal = (c, seq, n, ver) => objectSeal(c, { kind: 'msg', key: 's', seq, ver, plaintext: { pad: 'x'.repeat(n) } })
  const put = (A, c, seq, n, ver = 1) => A.put(`/v1/o/${c.addr}/msg/s/${seq}`, seal(c, seq, n, ver), { ...SEAL, 'x-pocket-ver': String(ver) })
  assert.equal((await put(M, mac, 1, 300 * KB)).status, 200)
  assert.equal((await put(M, mac, 2, 300 * KB)).status, 200)
  const a = blob(200 * KB)
  assert.equal((await P.put(`/v1/b/${mac.addr}/${a.idS}`, a.ct)).status, 200)
  let q = await (await M.get('/v1/me/quota')).json()
  assert.equal(q.store.used, r.relay.store.get('objBytesOfAcct', 'u_st1').b + a.ct.length, 'objects and blobs together')
  assert.equal(q.store.cap, 1 * MB)
  // the next message does not fit any more: 429 quota with the store figures and an hour to wait, answered from the
  // headers alone (a refused write costs no upload)
  const refused = await headersOnly(r, tokM, 'PUT', `/v1/o/${mac.addr}/msg/s/3`, seal(mac, 3, 300 * KB, 1), { ...SEAL, 'x-pocket-ver': '1' })
  assert.equal(refused.status, 429)
  assert.equal(refused.headers['retry-after'], '3600')
  assert.equal(refused.json.error, 'quota')
  assert.equal(refused.json.quota.store.cap, 1 * MB)
  assert.equal(refused.json.quota.store.used, q.store.used)
  let res
  // nor does another attachment: a reservation counts what it reserves
  const b = blob(300 * KB)
  res = await P.post(`/v1/b/${mac.addr}/${b.idS}/upload`, { bytes: b.ct.length })
  assert.equal(res.status, 429)
  assert.ok((await res.json()).quota.store)
  // a new version that is not larger still goes (the session list is rewritten all the time)
  assert.equal((await put(M, mac, 2, 250 * KB, 2)).status, 200)
  // a delete makes room at once
  assert.equal((await M.del(`/v1/o/${mac.addr}/msg/s/1`)).status, 200)
  assert.equal((await put(M, mac, 3, 300 * KB)).status, 200)
  q = await (await M.get('/v1/me/quota')).json()
  assert.equal(q.store.used, r.relay.store.get('objBytesOfAcct', 'u_st1').b + a.ct.length, 'the running figure matches the index')
  // so does purging the account; other accounts never share the room
  const O = api(r, await httpToken(r, coord, other, { iat: iat + 1000, quota: { storeMB: 1 } }))
  assert.equal((await put(O, other, 1, 300 * KB)).status, 200)
  assert.equal((await post(r, '/v1/purge', coord.purge('u_st1', { relay: '*' }))).status, 200)
  assert.equal((await put(O, other, 2, 300 * KB)).status, 200)
})

test('disk nearly full: nothing new is stored on it (503 full, Retry-After); reads, deletes and live delivery go on', async (t) => {
  let free = 50 * 1024 * MB
  const statfs = () => ({ bavail: Math.floor(free / 4096), bsize: 4096 })
  const coord = new Coord()
  const r = await startRelay(coord, { disk: { minFreeMB: 5120 } }, { statfs })
  t.after(() => r.stop())
  const mac = device('computer'), phone = device('phone'), away = device('phone')
  const Mc = await connect(r, coord, mac, { peers: [phone.addr, away.addr] })
  const Pc = await connect(r, coord, phone, { peers: [mac.addr] })
  const M = api(r, Mc.token), P = api(r, Pc.token)
  const sess = (key) => M.put(`/v1/o/${mac.addr}/sess/${key}`, objectSeal(mac, { key, ver: 1 }), { ...SEAL, 'x-pocket-ver': '1' })
  assert.equal((await sess('s1')).status, 200)
  const a = blob(1000)
  assert.equal((await P.put(`/v1/b/${mac.addr}/${a.idS}`, a.ct)).status, 200)
  // 5.15 GB free: small writes go, a 100 MB attachment would take the disk below 5 GB
  free = 5150 * MB
  r.relay.disk.refresh()
  const huge = 22 + 100 * MB + 16 * 1600
  let res = await P.post(`/v1/b/${mac.addr}/${b64u(crypto.randomBytes(16))}/upload`, { bytes: huge })
  assert.equal(res.status, 503)
  assert.equal((await res.json()).error, 'full')
  assert.equal((await sess('s2')).status, 200)
  // below the minimum: objects, attachments on disk and queued envelopes are refused (objects from the headers alone)
  free = 5000 * MB
  r.relay.disk.refresh()
  const refused = await headersOnly(r, Mc.token, 'PUT', `/v1/o/${mac.addr}/sess/s3`, objectSeal(mac, { key: 's3', ver: 1 }), { ...SEAL, 'x-pocket-ver': '1' })
  assert.equal(refused.status, 503)
  assert.equal(refused.headers['retry-after'], '600')
  assert.equal(refused.json.error, 'full')
  res = await sess('s3')
  assert.equal(res.status, 503)
  const b = blob(1000)
  assert.equal((await P.post(`/v1/b/${mac.addr}/${b.idS}/upload`, { bytes: b.ct.length })).status, 503, 'a reservation on this disk')
  assert.equal((await P.put(`/v1/b/${mac.addr}/${b.idS}`, b.ct)).status, 503, 'a direct upload')
  Mc.ws.send({ t: 'send', id: 'q1', to: away.addr, env: envelope(mac, { to: away.id, realm: mac.id, kind: 'evt' }), ttl: 600 })
  assert.equal((await Mc.ws.next('sent')).status, 'full', 'no queueing for an offline device')
  assert.equal(r.relay.store.get('qStats', away.addr).n, 0)
  // live delivery, reads and deletes carry on
  Mc.ws.send({ t: 'send', id: 'l1', to: phone.addr, env: envelope(mac, { to: phone.id, realm: mac.id, kind: 'evt' }), ttl: 0 })
  assert.equal((await Mc.ws.next('sent')).status, 'delivered')
  assert.equal((await P.get(`/v1/o/${mac.addr}/sess/s1`)).status, 200)
  assert.equal((await P.get(`/v1/b/${mac.addr}/${a.idS}`)).status, 200)
  assert.equal((await M.del(`/v1/o/${mac.addr}/sess/s1`)).status, 200)
  assert.equal((await P.del(`/v1/b/${mac.addr}/${a.idS}`)).status, 200)
  // room again: writes resume; the log said so once each way
  free = 6000 * MB
  r.relay.disk.refresh()
  assert.equal((await sess('s3')).status, 200)
  Mc.ws.send({ t: 'send', id: 'q2', to: away.addr, env: envelope(mac, { to: away.id, realm: mac.id, kind: 'evt' }), ttl: 600 })
  assert.equal((await Mc.ws.next('sent')).status, 'queued')
  const ops = r.logs.map((l) => JSON.parse(l).op)
  assert.equal(ops.filter((o) => o === 'disk-low').length, 1)
  assert.equal(ops.filter((o) => o === 'disk-ok').length, 1)
  Mc.ws.close(); Pc.ws.close()
})

test('disk nearly full on a relay with a bucket: attachments still go to the bucket; only a fallback to the disk is refused', async (t) => {
  const s3 = await startFakeS3({ keys: S3KEYS })
  t.after(() => s3.stop())
  const coord = new Coord()
  const r = await startRelay(coord, { disk: { minFreeMB: 5120 }, blobs: { store: 's3', backends: [backendOf(s3)] } }, { env: S3ENV, statfs: () => ({ bavail: 1000, bsize: MB }) })
  t.after(() => r.stop())
  await r.relay.blobs.probe()
  const mac = device('computer'), phone = device('phone')
  const P = api(r, await httpToken(r, coord, phone, { peers: [mac.addr] }))
  const a = blob(5000)
  const resv = await (await P.post(`/v1/b/${mac.addr}/${a.idS}/upload`, { bytes: a.ct.length })).json()
  assert.equal(resv.mode, 'presigned')
  assert.equal((await tfetch(resv.url, { method: 'PUT', body: a.ct, headers: resv.headers })).status, 200)
  assert.equal((await P.post(`/v1/b/${mac.addr}/${a.idS}/commit`, { bytes: a.ct.length })).status, 200)
  s3.state.down = true
  await r.relay.blobs.probe()
  const b = blob(5000)
  assert.equal((await P.post(`/v1/b/${mac.addr}/${b.idS}/upload`, { bytes: b.ct.length })).status, 503, 'the bucket is down and the disk has no room')
})

test('retention: a download renews a blob only when it delivers at least half of it; a few bytes of a range do not', async (t) => {
  let skew = 0
  const now = () => Date.now() + skew
  const coord = new Coord()
  const r = await startRelay(coord, { now, retention: { blobDays: 30, objectDays: 30 } })
  t.after(() => r.stop())
  const mac = device('computer')
  const signIn = async () => { const tok = await httpToken(r, coord, mac, { peers: [], iat: now() - 1000, exp: now() + 20 * 3600_000 }); return { tok, M: api(r, tok) } }
  let { tok, M } = await signIn()
  const base = `/v1/b/${mac.addr}`
  const lastRead = (b) => r.relay.store.get('blobGet', mac.addr, b.idS)?.last_read ?? null
  const nibbled = blob(200 * KB), halfRead = blob(200 * KB), read = blob(200 * KB), cut = blob(20 * MB)
  for (const b of [nibbled, halfRead, read, cut]) assert.equal((await M.put(`${base}/${b.idS}`, b.ct)).status, 200)
  const nibble = async (b) => {
    for (const range of ['bytes=0-0', 'bytes=-1', `bytes=${b.ct.length - 64}-`, 'bytes=1000-50000']) {
      const res = await M.get(`${base}/${b.idS}`, { range })
      assert.equal(res.status, 206)
      await res.arrayBuffer()
    }
  }
  await nibble(nibbled)
  let res = await M.get(`${base}/${halfRead.idS}`, { range: `bytes=${Math.floor(halfRead.ct.length / 2)}-` })
  await res.arrayBuffer()
  res = await M.get(`${base}/${read.idS}`)
  assert.deepEqual(Buffer.from(await res.arrayBuffer()), read.ct)
  // a download the client gives up on after the first bytes renews nothing either
  await new Promise((resolve) => {
    const u = new URL(r.base)
    const req = http.request({ host: u.hostname, port: u.port, path: `${base}/${cut.idS}`, headers: { authorization: `Bearer ${tok}` } }, (rs) => {
      rs.once('data', () => { req.destroy(); resolve() })
    })
    req.on('error', () => resolve())
    req.end()
  })
  assert.ok(await until(() => lastRead(halfRead) && lastRead(read)), 'half of a blob, or all of it, renews it')
  await sleep(300)
  assert.equal(lastRead(nibbled), null, 'tiny ranges, the last byte included, do not')
  assert.equal(lastRead(cut), null, 'nor does a download that was cut off')
  // 20 days on: the nibbled blob is nibbled again, the others read in full; 31 days after the upload, the sweep
  skew = 20 * DAY
  ;({ tok, M } = await signIn())
  await nibble(nibbled)
  for (const b of [halfRead, read]) await (await M.get(`${base}/${b.idS}`)).arrayBuffer()
  assert.ok(await until(() => lastRead(read) > Date.now() + 19 * DAY))
  skew = 31 * DAY
  await r.relay.sweep()
  assert.equal(r.relay.store.get('blobGet', mac.addr, nibbled.idS), undefined, 'nibbling no longer keeps a blob alive')
  assert.equal(r.relay.store.get('blobGet', mac.addr, cut.idS), undefined)
  assert.ok(r.relay.store.get('blobGet', mac.addr, read.idS), 'read in full at day 20: kept')
  assert.ok(r.relay.store.get('blobGet', mac.addr, halfRead.idS))
})

test('direct uploads under way: the sweep leaves their reservation, a second upload of the same blob waits, a reservation gone meanwhile takes the file with it', async (t) => {
  let skew = 0
  const now = () => Date.now() + skew
  const coord = new Coord()
  const r = await startRelay(coord, { now })
  t.after(() => r.stop())
  const mac = device('computer')
  const token = await httpToken(r, coord, mac, { peers: [], exp: Date.now() + 20 * 3600_000 })
  const M = api(r, token)
  const a = blob(100 * KB)
  const up = slowPut(r, token, `/v1/b/${mac.addr}/${a.idS}`, a.ct)
  assert.ok(await until(() => r.relay.blobs.uploading.size === 1))
  assert.equal((await M.post(`/v1/b/${mac.addr}/${a.idS}/upload`, { bytes: a.ct.length })).status, 429, 'no second reservation while it uploads')
  skew = 2 * 3600_000                     // the reservation has expired by now
  await r.relay.sweep()
  assert.ok(r.relay.store.get('blobGet', mac.addr, a.idS), 'kept while its bytes come in')
  up.finish()
  assert.equal((await up.result).status, 200)
  assert.deepEqual(Buffer.from(await (await M.get(`/v1/b/${mac.addr}/${a.idS}`)).arrayBuffer()), a.ct)
  // the realm is purged while another upload is under way: the bytes that arrive afterwards are not kept
  const b = blob(100 * KB)
  const up2 = slowPut(r, token, `/v1/b/${mac.addr}/${b.idS}`, b.ct)
  assert.ok(await until(() => r.relay.blobs.uploading.size === 1))
  await r.relay.purgeAddr(mac.addr)
  up2.finish()
  assert.equal((await up2.result).status, 404)
  assert.equal(fs.existsSync(path.join(r.dir, 'b', mac.addr, b.id.toString('hex'))), false)
  assert.deepEqual(fs.readdirSync(path.join(r.dir, 'tmp')), [], 'no temporary file left')
})

test('presigned PUTs: valid 15 minutes; what lands after its blob is gone is deleted for a day; committed blobs stay', async (t) => {
  let skew = 0
  const now = () => Date.now() + skew
  const s3 = await startFakeS3({ keys: S3KEYS })
  t.after(() => s3.stop())
  const coord = new Coord()
  const r = await startRelay(coord, { now, blobs: { store: 's3', backends: [backendOf(s3)] } }, { env: S3ENV })
  t.after(() => r.stop())
  await r.relay.blobs.probe()
  const mac = device('computer'), phone = device('phone')
  const P = api(r, await httpToken(r, coord, phone, { peers: [mac.addr], exp: Date.now() + 23 * 3600_000 }))
  const base = `/v1/b/${mac.addr}`
  const key = (b) => `hkb/p/${mac.addr}/${b.idS}`
  const reserve = async (b) => { const j = await (await P.post(`${base}/${b.idS}/upload`, { bytes: b.ct.length })).json(); assert.equal(j.mode, 'presigned'); return j }
  const upload = async (b, j) => assert.equal((await tfetch(j.url, { method: 'PUT', body: b.ct, headers: j.headers })).status, 200)
  const watched = () => r.relay.store.db.prepare('SELECT COUNT(*) AS n FROM presigns').get().n
  // kept: reserved, uploaded, committed
  const kept = blob(3000)
  const jk = await reserve(kept)
  assert.match(jk.url, /X-Amz-Expires=900(&|$)/)
  await upload(kept, jk)
  assert.equal((await P.post(`${base}/${kept.idS}/commit`, { bytes: kept.ct.length })).status, 200)
  // abandoned: uploaded, never committed
  const abandoned = blob(3000)
  await upload(abandoned, await reserve(abandoned))
  // deleted: committed, deleted, then uploaded again with the URL that is still valid
  const deleted = blob(3000)
  const jd = await reserve(deleted)
  await upload(deleted, jd)
  assert.equal((await P.post(`${base}/${deleted.idS}/commit`, { bytes: deleted.ct.length })).status, 200)
  assert.equal((await P.del(`${base}/${deleted.idS}`)).status, 200)
  assert.equal(s3.objects.has(key(deleted)), false)
  await upload(deleted, jd)
  assert.equal(watched(), 3)
  // 25 minutes on: no URL can start an upload any more
  skew = 25 * 60_000
  await r.relay.sweep()
  assert.ok(s3.objects.has(key(kept)), 'the committed blob stays')
  assert.ok(s3.objects.has(key(abandoned)), 'a reservation still open: left alone')
  assert.equal(s3.objects.has(key(deleted)), false, 'uploaded after its blob was deleted: gone')
  assert.equal(watched(), 2, 'the committed one is no longer watched')
  // 2 hours on: the abandoned reservation expired and was deleted with its object; then its upload "lands" late
  skew = 2 * 3600_000
  await r.relay.sweep()
  assert.equal(r.relay.store.get('blobGet', mac.addr, abandoned.idS), undefined)
  assert.equal(s3.objects.has(key(abandoned)), false)
  s3.objects.set(key(abandoned), abandoned.ct)
  skew = 3 * 3600_000
  await r.relay.sweep()
  assert.equal(s3.objects.has(key(abandoned)), false, 'a late upload is swept')
  assert.ok(s3.objects.has(key(kept)))
  // a day later nothing is watched any more
  skew = 25 * 3600_000
  await r.relay.sweep()
  assert.equal(watched(), 0)
  assert.ok(s3.objects.has(key(kept)), 'the committed blob is never touched')
  assert.ok(!r.logs.join('\n').includes('X-Amz-Signature'), 'no presigned URL in the log')
})

test('websocket before authentication: 64 KiB frames, a cap on sockets that have not authenticated, a deadline', async (t) => {
  const coord = new Coord()
  const r = await startRelay(coord, { limits: { unauthSockets: 3, authSeconds: 1 } })
  t.after(() => r.stop())
  const phone = device('phone'), mac = device('computer')
  // a frame over 64 KiB before auth closes the socket at once
  const w = await wsConnect(r.base)
  await w.next('challenge')
  w.send({ t: 'auth', ticket: 'x'.repeat(70 * 1024), a: 'a', s: 's' })
  assert.equal(await w.closed, 4413)
  // after auth the full frame size applies
  const a = await connect(r, coord, phone, { peers: [mac.addr] })
  a.ws.send({ t: 'ping', ts: 5, pad: 'z'.repeat(200 * 1024) })
  assert.ok(await a.ws.next((f) => f.t === 'pong' && f.ts === 5))
  // at most 3 sockets wait for auth at once (authenticated ones do not count); the next is turned away with 503
  const waiting = [await wsConnect(r.base), await wsConnect(r.base), await wsConnect(r.base)]
  await assert.rejects(wsConnect(r.base), (e) => e.status === 503)
  assert.equal(r.relay.hub.unauth, 3)
  // they get authSeconds to authenticate (4408), and their places come free
  for (const s of waiting) assert.equal(await s.closed, 4408)
  assert.ok(await until(() => r.relay.hub.unauth === 0))
  const b = await connect(r, coord, mac, { peers: [phone.addr] })
  assert.equal(b.ready.addr, mac.addr)
  a.ws.close(); b.ws.close()
})

test('control documents count only under coordination signatures: the right label, a key allowed to sign it; unknown key ids ask for keys at most once a minute', async (t) => {
  let fetches = 0
  const fetchImpl = async () => { fetches++; return new Response('{}', { status: 404 }) }
  const coord = new Coord()
  const ticketsOnly = new Coord({ kid: 'lab-tickets-only' })
  const pinnedKeys = [...coord.pinned, { ...ticketsOnly.pinned[0], use: ['ticket'] }]
  const r = await startRelay(coord, { coord: { url: 'https://coord.test', pinnedKeys } }, { fetchImpl })
  t.after(() => r.stop())
  const mac = device('computer', 'u_ctl')
  const M = api(r, await httpToken(r, coord, mac, { peers: [] }))
  assert.equal((await M.put(`/v1/o/${mac.addr}/sess/s`, objectSeal(mac, { key: 's', ver: 1 }), { ...SEAL, 'x-pocket-ver': '1' })).status, 200)
  const errOf = async (p, doc) => { const res = await post(r, p, doc); return [res.status, (await res.json()).error] }
  const gone = [{ addr: mac.addr, dev: mac.id, nbf: Number.MAX_SAFE_INTEGER, gone: true }]
  // a coordination key that may sign tickets but not revocations or purge orders
  assert.deepEqual(await errOf('/v1/revocations', ticketsOnly.revocations('u_ctl', gone)), [401, 'key-not-valid'])
  assert.deepEqual(await errOf('/v1/purge', ticketsOnly.purge('u_ctl', { relay: '*' })), [401, 'key-not-valid'])
  // a ticket is signed by coordination as well, under another label
  const [tp, ts] = coord.ticket(mac, { aud: 'hk1' }).split('.')
  assert.deepEqual(await errOf('/v1/revocations', { p: tp, s: ts }), [400, 'bad-format'])
  assert.deepEqual(await errOf('/v1/purge', { p: tp, s: ts }), [400, 'bad-format'])
  // the right payload with the signature of another document
  const rev = coord.revocations('u_ctl', gone), pur = coord.purge('u_ctl', { relay: '*' })
  assert.deepEqual(await errOf('/v1/purge', { p: pur.p, s: rev.s }), [401, 'bad-sig'])
  assert.deepEqual(await errOf('/v1/revocations', { p: rev.p, s: pur.s }), [401, 'bad-sig'])
  // documents from key ids nobody knows: refused, and a burst of them makes the relay fetch keys.json once at most
  const before = fetches
  for (let i = 0; i < 6; i++) assert.deepEqual(await errOf('/v1/revocations', new Coord({ kid: `nobody-${i}` }).revocations('u_ctl', gone)), [401, 'unknown-key'])
  assert.ok(fetches - before <= 1, `${fetches - before} key refreshes for 6 documents`)
  // bodies no signed document can have are not read: refused on the Content-Length alone (only headers are sent here,
  // since the relay answers and closes before a large body would be through)
  const status = await new Promise((resolve) => {
    const u = new URL(r.base)
    const req = http.request({ host: u.hostname, port: u.port, path: '/v1/revocations', method: 'POST', headers: { 'content-type': 'application/json', 'content-length': 3 * MB } }, (res) => { res.resume(); resolve(res.statusCode) })
    req.on('error', () => resolve(0))
    req.flushHeaders()
  })
  assert.equal(status, 413)
  // nothing happened: the data is there, the device still signs in
  assert.equal(r.relay.store.get('objCountRealm', mac.addr).n, 1)
  assert.match(await httpToken(r, coord, mac, { peers: [] }), /^rt_/)
})

test('public endpoints give the version without its patch level', async (t) => {
  const r = await startRelay(new Coord())
  t.after(() => r.stop())
  const short = VERSION.split('.').slice(0, 2).join('.')
  assert.match(short, /^\d+\.\d+$/)
  for (const p of ['/v1/info', '/.well-known/pocket-relay', '/v1/health']) {
    const j = await (await tfetch(`${r.base}${p}`)).json()
    assert.equal(j.version, short, p)
  }
})

test('configuration: storeMB and disk.minFreeMB are 5120 by default and adjustable; the disk guard never blocks when the system cannot tell', () => {
  const coord = new Coord()
  const env = { RELAY_RELAY_ID: 'hk9', RELAY_ACCOUNT: '*', RELAY_DATA_DIR: '/nonexistent/pocket-relay', RELAY_COORD_PINNED_KEYS: JSON.stringify(coord.pinned) }
  let cfg = loadConfig({ env })
  assert.equal(cfg.quota.storeMB, 5120)
  assert.equal(cfg.disk.minFreeMB, 5120)
  assert.equal(cfg.limits.authFrame, 64 * 1024)
  assert.equal(cfg.limits.unauthSockets, 1000)
  cfg = loadConfig({ env: { ...env, RELAY_DISK_MIN_FREE_MB: '1024', RELAY_QUOTA_STORE_MB: '' } })
  assert.equal(cfg.disk.minFreeMB, 1024)
  assert.equal(cfg.quota.storeMB, null, 'empty = unlimited')
  assert.equal(loadConfig({ env: { ...env, RELAY_DISK_MIN_FREE_MB: '' } }).disk.minFreeMB, 0, 'empty = no minimum')
  assert.throws(() => loadConfig({ env: { ...env, RELAY_DISK_MIN_FREE_MB: 'lots' } }), /disk\.minFreeMB/)
  const unknown = new DiskGuard({ dir: '/', minFreeMB: 100, statfs: () => { throw new Error('ENOSYS') } })
  assert.doesNotThrow(() => unknown.check(10 * MB))
  const g = new DiskGuard({ dir: '/', minFreeMB: 100, statfs: () => ({ bavail: 150, bsize: MB }) })
  assert.doesNotThrow(() => g.check(40 * MB))
  assert.throws(() => g.check(60 * MB), (e) => e.code === 'full' && e.extra.retryAfter === 600)
  assert.equal(g.ok(60 * MB), false)
  const off = new DiskGuard({ dir: '/', minFreeMB: 0, statfs: () => ({ bavail: 0, bsize: 4096 }) })
  assert.doesNotThrow(() => off.check(MB))
})
