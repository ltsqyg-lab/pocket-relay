// Attack tests (phase 3 red team, 2026-10-08; BUILD-PLAN §5 items 7, 8, 9, 13): what an attacker with a stolen
// ticket, a revoked or narrowed device, a replayed coordination document or malformed input can do to a relay.
// Each case here failed, or was not covered, before the matching fix (attack tests, October 2026).
import test from 'node:test'
import assert from 'node:assert/strict'
import crypto from 'node:crypto'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import net from 'node:net'
import { tfetch, Coord, device, startRelay, wsConnect, connect, httpToken, proof, objectSeal, api, envelope, ref, b64u, sleep } from './helpers.mjs'
import { startFakeS3 } from './fake-s3.mjs'

const SEAL = { 'content-type': 'application/x-pocket-seal' }
const DAY = 86_400_000
const post = (r, p, j) => tfetch(`${r.base}${p}`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(j) })
const challenge = async (r) => (await (await tfetch(`${r.base}/v1/auth/challenge`, { method: 'POST' })).json()).nonce
/** HTTP /v1/auth with a ticket and a proof made by `signer` over `nonce` (defaults: the device itself, a fresh nonce). */
async function httpAuth(r, ticket, dev, { nonce, signer = dev, relay = r.cfg.relayId } = {}) {
  const n = nonce ?? await challenge(r)
  const res = await post(r, '/v1/auth', { ticket, ...proof(signer, ticket, n, { relay }) })
  return { status: res.status, body: await res.json() }
}
/** WS auth with a ticket; returns the error code or 'ready'. */
async function wsAuth(r, ticket, signer, { relay = r.cfg.relayId } = {}) {
  const ws = await wsConnect(r.base)
  const ch = await ws.next('challenge')
  ws.send({ t: 'auth', ticket, ...proof(signer, ticket, ch.nonce, { relay }) })
  const f = await ws.next((x) => x.t === 'ready' || x.t === 'error')
  ws.close()
  return f.t === 'ready' ? 'ready' : f.code
}

test('§5-7 stolen tickets and proofs: HTTP and WebSocket refuse the same things', async (t) => {
  const coord = new Coord()
  const hk = await startRelay(coord)
  const self = await startRelay(coord, { relayId: 'r_selfhost01', account: 'u_mine' })
  t.after(async () => { await hk.stop(); await self.stop() })
  const phone = device('phone', 'u_lab1'), mine = device('phone', 'u_mine'), thief = device('phone', 'u_evil')
  const tk = coord.ticket(phone, { aud: 'hk1' })

  // a stolen ticket without the device's private key: the thief's own key does not match the ticket's sig key
  assert.equal((await httpAuth(hk, tk, phone, { signer: thief })).body.error, 'bad-sig')
  assert.equal(await wsAuth(hk, tk, thief), 'bad-sig')
  // the HTTP nonce is single use: a captured proof cannot be replayed, not even a second time by the device itself
  const n = await challenge(hk)
  const first = await httpAuth(hk, tk, phone, { nonce: n })
  assert.equal(first.status, 200)
  assert.equal((await httpAuth(hk, tk, phone, { nonce: n })).body.error, 'bad-nonce')
  // a nonce issued by another relay is unknown here; a proof made for another relay is refused even with our nonce
  const foreign = await challenge(self)
  assert.equal((await httpAuth(hk, tk, phone, { nonce: foreign })).body.error, 'bad-nonce')
  assert.equal((await httpAuth(hk, tk, phone, { relay: 'r_selfhost01' })).body.error, 'bad-proof')
  // a ticket for the official relay is refused by a self-hosted one (aud), on both paths
  assert.equal((await httpAuth(self, tk, phone)).body.error, 'wrong-aud')
  assert.equal(await wsAuth(self, tk, phone), 'wrong-aud')
  // a self-hosted relay bound to one account refuses every other account, even with a ticket made out to it
  const other = coord.ticket(phone, { aud: 'r_selfhost01' })
  assert.equal((await httpAuth(self, other, phone)).body.error, 'wrong-account')
  assert.equal(await wsAuth(self, other, phone), 'wrong-account')
  assert.equal((await httpAuth(self, coord.ticket(mine, { aud: 'r_selfhost01' }), mine)).status, 200, 'its own account works')
  // tickets from the future, older than 24 h of lifetime, or for another account's device with a borrowed key
  const now = Date.now()
  assert.equal((await httpAuth(hk, coord.ticket(phone, { iat: now + 10 * 60_000, exp: now + 3 * 3600_000 }), phone)).body.error, 'expired')
  assert.equal((await httpAuth(hk, coord.ticket(phone, { iat: now - 1000, exp: now + 25 * 3600_000 }), phone)).body.error, 'bad-ticket')
  const borrowed = coord.ticket({ ...thief, sigPub: phone.sigPub }, { aud: 'hk1' })    // thief's address with the victim's sig key
  assert.equal((await httpAuth(hk, borrowed, thief)).body.error, 'bad-sig', 'a ticket naming the victim\'s key needs the victim\'s private key')
  // an HTTP token is useless at another relay
  const H = api(self, first.body.token)
  assert.equal((await H.get(`/v1/o/${mine.addr}`)).status, 401)
})

test('§5-8 revocation: a revoked device loses sockets, tokens and history at once; old documents cannot lift it', async (t) => {
  const coord = new Coord()
  const r = await startRelay(coord)
  t.after(() => r.stop())
  const mac = device('computer'), phone = device('phone')
  const Mc = await connect(r, coord, mac, { peers: [phone.addr] })
  const Pc = await connect(r, coord, phone, { peers: [mac.addr] })
  const M = api(r, Mc.token)
  const P = api(r, await httpToken(r, coord, phone, { peers: [mac.addr] }))
  await M.put(`/v1/o/${mac.addr}/sess/s1`, objectSeal(mac, { key: 's1', ver: 1 }), { ...SEAL, 'x-pocket-ver': '1' })
  const bid = crypto.randomBytes(16), ct = ref.encryptBlob(crypto.randomBytes(32), bid, Buffer.from('attachment'))
  assert.equal((await M.put(`/v1/b/${mac.addr}/${b64u(bid)}`, ct)).status, 200)
  assert.equal((await P.get(`/v1/o/${mac.addr}/sess/s1`)).status, 200)

  // the phone is revoked (gone): socket closed, every token dead, history and attachments refused, tickets refused
  const older = coord.revocations('u_lab1', [{ addr: phone.addr, dev: phone.id, nbf: 1 }], { at: Date.now() - 60_000 })
  const gone = coord.revocations('u_lab1', [{ addr: phone.addr, dev: phone.id, nbf: Number.MAX_SAFE_INTEGER, gone: true }])
  assert.deepEqual(await (await post(r, '/v1/revocations', gone)).json(), { applied: 1 })
  assert.equal(await Pc.ws.closed, 4403)
  assert.equal((await P.get(`/v1/o/${mac.addr}/sess/s1`)).status, 401)
  assert.equal((await P.get(`/v1/o/${mac.addr}/msg/s1/range`)).status, 401)
  assert.equal((await P.get(`/v1/b/${mac.addr}/${b64u(bid)}`)).status, 401)
  await assert.rejects(connect(r, coord, phone, { peers: [mac.addr] }), (e) => e.code === 'revoked')
  await assert.rejects(httpToken(r, coord, phone, { peers: [mac.addr], iat: Date.now() + 1000 }), (e) => e.code === 'revoked', 'even a ticket issued later')
  // replaying an older document (an earlier, milder cut-off) does not lift `gone`
  await post(r, '/v1/revocations', older)
  await assert.rejects(connect(r, coord, phone, { peers: [mac.addr] }), (e) => e.code === 'revoked')
  // nor does an item about another device at the same address that is older than what the relay knows
  const stale = coord.revocations('u_lab1', [{ addr: phone.addr, dev: device('phone').id, nbf: 1 }], { at: Date.now() - DAY })
  await post(r, '/v1/revocations', stale)
  await assert.rejects(connect(r, coord, phone, { peers: [mac.addr] }), (e) => e.code === 'revoked')
  // envelopes to the revoked phone are dropped, not queued for whoever might hold its address later
  Mc.ws.send({ t: 'send', id: 'x1', to: phone.addr, env: envelope(mac, { to: phone.id, realm: mac.id }), ttl: 300 })
  assert.equal((await Mc.ws.next('sent')).status, 'offline')
  assert.equal(r.relay.store.get('qStats', phone.addr).n, 0)
  Mc.ws.close()
})

test('§5-9 narrowed access: old tickets stop at the relay, new tickets carry the new peers', async (t) => {
  const coord = new Coord()
  const r = await startRelay(coord)
  t.after(() => r.stop())
  const mac = device('computer'), phone = device('phone'), kid = device('phone')
  const Mc = await connect(r, coord, mac, { peers: [phone.addr, kid.addr] })
  const Kc = await connect(r, coord, kid, { peers: [mac.addr] })
  const K = api(r, Kc.token)
  await api(r, Mc.token).put(`/v1/o/${mac.addr}/sess/s1`, objectSeal(mac, { key: 's1', ver: 1 }), { ...SEAL, 'x-pocket-ver': '1' })
  assert.equal((await K.get(`/v1/o/${mac.addr}/sess/s1`)).status, 200)
  // coordination narrows the ACL: the kid's phone may no longer read the computer → cut-offs for both (nbf = now)
  const cut = Date.now() + 1
  await post(r, '/v1/revocations', coord.revocations('u_lab1', [{ addr: kid.addr, dev: kid.id, nbf: cut }, { addr: mac.addr, dev: mac.id, nbf: cut }]))
  assert.equal(await Kc.ws.closed, 4403)
  assert.equal(await Mc.ws.closed, 4403)
  assert.equal((await K.get(`/v1/o/${mac.addr}/sess/s1`)).status, 401, 'the old token is gone')
  await assert.rejects(connect(r, coord, kid, { peers: [mac.addr], iat: cut - 10 }), (e) => e.code === 'revoked', 'an old ticket with the old peers')
  // a new ticket has no peers: it authenticates but reads nothing and reaches nobody
  const K2 = await connect(r, coord, kid, { peers: [], iat: cut + 5 })
  assert.equal((await api(r, K2.token).get(`/v1/o/${mac.addr}/sess/s1`)).status, 403)
  K2.ws.send({ t: 'send', id: 'k1', to: mac.addr, env: envelope(kid, { to: mac.id, realm: mac.id }), ttl: 60 })
  assert.equal((await K2.ws.next('sent')).status, 'denied')
  K2.ws.send({ t: 'sub', realms: [mac.addr] })
  assert.deepEqual((await K2.ws.next('error')).realms, [mac.addr])
  K2.ws.close()
})

test('§5-8 an address is handed to a new device only after the old one is gone or 180 days silent (not 90)', async (t) => {
  let skew = 0
  const now = () => Date.now() + skew
  const coord = new Coord()
  const r = await startRelay(coord, { now })
  t.after(() => r.stop())
  const old = device('computer', 'u_a')
  const O = api(r, await httpToken(r, coord, old, { peers: [], iat: now() }))
  await O.put(`/v1/o/${old.addr}/sess/s`, objectSeal(old, { key: 's', ver: 1 }), { ...SEAL, 'x-pocket-ver': '1' })
  // 100 days later, no revocation seen: a device that claims the address with a fresh ticket is refused,
  // and the silent owner's data stays (coordination never reassigns an address within 180 days of its release)
  skew = 100 * DAY
  const squatter = device('computer', 'u_a', old.addr)
  await assert.rejects(httpToken(r, coord, squatter, { peers: [], iat: now(), exp: now() + 3600_000 }), (e) => e.code === 'denied')
  assert.equal(r.relay.store.get('objCountRealm', old.addr).n, 1, 'the old data is still there')
  // past 180 days of silence the address may go to the new device, which starts with a clean realm
  skew = 181 * DAY
  const T = await httpToken(r, coord, squatter, { peers: [], iat: now(), exp: now() + 3600_000 })
  assert.match(T, /^rt_/)
  assert.equal(r.relay.store.get('objCountRealm', old.addr).n, 0)
})

test('§5-13 challenges: outstanding nonces are capped for all clients together', async (t) => {
  const coord = new Coord()
  const r = await startRelay(coord, { limits: { nonces: 25, challengesPerIp: 1000 } })
  t.after(() => r.stop())
  const codes = []
  for (let i = 0; i < 30; i++) codes.push((await tfetch(`${r.base}/v1/auth/challenge`, { method: 'POST' })).status)
  assert.deepEqual(codes.slice(0, 25), Array(25).fill(200))
  assert.equal(codes[29], 429, 'the 26th outstanding challenge is refused instead of growing the map')
})

test('§5-13 S3 downloads: a 302 charges the whole object whatever the Range, and expires quickly', async (t) => {
  const keys = { AKLAB: 'secret-lab-key' }
  const s3 = await startFakeS3({ keys })
  t.after(() => s3.stop())
  const coord = new Coord()
  const backend = { name: 'intl', when: 'default', endpoint: s3.url, region: 'lab-1', bucket: 'hkb', accessKeyEnv: 'K', secretKeyEnv: 'S', pathStyle: true, prefix: 'p/' }
  const r = await startRelay(coord, { blobs: { store: 's3', backends: [backend] } }, { env: { K: 'AKLAB', S: 'secret-lab-key' } })
  t.after(() => r.stop())
  await r.relay.blobs.probe()
  const mac = device('computer'), phone = device('phone')
  const quota = { dayMB: 1, monthMB: 100, smallMB: 0 }      // no small-file allowance here; with one, see below
  const M = api(r, await httpToken(r, coord, mac, { peers: [phone.addr], quota }))
  const id = crypto.randomBytes(16), ct = ref.encryptBlob(crypto.randomBytes(32), id, crypto.randomBytes(300 * 1024))
  const base = `/v1/b/${mac.addr}/${b64u(id)}`
  const resv = await (await M.post(`${base}/upload`, { bytes: ct.length })).json()
  assert.equal((await tfetch(resv.url, { method: 'PUT', body: ct, headers: resv.headers })).status, 200)
  assert.equal((await M.post(`${base}/commit`, { bytes: ct.length })).status, 200)
  const used = async () => (await (await M.get('/v1/me/quota')).json()).day.used
  const u0 = await used()
  // asking the relay for one byte must not buy a URL for the whole object at the price of one byte
  const res = await M.get(base, { range: 'bytes=0-0' })
  assert.equal(res.status, 302)
  assert.equal(await used() - u0, ct.length, 'charged the stored size')
  assert.match(res.headers.get('location'), /X-Amz-Expires=120(&|$)/, 'the presigned GET lives 2 minutes')
  // so one day's quota (1 MB) covers the upload and two downloads of this 300 KB blob, not a million downloads
  const codes = []
  for (let i = 0; i < 4; i++) codes.push((await M.get(base, { range: 'bytes=0-0' })).status)
  assert.deepEqual(codes, [302, 429, 429, 429])
  // the small-file allowance (this blob is small) is charged the same way: 1 MB more buys three more 302s, not more
  const M2 = api(r, await httpToken(r, coord, mac, { peers: [phone.addr], quota: { ...quota, smallMB: 1 }, iat: Date.now() + 1000 }))
  const more = []
  for (let i = 0; i < 5; i++) more.push((await M2.get(base, { range: 'bytes=0-0' })).status)
  assert.deepEqual(more, [302, 302, 302, 429, 429])
  const q = await (await M2.get('/v1/me/quota')).json()
  assert.equal(q.small.used, 3 * ct.length, 'each 302 charged the stored size to the allowance')
})

test('§5-13 malformed input: WebSocket frames, HTTP paths and bodies never crash the relay or escape its data directory', async (t) => {
  const coord = new Coord()
  // the data directory inside a private parent: what appears next to it is the relay's doing, not another test's
  // (other test suites on the machine create their own temporary directories at the same time)
  const parentDir = fs.mkdtempSync(path.join(os.tmpdir(), 'pocket-relay-test-'))
  t.after(() => fs.rmSync(parentDir, { recursive: true, force: true }))
  const r = await startRelay(coord, {}, { dir: path.join(parentDir, 'data') })
  t.after(() => r.stop())
  const mac = device('computer'), phone = device('phone')
  const Mc = await connect(r, coord, mac, { peers: [phone.addr] })
  const M = api(r, Mc.token)
  const parent = path.dirname(r.dir)
  const before = new Set(fs.readdirSync(parent))

  // WebSocket: shapes the relay must answer with an error (or ignore), never with a crash
  const junk = [
    { t: 'send' }, { t: 'send', id: 'a'.repeat(65), to: phone.addr, env: {} }, { t: 'send', id: 'x', to: '100.64.0.1/../..', env: {} },
    { t: 'send', id: 'x', to: phone.addr, env: { h: 1, c: [], s: null } }, { t: 'send', id: 'x', to: phone.addr, env: { h: '!!', c: '', s: '' } },
    { t: 'send', id: 'x', to: phone.addr, ttl: -1, env: {} }, { t: 'send', id: 'x', to: phone.addr, ttl: 1e300, env: {} },
    { t: 'send', id: 'x', to: phone.addr, env: { h: b64u(Buffer.from('{"from":')), c: '', s: b64u(Buffer.alloc(64)) } },
    { t: 'sub', realms: 'x' }, { t: 'sub', realms: Array(300).fill(mac.addr) }, { t: 'sub', realms: [mac.addr], since: { [mac.addr]: -5 } },
    { t: 'sub', realms: [mac.addr], since: { [mac.addr]: 1e300 } }, { t: 'ack', q: [] }, { t: 'ack', q: Array(1001).fill(1) }, { t: 'ack', q: ['1'] },
    { t: 'ping', ts: 'x' }, { t: 'renew' }, { t: '__proto__' }, { t: 'constructor' }, { t: null }, {},
  ]
  for (const j of junk) Mc.ws.send(j)
  Mc.ws.send(JSON.stringify({ t: 'ping', ts: 1, nested: JSON.parse('['.repeat(5000) + ']'.repeat(5000)) }))
  await sleep(300)
  assert.equal(Mc.ws.closeCode, null, 'shapes are answered, the socket stays')
  Mc.ws.send({ t: 'ping', ts: 7 })
  assert.ok(await Mc.ws.next((f) => f.t === 'pong' && f.ts === 7), 'still answering')
  // frames that do close the socket: binary, broken UTF-8 / JSON, an over-long frame header, fragments without a start
  for (const [op, payload, fin] of [[0x2, Buffer.from('{}'), true], [0x1, Buffer.from([0xff, 0xfe]), true], [0x0, Buffer.from('{}'), true], [0x1, Buffer.from('{"t":'), false]]) {
    const w = await wsConnect(r.base)
    await w.next('challenge')
    w.raw(op, payload, { fin })
    if (!fin) w.raw(0x2, Buffer.from('x'))                   // interleaved data frame after an unfinished text frame
    const code = await w.closed
    assert.ok([1002, 4400, 4401].includes(code), `op ${op} closes with ${code}`)
  }
  {
    const w = await wsConnect(r.base)
    await w.next('challenge')
    const hdr = Buffer.alloc(10); hdr[0] = 0x81; hdr[1] = 0x80 | 127; hdr.writeBigUInt64BE(2n ** 62n, 2)
    w.socket.write(Buffer.concat([hdr, crypto.randomBytes(4)]))
    assert.equal(await w.closed, 4413, 'a frame claiming 2^62 bytes is refused before any allocation')
  }

  // HTTP: traversal and odd encodings in every path segment, odd methods, broken bodies and headers
  const paths = [
    `/v1/o/..%2f..%2f..%2fetc`, `/v1/o/${mac.addr}/..%2f..%2fx/k`, `/v1/o/${mac.addr}/sess/..%2f..%2f..%2fescape`, `/v1/o/${mac.addr}/sess/%00`,
    `/v1/o/${mac.addr}/msg/k/%2e%2e`, `/v1/o/${mac.addr}/msg/k/range?after=-1`, `/v1/o/${mac.addr}/msg/k/range?skip=${'1:1,'.repeat(500)}`,
    `/v1/o/${mac.addr}?kinds=info,../x`, `/v1/o/${mac.addr}?since=1e309&limit=0`, `/v1/o/${mac.addr}?inline=99999999999999999`,
    `/v1/b/${mac.addr}/..%2f..%2f..%2fescape`, `/v1/b/${mac.addr}/${'A'.repeat(22)}%00`, `/v1/b/100.64.0.1%2f..%2f..%2fx/${b64u(crypto.randomBytes(16))}`,
    `/v1/o/${mac.addr}/../../../../etc/passwd`, '/v1/%', '/v1/o/%zz/x', '//v1/info',
  ]
  for (const p of paths) {
    for (const method of ['GET', 'PUT', 'DELETE', 'POST', 'PATCH', 'OPTIONS']) {
      const res = await tfetch(r.base + p, { method, headers: { authorization: `Bearer ${Mc.token}`, 'x-pocket-ver': '1' }, body: ['GET', 'OPTIONS'].includes(method) ? undefined : crypto.randomBytes(80) })
      assert.ok(res.status >= 400 && res.status < 500, `${method} ${p} → ${res.status}`)
      await res.arrayBuffer()
    }
  }
  for (const [p, body, headers] of [
    ['/v1/auth', '{"ticket":', {}], ['/v1/auth', JSON.stringify({ ticket: 'a.b', a: 'x'.repeat(70000), s: '' }), {}],
    ['/v1/revocations', '[]', {}], ['/v1/purge', 'null', {}], [`/v1/b/${mac.addr}/${b64u(crypto.randomBytes(16))}/upload`, '{"bytes":-1}', { authorization: `Bearer ${Mc.token}` }],
    [`/v1/b/${mac.addr}/${b64u(crypto.randomBytes(16))}/upload`, '{"bytes":1e300}', { authorization: `Bearer ${Mc.token}` }],
    [`/v1/b/${mac.addr}/${b64u(crypto.randomBytes(16))}/commit`, '{"bytes":"1"}', { authorization: `Bearer ${Mc.token}` }],
  ]) {
    const res = await tfetch(r.base + p, { method: 'POST', headers: { 'content-type': 'application/json', ...headers }, body })
    assert.ok(res.status >= 400 && res.status < 500, `POST ${p} → ${res.status}`)
  }
  // a seal whose lengths point past the end, a header that is not JSON, a version that is not a number
  for (const [body, ver] of [[Buffer.from([0, 0, 0, 200, 1, 2, 3]), '1'], [Buffer.concat([Buffer.from([0, 0, 0, 2]), Buffer.from('{]'), Buffer.from([0, 0, 0, 0]), Buffer.alloc(64)]), '1'], [objectSeal(mac, { key: 'v', ver: 1 }), '1e3']]) {
    const res = await M.put(`/v1/o/${mac.addr}/sess/v`, body, { ...SEAL, 'x-pocket-ver': ver })
    assert.ok(res.status >= 400 && res.status < 500, `bad seal → ${res.status}`)
  }
  // an upload cut off halfway (a phone losing its network, or on purpose) used to crash the whole relay
  // (TypeError on req.socket in the "drop the rest of the body" listener, uncaught)
  {
    const id = b64u(crypto.randomBytes(16))
    const u = new URL(r.base)
    const sock = net.connect(Number(u.port), u.hostname)
    await new Promise((res) => sock.once('connect', res))
    sock.write(`PUT /v1/b/${mac.addr}/${id} HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer ${Mc.token}\r\nContent-Length: 100000\r\n\r\n`)
    sock.write(Buffer.alloc(100))
    await sleep(100)
    sock.destroy()
    await sleep(200)
    assert.equal(r.relay.store.get('blobGet', mac.addr, id)?.state ?? 'none', 'reserved', 'an interrupted upload stays a reservation (swept later)')
    assert.equal(fs.readdirSync(path.join(r.dir, 'tmp')).length, 0, 'its temporary file is removed')
  }

  // still alive, nothing written next to the data directory
  assert.equal((await tfetch(`${r.base}/v1/health`)).status, 200)
  const after = fs.readdirSync(parent).filter((f) => !before.has(f) && !f.startsWith('pocket-relay-test-'))
  assert.deepEqual(after, [], 'no files created outside the data directory')
  for (const f of fs.readdirSync(r.dir)) assert.ok(['o', 'b', 'tmp', 'relay.db', 'relay.db-wal', 'relay.db-shm'].includes(f), `unexpected entry in the data directory: ${f}`)
  Mc.ws.close()
})

test('§5-2 behind a proxy the operator-only metrics are never served, whatever the path spelling', async (t) => {
  const coord = new Coord()
  const r = await startRelay(coord, { trustProxy: true })
  t.after(() => r.stop())
  for (const p of ['/v1/metrics', '/v1/auth/../metrics', '/v1/./metrics', '/v1//metrics']) {
    const res = await tfetch(r.base + p, { headers: { 'x-forwarded-for': '203.0.113.9' } })
    assert.equal(res.status, 404, p)
    assert.ok(!/tokens|blobBytes/.test(await res.text()), p)
  }
  assert.equal((await tfetch(`${r.base}/v1/metrics`)).status, 200, 'a direct loopback request (the operator on the box) still gets them')
})
