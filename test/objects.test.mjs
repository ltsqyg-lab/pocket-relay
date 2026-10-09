// Objects: owner-only writes, versions, header cross-checks, list / heads / range, notifications (RELAY.md §5.4, §6.3).
import test from 'node:test'
import assert from 'node:assert/strict'
import { tfetch, Coord, device, startRelay, connect, httpToken, objectSeal, api, sleep, ref } from './helpers.mjs'

const SEAL = { 'content-type': 'application/x-pocket-seal' }

test('objects: owner writes, readers read, versions grow, headers must agree', async (t) => {
  const coord = new Coord()
  const r = await startRelay(coord)
  t.after(() => r.stop())
  const mac = device('computer'), phone = device('phone'), stranger = device('phone'), other = device('computer')
  const M = api(r, await httpToken(r, coord, mac, { peers: [phone.addr] }))
  const P = api(r, await httpToken(r, coord, phone, { peers: [mac.addr] }))
  const S = api(r, await httpToken(r, coord, stranger, { peers: [] }))
  const O = api(r, await httpToken(r, coord, other, { peers: [] }))
  const base = `/v1/o/${mac.addr}`

  const s1 = objectSeal(mac, { kind: 'sess', key: 'abc', ver: 100 })
  let res = await M.put(`${base}/sess/abc`, s1, { ...SEAL, 'x-pocket-ver': '100' })
  assert.equal(res.status, 200)
  const w1 = await res.json()
  assert.equal(w1.ver, 100)
  assert.ok(w1.rev >= 1)

  // readers
  res = await P.get(`${base}/sess/abc`)
  assert.equal(res.status, 200)
  assert.equal(res.headers.get('x-pocket-ver'), '100')
  assert.equal(res.headers.get('etag'), '"100"')
  assert.deepEqual(Buffer.from(await res.arrayBuffer()), s1)
  const parsed = ref.sealFromBin(s1).seal
  assert.equal(JSON.parse(parsed.h.toString()).key, 'abc')
  res = await P.get(`${base}/sess/abc`, { 'if-none-match': '"100"' })
  assert.equal(res.status, 304)
  assert.equal((await S.get(`${base}/sess/abc`)).status, 403, 'not a peer')
  assert.equal((await O.get(`${base}/sess/abc`)).status, 403, 'another computer')

  // only the owner writes
  assert.equal((await P.put(`${base}/sess/abc`, objectSeal(mac, { key: 'abc', ver: 200 }), { ...SEAL, 'x-pocket-ver': '200' })).status, 403)
  assert.equal((await O.put(`${base}/sess/abc`, objectSeal(other, { key: 'abc', ver: 200 }), { ...SEAL, 'x-pocket-ver': '200' })).status, 403)

  // versions only grow
  res = await M.put(`${base}/sess/abc`, objectSeal(mac, { key: 'abc', ver: 100 }), { ...SEAL, 'x-pocket-ver': '100' })
  assert.equal(res.status, 409)
  assert.deepEqual(await res.json(), { error: 'ver', ver: 100 })

  // header cross-checks
  const bad = [
    [objectSeal(mac, { key: 'abc', ver: 300 }), '301', 'ver differs from the header'],
    [objectSeal(mac, { key: 'xyz', ver: 300 }), '300', 'key differs'],
    [objectSeal(mac, { kind: 'usage', key: 'abc', ver: 300 }), '300', 'kind differs'],
    [objectSeal(other, { key: 'abc', ver: 300 }), '300', 'realm is another computer'],
    [objectSeal(mac, { key: 'abc', ver: 300, over: { by: phone.id } }), '300', 'by is not the owner'],
    [objectSeal(mac, { key: 'abc', ver: 300, seq: 3 }), '300', 'seq on a kind without seq'],
  ]
  for (const [body, ver, why] of bad) {
    res = await M.put(`${base}/sess/abc`, body, { ...SEAL, 'x-pocket-ver': ver })
    assert.equal(res.status, 400, why)
    assert.equal((await res.json()).error, 'mismatch', why)
  }
  // malformed: not a seal, trailing bytes, missing version, oversized
  assert.equal((await M.put(`${base}/sess/abc`, Buffer.from('nope'), { ...SEAL, 'x-pocket-ver': '400' })).status, 400)
  assert.equal((await M.put(`${base}/sess/abc`, Buffer.concat([objectSeal(mac, { key: 'abc', ver: 400 }), Buffer.from('x')]), { ...SEAL, 'x-pocket-ver': '400' })).status, 400)
  assert.equal((await M.put(`${base}/sess/abc`, objectSeal(mac, { key: 'abc', ver: 400 }), SEAL)).status, 400)
  const huge = objectSeal(mac, { key: 'abc', ver: 500, plaintext: { pad: 'x'.repeat(70 * 1024) } })
  assert.equal((await M.put(`${base}/sess/abc`, huge, { ...SEAL, 'x-pocket-ver': '500' })).status, 413)
  // seq required for msg; unknown kind; bad key
  assert.equal((await M.put(`${base}/msg/abc`, objectSeal(mac, { kind: 'msg', key: 'abc', ver: 1 }), { ...SEAL, 'x-pocket-ver': '1' })).status, 400)
  assert.equal((await M.put(`${base}/other/abc`, s1, { ...SEAL, 'x-pocket-ver': '1' })).status, 404)
  assert.equal((await M.put(`${base}/sess/a.b`, s1, { ...SEAL, 'x-pocket-ver': '1' })).status, 404)
  assert.equal((await P.get(`${base}/sess/missing`)).status, 404)
  // no token / bad token
  assert.equal((await tfetch(`${r.base}${base}/sess/abc`)).status, 401)
  assert.equal((await api(r, 'rt_' + 'A'.repeat(43)).get(`${base}/sess/abc`)).status, 401)
})

test('objects: list since / inline / kinds / paging, heads, range with lite, skip, byte caps', async (t) => {
  const coord = new Coord()
  const r = await startRelay(coord)
  t.after(() => r.stop())
  const mac = device('computer'), phone = device('phone')
  const M = api(r, await httpToken(r, coord, mac, { peers: [phone.addr] }))
  const P = api(r, await httpToken(r, coord, phone, { peers: [mac.addr] }))
  const base = `/v1/o/${mac.addr}`
  const put = async (o, path) => { const res = await M.put(`${base}/${path}`, objectSeal(mac, o), { ...SEAL, 'x-pocket-ver': String(o.ver) }); assert.equal(res.status, 200, path); return res.json() }

  await put({ kind: 'info', key: 'info', ver: 1 }, 'info/info')
  await put({ kind: 'usage', key: 'usage', ver: 1 }, 'usage/usage')
  const sA = await put({ kind: 'sess', key: 'sA', ver: 1 }, 'sess/sA')
  await put({ kind: 'sess', key: 'sB', ver: 1 }, 'sess/sB')
  for (let i = 1; i <= 5; i++) await put({ kind: 'msg', key: 'sA', seq: i, ver: 10 + i, plaintext: { seq: i, text: 'm'.repeat(i === 3 ? 6000 : 10) } }, `msg/sA/${i}`)
  await put({ kind: 'lite', key: 'sA', seq: 3, ver: 13, plaintext: { seq: 3, lite: true } }, 'lite/sA/3')

  // since=0: everything that exists of the default kinds, complete
  let j = await (await P.get(`${base}`)).json()
  assert.equal(j.full, true)
  assert.deepEqual(j.items.map((x) => `${x.kind}/${x.key}`), ['info/info', 'usage/usage', 'sess/sA', 'sess/sB'])
  assert.ok(j.items.every((x) => !x.seal), 'no inline by default')
  // inline + kinds + paging
  j = await (await P.get(`${base}?kinds=sess&inline=65536&limit=1`)).json()
  assert.equal(j.items.length, 1)
  assert.equal(j.more, true)
  assert.ok(Buffer.from(j.items[0].seal, 'base64url').length === j.items[0].bytes)
  const j2 = await (await P.get(`${base}?kinds=sess&since=${j.items[0].rev}`)).json()
  assert.deepEqual(j2.items.map((x) => x.key), ['sB'])
  assert.equal(j2.full, undefined)
  assert.equal((await P.get(`${base}?kinds=sess,bogus`)).status, 400)

  // heads
  j = await (await P.get(`${base}/heads?kind=msg`)).json()
  assert.deepEqual(j.heads, [{ key: 'sA', last: 5, ver: 15, count: 5 }])

  // range: all, prefer lite, skip, after/limit, byte cap
  const seqsOf = (buf) => ref.sealStream(buf).map((s) => [JSON.parse(s.h).kind, JSON.parse(s.h).seq])
  let res = await P.get(`${base}/msg/sA/range?after=0`)
  assert.equal(res.headers.get('content-type'), 'application/x-pocket-seal-stream')
  assert.equal(res.headers.get('x-pocket-last'), '5')
  assert.equal(res.headers.get('x-pocket-more'), null)
  assert.deepEqual(seqsOf(Buffer.from(await res.arrayBuffer())), [['msg', 1], ['msg', 2], ['msg', 3], ['msg', 4], ['msg', 5]])
  res = await P.get(`${base}/msg/sA/range?after=0&prefer=lite`)
  assert.deepEqual(seqsOf(Buffer.from(await res.arrayBuffer())), [['msg', 1], ['msg', 2], ['lite', 3], ['msg', 4], ['msg', 5]])
  res = await P.get(`${base}/msg/sA/range?after=3&skip=5:15`)
  assert.deepEqual(seqsOf(Buffer.from(await res.arrayBuffer())), [['msg', 4]], 'skip omits the seq whose version is unchanged')
  res = await P.get(`${base}/msg/sA/range?after=1&limit=2`)
  assert.deepEqual(seqsOf(Buffer.from(await res.arrayBuffer())), [['msg', 2], ['msg', 3]])
  res = await P.get(`${base}/msg/sA/range?after=0&max=1000`)
  assert.equal(res.headers.get('x-pocket-more'), '1')
  const capped = seqsOf(Buffer.from(await res.arrayBuffer()))
  assert.ok(capped.length >= 1 && capped.length < 5, 'byte cap cuts the stream, at least one item')
  res = await P.get(`${base}/msg/sA/range?after=2&max=1`)
  assert.deepEqual(seqsOf(Buffer.from(await res.arrayBuffer())), [['msg', 3]], 'one item even if it is over the cap')
  assert.equal((await P.get(`${base}/msg/sA/range?after=x`)).status, 400)
  assert.equal((await P.get(`${base}/msg/sA/range?skip=bad`)).status, 400)

  // deletes: one seq, then the whole key; listing with since shows tombstones
  const before = sA.rev
  assert.equal((await M.del(`${base}/msg/sA/5`)).status, 200)
  j = await (await P.get(`${base}/heads?kind=msg`)).json()
  assert.deepEqual(j.heads, [{ key: 'sA', last: 4, ver: 14, count: 4 }])
  assert.equal((await P.del(`${base}/msg/sA`)).status, 403, 'readers cannot delete')
  const d = await (await M.del(`${base}/msg/sA`)).json()
  assert.equal(d.deleted, 4)
  j = await (await P.get(`${base}/heads?kind=msg`)).json()
  assert.deepEqual(j.heads, [])
  j = await (await P.get(`${base}?kinds=msg,sess&since=${before}`)).json()
  const tomb = j.items.find((x) => x.kind === 'msg' && x.del && x.seq === undefined)
  assert.ok(tomb, 'key-level delete is listed without a seq')
  assert.equal((await M.del(`${base}/msg/sA`)).status, 404)
  assert.equal((await M.del(`${base}/sess/sB`)).status, 200)
  assert.equal((await P.get(`${base}/sess/sB`)).status, 404)
})

test('objects: change notifications, replay with since, resync when history is gone', async (t) => {
  const coord = new Coord()
  const r = await startRelay(coord)
  t.after(() => r.stop())
  const mac = device('computer'), phone = device('phone'), stranger = device('phone')
  const Mc = await connect(r, coord, mac, { peers: [phone.addr] })
  const M = api(r, Mc.token)
  const Pc = await connect(r, coord, phone, { peers: [mac.addr] })
  const base = `/v1/o/${mac.addr}`
  Pc.ws.send({ t: 'sub', realms: [mac.addr, stranger.addr] })
  assert.deepEqual((await Pc.ws.next('error')).realms, [stranger.addr], 'unreadable realm refused')

  let res = await M.put(`${base}/sess/k1`, objectSeal(mac, { key: 'k1', ver: 5 }), { ...SEAL, 'x-pocket-ver': '5' })
  const w = await res.json()
  const n1 = await Pc.ws.next('obj')
  assert.deepEqual(n1, { t: 'obj', realm: mac.addr, kind: 'sess', key: 'k1', ver: 5, rev: w.rev, bytes: n1.bytes })
  await M.put(`${base}/msg/k1/1`, objectSeal(mac, { kind: 'msg', key: 'k1', seq: 1, ver: 7 }), { ...SEAL, 'x-pocket-ver': '7' })
  const n2 = await Pc.ws.next('obj')
  assert.equal(n2.seq, 1)
  await M.del(`${base}/sess/k1`)
  const n3 = await Pc.ws.next('obj')
  assert.equal(n3.del, true)

  // a second phone subscribes with since = the first rev: replay of what changed after it
  const phone2 = device('phone')
  const P2 = await connect(r, coord, phone2, { peers: [mac.addr] })
  P2.ws.send({ t: 'sub', realms: [mac.addr], since: { [mac.addr]: w.rev } })
  const rep = [await P2.ws.next('obj'), await P2.ws.next('obj')]
  assert.deepEqual(rep.map((x) => [x.kind, x.del ?? false]).sort(), [['msg', false], ['sess', true]])
  // since from the future, or before purged history: resync
  P2.ws.send({ t: 'sub', realms: [mac.addr], since: { [mac.addr]: 999999 } })
  assert.deepEqual(await P2.ws.next('resync'), { t: 'resync', realm: mac.addr })
  r.relay.store.run('realmPurged', 1000, mac.addr)
  P2.ws.send({ t: 'sub', realms: [mac.addr], since: { [mac.addr]: 1 } })
  assert.deepEqual(await P2.ws.next('resync'), { t: 'resync', realm: mac.addr })
  // HTTP list below the purged horizon is a complete listing
  const j = await (await api(r, P2.token).get(`${base}?since=1&kinds=msg`)).json()
  assert.equal(j.full, true)

  // unsubscribe by replacing the set
  P2.ws.send({ t: 'sub', realms: [] })
  await sleep(50)
  await M.put(`${base}/sess/k2`, objectSeal(mac, { key: 'k2', ver: 9 }), { ...SEAL, 'x-pocket-ver': '9' })
  assert.equal((await Pc.ws.next('obj')).key, 'k2')
  assert.deepEqual(await P2.ws.collect('obj', 200), [])
  Mc.ws.close(); Pc.ws.close(); P2.ws.close()
})

test('objects: write rate per owner, account isolation', async (t) => {
  const coord = new Coord()
  const r = await startRelay(coord, { limits: { objectWritesPerSecond: 5 } })
  t.after(() => r.stop())
  const mac = device('computer', 'u_a'), intruder = device('phone', 'u_b')
  const M = api(r, await httpToken(r, coord, mac, { peers: [] }))
  let limited = 0, retryAfter = null
  for (let i = 1; i <= 12; i++) {
    const res = await M.put(`/v1/o/${mac.addr}/msg/k/${i}`, objectSeal(mac, { kind: 'msg', key: 'k', seq: i, ver: i }), { ...SEAL, 'x-pocket-ver': String(i) })
    if (res.status === 429) { limited++; retryAfter = res.headers?.['retry-after'] ?? res.headers?.get?.('retry-after') ?? retryAfter }
  }
  assert.ok(limited > 0, 'rate limited')
  assert.equal(String(retryAfter), '1', 'a rate refusal tells the writer to come back in a second, not to stop')
  // a device of another account whose (forged-by-coordination) peers name this computer still cannot read it
  const I = api(r, await httpToken(r, coord, intruder, { peers: [mac.addr] }))
  assert.equal((await I.get(`/v1/o/${mac.addr}?kinds=msg`)).status, 403)
})
