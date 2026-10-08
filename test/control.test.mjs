// Revocations (push and poll), purge orders, key rotation, address reassignment (RELAY.md §3.3, §6.5, §15).
import test from 'node:test'
import assert from 'node:assert/strict'
import crypto from 'node:crypto'
import { tfetch, Coord, device, startRelay, connect, httpToken, objectSeal, api, envelope, ref, b64u, sleep } from './helpers.mjs'

const SEAL = { 'content-type': 'application/x-pocket-seal' }
const post = (r, p, j) => tfetch(`${r.base}${p}`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(j) })

test('revocations pushed: sockets closed, tokens void, gone deletes data, suspension lifted by newer tickets', async (t) => {
  const coord = new Coord()
  const r = await startRelay(coord)
  t.after(() => r.stop())
  const mac = device('computer'), phone = device('phone')
  const Mc = await connect(r, coord, mac, { peers: [phone.addr] })
  const Pc = await connect(r, coord, phone, { peers: [mac.addr] })
  const M = api(r, Mc.token), P = api(r, Pc.token)
  await M.put(`/v1/o/${mac.addr}/sess/s1`, objectSeal(mac, { key: 's1', ver: 1 }), { ...SEAL, 'x-pocket-ver': '1' })
  const b = crypto.randomBytes(16), ct = ref.encryptBlob(crypto.randomBytes(32), b, Buffer.from('hello'))
  assert.equal((await P.put(`/v1/b/${mac.addr}/${b64u(b)}`, ct)).status, 200)

  // suspend the phone: its socket closes, its token stops working, its old tickets are refused
  const cut = Date.now() + 1                 // strictly after the tickets above were issued
  let res = await post(r, '/v1/revocations', coord.revocations('u_lab1', [{ addr: phone.addr, dev: phone.id, nbf: cut }]))
  assert.deepEqual(await res.json(), { applied: 1 })
  assert.equal((await Pc.ws.next('error')).code, 'revoked')
  assert.equal(await Pc.ws.closed, 4403)
  assert.equal((await P.get(`/v1/o/${mac.addr}/sess/s1`)).status, 401)
  await assert.rejects(connect(r, coord, phone, { peers: [mac.addr], iat: cut - 1000 }), (e) => e.code === 'revoked')
  // the same document again changes nothing
  assert.deepEqual(await (await post(r, '/v1/revocations', coord.revocations('u_lab1', [{ addr: phone.addr, dev: phone.id, nbf: cut }]))).json(), { applied: 0 })
  // lifted: a ticket issued after the cut-off works
  const P2 = await connect(r, coord, phone, { peers: [mac.addr], iat: cut + 1 })
  assert.equal(P2.ready.addr, phone.addr)
  // the computer was not affected
  assert.equal((await M.get(`/v1/o/${mac.addr}/sess/s1`)).status, 200)

  // revoke the computer: gone → its realm's objects and blobs are deleted, envelopes to it dropped
  res = await post(r, '/v1/revocations', coord.revocations('u_lab1', [{ addr: mac.addr, dev: mac.id, nbf: Number.MAX_SAFE_INTEGER, gone: true }]))
  assert.deepEqual(await res.json(), { applied: 1 })
  assert.equal(await Mc.ws.closed, 4403)
  assert.equal(r.relay.store.get('objCountRealm', mac.addr).n, 0)
  assert.equal(r.relay.store.all('blobsOfRealm', mac.addr).length, 0)
  P2.ws.send({ t: 'send', id: 'x', to: mac.addr, env: envelope(phone, { to: mac.id, realm: mac.id }), ttl: 60 })
  assert.equal((await P2.ws.next('sent')).status, 'offline')
  await assert.rejects(connect(r, coord, mac, { peers: [phone.addr] }), (e) => e.code === 'revoked')

  // bad documents
  assert.equal((await post(r, '/v1/revocations', { p: 'x', s: 'y' })).status, 400)
  const forged = new Coord({ kid: coord.kid })
  assert.equal((await post(r, '/v1/revocations', forged.revocations('u_lab1', [{ addr: mac.addr, nbf: 1 }]))).status, 401)
  assert.equal((await post(r, '/v1/revocations', coord.purge('u_lab1'))).status, 400, 'a purge order is not a revocation document')
  P2.ws.close()
})

test('revocations polled from coordination; a bound relay polls its account and refuses other accounts\' documents', async (t) => {
  const coord = new Coord()
  const seen = []
  const fetchImpl = async (url, opts) => {
    const u = new URL(url)
    if (u.origin === 'https://coord.test') {
      seen.push(u.pathname + u.search)
      if (u.pathname === '/v2/relay/revocations') return new Response(JSON.stringify(coord.feed(u.searchParams.get('acct'), Number(u.searchParams.get('since')))), { status: 200 })
      return new Response('{}', { status: 404 })
    }
    return fetch(url, opts)
  }
  const r = await startRelay(coord, { relayId: 'r_self9', account: 'u_mine', coord: { url: 'https://coord.test', pinnedKeys: coord.pinned } }, { fetchImpl })
  t.after(() => r.stop())
  const phone = device('phone', 'u_mine')
  const Pc = await connect(r, coord, phone, { aud: 'r_self9', peers: [] }, { relay: 'r_self9' })
  coord.revocations('u_mine', [{ addr: phone.addr, dev: phone.id, nbf: Date.now() + 1 }])
  await r.relay.pollAccount('u_mine')
  assert.equal(await Pc.ws.closed, 4403)
  assert.ok(seen.some((s) => s === '/v2/relay/revocations?acct=u_mine&since=0'))
  assert.equal(r.relay.store.get('curGet', 'u_mine').cursor, 1, 'cursor advances')
  await r.relay.pollAccount('u_mine')
  assert.ok(seen.includes('/v2/relay/revocations?acct=u_mine&since=1'))
  // a document about another account is refused by a bound relay
  const other = coord.revocations('u_other', [{ addr: '100.64.9.9', nbf: Date.now() }])
  assert.equal((await post(r, '/v1/revocations', other)).status, 403)
})

test('purge orders: wrong label, wrong relay, older than 7 days, replayed; account and realm scopes', async (t) => {
  const coord = new Coord()
  const r = await startRelay(coord)
  t.after(() => r.stop())
  const mac = device('computer', 'u_p'), mac2 = device('computer', 'u_p'), keep = device('computer', 'u_keep'), phone = device('phone', 'u_p')
  for (const c of [mac, mac2, keep]) {
    const A = api(r, await httpToken(r, coord, c, { peers: [] }))
    await A.put(`/v1/o/${c.addr}/sess/s`, objectSeal(c, { key: 's', ver: 1 }), { ...SEAL, 'x-pocket-ver': '1' })
  }
  // an envelope queued for the phone
  const Mc = await connect(r, coord, mac, { peers: [phone.addr] })
  Mc.ws.send({ t: 'send', id: 'q', to: phone.addr, env: envelope(mac, { to: phone.id, realm: mac.id, kind: 'evt' }), ttl: 600 })
  assert.equal((await Mc.ws.next('sent')).status, 'queued')

  assert.equal((await post(r, '/v1/purge', coord.revocations('u_p', []))).status, 400, 'wrong label')
  let res = await post(r, '/v1/purge', coord.purge('u_p', { relay: 'r_elsewhere' }))
  assert.equal(res.status, 403, 'wrong relay')
  res = await post(r, '/v1/purge', coord.purge('u_p', { at: Date.now() - 8 * 86400_000 }))
  assert.equal(res.status, 401)
  assert.equal((await res.json()).error, 'stale')

  // one realm
  res = await post(r, '/v1/purge', coord.purge('u_p', { addrs: [mac2.addr] }))
  assert.deepEqual(await res.json(), { deleted: { objects: 1, blobs: 0, queued: 0 } })
  assert.equal(r.relay.store.get('objCountRealm', mac2.addr).n, 0)
  assert.equal(r.relay.store.get('objCountRealm', mac.addr).n, 1)
  // the whole account ("*" relay)
  const order = coord.purge('u_p', { relay: '*' })
  res = await post(r, '/v1/purge', order)
  const d = (await res.json()).deleted
  assert.equal(d.objects, 1)
  assert.equal(d.queued, 1)
  assert.equal(r.relay.store.get('objCountRealm', mac.addr).n, 0)
  assert.equal(r.relay.store.get('objCountRealm', keep.addr).n, 1, 'other accounts untouched')
  // replayed: acknowledged, nothing done
  assert.deepEqual(await (await post(r, '/v1/purge', order)).json(), { deleted: { objects: 0, blobs: 0, queued: 0 }, already: true })
  Mc.ws.close()
})

test('coordination key rotation: a ticket from an unknown kid triggers a keys.json refresh', async (t) => {
  const c1 = new Coord({ kid: 'k1' })
  const c2 = new Coord({ kid: 'k2' })
  let served = null
  const fetchImpl = async (url, opts) => {
    const u = new URL(url)
    if (u.origin === 'https://coord.test') {
      if (u.pathname === '/.well-known/pocket/keys.json' && served) return new Response(JSON.stringify(served), { status: 200 })
      return new Response('{}', { status: 404 })
    }
    return fetch(url, opts)
  }
  const r = await startRelay(c1, { coord: { url: 'https://coord.test', pinnedKeys: c1.pinned } }, { fetchImpl })
  t.after(() => r.stop())
  const phone = device('phone')
  // nothing published yet: unknown key
  await assert.rejects(connect(r, c2, phone, { peers: [] }), (e) => e.code === 'unknown-key')
  // a keys document signed by an untrusted key is ignored
  served = c2.keysDoc([...c1.pinned, ...c2.pinned], [c2])
  r.relay.keys.lastTry = 0
  await assert.rejects(connect(r, c2, phone, { peers: [] }), (e) => e.code === 'unknown-key')
  // signed by the pinned key: adopted
  served = c1.keysDoc([...c1.pinned, ...c2.pinned], [c1])
  r.relay.keys.lastTry = 0
  const ok = await connect(r, c2, phone, { peers: [] })
  assert.equal(ok.ready.addr, phone.addr)
  assert.ok(r.relay.keys.list.some((k) => k.kid === 'k2'))
  ok.ws.close()
})

test('address reassigned to another device (90+ days after a revocation): old data goes, new device works', async (t) => {
  const coord = new Coord()
  const r = await startRelay(coord)
  t.after(() => r.stop())
  const old = device('computer', 'u_old')
  const A = api(r, await httpToken(r, coord, old, { peers: [] }))
  await A.put(`/v1/o/${old.addr}/sess/s`, objectSeal(old, { key: 's', ver: 1 }), { ...SEAL, 'x-pocket-ver': '1' })
  await post(r, '/v1/revocations', coord.revocations('u_old', [{ addr: old.addr, dev: old.id, nbf: Number.MAX_SAFE_INTEGER, gone: true }]))
  const fresh = device('computer', 'u_new', old.addr)
  const B = await connect(r, coord, fresh, { peers: [] })
  assert.equal(B.ready.addr, old.addr)
  assert.equal(r.relay.store.get('objCountRealm', old.addr).n, 0)
  const res = await api(r, B.token).put(`/v1/o/${old.addr}/sess/s`, objectSeal(fresh, { key: 's', ver: 1 }), { ...SEAL, 'x-pocket-ver': '1' })
  assert.equal(res.status, 200, 'the new owner writes into a clean realm')
  // a third device claiming the address while the current one is active (not gone, recently seen) is refused
  const squatter = device('computer', 'u_x', old.addr)
  await assert.rejects(connect(r, coord, squatter, { peers: [] }), (e) => e.code === 'wrong-account')
  const sibling = device('phone', 'u_new', old.addr)
  await assert.rejects(connect(r, coord, sibling, { peers: [] }), (e) => e.code === 'denied', 'same account, address still in use')
  assert.equal(r.relay.store.get('objCountRealm', old.addr).n, 1, 'the active owner keeps its data')
  B.ws.close()
})
