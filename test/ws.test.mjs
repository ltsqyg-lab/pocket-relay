// WebSocket: authentication, renewal, envelopes, queue, presence, limits (RELAY.md §3.1, §5, §15).
import test from 'node:test'
import assert from 'node:assert/strict'
import { Coord, device, startRelay, wsConnect, connect, httpToken, api, proof, envelope, sleep, b64u } from './helpers.mjs'

test('websocket: challenge, auth, ready; failures close with the right codes', async (t) => {
  const coord = new Coord()
  const r = await startRelay(coord, { limits: { authSeconds: 1 } })
  t.after(() => r.stop())
  const phone = device('phone'), mac = device('computer')

  // ready carries addr, dev, acct, exp, token, peers with presence
  const a = await connect(r, coord, phone, { peers: [mac.addr] })
  assert.equal(a.ready.addr, phone.addr)
  assert.equal(a.ready.dev, phone.id)
  assert.equal(a.ready.acct, 'u_lab1')
  assert.match(a.ready.token, /^rt_[A-Za-z0-9_-]{43}$/)
  assert.deepEqual(a.ready.peers, [{ addr: mac.addr, online: false }])
  assert.equal(a.ready.queued, 0)

  // a proof answering an old challenge
  const ws1 = await wsConnect(r.base)
  const ch1 = await ws1.next('challenge')
  assert.equal(ch1.relay, 'hk1')
  const ws1b = await wsConnect(r.base)
  await ws1b.next('challenge')
  const tk = coord.ticket(phone, { aud: 'hk1' })
  ws1b.send({ t: 'auth', ticket: tk, ...proof(phone, tk, ch1.nonce) })          // nonce issued to another socket
  assert.equal((await ws1b.next('error')).code, 'bad-nonce')
  assert.equal(await ws1b.closed, 4401)
  // reusing the same nonce on its own socket after a failure is impossible: the nonce is single use
  ws1.send({ t: 'auth', ticket: tk, ...proof(phone, tk, ch1.nonce, { ts: Date.now() - 10 * 60_000 }) })
  assert.equal((await ws1.next('error')).code, 'stale')
  assert.equal(await ws1.closed, 4401)

  // stolen ticket, attacker's key
  const evil = device('phone')
  const ws2 = await wsConnect(r.base)
  const ch2 = await ws2.next('challenge')
  ws2.send({ t: 'auth', ticket: tk, ...proof(evil, tk, ch2.nonce) })
  assert.equal((await ws2.next('error')).code, 'bad-sig')
  assert.equal(await ws2.closed, 4401)

  // ticket for another relay, ticket signed by an unknown coordination key, expired ticket
  for (const [opts, code] of [[{ aud: 'r_other' }, 'wrong-aud'], [{ kid: 'zz', key: new Coord().key.priv }, 'unknown-key'], [{ iat: Date.now() - 7 * 3600_000, exp: Date.now() - 3600_000 }, 'expired']]) {
    const w = await wsConnect(r.base)
    const ch = await w.next('challenge')
    const tick = coord.ticket(phone, opts)
    w.send({ t: 'auth', ticket: tick, ...proof(phone, tick, ch.nonce) })
    assert.equal((await w.next('error')).code, code, code)
    assert.equal(await w.closed, 4401)
  }

  // no auth within the limit
  const ws3 = await wsConnect(r.base)
  await ws3.next('challenge')
  assert.equal(await ws3.closed, 4408)

  // frames before auth
  const ws4 = await wsConnect(r.base)
  await ws4.next('challenge')
  ws4.send({ t: 'send', id: 'x', to: mac.addr, env: {} })
  assert.equal(await ws4.closed, 4401)

  // malformed frame
  const ws5 = await wsConnect(r.base)
  await ws5.next('challenge')
  ws5.raw(0x1, Buffer.from('not json'))
  assert.equal(await ws5.closed, 4400)
  a.ws.close()
})

test('websocket: renewal on the same socket; renewal for another device is refused; ticket expiry closes', async (t) => {
  const coord = new Coord()
  const r = await startRelay(coord)
  t.after(() => r.stop())
  const phone = device('phone'), mac = device('computer'), other = device('phone')
  const a = await connect(r, coord, phone, { peers: [] })
  a.ws.send({ t: 'renew' })
  const ch = await a.ws.next('challenge')
  const tk = coord.ticket(phone, { peers: [mac.addr] })
  a.ws.send({ t: 'auth', ticket: tk, ...proof(phone, tk, ch.nonce) })
  const ready2 = await a.ws.next('ready')
  assert.deepEqual(ready2.peers.map((x) => x.addr), [mac.addr], 'renewal brings the new peers')
  assert.notEqual(ready2.token, a.ready.token)
  // renewal with a ticket of another device
  a.ws.send({ t: 'renew' })
  const ch3 = await a.ws.next('challenge')
  const tk3 = coord.ticket(other)
  a.ws.send({ t: 'auth', ticket: tk3, ...proof(other, tk3, ch3.nonce) })
  assert.equal((await a.ws.next('error')).code, 'denied')
  assert.equal(await a.ws.closed, 4401)

  // a ticket about to expire: the relay closes 4401 'expired' at exp + 5 min of skew → simulate with a short ticket
  const skewed = await startRelay(coord, { now: () => Date.now() + 5 * 60_000 - 1500 })
  t.after(() => skewed.stop())
  const b = await connect(skewed, coord, phone, { iat: Date.now() - 1000, exp: Date.now() + 500 })
  assert.equal((await b.ws.next('error', 6000)).code, 'expired')
  assert.equal(await b.ws.closed, 4401)
})

test('websocket: a relay bound to one account refuses the others', async (t) => {
  const coord = new Coord()
  const r = await startRelay(coord, { relayId: 'r_self1', account: 'u_mine' })
  t.after(() => r.stop())
  const mine = device('phone', 'u_mine'), theirs = device('phone', 'u_theirs')
  const ok = await connect(r, coord, mine, { aud: 'r_self1' }, { relay: 'r_self1' })
  assert.equal(ok.ready.acct, 'u_mine')
  await assert.rejects(connect(r, coord, theirs, { aud: 'r_self1' }, { relay: 'r_self1' }), (e) => e.code === 'wrong-account')
  ok.ws.close()
})

test('envelopes: peers only, fan-out, header cross-checks, statuses', async (t) => {
  const coord = new Coord()
  const r = await startRelay(coord)
  t.after(() => r.stop())
  const mac = device('computer'), p1 = device('phone'), p2 = device('phone'), stranger = device('phone')
  const M = await connect(r, coord, mac, { peers: [p1.addr, p2.addr] })
  const A = await connect(r, coord, p1, { peers: [mac.addr] })
  // presence: A sees the computer online at ready; the computer is told A came online
  assert.deepEqual(A.ready.peers, [{ addr: mac.addr, online: true }])
  const pres = await M.ws.next((f) => f.t === 'presence' && f.addr === p1.addr)
  assert.equal(pres.online, true)

  const e1 = envelope(p1, { to: mac.id, realm: mac.id })
  A.ws.send({ t: 'send', id: 'f1', to: mac.addr, env: e1, ttl: 60 })
  const got = await M.ws.next('msg')
  assert.equal(got.from, p1.addr)
  assert.deepEqual(got.env, e1)
  assert.ok(got.at > 0 && got.q === undefined)
  assert.deepEqual(await A.ws.next('sent'), { t: 'sent', id: 'f1', status: 'delivered', n: 1, queued: 0 })

  // not a peer
  A.ws.send({ t: 'send', id: 'f2', to: stranger.addr, env: envelope(p1, { to: stranger.id, realm: mac.id }), ttl: 60 })
  assert.equal((await A.ws.next('sent')).status, 'denied')
  // header says another sender
  A.ws.send({ t: 'send', id: 'f3', to: mac.addr, env: envelope(p2, { to: mac.id, realm: mac.id }), ttl: 60 })
  assert.equal((await A.ws.next('sent')).status, 'denied')
  // header addressed to another device than the relay knows at that address
  A.ws.send({ t: 'send', id: 'f3b', to: mac.addr, env: envelope(p1, { to: p2.id, realm: mac.id }), ttl: 60 })
  assert.equal((await A.ws.next('sent')).status, 'denied')

  // '*' from the computer: delivered to the online phone, queued for the offline one → partial
  const ev = envelope(mac, { to: '*', realm: mac.id, kind: 'evt', payload: { op: 'notify' } })
  M.ws.send({ t: 'send', id: 'e1', to: '*', env: ev, ttl: 600 })
  assert.deepEqual(await M.ws.next('sent'), { t: 'sent', id: 'e1', status: 'partial', n: 1, queued: 1 })
  assert.equal((await A.ws.next('msg')).from, mac.addr)
  // '*' with a header not addressed to '*'
  M.ws.send({ t: 'send', id: 'e2', to: '*', env: envelope(mac, { to: p1.id, realm: mac.id, kind: 'evt' }), ttl: 0 })
  assert.equal((await M.ws.next('sent')).status, 'denied')
  // ttl 0 to an offline peer
  M.ws.send({ t: 'send', id: 'e3', to: p2.addr, env: envelope(mac, { to: p2.id, realm: mac.id, kind: 'evt' }), ttl: 0 })
  assert.deepEqual(await M.ws.next('sent'), { t: 'sent', id: 'e3', status: 'offline', n: 0, queued: 0 })
  // malformed frames
  M.ws.send({ t: 'send', id: 'e4', to: 'nope', env: ev })
  assert.equal((await M.ws.next('error')).code, 'bad-request')
  M.ws.send({ t: 'send', id: 'e5', to: p1.addr, env: { h: ev.h, c: ev.c + '=', s: ev.s } })
  assert.equal((await M.ws.next('error')).code, 'bad-request')
  M.ws.send({ t: 'ping', ts: 42 })
  assert.deepEqual(await M.ws.next('pong'), { t: 'pong', ts: 42 })

  // p2 comes online later: gets the queued envelope with q, in order; acks it
  const B = await connect(r, coord, p2, { peers: [mac.addr] })
  assert.equal(B.ready.queued, 1)
  const q = await B.ws.next('msg')
  assert.ok(q.q > 0)
  assert.deepEqual(q.env, ev)
  B.ws.send({ t: 'ack', q: q.q })
  await sleep(100)
  B.ws.close()
  await sleep(250)
  const B2 = await connect(r, coord, p2, { peers: [mac.addr] })
  assert.equal(B2.ready.queued, 0, 'acked envelopes are gone')
  M.ws.close(); A.ws.close(); B2.ws.close()
})

test('queue: order, redelivery until acked, TTL expiry with the expired notice, full', async (t) => {
  const coord = new Coord()
  const r = await startRelay(coord, { limits: { queueEnvelopes: 3 } })
  t.after(() => r.stop())
  const mac = device('computer'), phone = device('phone')
  const M = await connect(r, coord, mac, { peers: [phone.addr] })
  const envs = [1, 2, 3].map((i) => envelope(mac, { to: phone.id, realm: mac.id, kind: 'evt', seq: i, payload: { op: 'notify', i } }))
  for (const [i, e] of envs.entries()) M.ws.send({ t: 'send', id: `q${i}`, to: phone.addr, env: e, ttl: 600 })
  for (let i = 0; i < 3; i++) assert.equal((await M.ws.next('sent')).status, 'queued')
  M.ws.send({ t: 'send', id: 'q3', to: phone.addr, env: envelope(mac, { to: phone.id, realm: mac.id, kind: 'evt' }), ttl: 600 })
  assert.deepEqual(await M.ws.next('sent'), { t: 'sent', id: 'q3', status: 'full', n: 0, queued: 0 })

  // first connection: three messages in order, ack only the first
  const P1 = await connect(r, coord, phone, { peers: [mac.addr] })
  const got = [await P1.ws.next('msg'), await P1.ws.next('msg'), await P1.ws.next('msg')]
  assert.deepEqual(got.map((m) => m.env), envs)
  assert.ok(got[0].q < got[1].q && got[1].q < got[2].q)
  P1.ws.send({ t: 'ack', q: got[0].q })
  await sleep(100)
  P1.ws.close()
  await sleep(200)
  // redelivered: the two unacked ones
  const P2 = await connect(r, coord, phone, { peers: [mac.addr] })
  assert.equal(P2.ready.queued, 2)
  const again = [await P2.ws.next('msg'), await P2.ws.next('msg')]
  assert.deepEqual(again.map((m) => m.q), [got[1].q, got[2].q])
  for (const m of again) P2.ws.send({ t: 'ack', q: m.q })
  // an ack for someone else's queue entry does nothing (and is not an error)
  P2.ws.send({ t: 'ack', q: 999999 })
  await sleep(100)
  P2.ws.close()
  await sleep(250)

  // TTL: a short-lived envelope expires; the sender hears about it
  M.ws.send({ t: 'send', id: 'short', to: phone.addr, env: envelope(mac, { to: phone.id, realm: mac.id, kind: 'evt' }), ttl: 1 })
  assert.equal((await M.ws.next('sent')).status, 'queued')
  const exp = await M.ws.next('expired', 8000)
  assert.deepEqual(exp, { t: 'expired', id: 'short', to: phone.addr })
  const P3 = await connect(r, coord, phone, { peers: [mac.addr] })
  assert.equal(P3.ready.queued, 0)
  M.ws.close(); P3.ws.close()
})

test('presence: offline after the debounce; a quick reconnect is not reported', async (t) => {
  const coord = new Coord()
  const r = await startRelay(coord, { limits: { presenceDebounceMs: 400 } })
  t.after(() => r.stop())
  const mac = device('computer'), phone = device('phone')
  const P = await connect(r, coord, phone, { peers: [mac.addr] })
  const M = await connect(r, coord, mac, { peers: [phone.addr] })
  assert.equal((await P.ws.next('presence')).online, true)
  M.ws.close()
  await sleep(100)
  const M2 = await connect(r, coord, mac, { peers: [phone.addr] })
  assert.deepEqual(await P.ws.collect('presence', 700), [], 'a reconnect inside the debounce window is silent')
  M2.ws.close()
  const off = await P.ws.next('presence', 2000)
  assert.equal(off.online, false)
  assert.equal(off.addr, mac.addr)
  P.ws.close()
})

test('limits: two sockets per device (the oldest is replaced), too-large envelopes, rate, frame size', async (t) => {
  const coord = new Coord()
  const r = await startRelay(coord, { limits: { frameBurst: 10, frameRate: 5, envelope: 2048, frame: 64 * 1024 } })
  t.after(() => r.stop())
  const mac = device('computer'), phone = device('phone')
  const s1 = await connect(r, coord, phone, { peers: [mac.addr] })
  await sleep(10)
  const s2 = await connect(r, coord, phone, { peers: [mac.addr] })
  const s3 = await connect(r, coord, phone, { peers: [mac.addr] })
  assert.equal(await s1.ws.closed, 4409)
  const M = await connect(r, coord, mac, { peers: [phone.addr] })
  // envelope ciphertext over the limit
  const big = envelope(mac, { to: phone.id, realm: mac.id, kind: 'evt', payload: { op: 'x', pad: 'y'.repeat(4000) } })
  M.ws.send({ t: 'send', id: 'big', to: phone.addr, env: big, ttl: 0 })
  assert.equal((await M.ws.next('sent')).status, 'too-large')
  // rate: burst then 'rate'
  for (let i = 0; i < 14; i++) M.ws.send({ t: 'ping', ts: i })
  const errs = await M.ws.collect('error', 300)
  assert.ok(errs.some((e) => e.code === 'rate'), 'rate limited')
  // a frame over the WebSocket limit closes 4413
  s2.ws.send({ t: 'ping', pad: 'z'.repeat(70 * 1024) })
  assert.equal(await s2.ws.closed, 4413)
  s3.ws.close(); M.ws.close()
})

test('logs never contain tickets, tokens, nonces or envelope bytes', async (t) => {
  const coord = new Coord()
  const r = await startRelay(coord)
  t.after(() => r.stop())
  const mac = device('computer'), phone = device('phone')
  const M = await connect(r, coord, mac, { peers: [phone.addr] })
  const P = await connect(r, coord, phone, { peers: [mac.addr] })
  const e = envelope(phone, { to: mac.id, realm: mac.id })
  P.ws.send({ t: 'send', id: 'l1', to: mac.addr, env: e, ttl: 60 })
  await M.ws.next('msg')
  const all = r.logs.join('\n')
  for (const secret of [M.ticket, P.ticket, M.token, P.token, e.h, e.c, e.s, M.ticket.split('.')[1]]) assert.ok(!all.includes(secret), 'secret in logs')
  assert.ok(r.logs.length > 0)
  M.ws.close(); P.ws.close()
})

test('acks: a long queue can be acked beyond the frame rate (single and batched); tokens per device are capped', async (t) => {
  const coord = new Coord()
  const r = await startRelay(coord, { limits: { frameBurst: 10, frameRate: 5 } })
  t.after(() => r.stop())
  const mac = device('computer'), phone = device('phone')
  const M = await connect(r, coord, mac, { peers: [phone.addr] })
  // fill the phone's queue without hitting the computer's frame limit
  const env = envelope(mac, { to: phone.id, realm: mac.id, kind: 'evt' })
  const now = Date.now()
  for (let i = 0; i < 60; i++) r.relay.store.run('qAdd', phone.addr, 'u_lab1', mac.addr, `f${i}`, JSON.stringify(env), 300, now, now + 600_000)
  const P = await connect(r, coord, phone, { peers: [mac.addr] })
  assert.equal(P.ready.queued, 60)
  const qs = []
  for (let i = 0; i < 60; i++) qs.push((await P.ws.next('msg')).q)
  for (const q of qs.slice(0, 30)) P.ws.send({ t: 'ack', q })            // 30 single acks: over the 10-frame burst
  P.ws.send({ t: 'ack', q: qs.slice(30) })                                // and one batch of 30
  P.ws.send({ t: 'ack', q: [1, 'x'] })
  assert.equal((await P.ws.next('error')).code, 'bad-request')
  await sleep(150)
  assert.equal(r.relay.store.get('qStats', phone.addr).n, 0, 'all acked')
  // tokens: at most 16 live per device, the oldest goes first
  const first = P.token
  const toks = []
  for (let i = 0; i < 16; i++) toks.push(await httpToken(r, coord, phone, { peers: [mac.addr] }))
  assert.equal((await api(r, first).get('/v1/me/quota')).status, 401, 'oldest token dropped')
  assert.equal((await api(r, toks.at(-1)).get('/v1/me/quota')).status, 200)
  M.ws.close(); P.ws.close()
})
