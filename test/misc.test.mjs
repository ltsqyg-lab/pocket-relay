// HTTP auth, public endpoints, configuration, object retention, a full-scenario log scan.
import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import crypto from 'node:crypto'
import { tfetch, Coord, device, startRelay, connect, httpToken, objectSeal, api, envelope, proof, ref, b64u } from './helpers.mjs'
import { startFakeS3 } from './fake-s3.mjs'
import { loadConfig, ConfigError } from '../src/config.mjs'

const SEAL = { 'content-type': 'application/x-pocket-seal' }

test('HTTP auth: challenge is single use and expires; info, well-known, health, metrics on loopback', async (t) => {
  let skew = 0
  const coord = new Coord()
  const r = await startRelay(coord, { relayId: 'hk1', now: () => Date.now() + skew })
  t.after(() => r.stop())
  const phone = device('phone')
  const ch = await (await tfetch(`${r.base}/v1/auth/challenge`, { method: 'POST' })).json()
  assert.equal(ch.relay, 'hk1')
  assert.equal(ch.exp - ch.ts, 60_000)
  const ticket = coord.ticket(phone, { aud: 'hk1' })
  const body = JSON.stringify({ ticket, ...proof(phone, ticket, ch.nonce) })
  let res = await tfetch(`${r.base}/v1/auth`, { method: 'POST', headers: { 'content-type': 'application/json' }, body })
  const ok = await res.json()
  assert.match(ok.token, /^rt_/)
  assert.equal(ok.addr, phone.addr)
  res = await tfetch(`${r.base}/v1/auth`, { method: 'POST', headers: { 'content-type': 'application/json' }, body })
  assert.equal(res.status, 401)
  assert.equal((await res.json()).error, 'bad-nonce', 'single use')
  const ch2 = await (await tfetch(`${r.base}/v1/auth/challenge`, { method: 'POST' })).json()
  skew = 61_000
  const t2 = coord.ticket(phone, { aud: 'hk1' })
  res = await tfetch(`${r.base}/v1/auth`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ ticket: t2, ...proof(phone, t2, ch2.nonce, { ts: Date.now() + skew }) }) })
  assert.equal((await res.json()).error, 'bad-nonce', 'expired after 60 s')
  skew = 0
  // public endpoints
  const info = await (await tfetch(`${r.base}/v1/info`)).json()
  assert.equal(info.service, 'pocket-relay')
  assert.equal(info.relayId, 'hk1')
  assert.deepEqual(info.features, ['ws', 'objects', 'blobs'])
  assert.equal(info.limits.envelope, 1048576)
  assert.equal(info.state, 'claimed')
  assert.deepEqual(await (await tfetch(`${r.base}/.well-known/pocket-relay`)).json(), { v: 1, state: 'claimed', relayId: 'hk1', account: '*', version: info.version, edition: 'intl' })
  assert.equal((await tfetch(`${r.base}/v1/health`)).status, 200)
  const m = await (await tfetch(`${r.base}/v1/metrics`)).json()
  assert.ok('connections' in m && 'queue' in m)
  assert.equal((await tfetch(`${r.base}/v1/nothing`)).status, 404)
  // the quota endpoint for the token holder
  const q = await (await api(r, ok.token).get('/v1/me/quota')).json()
  assert.deepEqual(Object.keys(q), ['day', 'month', 'small', 'store'])
})

test('configuration: file with comments, environment overrides, validation errors', (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pocket-relay-test-'))
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }))
  const coord = new Coord()
  const f = path.join(dir, 'relay.json')
  fs.writeFileSync(f, `{
    // pasted from the App's "add relay" screen
    "relayId": "r_abc", "account": "u_1",
    "coord": { "url": "https://pocket.pocketcli.net/", "pinnedKeys": ${JSON.stringify(coord.pinned)} },
    "dataDir": "${dir}/data", /* trailing comma follows */
  }`)
  const cfg = loadConfig({ file: f, env: { RELAY_LISTEN_PORT: '9443', RELAY_QUOTA_DAY_MB: '50', RELAY_TRUST_PROXY: 'true', RELAY_BLOBS: '{"store":"disk"}' } })
  assert.equal(cfg.relayId, 'r_abc')
  assert.equal(cfg.coord.url, 'https://pocket.pocketcli.net')
  assert.equal(cfg.listen.port, 9443)
  assert.equal(cfg.quota.dayMB, 50)
  assert.equal(cfg.trustProxy, true)
  assert.equal(cfg.limits.socketsPerDevice, 2)
  // everything from the environment
  const env = { RELAY_RELAY_ID: 'hk9', RELAY_ACCOUNT: '*', RELAY_DATA_DIR: dir, RELAY_COORD_PINNED_KEYS: JSON.stringify(coord.pinned) }
  assert.equal(loadConfig({ env }).relayId, 'hk9')
  const bad = [
    [{ ...env, RELAY_RELAY_ID: '' }, /relayId/],
    [{ ...env, RELAY_ACCOUNT: '' }, /account/],
    [{ ...env, RELAY_COORD_PINNED_KEYS: '[]' }, /pinnedKeys/],
    [{ ...env, RELAY_COORD_PINNED_KEYS: '[{"kid":"x","pub":"AAAA","use":[],"nbf":0,"exp":1}]' }, /invalid entry/],
    [{ ...env, RELAY_TIMEZONE: 'Mars/Olympus' }, /timezone/],
    [{ ...env, RELAY_BLOBS: '{"store":"s3","backends":[{"name":"x","endpoint":"https://s3.example.com"}]}' }, /region and bucket/],
  ]
  for (const [e, re] of bad) assert.throws(() => loadConfig({ env: e }), (x) => x instanceof ConfigError && re.test(x.message))
})

test('object retention: unread objects go after objectDays; a computer seen this week keeps its session list', async (t) => {
  let skew = 0
  const now = () => Date.now() + skew
  const coord = new Coord()
  const r = await startRelay(coord, { now })
  t.after(() => r.stop())
  const active = device('computer'), idle = device('computer')
  for (const c of [active, idle]) {
    const A = api(r, await httpToken(r, coord, c, { peers: [] }))
    await A.put(`/v1/o/${c.addr}/sess/s`, objectSeal(c, { key: 's', ver: 1 }), { ...SEAL, 'x-pocket-ver': '1' })
    await A.put(`/v1/o/${c.addr}/msg/s/1`, objectSeal(c, { kind: 'msg', key: 's', seq: 1, ver: 1 }), { ...SEAL, 'x-pocket-ver': '1' })
  }
  skew = 31 * 86400_000
  r.relay.store.run('identTouch', now(), active.addr)       // the active computer connected recently
  await r.relay.sweep()
  const live = (c, kind, key, seq) => !(r.relay.store.get('objGet', c.addr, kind, key, seq)?.del ?? 1)
  assert.equal(live(active, 'sess', 's', 0), true, 'session list of an active computer is kept')
  assert.equal(live(active, 'msg', 's', 1), false, 'old messages go')
  assert.equal(live(idle, 'sess', 's', 0), false, 'idle computer: everything goes')
  // tombstones go after their own period
  skew = 62 * 86400_000
  r.relay.store.run('identTouch', now(), active.addr)
  await r.relay.sweep()
  assert.equal(r.relay.store.get('objGet', idle.addr, 'sess', 's', 0), undefined)
  assert.ok(r.relay.store.get('realmGet', idle.addr).purged_rev > 0)
})

test('a full round through the relay leaves no secrets in its log', async (t) => {
  const s3 = await startFakeS3({ keys: { AK1: 'sk-1' } })
  t.after(() => s3.stop())
  const coord = new Coord()
  const r = await startRelay(coord, { blobs: { store: 's3', backends: [{ name: 'd', when: 'default', endpoint: s3.url, region: 'r', bucket: 'b', accessKeyEnv: 'K', secretKeyEnv: 'S', pathStyle: true }] } }, { env: { K: 'AK1', S: 'sk-1' } })
  t.after(() => r.stop())
  await r.relay.blobs.probe()
  const mac = device('computer'), phone = device('phone')
  const ch = await (await tfetch(`${r.base}/v1/auth/challenge`, { method: 'POST' })).json()
  const Mc = await connect(r, coord, mac, { peers: [phone.addr] })
  const Pc = await connect(r, coord, phone, { peers: [mac.addr] })
  const M = api(r, Mc.token), P = api(r, Pc.token)
  const env = envelope(phone, { to: mac.id, realm: mac.id })
  Pc.ws.send({ t: 'send', id: 'a', to: mac.addr, env, ttl: 60 })
  await Mc.ws.next('msg')
  const obj = objectSeal(mac, { key: 'k', ver: 1, plaintext: { title: 'SECRET-TITLE' } })
  await M.put(`/v1/o/${mac.addr}/sess/k`, obj, { ...SEAL, 'x-pocket-ver': '1' })
  const id = crypto.randomBytes(16), ct = ref.encryptBlob(crypto.randomBytes(32), id, Buffer.from('attachment'))
  const resv = await (await P.post(`/v1/b/${mac.addr}/${b64u(id)}/upload`, { bytes: ct.length })).json()
  await tfetch(resv.url, { method: 'PUT', body: ct, headers: resv.headers })
  await P.post(`/v1/b/${mac.addr}/${b64u(id)}/commit`, { bytes: ct.length })
  const loc = (await M.get(`/v1/b/${mac.addr}/${b64u(id)}`)).headers.get('location')
  const all = r.logs.join('\n')
  const secrets = [Mc.ticket, Pc.ticket, Mc.token, Pc.token, ch.nonce, env.h, env.c, env.s, b64u(obj), obj.toString('hex').slice(0, 64), resv.url, loc,
    new URL(resv.url).searchParams.get('X-Amz-Signature'), 'sk-1', 'Bearer']
  for (const s of secrets) assert.ok(!all.includes(s), `log contains ${String(s).slice(0, 24)}…`)
  assert.ok(all.includes('obj-put') && all.includes('blob-commit'), 'operations are logged')
  Mc.ws.close(); Pc.ws.close()
})

test('limits: connections per IP, JSON body size', async (t) => {
  const coord = new Coord()
  const r = await startRelay(coord, { limits: { connectionsPerIp: 3 } })
  t.after(() => r.stop())
  const { wsConnect } = await import('./helpers.mjs')
  const socks = [await wsConnect(r.base), await wsConnect(r.base), await wsConnect(r.base)]
  await assert.rejects(wsConnect(r.base), 'the fourth connection from one IP is dropped')
  for (const s of socks) s.close()
  await new Promise((res) => setTimeout(res, 300))
  const big = JSON.stringify({ bytes: 1, pad: 'x'.repeat(70 * 1024) })
  const res = await tfetch(`${r.base}/v1/auth`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: big })
  assert.equal(res.status, 413)
})
