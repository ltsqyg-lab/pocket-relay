// Running without a domain (RELAY.md §12.1): self-signed TLS for the public address, the connection line, the
// unclaimed state, POST /v1/claim, restarts, reset-claim from another process, the official configuration unchanged,
// and the relay as a process the way the Docker image runs it.
import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import http from 'node:http'
import crypto from 'node:crypto'
import { spawn, spawnSync, execFileSync } from 'node:child_process'
import { fileURLToPath } from 'node:url'
import { Coord, device, startRelay, connect, objectSeal, pinnedRequest, wsConnect, tfetch, sleep } from './helpers.mjs'
import { parseConnect, formatConnect, connectInfo, publiclyTrusted, readBinding, claimFiles, nonPublicIp } from '../src/claim.mjs'
import { hostOfCert, pinOf, makeSelfSigned } from '../src/selfcert.mjs'
import { finalize, loadConfig, ConfigError, OFFICIAL_COORD_KEYS } from '../src/config.mjs'

const MAIN = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'src', 'main.mjs')
const SEAL = { 'content-type': 'application/x-pocket-seal' }
const hasOpenssl = (() => { try { execFileSync('openssl', ['version'], { stdio: 'pipe' }); return true } catch { return false } })()
const json = (obj, status = 200) => new Response(JSON.stringify(obj), { status, headers: { 'content-type': 'application/json' } })
/** A fake coordination for fetch: whoami answers `ip` (a function may change it), everything else 404; calls are recorded. */
function fakeCoord(ip = '127.0.0.1') {
  const calls = []
  const fetchImpl = async (url) => {
    const u = new URL(url)
    calls.push(u.pathname)
    if (u.pathname === '/v2/whoami') { const v = typeof ip === 'function' ? ip() : ip; return v instanceof Response ? v : json({ ip: v }) }
    return new Response('not found', { status: 404 })
  }
  return { fetchImpl, calls }
}
const claimable = (coord, over = {}) => ({ relayId: null, account: null, tls: 'auto', coord: { url: 'https://coord.test', pinnedKeys: coord.pinned }, ...over })
const lineOf = (r) => fs.readFileSync(claimFiles(r.dir).connect, 'utf8').trim()
const mode = (f) => fs.statSync(f).mode & 0o777
async function until(fn, ms = 5000, what = 'condition') {
  const end = Date.now() + ms
  for (;;) { const v = await fn(); if (v) return v; if (Date.now() > end) throw new Error(`timeout waiting for ${what}`); await sleep(50) }
}
const P = (r, p, o = {}) => pinnedRequest(r.base + p, { pin: r.pin, ...o })
const post = (r, p, body, o = {}) => P(r, p, { method: 'POST', body: JSON.stringify(body), ...o })

test('unclaimed: self-signed certificate for the address coordination reports, the line, and only three endpoints answer', async (t) => {
  const coord = new Coord()
  const fc = fakeCoord('127.0.0.1')
  const r = await startRelay(coord, claimable(coord), { fetchImpl: fc.fetchImpl })
  t.after(() => r.stop())
  assert.ok(fc.calls.includes('/v2/whoami'), 'asked coordination for the public address')
  assert.match(r.base, /^https:/)
  // files: 0600 in the data directory, the certificate for 127.0.0.1
  const F = claimFiles(r.dir)
  for (const f of [F.claim, F.connect, F.selfKey, F.selfCert, F.public]) assert.equal(mode(f), 0o600, f)
  assert.equal(mode(F.tlsDir), 0o700)
  assert.equal(fs.existsSync(F.binding), false)
  const cert = new crypto.X509Certificate(fs.readFileSync(F.selfCert))
  assert.equal(hostOfCert(cert), '127.0.0.1')
  assert.equal(r.pin, pinOf(cert))
  // the line: in connect.txt and on standard output, with the pin and the claim code
  const line = lineOf(r)
  const c = parseConnect(line)
  assert.deepEqual([c.host, c.port, c.pin], ['127.0.0.1', r.port, r.pin])
  assert.equal(c.claim, JSON.parse(fs.readFileSync(F.claim, 'utf8')).claim)
  assert.equal(line, `pocket-relay://127.0.0.1:${r.port}?pin=${r.pin}&claim=${c.claim}`)
  const out = r.printed.join('')
  for (const want of [line, 'In the Pocket app: Settings → Relay → Add your own relay, then paste this line', '在 Pocket App:我的 → 中继 → 添加自建中继,粘贴这一行',
    `TCP port ${r.port}`, `TCP ${r.port} 端口`, 'connect-string']) assert.ok(out.includes(want), `output has ${want}`)
  // what answers
  let x = await P(r, '/.well-known/pocket-relay')
  assert.equal(x.status, 200)
  assert.deepEqual(x.json(), { v: 1, state: 'unclaimed' })
  x = await P(r, '/v1/info')
  assert.equal(x.status, 200)
  assert.equal(x.json().state, 'unclaimed')
  assert.equal(x.json().relayId, null)
  for (const [m, p] of [['GET', '/v1/health'], ['POST', '/v1/auth/challenge'], ['POST', '/v1/auth'], ['GET', '/v1/o/100.64.0.9'], ['POST', '/v1/revocations'], ['POST', '/v1/purge'], ['GET', '/v1/metrics'], ['GET', '/nothing']]) {
    x = await P(r, p, { method: m, ...(m === 'POST' ? { body: '{}' } : {}) })
    assert.equal(x.status, 503, `${m} ${p}`)
    assert.deepEqual(x.json(), { error: 'unclaimed', code: 'unclaimed' }, `${m} ${p}`)
  }
  await assert.rejects(wsConnect(r.base, '/v1/ws', { pin: r.pin }), (e) => e.status === 503, 'WebSocket refused')
  await assert.rejects(pinnedRequest(r.base + '/v1/info', { pin: 'sha256:' + 'a'.repeat(64) }), (e) => e.code === 'PIN_MISMATCH')
  await assert.rejects(tfetch(r.base + '/v1/info'), 'a client checking CAs refuses the self-signed certificate')
})

test('claim: tries are counted (5 a minute per IP), a malformed claim does not use the code up, the right one binds at once', async (t) => {
  let skew = 0
  const coord = new Coord()
  const r = await startRelay(coord, { ...claimable(coord), now: () => Date.now() + skew }, { fetchImpl: fakeCoord().fetchImpl })
  t.after(() => r.stop())
  const { claim } = parseConnect(lineOf(r))
  const wrong = crypto.randomBytes(32).toString('base64url')
  for (let i = 0; i < 5; i++) {
    const x = await post(r, '/v1/claim', { claim: wrong, relayId: 'r_test0001', account: 'u_owner' })
    assert.equal(x.status, 403)
    assert.deepEqual(x.json(), { error: 'bad-claim', code: 'bad-claim' })
  }
  let x = await post(r, '/v1/claim', { claim, relayId: 'r_test0001', account: 'u_owner' })
  assert.equal(x.status, 429, 'sixth try in a minute: refused even with the right code')
  assert.equal(x.json().code, 'rate')
  assert.ok(Number(x.headers['retry-after']) >= 1 && Number(x.headers['retry-after']) <= 60)
  skew = 61_000
  for (const [body, status, code] of [
    [{ claim, relayId: 'bad id!', account: 'u_owner' }, 400, 'bad-request'],
    [{ claim, relayId: 'r_test0001', account: '*' }, 400, 'bad-request'],
    [{ claim, relayId: 'r_test0001', account: '' }, 400, 'bad-request'],
  ]) {
    x = await post(r, '/v1/claim', body)
    assert.equal(x.status, status, JSON.stringify(body))
    assert.equal(x.json().code, code)
  }
  assert.equal(r.relay.state.bound, false, 'still unclaimed; the code is still good')
  x = await post(r, '/v1/claim', { claim, relayId: 'r_test0001', account: 'u_owner' })
  assert.equal(x.status, 200)
  assert.deepEqual(x.json(), { ok: true, relayId: 'r_test0001', account: 'u_owner' })
  // binding.json written, claim.json gone, the line without the claim code
  const F = claimFiles(r.dir)
  assert.equal(mode(F.binding), 0o600)
  const b = JSON.parse(fs.readFileSync(F.binding, 'utf8'))
  assert.deepEqual([b.relayId, b.account, typeof b.at], ['r_test0001', 'u_owner', 'number'])
  assert.equal(fs.existsSync(F.claim), false)
  assert.equal(lineOf(r), `pocket-relay://127.0.0.1:${r.port}?pin=${r.pin}`)
  assert.ok(r.printed.at(-1).includes('claimed (relay r_test0001)'))
  x = await post(r, '/v1/claim', { claim, relayId: 'r_other', account: 'u_thief' })
  assert.equal(x.status, 409)
  assert.deepEqual(x.json(), { error: 'claimed', code: 'claimed' })
  // the claim code (and the wrong ones) never reach the log
  const logs = r.logs.join('\n')
  assert.ok(!logs.includes(claim) && !logs.includes(wrong))
  assert.ok(logs.includes('"op":"claimed"'))
})

test('a claimed relay serves its account (over the pinned TLS), keeps binding and certificate across a restart', async (t) => {
  const coord = new Coord()
  const fc = fakeCoord()
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pocket-relay-test-'))
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }))
  let r = await startRelay(coord, claimable(coord), { fetchImpl: fc.fetchImpl, dir, keep: true })
  const { claim } = parseConnect(lineOf(r))
  assert.equal((await post(r, '/v1/claim', { claim, relayId: 'r_mine00001', account: 'u_mine' })).status, 200)
  const wk = (await P(r, '/.well-known/pocket-relay')).json()
  assert.deepEqual([wk.v, wk.state, wk.relayId, wk.account], [1, 'claimed', 'r_mine00001', 'u_mine'])
  // tickets for this relay id and account work, on the socket and over HTTP; another account's do not
  const mac = device('computer', 'u_mine'), phone = device('phone', 'u_mine'), stranger = device('phone', 'u_else')
  const M = await connect(r, coord, mac, { aud: 'r_mine00001', peers: [phone.addr] })
  assert.equal(M.ready.acct, 'u_mine')
  const ch = await post(r, '/v1/auth/challenge', {})
  assert.equal(ch.status, 200)
  assert.equal(ch.json().relay, 'r_mine00001')
  await assert.rejects(connect(r, coord, stranger, { aud: 'r_mine00001' }), (e) => e.code === 'wrong-account')
  await assert.rejects(connect(r, coord, phone, { aud: 'hk1' }), (e) => e.code === 'wrong-aud')
  M.ws.close()
  const pin = r.pin
  await r.stop()
  // restart: same binding, same certificate, nothing to claim
  r = await startRelay(coord, claimable(coord), { fetchImpl: fc.fetchImpl, dir, keep: true })
  t.after(() => r.stop())
  assert.deepEqual([r.relay.state.bound, r.relay.state.source, r.relay.state.relayId], [true, 'claim', 'r_mine00001'])
  assert.equal(r.pin, pin, 'certificate kept')
  assert.ok(!r.logs.some((l) => l.includes('tls-self-signed')), 'no new certificate')
  assert.equal(fs.existsSync(claimFiles(dir).claim), false)
  assert.ok(!r.printed.join('').includes('claim='), 'nothing to claim')
  const P2 = await connect(r, coord, phone, { aud: 'r_mine00001', peers: [mac.addr] })
  assert.equal(P2.ready.addr, phone.addr)
  P2.ws.close()
})

test('reset-claim in another process: the running relay drops its sockets, takes the new code; a new owner does not see the old data', async (t) => {
  const coord = new Coord()
  const r = await startRelay(coord, claimable(coord), { fetchImpl: fakeCoord().fetchImpl, bindingPollMs: 100 })
  t.after(() => r.stop())
  const first = parseConnect(lineOf(r)).claim
  assert.equal((await post(r, '/v1/claim', { claim: first, relayId: 'r_old000001', account: 'u_old' })).status, 200)
  const mac = device('computer', 'u_old')
  const M = await connect(r, coord, mac, { aud: 'r_old000001' })
  const put = await pinnedRequest(`${r.base}/v1/o/${mac.addr}/sess/k1`, { pin: r.pin, method: 'PUT', body: objectSeal(mac, { key: 'k1', ver: 1 }),
    headers: { ...SEAL, 'x-pocket-ver': '1', authorization: `Bearer ${M.token}` } })
  assert.equal(put.status, 200)
  const env = { PATH: process.env.PATH, RELAY_DATA_DIR: r.dir, RELAY_LISTEN_PORT: String(r.port), RELAY_COORD_URL: 'http://127.0.0.1:9',
    RELAY_COORD_PINNED_KEYS: JSON.stringify(coord.pinned) }
  const res = spawnSync(process.execPath, [MAIN, 'reset-claim'], { env, encoding: 'utf8', timeout: 20_000 })
  assert.equal(res.status, 0, res.stderr)
  assert.match(res.stdout, /Unbound from relay r_old000001 \(account u_old\)/)
  const fresh = parseConnect(res.stdout.match(/pocket-relay:\/\/\S+/)[0])
  assert.ok(fresh.claim && fresh.claim !== first)
  assert.equal(fresh.pin, r.pin, 'same certificate')
  assert.equal(await M.ws.closed, 4403, 'the running relay closed the socket')
  assert.deepEqual((await P(r, '/.well-known/pocket-relay')).json(), { v: 1, state: 'unclaimed' })
  assert.equal((await post(r, '/v1/auth/challenge', {})).status, 503)
  await until(() => r.printed.join('').includes(fresh.claim), 3000, 'the relay to print the new line')
  assert.equal(lineOf(r), `pocket-relay://127.0.0.1:${r.port}?pin=${r.pin}&claim=${fresh.claim}`)
  // a new owner: the old account's data goes
  const x = await post(r, '/v1/claim', { claim: fresh.claim, relayId: 'r_new000001', account: 'u_new' })
  assert.equal(x.status, 200)
  await until(() => !r.relay.store.get('identGet', mac.addr), 3000, 'the old account to be forgotten')
  const o = r.relay.store.get('objGet', mac.addr, 'sess', 'k1', 0)
  assert.ok(!o || o.del, 'old object deleted')
  assert.ok(r.logs.some((l) => l.includes('purge-other-account') && l.includes('u_old')))
  // the configuration binding cannot be reset from the command line
  const cfgEnv = { ...env, RELAY_RELAY_ID: 'r_cfg', RELAY_ACCOUNT: 'u_cfg' }
  const refused = spawnSync(process.execPath, [MAIN, 'reset-claim'], { env: cfgEnv, encoding: 'utf8', timeout: 20_000 })
  assert.equal(refused.status, 1)
  assert.match(refused.stderr, /come from the configuration/)
  assert.equal(readBinding(r.dir).relayId, 'r_new000001', 'binding untouched')
})

test('the official relay configuration is unchanged: hk1, every account, plain HTTP behind the proxy, no claim, no lookups', async (t) => {
  const coord = new Coord()
  const fc = fakeCoord()
  const r = await startRelay(coord, { relayId: 'hk1', account: '*', publicUrl: 'https://pocket.example/relay', listen: { host: '127.0.0.1', port: 0 }, tls: null,
    trustProxy: true, coord: { url: 'https://coord.test', pinnedKeys: coord.pinned } }, { fetchImpl: fc.fetchImpl })
  t.after(() => r.stop())
  assert.equal(r.cfg.tlsMode, 'off')
  assert.match(r.base, /^http:/)
  assert.equal(r.relay.state.source, 'config')
  assert.equal(r.relay.state.pin, null)
  assert.deepEqual(fc.calls, [], 'no whoami (publicUrl given, TLS at the proxy)')
  assert.deepEqual(r.printed, [], 'nothing printed')
  for (const f of ['tls', 'claim.json', 'binding.json', 'public.json', 'connect.txt']) assert.equal(fs.existsSync(path.join(r.dir, f)), false, f)
  assert.equal((await tfetch(`${r.base}/v1/health`)).status, 200)
  assert.deepEqual(await (await tfetch(`${r.base}/.well-known/pocket-relay`)).json(), { v: 1, state: 'claimed', relayId: 'hk1', account: '*', version: (await (await tfetch(`${r.base}/v1/info`)).json()).version })
  const cl = await tfetch(`${r.base}/v1/claim`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ claim: 'x'.repeat(43), relayId: 'r_x', account: 'u_x' }) })
  assert.equal(cl.status, 409)
  // any account, client IP from X-Forwarded-For
  const a = device('phone', 'u_a'), b = device('phone', 'u_b')
  const A = await connect(r, coord, a), B = await connect(r, coord, b)
  assert.deepEqual([A.ready.acct, B.ready.acct], ['u_a', 'u_b'])
  await tfetch(`${r.base}/v1/nothing`, { headers: { 'x-forwarded-for': '198.51.100.23' } })
  assert.ok(r.logs.some((l) => l.includes('198.51.100.23')))
  A.ws.close(); B.ws.close()
  // same configuration through loadConfig, as e2ee-deploy.mjs writes it
  const f = path.join(r.dir, 'relay.json')
  fs.writeFileSync(f, JSON.stringify({ relayId: 'hk1', account: '*', publicUrl: 'https://pocket.pocketcli.net/relay', listen: { host: '127.0.0.1', port: 8601 }, tls: null, trustProxy: true,
    coord: { url: 'https://pocket.pocketcli.net', pinnedKeys: coord.pinned }, dataDir: '/var/lib/pocket-relay', blobs: { store: 'disk' } }))
  const cfg = loadConfig({ file: f, env: {} })
  assert.deepEqual([cfg.relayId, cfg.account, cfg.tlsMode, cfg.tls, cfg.trustProxy, cfg.publicUrl], ['hk1', '*', 'off', null, true, 'https://pocket.pocketcli.net/relay'])
})

test('whoami fails: TLS served anyway, the relay says how to set the address, keeps asking, prints the line once it knows', async (t) => {
  let answer = new Response('down', { status: 503 })
  const coord = new Coord()
  const r = await startRelay(coord, claimable(coord), { fetchImpl: fakeCoord(() => answer).fetchImpl, whoamiRetryMs: 100 })
  t.after(() => r.stop())
  const first = r.pin
  assert.match(r.printed.join(''), new RegExp(`could not find this server's public IP address[\\s\\S]*RELAY_PUBLIC_URL=https://<public IP>:${r.port}[\\s\\S]*公网 IP`))
  assert.equal(fs.existsSync(claimFiles(r.dir).connect), false)
  assert.equal(hostOfCert(new crypto.X509Certificate(fs.readFileSync(claimFiles(r.dir).selfCert))), null, 'certificate without a host for now')
  assert.equal((await P(r, '/.well-known/pocket-relay')).status, 200, 'TLS works meanwhile')
  answer = json({ ip: '127.0.0.1' })
  await until(() => fs.existsSync(claimFiles(r.dir).connect), 3000, 'connect.txt')
  const c = parseConnect(lineOf(r))
  assert.notEqual(c.pin, first, 'new certificate for the address')
  assert.equal(c.pin, r.pin)
  assert.equal((await P(r, '/v1/info')).status, 200, 'served with the new certificate')
  await assert.rejects(pinnedRequest(r.base + '/v1/info', { pin: first }), (e) => e.code === 'PIN_MISMATCH')
  assert.ok(r.printed.join('').includes(lineOf(r)))
})

test('publicUrl: no whoami, a DNS name or an IPv6 address in the certificate; a base path makes no line', async (t) => {
  const coord = new Coord()
  const fc = fakeCoord()
  const r = await startRelay(coord, claimable(coord, { publicUrl: 'https://Relay.Example.com:8443/' }), { fetchImpl: fc.fetchImpl })
  t.after(() => r.stop())
  assert.ok(!fc.calls.includes('/v2/whoami'))
  assert.equal(r.cfg.publicUrl, 'https://relay.example.com:8443')
  const cert = new crypto.X509Certificate(fs.readFileSync(claimFiles(r.dir).selfCert))
  assert.equal(cert.subjectAltName, 'DNS:relay.example.com')
  const c = parseConnect(lineOf(r))
  assert.deepEqual([c.host, c.port, c.pin], ['relay.example.com', 8443, r.pin])
  const r2 = await startRelay(coord, claimable(coord, { publicUrl: 'https://[2001:db8::7]' }), { fetchImpl: fc.fetchImpl })
  t.after(() => r2.stop())
  assert.match(lineOf(r2), /^pocket-relay:\/\/\[2001:db8::7\]:443\?pin=sha256:[0-9a-f]{64}&claim=[A-Za-z0-9_-]{43}$/)
  assert.equal(parseConnect(lineOf(r2)).url, 'https://[2001:db8::7]:443')
  assert.equal(new crypto.X509Certificate(fs.readFileSync(claimFiles(r2.dir).selfCert)).checkIP('2001:db8::7'), '2001:db8::7')
  // the App takes no path: such a relay explains instead of printing a line it would refuse
  const r3 = await startRelay(coord, claimable(coord, { publicUrl: 'https://example.com/pocket' }), { fetchImpl: fc.fetchImpl })
  t.after(() => r3.stop())
  assert.equal(fs.existsSync(claimFiles(r3.dir).connect), false)
  assert.match(r3.printed.join(''), /publicUrl has a path \(https:\/\/example\.com\/pocket\)/)
  assert.equal(connectInfo({ cfg: r3.cfg, port: r3.port }).why, 'path')
})

test('connection line: format and parse', () => {
  const pin = 'sha256:' + 'ab'.repeat(32), claim = crypto.randomBytes(32).toString('base64url')
  const cases = [
    [{ host: '203.0.113.7', port: 8443, pin, claim }, `pocket-relay://203.0.113.7:8443?pin=${pin}&claim=${claim}`],
    [{ host: '[2001:DB8::1]', port: 8443, pin }, `pocket-relay://[2001:db8::1]:8443?pin=${pin}`],
    [{ host: 'Relay.Example.com', port: 443 }, 'pocket-relay://relay.example.com:443'],
  ]
  for (const [i, want] of cases) {
    const line = formatConnect(i)
    assert.equal(line, want)
    const p = parseConnect(`  ${line}\n`)
    assert.equal(formatConnect(p), line, 'round trip')
  }
  assert.equal(parseConnect(cases[0][1]).url, 'https://203.0.113.7:8443')
  assert.equal(parseConnect(`pocket-relay://203.0.113.7:8443/?pin=${pin}&later=1`).pin, pin, 'one trailing slash and unknown parameters are fine (as in the App)')
  for (const bad of ['https://203.0.113.7:8443', 'pocket-relay://203.0.113.7', 'pocket-relay://203.0.113.7:0', `pocket-relay://203.0.113.7:8443?pin=sha1:${'a'.repeat(40)}`,
    `pocket-relay://203.0.113.7:8443?pin=${pin}&claim=short`, 'pocket-relay://u:p@203.0.113.7:8443', `pocket-relay://203.0.113.7:8443/relay?pin=${pin}`,
    'pocket-relay://203.0.113.7:8443', `pocket-relay://203.0.113.7:8443?pin=${pin}&pin=${pin}`, `pocket-relay://[2001:db8::1]:8443?claim=${claim}`,
    'pocket-relay://bad_host:8443', 'pocket-relay://127.1:8443', 'pocket-relay://0x7f.1:8443', 'pocket-relay://1.2.3:8443', 'not a line']) {
    assert.throws(() => parseConnect(bad), bad)
  }
  assert.throws(() => formatConnect({ host: '203.0.113.7', port: 70000, pin }))
  assert.throws(() => formatConnect({ host: '203.0.113.7', port: 8443 }), /needs a pin/)
  assert.deepEqual(['10.1.2.3', '100.64.0.1', '127.0.0.1', '::1', 'fe80::1', 'fd00::1', '192.168.1.1'].map(nonPublicIp), [true, true, true, true, true, true, true])
  assert.deepEqual(['203.0.113.7', '8.8.8.8', '2606:4700::1111'].map(nonPublicIp), [false, false, false])
})

test('configuration: relayId and account together or not at all; tls modes; the official coordination key by default; publicUrl checks', () => {
  const base = { dataDir: '/tmp/x' }
  const c = finalize(base)
  assert.deepEqual([c.relayId, c.account, c.tlsMode, c.tls, c.coord.url], [null, null, 'self', 'self', 'https://pocket.pocketcli.net'])
  assert.deepEqual(c.coord.pinnedKeys, OFFICIAL_COORD_KEYS)
  assert.equal(OFFICIAL_COORD_KEYS[0].kid, 'c1')
  assert.equal(finalize(c).tlsMode, 'self', 'finalize twice: same result')
  assert.equal(finalize({ ...base, trustProxy: true }).tlsMode, 'off', 'auto behind a proxy = plain HTTP')
  assert.equal(finalize({ ...base, trustProxy: true, tls: 'self' }).tlsMode, 'self')
  assert.equal(finalize({ ...base, tls: null }).tlsMode, 'off')
  assert.equal(finalize({ ...base, tls: false }).tlsMode, 'off')
  assert.equal(finalize({ ...base, tls: 'off' }).tlsMode, 'off')
  assert.deepEqual(finalize({ ...base, tls: { cert: '/c', key: '/k' } }).tls, { cert: '/c', key: '/k' })
  assert.equal(loadConfig({ env: { RELAY_DATA_DIR: '/tmp/x', RELAY_TLS: '' } }).tlsMode, 'off', 'RELAY_TLS= (empty) = plain HTTP')
  assert.equal(loadConfig({ env: { RELAY_DATA_DIR: '/tmp/x', RELAY_TLS: 'self' } }).tlsMode, 'self')
  // the example file shipped with the relay loads as is and means the defaults
  const ex = loadConfig({ file: path.join(path.dirname(MAIN), '..', 'relay.example.json'), env: {} })
  assert.deepEqual([ex.relayId, ex.account, ex.tlsMode, ex.publicUrl, ex.coord.url, ex.listen.port], [null, null, 'self', null, 'https://pocket.pocketcli.net', 8443])
  assert.deepEqual(ex.coord.pinnedKeys, OFFICIAL_COORD_KEYS)
  for (const [over, re] of [
    [{ relayId: 'r_x' }, /go together/], [{ account: 'u_x' }, /go together/], [{ tls: 'yes' }, /tls must be/], [{ tls: { cert: '/c' } }, /tls must be/],
    [{ publicUrl: 'http://203.0.113.7:8443' }, /publicUrl/], [{ publicUrl: 'https://203.0.113.7:8443/?x=1' }, /publicUrl/], [{ publicUrl: 'not a url' }, /publicUrl/],
  ]) assert.throws(() => finalize({ ...base, ...over }), (e) => e instanceof ConfigError && re.test(e.message), JSON.stringify(over))
})

test('certificate files: the line pins the configured certificate; one from a public CA is not pinned', { skip: !hasOpenssl && 'no openssl command' }, async (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pocket-relay-test-'))
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }))
  const run = (...a) => execFileSync('openssl', a, { cwd: dir, stdio: 'pipe' })
  run('ecparam', '-name', 'prime256v1', '-genkey', '-noout', '-out', 'ca.key')
  fs.writeFileSync(path.join(dir, 'ca.ext'), 'basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\n')
  run('req', '-new', '-key', 'ca.key', '-subj', '/CN=Test Root', '-out', 'ca.csr')
  run('x509', '-req', '-in', 'ca.csr', '-signkey', 'ca.key', '-days', '30', '-sha256', '-extfile', 'ca.ext', '-out', 'ca.crt')
  run('ecparam', '-name', 'prime256v1', '-genkey', '-noout', '-out', 'leaf.key')
  run('req', '-new', '-key', 'leaf.key', '-subj', '/CN=127.0.0.1', '-out', 'leaf.csr')
  fs.writeFileSync(path.join(dir, 'leaf.ext'), 'subjectAltName=IP:127.0.0.1,DNS:relay.test\nextendedKeyUsage=serverAuth\nbasicConstraints=CA:FALSE\n')
  run('x509', '-req', '-in', 'leaf.csr', '-CA', 'ca.crt', '-CAkey', 'ca.key', '-set_serial', '0x' + crypto.randomBytes(8).toString('hex'), '-days', '20', '-sha256', '-extfile', 'leaf.ext', '-out', 'leaf.crt')
  const leaf = fs.readFileSync(path.join(dir, 'leaf.crt'), 'utf8'), ca = fs.readFileSync(path.join(dir, 'ca.crt'), 'utf8')
  fs.writeFileSync(path.join(dir, 'chain.pem'), leaf + ca)
  const chain = leaf + ca
  assert.equal(publiclyTrusted(chain, '127.0.0.1', { roots: [ca] }), true, 'chains to the given root and names the host')
  assert.equal(publiclyTrusted(chain, 'relay.test', { roots: [ca] }), true)
  assert.equal(publiclyTrusted(chain, '203.0.113.7', { roots: [ca] }), false, 'not for this host')
  assert.equal(publiclyTrusted(chain, '203.0.113.7', { roots: [ca], anyHost: true }), true)
  assert.equal(publiclyTrusted(leaf, '127.0.0.1', { roots: [makeSelfSigned({ host: 'x.test' }).certPem] }), false, 'another root')
  assert.equal(publiclyTrusted(chain, '127.0.0.1'), false, 'not in the public CA list')
  assert.equal(publiclyTrusted(chain, '127.0.0.1', { roots: [ca], now: Date.now() + 40 * 86_400_000 }), false, 'expired')
  const coord = new Coord()
  const r = await startRelay(coord, claimable(coord, { tls: { cert: path.join(dir, 'chain.pem'), key: path.join(dir, 'leaf.key') } }), { fetchImpl: fakeCoord().fetchImpl })
  t.after(() => r.stop())
  assert.equal(r.cfg.tlsMode, 'files')
  assert.equal(r.pin, pinOf(leaf))
  const c = parseConnect(lineOf(r))
  assert.equal(c.pin, pinOf(leaf), 'a certificate from a private CA is pinned')
  assert.ok(c.claim)
  assert.equal((await P(r, '/v1/info')).status, 200)
  assert.equal(fs.existsSync(claimFiles(r.dir).tlsDir), false, 'no self-signed certificate made')
  // what connect-string shows for a CA certificate: no pin, the pin printed beside it
  const info = connectInfo({ cfg: r.cfg, port: r.port })
  assert.equal(info.publicCa, false)
})

test('main.mjs as the Docker image runs it: environment only, prints the line, --health, connect-string, claim, reset-claim, SIGTERM', async (t) => {
  const coordSrv = http.createServer((req, res) => {
    if (req.url === '/v2/whoami') { res.writeHead(200, { 'content-type': 'application/json' }); return res.end(JSON.stringify({ ip: '127.0.0.1' })) }
    res.writeHead(404); res.end()
  })
  await new Promise((r) => coordSrv.listen(0, '127.0.0.1', r))
  t.after(() => coordSrv.close())
  const port = await new Promise((r) => { const s = http.createServer().listen(0, '127.0.0.1', () => { const p = s.address().port; s.close(() => r(p)) }) })
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pocket-relay-test-'))
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }))
  const env = { PATH: process.env.PATH, HOME: process.env.HOME, RELAY_DATA_DIR: dir, RELAY_LISTEN_HOST: '127.0.0.1', RELAY_LISTEN_PORT: String(port),
    RELAY_COORD_URL: `http://127.0.0.1:${coordSrv.address().port}` }
  const child = spawn(process.execPath, [MAIN], { env, stdio: ['ignore', 'pipe', 'pipe'] })
  let out = '', err = ''
  child.stdout.on('data', (d) => { out += d })
  child.stderr.on('data', (d) => { err += d })
  const exited = new Promise((r) => child.on('exit', (code, sig) => r({ code, sig })))
  t.after(() => { if (child.exitCode === null) child.kill('SIGKILL') })
  await until(() => /pocket-relay:\/\/\S+claim=/.test(out) && / started /.test(out), 15_000, `the line and the start on standard output (stderr: ${err})`)
  const line = out.match(/pocket-relay:\/\/\S+/)[0]
  const c = parseConnect(line)
  assert.deepEqual([c.host, c.port], ['127.0.0.1', port])
  assert.match(out, /started .*state=unclaimed .*tls=self .*pin=sha256:/)
  assert.ok(!/ claim=/.test(out.split('\n').filter((l) => / (info|warn|error) /.test(l)).join('\n')), 'no claim code in log lines')
  const cli = (...a) => spawnSync(process.execPath, [MAIN, ...a], { env, encoding: 'utf8', timeout: 20_000 })
  let res = cli('--health')
  assert.equal(res.status, 0, 'healthy while unclaimed (it asks /v1/info)')
  res = cli('connect-string')
  assert.equal(res.status, 0, res.stderr)
  assert.ok(res.stdout.includes(line))
  res = cli('frobnicate')
  assert.equal(res.status, 64)
  // coordination's part: claim over TLS pinned to the line's pin
  const base = c.url
  const x = await pinnedRequest(base + '/v1/claim', { pin: c.pin, method: 'POST', body: JSON.stringify({ claim: c.claim, relayId: 'r_proc00001', account: 'u_proc' }) })
  assert.equal(x.status, 200, x.text)
  res = cli('connect-string')
  assert.ok(res.stdout.includes(`pocket-relay://127.0.0.1:${port}?pin=${c.pin}\n`), res.stdout)
  assert.equal(cli('--health').status, 0)
  res = cli('reset-claim')
  assert.equal(res.status, 0, res.stderr)
  const fresh = parseConnect(res.stdout.match(/pocket-relay:\/\/\S+/)[0])
  await until(async () => (await pinnedRequest(base + '/.well-known/pocket-relay', { pin: c.pin })).json().state === 'unclaimed', 10_000, 'the relay to notice reset-claim')
  await until(() => out.includes(fresh.claim), 5000, 'the relay to print the new line')
  child.kill('SIGTERM')
  const ex = await exited
  assert.equal(ex.code, 0, err)
})
