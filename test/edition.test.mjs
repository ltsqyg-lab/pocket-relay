// The two editions (RELAY.md §2.1): RELAY_EDITION=cn talks only to the mainland China coordination server and pins only
// its key; a claim from the other edition's coordination server is refused with a clear message; the international
// edition stays the default and the official configurations are unchanged.
import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { spawn } from 'node:child_process'
import { fileURLToPath } from 'node:url'
import { Coord, startRelay, pinnedRequest, tfetch, sleep } from './helpers.mjs'
import { finalize, loadConfig, ConfigError, EDITIONS, CN_COORD_KEYS, OFFICIAL_COORD_KEYS, editionOfUrl } from '../src/config.mjs'
import { readClaim, readBinding, parseConnect } from '../src/claim.mjs'

const HERE = path.dirname(fileURLToPath(import.meta.url))
const MAIN = path.join(HERE, '..', 'src', 'main.mjs')
const CN = 'https://api.pocketcli.cn', INTL = 'https://pocket.pocketcli.net'
const json = (obj, status = 200) => new Response(JSON.stringify(obj), { status, headers: { 'content-type': 'application/json' } })

test('configuration: international by default; RELAY_EDITION=cn picks the mainland coordination server and only its key', () => {
  const base = { dataDir: '/tmp/x' }
  const intl = finalize(base)
  assert.deepEqual([intl.edition, intl.coord.url], ['intl', INTL])
  assert.deepEqual(intl.coord.pinnedKeys, OFFICIAL_COORD_KEYS)
  const cn = finalize({ ...base, edition: 'cn' })
  assert.deepEqual([cn.edition, cn.coord.url], ['cn', CN])
  assert.deepEqual(cn.coord.pinnedKeys, CN_COORD_KEYS)
  assert.notEqual(CN_COORD_KEYS[0].pub, OFFICIAL_COORD_KEYS[0].pub)
  assert.equal(finalize(cn).coord.url, CN, 'finalize twice: same result')
  const env = loadConfig({ env: { RELAY_DATA_DIR: '/tmp/x', RELAY_EDITION: 'cn' } })
  assert.deepEqual([env.edition, env.coord.url, env.coord.pinnedKeys[0].pub], ['cn', CN, CN_COORD_KEYS[0].pub])
  // the official mainland relay (e2ee-deploy.mjs writes coord.url and the keys, no edition): cn
  const official = finalize({ ...base, relayId: 'cn1', account: '*', coord: { url: `${CN}/`, pinnedKeys: CN_COORD_KEYS } })
  assert.deepEqual([official.edition, official.coord.url], ['cn', CN])
  // a lab: coord.url null = no coordination, whatever the edition
  assert.equal(finalize({ ...base, edition: 'cn', coord: { url: null, pinnedKeys: CN_COORD_KEYS } }).coord.url, null)
  assert.deepEqual([editionOfUrl('https://api.pocketcli.cn:443/x'), editionOfUrl(INTL), editionOfUrl('https://example.com'), editionOfUrl('nope')], ['cn', 'intl', null, null])
  for (const [over, re] of [
    [{ edition: 'eu' }, /edition must be/],
    [{ edition: 'cn', coord: { url: INTL } }, /disagree/],
    [{ edition: 'intl', coord: { url: CN } }, /disagree/],
    [{ edition: 'cn', coord: { pinnedKeys: OFFICIAL_COORD_KEYS } }, /key of the "intl" edition/],
    [{ coord: { pinnedKeys: CN_COORD_KEYS } }, /key of the "cn" edition/],
  ]) assert.throws(() => finalize({ ...base, ...over }), (e) => e instanceof ConfigError && re.test(e.message), JSON.stringify(over))
})

test('cn edition: every request goes to api.pocketcli.cn (public address, keys, revocations); /v1/info says cn', async (t) => {
  const coord = new Coord()
  const calls = []
  const fetchImpl = async (url) => {
    calls.push(String(url))
    if (new URL(url).pathname === '/v2/whoami') return json({ ip: '127.0.0.1' })
    return new Response('nothing here', { status: 404 })
  }
  // claimable, its own certificate: asks for the public address at start
  const r = await startRelay(coord, { edition: 'cn', relayId: null, account: null, tls: 'auto', coord: { pinnedKeys: coord.pinned } }, { fetchImpl })
  t.after(() => r.stop())
  assert.equal(r.cfg.coord.url, CN)
  await r.relay.keys.refresh('test')
  await r.relay.pollAccount('u_someone')
  assert.deepEqual(calls.map((u) => new URL(u).pathname), ['/v2/whoami', '/.well-known/pocket/keys.json', '/v2/relay/revocations'])
  for (const u of calls) assert.equal(new URL(u).origin, CN, u)
  const info = (await pinnedRequest(`${r.base}/v1/info`, { pin: r.pin })).json()
  assert.equal(info.edition, 'cn')
  assert.equal((await pinnedRequest(`${r.base}/.well-known/pocket-relay`, { pin: r.pin })).json().edition, 'cn')
  const out = r.printed.join('')
  assert.ok(out.includes('这台服务器是国内版') && out.includes('mainland China edition'), out)
})

/** A claimable relay behind a (pretend) proxy, so a test can say which address a claim comes from. */
async function behindProxy(coord, over = {}) {
  return startRelay(coord, { relayId: null, account: null, tls: null, trustProxy: true, publicUrl: 'https://relay.example.com', ...over })
}
const claim = (r, body, ip = '198.51.100.9') => tfetch(`${r.base}/v1/claim`, { method: 'POST', headers: { 'content-type': 'application/json', 'x-forwarded-for': ip }, body: JSON.stringify(body) })

test('a claim from the other edition\'s coordination server is refused (the code still works); the right one binds', async (t) => {
  const coord = new Coord()
  // international relay, claim from the mainland coordination server's address
  const r = await behindProxy(coord)
  t.after(() => r.stop())
  const code = readClaim(r.dir)
  let x = await claim(r, { claim: code, relayId: 'r_wrong0001', account: 'u_cn' }, EDITIONS.cn.coordIps[0])
  assert.equal(x.status, 403)
  let j = await x.json()
  assert.deepEqual([j.error, j.code, j.edition], ['wrong-edition', 'wrong-edition', 'intl'])
  assert.ok(j.zh.includes('国际版') && j.zh.includes(EDITIONS.cn.install), j.zh)
  assert.ok(j.en.includes('international edition') && j.en.includes(EDITIONS.cn.install), j.en)
  assert.equal(readBinding(r.dir), null, 'not bound')
  assert.equal(readClaim(r.dir), code, 'the claim code is still the same')
  const printed = r.printed.join('')
  assert.ok(printed.includes('刚才在国内版 App 里添加,已拒绝') && printed.includes(EDITIONS.cn.install), printed)
  assert.ok(r.logs.some((l) => l.includes('claim-wrong-edition') && l.includes(EDITIONS.cn.coordIps[0])))
  assert.ok(!r.logs.join('\n').includes(code), 'the claim code never reaches the log')
  // an IPv4-mapped address is the same address
  x = await claim(r, { claim: code, relayId: 'r_wrong0001', account: 'u_cn' }, `::ffff:${EDITIONS.cn.coordIps[0]}`)
  assert.equal(x.status, 403)
  // a claim that names its edition or its coordination server
  x = await claim(r, { claim: code, relayId: 'r_wrong0001', account: 'u_cn', edition: 'cn' })
  assert.equal((await x.json()).code, 'wrong-edition')
  // the wrong code is still just a wrong code, wherever it comes from
  x = await claim(r, { claim: 'A'.repeat(43), relayId: 'r_wrong0001', account: 'u_cn' }, EDITIONS.cn.coordIps[0])
  assert.equal((await x.json()).code, 'bad-claim')
  // its own edition's coordination server (by address, by name): binds
  x = await claim(r, { claim: code, relayId: 'r_right0001', account: 'u_intl', edition: 'intl', coord: INTL }, EDITIONS.intl.coordIps[0])
  assert.equal(x.status, 200)
  assert.equal(readBinding(r.dir).account, 'u_intl')
})

test('cn edition: refuses claims from the international coordination server, by address, edition or coordination URL', async (t) => {
  const coord = new Coord()
  const r = await behindProxy(coord, { edition: 'cn', coord: { url: null, pinnedKeys: coord.pinned } })
  t.after(() => r.stop())
  const code = readClaim(r.dir)
  for (const [body, ip] of [
    [{}, EDITIONS.intl.coordIps[0]],
    [{ edition: 'intl' }, '198.51.100.9'],
    [{ coord: `${INTL}/` }, '198.51.100.9'],
    [{ coord: 'https://coord.example.org' }, '198.51.100.9'],     // not its coordination server at all
  ]) {
    const x = await claim(r, { claim: code, relayId: 'r_x0000001', account: 'u_x', ...body }, ip)
    assert.equal(x.status, 403, JSON.stringify(body))
    const j = await x.json()
    assert.equal(j.code, 'wrong-edition')
    assert.ok(typeof j.zh === 'string' && typeof j.en === 'string')
  }
  const j = await (await claim(r, { claim: code, relayId: 'r_x0000001', account: 'u_x' }, EDITIONS.intl.coordIps[0])).json()
  assert.ok(j.zh.includes('国内版') && j.zh.includes(EDITIONS.intl.install), j.zh)
  assert.equal(readBinding(r.dir), null)
  const ok = await claim(r, { claim: code, relayId: 'r_cn000001', account: 'u_cn', edition: 'cn' }, EDITIONS.cn.coordIps[0])
  assert.equal(ok.status, 200)
})

test('cn edition as a process: no request leaves for anywhere but api.pocketcli.cn; the printed line says 国内版', async (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pocket-relay-test-'))
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }))
  // every fetch of the process is answered here and written down (the relay makes no other outbound connections)
  const log = path.join(dir, 'fetch.log')
  const pre = path.join(dir, 'pre.mjs')
  fs.writeFileSync(pre, `import fs from 'node:fs'
globalThis.fetch = async (url) => {
  fs.appendFileSync(${JSON.stringify(log)}, String(url) + '\\n')
  if (new URL(url).pathname === '/v2/whoami') return new Response('{"ip":"127.0.0.1"}', { status: 200, headers: { 'content-type': 'application/json' } })
  return new Response('no', { status: 404 })
}
`)
  const env = { PATH: process.env.PATH, RELAY_EDITION: 'cn', RELAY_DATA_DIR: path.join(dir, 'data'), RELAY_LISTEN_HOST: '127.0.0.1', RELAY_LISTEN_PORT: '0' }
  const child = spawn(process.execPath, ['--import', pre, MAIN], { env, stdio: ['ignore', 'pipe', 'pipe'] })
  t.after(() => child.kill('SIGKILL'))
  let out = ''
  child.stdout.on('data', (d) => { out += d })
  child.stderr.on('data', (d) => { out += d })
  const end = Date.now() + 15_000
  while (!/pocket-relay:\/\/\S+claim=/.test(out) && Date.now() < end) await sleep(100)
  assert.match(out, /这台服务器是国内版/)
  const line = parseConnect(out.match(/pocket-relay:\/\/\S+/)[0])
  assert.equal(line.host, '127.0.0.1')
  assert.match(out, / started .*edition=cn/)
  await sleep(5600)          // the coordination keys are refreshed 5 s after start
  child.kill('SIGTERM')
  const urls = fs.readFileSync(log, 'utf8').trim().split('\n')
  assert.ok(urls.some((u) => u.endsWith('/v2/whoami')) && urls.some((u) => u.endsWith('/.well-known/pocket/keys.json')), urls.join(' '))
  for (const u of urls) assert.equal(new URL(u).origin, CN, u)
})
