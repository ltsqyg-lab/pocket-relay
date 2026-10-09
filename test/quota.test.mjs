// Quotas (RELAY.md §8.3): the small-file allowance after the day or month is used up, caps that follow the account's
// newest ticket whichever device holds it (kept across restarts, forgotten on purge), counters swept with the rest.
import test from 'node:test'
import assert from 'node:assert/strict'
import crypto from 'node:crypto'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { tfetch, Coord, device, startRelay, httpToken, api, ref, b64u } from './helpers.mjs'

const KB = 1024, MB = 1024 * 1024
const blob = (n, id = crypto.randomBytes(16)) => ({ id, idS: b64u(id), ct: ref.encryptBlob(crypto.randomBytes(32), id, crypto.randomBytes(n)) })
const post = (r, p, j) => tfetch(`${r.base}${p}`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(j) })

test('small-file allowance: small blobs keep moving after the day and the month are used up, large ones wait; bounded, tomorrow again', async (t) => {
  let skew = 0
  // 2026-10-08 10:00:00 in Asia/Shanghai = 02:00:00Z
  const T0 = Date.UTC(2026, 9, 8, 2, 0, 0)
  const now = () => T0 + skew
  const coord = new Coord()
  // small = at most 512 KiB of plaintext here (the default is 2 MiB), so the test moves little data
  const r = await startRelay(coord, { now, timezone: 'Asia/Shanghai', quota: { smallFileMB: 0.5 } })
  t.after(() => r.stop())
  const mac = device('computer'), phone = device('phone')
  const quota = { dayMB: 1, monthMB: 1.5, smallMB: 1 }
  const signIn = async () => api(r, await httpToken(r, coord, mac, { peers: [phone.addr], iat: now() - 1000, exp: now() + 23 * 3600_000, quota }))
  let M = await signIn()
  const base = `/v1/b/${mac.addr}`
  const me = async () => (await M.get('/v1/me/quota')).json()

  // day 1: a large blob uses most of the day
  const A = blob(900 * KB)
  assert.equal((await M.put(`${base}/${A.idS}`, A.ct)).status, 200)
  let q = await me()
  assert.equal(q.day.used, A.ct.length)
  assert.deepEqual(q.small, { used: 0, cap: 1 * MB, file: 22 + 512 * KB + 16 * 8 }, 'the largest small blob: the PKB1 size of 512 KiB')
  // another large blob does not fit: refused until midnight Shanghai, and the answer shows the allowance
  const B = blob(600 * KB)
  let res = await M.post(`${base}/${B.idS}/upload`, { bytes: B.ct.length })
  assert.equal(res.status, 429)
  let body = await res.json()
  assert.equal(body.error, 'quota')
  assert.ok(body.retryAfter > 13 * 3600 && body.retryAfter <= 14 * 3600, `until midnight (${body.retryAfter}s)`)
  assert.equal(res.headers.get('retry-after'), String(body.retryAfter))
  assert.equal(body.quota.small.cap, 1 * MB)
  // a small blob still goes, on the allowance; uploads and downloads both count there, not in the day
  const S1 = blob(400 * KB)
  assert.equal((await M.put(`${base}/${S1.idS}`, S1.ct)).status, 200)
  assert.equal((await M.get(`${base}/${S1.idS}`)).status, 200)
  q = await me()
  assert.equal(q.day.used, A.ct.length, 'the day counter did not move')
  assert.equal(q.month.used, A.ct.length)
  assert.equal(q.small.used, 2 * S1.ct.length)
  // a large blob read in small ranges is still large
  res = await M.get(`${base}/${A.idS}`, { range: 'bytes=0-199999' })
  assert.equal(res.status, 429)
  // HEAD stays free
  assert.equal((await M.head(`${base}/${A.idS}`)).status, 200)
  // the allowance runs out too: refused until midnight
  const S2 = blob(300 * KB)
  res = await M.post(`${base}/${S2.idS}/upload`, { bytes: S2.ct.length })
  assert.equal(res.status, 429)
  body = await res.json()
  assert.ok(body.retryAfter > 13 * 3600 && body.retryAfter <= 14 * 3600, `allowance back tomorrow (${body.retryAfter}s)`)

  // day 2: a new day (the token from yesterday has expired: a fresh ticket, same caps); the month has room for B, then it is used up
  skew = 86_400_000
  M = await signIn()
  q = await me()
  assert.equal(q.day.used, 0)
  assert.equal(q.small.used, 0, 'a new allowance every day')
  assert.equal(q.month.used, A.ct.length, 'the allowance never counted in the month')
  assert.equal((await M.put(`${base}/${B.idS}`, B.ct)).status, 200)
  const D = blob(600 * KB)
  res = await M.post(`${base}/${D.idS}/upload`, { bytes: D.ct.length })
  assert.equal(res.status, 429)
  assert.ok((await res.json()).retryAfter > 20 * 86400, 'a large blob waits for the next month')
  // small blobs still go with the month used up, and come back tomorrow (not next month) when the allowance ends
  assert.equal((await M.put(`${base}/${S2.idS}`, S2.ct)).status, 200)
  const S3 = blob(400 * KB), S4 = blob(400 * KB)
  assert.equal((await M.put(`${base}/${S3.idS}`, S3.ct)).status, 200)
  res = await M.post(`${base}/${S4.idS}/upload`, { bytes: S4.ct.length })
  assert.equal(res.status, 429)
  body = await res.json()
  assert.ok(body.retryAfter > 13 * 3600 && body.retryAfter <= 14 * 3600, `tomorrow, not next month (${body.retryAfter}s)`)
  q = await me()
  assert.equal(q.small.used, S2.ct.length + S3.ct.length)
  assert.ok(q.month.used > q.month.cap - 40 * KB, 'the month is (nearly) used up')
})

test('small-file allowance: no allowance with smallMB 0, and none for stored bytes', async (t) => {
  const coord = new Coord()
  const r = await startRelay(coord, { quota: { smallFileMB: 0.5 } })
  t.after(() => r.stop())
  const a = device('computer', 'u_q_none'), b = device('computer', 'u_q_store')
  const A = api(r, await httpToken(r, coord, a, { quota: { dayMB: 0.5, smallMB: 0 } }))
  const S = blob(400 * KB), S2 = blob(400 * KB)
  assert.equal((await A.put(`/v1/b/${a.addr}/${S.idS}`, S.ct)).status, 200)
  assert.equal((await A.post(`/v1/b/${a.addr}/${S2.idS}/upload`, { bytes: S2.ct.length })).status, 429, 'smallMB 0: no allowance')
  // the store cap applies whatever the allowance
  const B = api(r, await httpToken(r, coord, b, { quota: { dayMB: 0.5, storeMB: 1, smallMB: 50 } }))
  const x = blob(400 * KB), y = blob(400 * KB), z = blob(400 * KB)
  assert.equal((await B.put(`/v1/b/${b.addr}/${x.idS}`, x.ct)).status, 200)
  assert.equal((await B.put(`/v1/b/${b.addr}/${y.idS}`, y.ct)).status, 200, 'over the day: on the allowance')
  const res = await B.post(`/v1/b/${b.addr}/${z.idS}/upload`, { bytes: z.ct.length })
  assert.equal(res.status, 429)
  const body = await res.json()
  assert.ok(body.quota.store && body.quota.store.used === x.ct.length + y.ct.length, 'refused for stored bytes')
})

test('caps follow the account\'s newest ticket, whichever device presents it; kept across a restart; forgotten on purge', async (t) => {
  const T0 = Date.UTC(2026, 9, 9, 4, 0, 0)   // 12:00 in Shanghai
  const now = () => T0
  const coord = new Coord()
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pocket-relay-test-'))
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }))
  const over = { now, timezone: 'Asia/Shanghai', quota: { dayMB: 5 } }
  let r = await startRelay(coord, over, { dir, keep: true })
  t.after(async () => { try { await r.relay.close() } catch { /* closed */ } })
  const mac = device('computer', 'u_q1'), phone = device('phone', 'u_q1'), other = device('computer', 'u_q2')
  const limited = { dayMB: 1, monthMB: 100, smallMB: 0 }, open = { dayMB: 0, monthMB: 0 }
  // the computer still holds an old ticket (1 MB a day); the phone just renewed (no limit): the newer one counts
  let M = api(r, await httpToken(r, coord, mac, { peers: [phone.addr], iat: T0 - 3 * 3600_000, quota: limited }))
  let P = api(r, await httpToken(r, coord, phone, { peers: [mac.addr], iat: T0 - 60_000, quota: open }))
  const base = `/v1/b/${mac.addr}`
  const big = blob(1500 * KB)
  assert.equal((await M.put(`${base}/${big.idS}`, big.ct)).status, 200, 'the computer uploads past its own ticket\'s cap')
  assert.equal((await (await M.get('/v1/me/quota')).json()).day.cap, 0, 'the account has no cap now')
  // the quota is lowered: the computer renews and gets the new caps; the phone's older ticket no longer counts
  M = api(r, await httpToken(r, coord, mac, { peers: [phone.addr], iat: T0 - 1000, quota: limited }))
  let res = await P.get(`${base}/${big.idS}`)
  assert.equal(res.status, 429, 'the phone is held to the newer ticket\'s cap')
  assert.equal((await (await P.get('/v1/me/quota')).json()).day.cap, 1 * MB)
  // an older ticket shown afterwards changes nothing
  P = api(r, await httpToken(r, coord, phone, { peers: [mac.addr], iat: T0 - 2 * 3600_000, quota: open }))
  assert.equal((await P.get(`${base}/${big.idS}`)).status, 429)
  // other accounts keep their own caps
  const O = api(r, await httpToken(r, coord, other, { iat: T0 - 1000, quota: open }))
  const ob = blob(1500 * KB)
  assert.equal((await O.put(`/v1/b/${other.addr}/${ob.idS}`, ob.ct)).status, 200)
  // a restart keeps the newest ticket's caps (the tokens are gone; the phone signs in with its old ticket again)
  await r.relay.close()
  r = await startRelay(coord, over, { dir, keep: true })
  P = api(r, await httpToken(r, coord, phone, { peers: [mac.addr], iat: T0 - 60_000, quota: open }))
  assert.equal((await (await P.get('/v1/me/quota')).json()).day.cap, 1 * MB, 'kept across the restart')
  // the newest ticket carries no quota: the configuration's caps apply
  M = api(r, await httpToken(r, coord, mac, { peers: [phone.addr], iat: T0 }))
  assert.equal((await (await M.get('/v1/me/quota')).json()).day.cap, 5 * MB)
  // a ticket with smallMB sets the allowance; without it the configured 50 MB applies
  M = api(r, await httpToken(r, coord, mac, { peers: [phone.addr], iat: T0 + 1000, quota: { ...limited, smallMB: 7 } }))
  assert.equal((await (await M.get('/v1/me/quota')).json()).small.cap, 7 * MB)
  M = api(r, await httpToken(r, coord, mac, { peers: [phone.addr], iat: T0 + 2000, quota: { dayMB: 1 } }))
  assert.equal((await (await M.get('/v1/me/quota')).json()).small.cap, 50 * MB)
  // purging the account forgets its newest ticket along with the counters
  assert.ok(r.relay.store.get('acctQuotaGet', 'u_q1'))
  res = await post(r, '/v1/purge', coord.purge('u_q1', { relay: '*', at: T0 }))
  assert.equal(res.status, 200)
  assert.equal(r.relay.store.get('acctQuotaGet', 'u_q1'), undefined)
  assert.ok(r.relay.store.get('acctQuotaGet', 'u_q2'), 'other accounts untouched')
})

test('useTicketQuota false: the configuration\'s caps, whatever the tickets say; old allowance counters are swept', async (t) => {
  let skew = 0
  const T0 = Date.UTC(2026, 9, 9, 4, 0, 0)
  const now = () => T0 + skew
  const coord = new Coord()
  const r = await startRelay(coord, { now, quota: { dayMB: 2, smallMB: 3, useTicketQuota: false } })
  t.after(() => r.stop())
  const mac = device('computer', 'u_q3')
  const M = api(r, await httpToken(r, coord, mac, { iat: T0 - 1000, quota: { dayMB: 0, monthMB: 0, smallMB: 0 } }))
  const q = await (await M.get('/v1/me/quota')).json()
  assert.equal(q.day.cap, 2 * MB)
  assert.equal(q.small.cap, 3 * MB)
  r.relay.store.run('trafAdd', 'u_q3', 's:2026-05-01', 10)
  r.relay.store.run('trafAdd', 'u_q3', 's:2026-10-09', 10)
  r.relay.store.run('acctQuotaPut', 'u_gone', T0 - 100 * 86_400_000, null)
  r.relay.quota.sweep()
  assert.equal(r.relay.store.get('trafGet', 'u_q3', 's:2026-05-01'), undefined, 'old allowance counters dropped')
  assert.ok(r.relay.store.get('trafGet', 'u_q3', 's:2026-10-09'), 'today\'s kept')
  assert.equal(r.relay.store.get('acctQuotaGet', 'u_gone'), undefined, 'an account silent for months: its newest-ticket record dropped')
  assert.ok(r.relay.store.get('acctQuotaGet', 'u_q3'), 'a live account keeps its record')
})
