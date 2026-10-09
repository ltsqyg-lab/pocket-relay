// SPDX-License-Identifier: MIT
// Copyright (c) 2026 the Pocket authors
//
// Tests for pake.mjs (device pairing, E2EE.md §6):   node --test docs/protocol/pake.test.mjs
// Uses vectors.json (`spake2`: RFC 9382 Appendix B; `pair`: Pocket's pairing context), Node's own ECDH as an oracle for
// the scalar multiplication, and live runs with random codes and keys.
import test from 'node:test'
import assert from 'node:assert/strict'
import crypto from 'node:crypto'
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import * as K from './pake.mjs'

const HERE = path.dirname(fileURLToPath(import.meta.url))
const V = JSON.parse(fs.readFileSync(path.join(HERE, 'vectors.json'), 'utf8'))
const H = (s) => Buffer.from(s, 'hex'), BN = (s) => BigInt('0x' + s), hex = (b) => Buffer.from(b).toString('hex')
const hex32 = (v) => v.toString(16).padStart(64, '0')
const errCode = (fn) => { try { fn(); return null } catch (e) { if (e instanceof K.PairError) return e.code; throw e } }
const params = (c) => ({ acct: c.acct, pendingId: c.pendingId, attempt: c.attempt, genesis: c.genesis, sigA: c.sigA, kxA: c.kxA, sigB: c.sigB, kxB: c.kxB })
const keyPair = () => { const e = crypto.createECDH('prime256v1'); e.generateKeys(); return e.getPublicKey() }
const device = () => ({ sig: keyPair(), kx: keyPair() })
const { p256 } = K

test('RFC 9382 Appendix B: every value reproduces (SPAKE2-P256-SHA256-HKDF-HMAC, no AAD)', () => {
  assert.equal(V.spake2.rfc9382.length, 4)
  for (const t of V.spake2.rfc9382) {
    const w = BN(t.wHex), x = BN(t.xHex), y = BN(t.yHex)
    const pA = K.spake2Public('A', w, x), pB = K.spake2Public('B', w, y)
    assert.equal(hex(pA), t.pAHex); assert.equal(hex(pB), t.pBHex)
    const kA = K.spake2SharedK('A', w, x, pB), kB = K.spake2SharedK('B', w, y, pA)
    assert.equal(hex(kA), t.KHex); assert.equal(hex(kB), t.KHex)
    const TT = K.spake2Transcript(Buffer.from(t.A), Buffer.from(t.B), pA, pB, kA, w)
    assert.equal(hex(TT), t.TTHex)
    const ks = K.spake2KeySchedule(TT, Buffer.alloc(0))
    assert.equal(hex(Buffer.concat([ks.Ke, ks.Ka])), t.hashTTHex)
    assert.equal(hex(ks.Ke), t.KeHex); assert.equal(hex(ks.Ka), t.KaHex)
    assert.equal(hex(ks.KcA), t.KcAHex); assert.equal(hex(ks.KcB), t.KcBHex)
    assert.equal(hex(K.spake2Mac(ks.KcA, TT)), t.cAHex); assert.equal(hex(K.spake2Mac(ks.KcB, TT)), t.cBHex)
  }
})

test('M and N are the RFC 9382 points: on P-256, distinct, neither is G', () => {
  assert.equal(K.SPAKE2_M, V.spake2.M); assert.equal(K.SPAKE2_N, V.spake2.N)
  assert.equal(K.SPAKE2_M, '02886e2f97ace46e55ba9dd7242579f2993b64e16ef3dcab95afd497333d8fa12f')
  assert.equal(K.SPAKE2_N, '03d8bbd6c639c62937b04d997f38c3770719c629d7014d49a24b4f98baa1292b49')
  assert.equal(hex(K.encodePoint(p256.M)), V.spake2.MUncompressedHex)
  assert.equal(hex(K.encodePoint(p256.N)), V.spake2.NUncompressedHex)
  for (const pt of [p256.M, p256.N]) {
    assert.ok(p256.onCurve(pt[0], pt[1]))
    assert.notEqual(pt[0], p256.G[0])
    assert.equal(p256.affine(p256.mul(p256.n, p256.proj(pt))), null)       // order n
  }
  assert.notEqual(p256.M[0], p256.N[0])
})

test('pairing vectors: context, w, shares, K, transcript, keys and confirmations', () => {
  assert.equal(K.PAIR_LABEL, V.pair.label); assert.equal(K.PAIR_MAX_ATTEMPTS, V.pair.maxAttempts)
  for (const c of V.pair.valid) {
    const p = params(c), x = BN(c.xHex), y = BN(c.yHex)
    assert.equal(hex(K.pairCtxW(p)), c.ctxWHex, c.name)
    assert.equal(hex(K.pairCtx(p)), c.ctxHex, c.name)
    const w = K.pairW(c.code, K.pairCtxW(p))
    assert.equal(hex32(w), c.wHex, c.name)
    assert.equal(K.didOf(c.sigA, c.kxA), c.didA); assert.equal(K.didOf(c.sigB, c.kxB), c.didB)
    // low level
    const pA = K.spake2Public('A', w, x), pB = K.spake2Public('B', w, y), kk = K.spake2SharedK('A', w, x, pB)
    assert.equal(hex(pA), c.pAHex); assert.equal(hex(pB), c.pBHex); assert.equal(hex(kk), c.KHex)
    assert.equal(hex(K.spake2SharedK('B', w, y, pA)), c.KHex)
    const TT = K.spake2Transcript(Buffer.from(c.idA), Buffer.from(c.idB), pA, pB, kk, w)
    assert.equal(hex(TT), c.TTHex)
    const ks = K.spake2KeySchedule(TT, K.pairCtx(p))
    assert.deepEqual([hex(ks.Ke), hex(ks.Ka), hex(ks.KcA), hex(ks.KcB)], [c.KeHex, c.KaHex, c.KcAHex, c.KcBHex])
    // the two roles
    const b = K.startB(c.code, p, { testScalar: y })
    assert.equal(hex(b.pB), c.pBHex)
    const a = K.answerA(c.code, p, b.pB, { testScalar: x })
    assert.equal(hex(a.pA), c.pAHex); assert.equal(hex(a.cA), c.cAHex)
    const r = K.finishB(b.state, { sigA: c.sigA, kxA: c.kxA }, a.pA, a.cA)
    assert.equal(r.ok, true, c.name); assert.equal(hex(r.cB), c.cBHex); assert.equal(hex(r.Ke), c.KeHex)
    const f = a.confirmB(r.cB)
    assert.equal(f.ok, true); assert.equal(hex(f.Ke), c.KeHex)
    assert.equal(K.formatPairCode(c.code), c.display)
  }
})

test('the scalar multiplication agrees with Node\'s ECDH (k·G and the x-coordinate of K)', () => {
  for (let i = 0; i < 16; i++) {
    const k = p256.randomScalar(), e = crypto.createECDH('prime256v1')
    e.setPrivateKey(H(hex32(k)))
    assert.ok(K.encodePoint(p256.affine(p256.mul(k, p256.proj(p256.G)))).equals(e.getPublicKey()))
  }
  for (const c of V.pair.valid) {
    // K = x·(pB − w·N): let Node multiply the same point by x and compare the x-coordinate (what ECDH returns)
    const p = params(c), w = K.pairW(c.code, K.pairCtxW(p)), q = K.decodePoint(H(c.pBHex))
    const t = p256.affine(p256.add(p256.proj(q), p256.neg(p256.mul(w, p256.proj(p256.N)))))
    const e = crypto.createECDH('prime256v1')
    e.setPrivateKey(H(c.xHex))
    assert.equal(hex(e.computeSecret(K.encodePoint(t))), c.KHex.slice(2, 66), c.name)
  }
})

test('complete addition: infinity, doubling and inverses need no special case', () => {
  const G = p256.proj(p256.G), O = p256.INF, aff = p256.affine
  assert.deepEqual(aff(p256.add(G, O)), p256.G)
  assert.deepEqual(aff(p256.add(O, G)), p256.G)
  assert.equal(aff(p256.add(O, O)), null)
  assert.equal(aff(p256.add(G, p256.neg(G))), null)
  assert.deepEqual(aff(p256.add(G, G)), aff(p256.mul(2n, G)))
  assert.deepEqual(aff(p256.add(p256.mul(5n, G), p256.mul(7n, G))), aff(p256.mul(12n, G)))
  assert.equal(aff(p256.mul(0n, G)), null)
  assert.deepEqual(aff(p256.mul(p256.n - 1n, G)), aff(p256.neg(G)))
  assert.deepEqual(aff(p256.mul(1n, G)), p256.G)
})

test('a wrong code, or a different view of the context, fails at the side that must notice', () => {
  assert.ok(V.pair.invalid.length >= 8)
  for (const c of V.pair.invalid) {
    const nd = c.newDevice, ap = c.approver
    if (c.error === 'bad-confirm') {
      const b = K.startB(nd.code, params(nd), { testScalar: BN(nd.yHex) })
      const a = K.answerA(ap.code, params(ap), b.pB, { testScalar: BN(ap.xHex) })
      assert.equal(hex(b.pB), c.pBHex, c.name); assert.equal(hex(a.pA), c.pAHex, c.name); assert.equal(hex(a.cA), c.cAHex, c.name)
      const r = K.finishB(b.state, { sigA: nd.sigA, kxA: nd.kxA }, a.pA, a.cA)
      if (c.detectedBy === 'newDevice') assert.deepEqual(r, { ok: false, code: 'bad-confirm' }, c.name)
      else {
        assert.equal(r.ok, true, c.name)
        assert.deepEqual(a.confirmB(H(c.cBHex)), { ok: false, code: 'bad-confirm' }, c.name)
      }
    } else if (c.detectedBy === 'approver') {
      assert.equal(errCode(() => K.answerA(ap.code, params(ap), H(c.pBHex), { testScalar: BN(ap.xHex) })), c.error, c.name)
    } else {
      const b = K.startB(nd.code, params(nd), { testScalar: BN(nd.yHex) })
      assert.deepEqual(K.finishB(b.state, { sigA: nd.sigA, kxA: nd.kxA }, H(c.pAHex), H(c.cAHex)), { ok: false, code: c.error }, c.name)
    }
  }
})

test('received points: infinity, wrong length, other encodings, off the curve, coordinates ≥ p are all refused', () => {
  const c = V.pair.valid[0], p = params(c)
  for (const t of V.spake2.invalidPoints) {
    assert.equal(errCode(() => K.decodePoint(H(t.hex))), 'bad-point', t.name)
    assert.equal(errCode(() => K.answerA(c.code, p, H(t.hex))), 'bad-point', `answerA: ${t.name}`)
    const b = K.startB(c.code, p)
    assert.deepEqual(K.finishB(b.state, { sigA: c.sigA, kxA: c.kxA }, H(t.hex), Buffer.alloc(32)), { ok: false, code: 'bad-point' }, `finishB: ${t.name}`)
  }
  // base64url on the wire: malformed text is refused the same way
  for (const s of ['', 'AA==', '!'.repeat(87), H(c.pBHex).toString('base64url') + 'A']) assert.equal(errCode(() => K.decodePoint(s)), 'bad-point', s)
  assert.ok(K.decodePoint(H(c.pBHex).toString('base64url')))
})

test('live runs: random codes, keys and scalars; both sides end with the same Ke; wire values may be base64url', () => {
  for (let i = 0; i < 6; i++) {
    const A = device(), B = device(), code = K.newPairCode()
    const base = { acct: `u_${crypto.randomBytes(6).toString('hex')}`, pendingId: `pd_${crypto.randomBytes(8).toString('hex')}`, attempt: 1 + i % 5,
      genesis: crypto.randomBytes(32).toString('base64url'), sigB: B.sig.toString('base64url'), kxB: B.kx }
    const b = K.startB(code, base)
    const a = K.answerA(K.parsePairCode(K.formatPairCode(code)), { ...base, sigA: A.sig, kxA: A.kx.toString('base64url') }, b.pB.toString('base64url'))
    const r = K.finishB(b.state, { sigA: A.sig.toString('base64url'), kxA: A.kx }, a.pA.toString('base64url'), a.cA.toString('base64url'))
    assert.equal(r.ok, true)
    const f = a.confirmB(r.cB.toString('base64url'))
    assert.equal(f.ok, true)
    assert.ok(f.Ke.equals(r.Ke))
    assert.equal(r.cB.length, 32); assert.equal(a.cA.length, 32); assert.equal(a.pA.length, 65); assert.equal(b.pB.length, 65)
  }
})

test('B makes its offer without knowing which admin will answer; any admin of the lock can complete it', () => {
  const A1 = device(), A2 = device(), B = device(), code = '271828', y = p256.randomScalar()
  const base = { acct: 'u_x', pendingId: 'pd_offer', attempt: 1, genesis: Buffer.alloc(32, 7), sigB: B.sig, kxB: B.kx }
  for (const A of [A1, A2]) {
    const b = K.startB(code, base, { testScalar: y })                       // the same offer both times
    const a = K.answerA(code, { ...base, sigA: A.sig, kxA: A.kx }, b.pB)
    assert.equal(K.finishB(b.state, { sigA: A.sig, kxA: A.kx }, a.pA, a.cA).ok, true)
  }
  // …but B checks against the admin that really answered: told A2 when A1 answered → bad-confirm
  const b = K.startB(code, base, { testScalar: y }), a = K.answerA(code, { ...base, sigA: A1.sig, kxA: A1.kx }, b.pB)
  assert.deepEqual(K.finishB(b.state, { sigA: A2.sig, kxA: A2.kx }, a.pA, a.cA), { ok: false, code: 'bad-confirm' })
})

test('a state answers once; confirmB answers once', () => {
  const A = device(), B = device(), base = { acct: 'u_x', pendingId: 'pd_once', attempt: 3, genesis: Buffer.alloc(32), sigB: B.sig, kxB: B.kx }
  const b = K.startB('000000', base), a = K.answerA('000000', { ...base, sigA: A.sig, kxA: A.kx }, b.pB)
  const r = K.finishB(b.state, { sigA: A.sig, kxA: A.kx }, a.pA, a.cA)
  assert.equal(r.ok, true)
  assert.equal(errCode(() => K.finishB(b.state, { sigA: A.sig, kxA: A.kx }, a.pA, a.cA)), 'used')
  assert.deepEqual(a.confirmB(Buffer.alloc(32)), { ok: false, code: 'bad-confirm' })
  assert.equal(errCode(() => a.confirmB(r.cB)), 'used')                     // no second try after a wrong value
  assert.equal(errCode(() => K.finishB({ role: 'B' }, { sigA: A.sig, kxA: A.kx }, a.pA, a.cA)), 'bad-params')
  assert.equal(JSON.stringify(b.state).includes(hex32(K.pairW('000000', K.pairCtxW(base)))), false)   // nothing secret in the handle
})

test('the pairing code: 6 ASCII digits, uniform-looking, formatted 3 + 3, typed input normalised', () => {
  const seen = new Set(), firstDigit = new Array(10).fill(0)
  for (let i = 0; i < 3000; i++) {
    const c = K.newPairCode()
    assert.match(c, /^[0-9]{6}$/)
    seen.add(c); firstDigit[Number(c[0])]++
  }
  assert.ok(seen.size > 2950)
  assert.ok(firstDigit.every((n) => n > 200), `leading digits ${firstDigit}`)   // ~300 each; leading zeros happen
  for (const t of V.pair.codes.format) assert.equal(K.formatPairCode(t.code), t.display)
  for (const t of V.pair.codes.parse) assert.equal(K.parsePairCode(t.input), t.code, JSON.stringify(t.input))
  assert.equal(K.parsePairCode(null), null); assert.equal(K.parsePairCode('1'.repeat(65)), null)
  assert.equal(errCode(() => K.formatPairCode('12345')), 'bad-code')
})

test('bad inputs are refused with a code', () => {
  const A = device(), B = device()
  const ok = { acct: 'u_x', pendingId: 'pd_x', attempt: 1, genesis: Buffer.alloc(32), sigA: A.sig, kxA: A.kx, sigB: B.sig, kxB: B.kx }
  const pB = K.startB('123456', ok).pB
  for (const code of ['12345', '1234567', '12345a', '１２３４５６', 123456, null]) {
    assert.equal(errCode(() => K.startB(code, ok)), 'bad-code', String(code))
    assert.equal(errCode(() => K.answerA(code, ok, pB)), 'bad-code', String(code))
  }
  for (const [what, bad] of [['attempt 0', { attempt: 0 }], ['attempt 256', { attempt: 256 }], ['attempt 1.5', { attempt: 1.5 }],
    ['empty acct', { acct: '' }], ['acct of 256 bytes', { acct: 'a'.repeat(256) }], ['lone surrogate', { pendingId: 'pd_\ud800' }],
    ['genesis of 31 bytes', { genesis: Buffer.alloc(31) }], ['genesis with padding', { genesis: Buffer.alloc(32).toString('base64') }],
    ['kxB not on the curve', { kxB: Buffer.concat([B.kx.subarray(0, 64), Buffer.from([B.kx[64] ^ 1])]) }],
    ['sigA compressed', { sigA: Buffer.concat([Buffer.from([2]), A.sig.subarray(1, 33)]) }]]) {
    assert.equal(errCode(() => K.answerA('123456', { ...ok, ...bad }, pB)), 'bad-params', what)
  }
  assert.equal(errCode(() => K.startB('123456', { ...ok, attempt: 0 })), 'bad-params')
  assert.equal(errCode(() => K.answerA('123456', ok, pB, { testScalar: 0n })), 'bad-params')
  assert.equal(errCode(() => K.answerA('123456', ok, pB, { testScalar: p256.n })), 'bad-params')
  assert.equal(errCode(() => K.spake2Public('C', 1n, 1n)), 'bad-params')
  assert.ok(K.startB('123456', { ...ok, acct: 'é'.repeat(127) }).pB)       // 254 bytes of UTF-8
})

test('HKDF here equals Node\'s hkdfSync (RFC 5869 A.1, empty salt, the 48-byte w output)', () => {
  const v = V.hkdf[0]
  assert.equal(hex(p256.hkdf256(Buffer.from(v.ikm, 'base64url'), Buffer.from(v.salt, 'base64url'), Buffer.from(v.info, 'base64url'), v.length)), v.okmHex)
  for (const [ikm, salt, info, len] of [[Buffer.from('123456'), Buffer.alloc(32), crypto.randomBytes(300), 48], [crypto.randomBytes(16), Buffer.alloc(0), crypto.randomBytes(400), 32]]) {
    assert.ok(p256.hkdf256(ikm, salt, info, len).equals(Buffer.from(crypto.hkdfSync('sha256', ikm, salt, info, len))))
  }
})

test('the file inlines the way the desktop agent does it (import line dropped, export keywords removed, function scope)', () => {
  const src = fs.readFileSync(path.join(HERE, 'pake.mjs'), 'utf8')
  const imports = src.match(/^import .*$/gm)
  assert.deepEqual(imports, ["import crypto from 'node:crypto'"])
  assert.equal(/^export (?!function |const |class )/m.test(src), false)    // every export is `export function|const|class`
  const body = src.replace(/^import .*$/gm, '').replace(/^export (function|class|const) /gm, '$1 ')
  const api = new Function('crypto', `${body}\nreturn { startB, answerA, finishB, spake2Public }`)(crypto)
  const c = V.pair.valid[1], p = params(c)
  const b = api.startB(c.code, p, { testScalar: BN(c.yHex) }), a = api.answerA(c.code, p, b.pB, { testScalar: BN(c.xHex) })
  assert.equal(hex(a.cA), c.cAHex)
  assert.equal(hex(api.finishB(b.state, p, a.pA, a.cA).cB), c.cBHex)
})
