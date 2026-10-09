// SPDX-License-Identifier: MIT
// Copyright (c) 2026 the Pocket authors. MIT License: see the end of this file.
//
// Pocket device pairing — reference implementation (pocket-pair/1).
// A new device shows a 6-digit pairing code; the user types it on a device that is already in the account's device
// lock; the two run SPAKE2 (RFC 9382, ciphersuite SPAKE2-P256-SHA256-HKDF-HMAC) with the code as the password and
// Pocket's pairing context bound in. Spec: E2EE.md §6. Vectors: vectors.json `spake2` and `pair`. Tests:
// `node --test docs/protocol/pake.test.mjs`.
//
// One file, no dependencies besides node:crypto; runs on Node.js 22 and Bun. Products use it verbatim: the coordination
// server keeps a byte-identical copy, the desktop agent inlines it (drops the import line and the `export ` keywords,
// wraps it in a function scope) and checks the copy against this file. Do not edit a copy; change this file, its
// vectors and its tests, then re-copy.
//
//   new device B (shows the code)                        approver A (an admin of the lock; the user types the code)
//   ─────────────────────────────                        ──────────────────────────────────────────────────────────
//   code = newPairCode(); show formatPairCode(code)
//   b = startB(code, { acct, pendingId, attempt,
//                      genesis, sigB, kxB })
//   offer { pendingId, attempt, pB: b64u(b.pB) }   ───▶  code = parsePairCode(what the user typed)
//                                                        a = answerA(code, { acct, pendingId, attempt, genesis,
//                                                                            sigA, kxA, sigB, kxB }, pB)
//                                                  ◀───  answer { pendingId, attempt, pA: b64u(a.pA), cA: b64u(a.cA) }
//   r = finishB(b.state, { sigA, kxA }, pA, cA)            (sigA, kxA: the answering admin's keys in the lock B validated)
//   r.ok → pin genesis; confirm { cB: b64u(r.cB) } ───▶  c = a.confirmB(cB)
//   else → fail, next attempt with a new code             c.ok → sign the lock statement that adds B; else give up
//
// B's offer goes out before anyone has answered, and an account usually has several admin devices, so B cannot know
// A's keys when it computes pB. That is why the password scalar w is derived from ctxW (the context without A's keys)
// while A's identity is bound by the transcript (idA) and by the confirmation keys' AAD (the full ctx).
//
// Arithmetic is BigInt: projective coordinates, the complete addition formula of Renes–Costello–Batina 2016
// (Algorithm 4, a = −3, also used for doubling) and a Montgomery ladder over a fixed 256 bits with branch-free
// conditional swaps. No secret-dependent branches or operation counts; BigInt itself is not constant-time, which is
// acceptable here (E2EE.md §6.7): every secret lives for one attempt and only a process on the same device could time it.

import crypto from 'node:crypto'

export const PAIR_LABEL = 'pocket-pair/1'
export const PAIR_MAX_ATTEMPTS = 5           // per pending entry, counted by both devices and by coordination
export const PAIR_CODE_DIGITS = 6

export class PairError extends Error {
  constructor(code, detail) { super(detail ? `${code}: ${detail}` : code); this.name = 'PairError'; this.code = code }
}
// codes: bad-code (not 6 ASCII digits; w = 0) · bad-params (a context field is malformed) · bad-point (a received
// point is invalid, or K is the point at infinity) · bad-confirm (key confirmation failed) · used (a state used twice)
const pairFail = (code, detail) => { throw new PairError(code, detail) }

// ---- bytes ---------------------------------------------------------------------------------------------------------
const B64U_RE = /^[A-Za-z0-9_-]*$/
/** Bytes from a Uint8Array or a strict base64url string (no padding, canonical); null if malformed or not `len` long. */
function bytesOf(v, len) {
  let b = null
  if (typeof v === 'string') {
    if (B64U_RE.test(v) && v.length % 4 !== 1) {
      const d = Buffer.from(v, 'base64url')
      if (d.toString('base64url') === v) b = d
    }
  } else if (v instanceof Uint8Array) b = Buffer.from(v)
  return b && (len === undefined || b.length === len) ? b : null
}
const utf8 = (s) => Buffer.from(s, 'utf8')
const toBig = (b) => (b.length ? BigInt('0x' + Buffer.from(b).toString('hex')) : 0n)
const be32 = (v) => Buffer.from(v.toString(16).padStart(64, '0'), 'hex')
const le64 = (n) => { const b = Buffer.alloc(8); b.writeBigUInt64LE(BigInt(n)); return b }
const ctEqual = (a, b) => a.length === b.length && crypto.timingSafeEqual(a, b)

// ---- SHA-256, HMAC, HKDF (RFC 5869; an empty salt means 32 zero bytes) --------------------------------------------
const sha256 = (...parts) => crypto.createHash('sha256').update(Buffer.concat(parts)).digest()
const hmac256 = (key, ...parts) => crypto.createHmac('sha256', key).update(Buffer.concat(parts)).digest()
function hkdf256(ikm, salt, info, len) {
  const prk = hmac256(salt.length ? salt : Buffer.alloc(32), ikm)
  const out = []
  let t = Buffer.alloc(0)
  for (let i = 1, n = 0; n < len; i++, n += 32) { t = hmac256(prk, t, info, Buffer.from([i])); out.push(t) }
  return Buffer.concat(out).subarray(0, len)
}

// ---- P-256 ---------------------------------------------------------------------------------------------------------
const FP = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffffn   // field prime p
const FN = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n   // group order n (cofactor 1)
const FB = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604bn   // b; a = −3
const GEN = [0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296n,
  0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5n]
const fmul = (a, b) => (a * b) % FP
const fadd = (a, b) => (a + b) % FP
const fsub = (a, b) => (a - b + FP) % FP
function fpow(a, e) {                         // e is always public (p − 2, (p + 1) / 4)
  let r = 1n
  for (a %= FP; e > 0n; e >>= 1n) { if (e & 1n) r = (r * a) % FP; a = (a * a) % FP }
  return r
}
const onCurve = (x, y) => fmul(y, y) === fadd(fsub(fmul(fmul(x, x), x), fmul(3n, x)), FB)

// Points are projective [X, Y, Z] with x = X/Z, y = Y/Z; the point at infinity is [0, 1, 0].
const INF = Object.freeze([0n, 1n, 0n])
const proj = ([x, y]) => [x, y, 1n]
/** Complete addition, Renes–Costello–Batina 2016, Algorithm 4 (a = −3): valid for every pair, P = Q and infinity included. */
function padd([X1, Y1, Z1], [X2, Y2, Z2]) {
  let t0 = fmul(X1, X2), t1 = fmul(Y1, Y2), t2 = fmul(Z1, Z2)
  let t3 = fadd(X1, Y1), t4 = fadd(X2, Y2)
  t3 = fmul(t3, t4); t4 = fadd(t0, t1); t3 = fsub(t3, t4)
  t4 = fadd(Y1, Z1)
  let X3 = fadd(Y2, Z2)
  t4 = fmul(t4, X3); X3 = fadd(t1, t2); t4 = fsub(t4, X3)
  X3 = fadd(X1, Z1)
  let Y3 = fadd(X2, Z2)
  X3 = fmul(X3, Y3); Y3 = fadd(t0, t2); Y3 = fsub(X3, Y3)
  let Z3 = fmul(FB, t2)
  X3 = fsub(Y3, Z3); Z3 = fadd(X3, X3); X3 = fadd(X3, Z3)
  Z3 = fsub(t1, X3); X3 = fadd(t1, X3)
  Y3 = fmul(FB, Y3)
  t1 = fadd(t2, t2); t2 = fadd(t1, t2)
  Y3 = fsub(Y3, t2); Y3 = fsub(Y3, t0)
  t1 = fadd(Y3, Y3); Y3 = fadd(t1, Y3)
  t1 = fadd(t0, t0); t0 = fadd(t1, t0); t0 = fsub(t0, t2)
  t1 = fmul(t4, Y3); t2 = fmul(t0, Y3)
  Y3 = fmul(X3, Z3); Y3 = fadd(Y3, t2)
  X3 = fmul(t3, X3); X3 = fsub(X3, t1)
  Z3 = fmul(t4, Z3); t1 = fmul(t3, t0); Z3 = fadd(Z3, t1)
  return [X3, Y3, Z3]
}
const pneg = ([X, Y, Z]) => [X, (FP - Y) % FP, Z]
/** Swap a and b when bit = 1, without a branch on bit. */
function cswap(a, b, bit) {
  const mask = -bit                          // 0n or −1n (all ones)
  const a2 = [], b2 = []
  for (let i = 0; i < 3; i++) { const t = mask & (a[i] ^ b[i]); a2.push(a[i] ^ t); b2.push(b[i] ^ t) }
  return [a2, b2]
}
/** k · P for 0 ≤ k < 2^256: Montgomery ladder, always 256 steps of one addition and one doubling. */
function pmul(k, pt) {
  let r0 = INF, r1 = pt
  for (let i = 255n; i >= 0n; i--) {
    const bit = (k >> i) & 1n;
    [r0, r1] = cswap(r0, r1, bit)
    r1 = padd(r0, r1)
    r0 = padd(r0, r0);
    [r0, r1] = cswap(r0, r1, bit)
  }
  return r0
}
/** Affine [x, y], or null for the point at infinity. */
function affine([X, Y, Z]) {
  if (Z === 0n) return null
  const zi = fpow(Z, FP - 2n)
  return [fmul(X, zi), fmul(Y, zi)]
}
/** SEC1 uncompressed encoding, 65 bytes. */
export function encodePoint([x, y]) { return Buffer.concat([Buffer.from([4]), be32(x), be32(y)]) }
/** Strict decoding of a received point: 65 bytes, 0x04, x < p, y < p, on the curve (cofactor 1: then also in the group). */
export function decodePoint(v) {
  const b = bytesOf(v, 65)
  if (!b || b[0] !== 4) pairFail('bad-point', 'not a 65-byte uncompressed point')
  const x = toBig(b.subarray(1, 33)), y = toBig(b.subarray(33))
  if (x >= FP || y >= FP || !onCurve(x, y)) pairFail('bad-point', 'not on P-256')
  return [x, y]
}
/** SEC1 compressed point (33 bytes) to affine; used for the constants M and N. */
function decompress(hex) {
  const b = Buffer.from(hex, 'hex')
  const x = toBig(b.subarray(1))
  if (b.length !== 33 || (b[0] !== 2 && b[0] !== 3) || x >= FP) pairFail('bad-point', 'bad compressed point')
  const rhs = fadd(fsub(fmul(fmul(x, x), x), fmul(3n, x)), FB)
  let y = fpow(rhs, (FP + 1n) / 4n)          // p ≡ 3 (mod 4)
  if (fmul(y, y) !== rhs) pairFail('bad-point', 'bad compressed point')
  if ((y & 1n) !== BigInt(b[0] & 1)) y = FP - y
  return [x, y]
}

// ---- SPAKE2 (RFC 9382) -----------------------------------------------------------------------------------------------
/** RFC 9382 §6, P-256 (SEC1 compressed). A uses M, B uses N. */
export const SPAKE2_M = '02886e2f97ace46e55ba9dd7242579f2993b64e16ef3dcab95afd497333d8fa12f'
export const SPAKE2_N = '03d8bbd6c639c62937b04d997f38c3770719c629d7014d49a24b4f98baa1292b49'
const PT_M = decompress(SPAKE2_M), PT_N = decompress(SPAKE2_N)

function scalarOf(v, what) {
  const s = typeof v === 'bigint' ? v : (v instanceof Uint8Array && v.length === 32 ? toBig(v) : -1n)
  if (s < 1n || s >= FN) pairFail('bad-params', `${what} must be in [1, n − 1]`)
  return s
}
/** Uniform in [1, n − 1] by rejection sampling. */
function randomScalar() {
  for (;;) { const s = toBig(crypto.randomBytes(32)); if (s >= 1n && s < FN) return s }
}
/** pA = s·G + w·M (role 'A') or pB = s·G + w·N (role 'B'); 65 bytes. */
export function spake2Public(role, w, s) {
  if (role !== 'A' && role !== 'B') pairFail('bad-params', 'role')
  const pt = affine(padd(pmul(scalarOf(s, 'scalar'), proj(GEN)), pmul(scalarOf(w, 'w'), proj(role === 'A' ? PT_M : PT_N))))
  if (!pt) pairFail('bad-point', 'share is the point at infinity')
  return encodePoint(pt)
}
/** K = s·(pB − w·N) for A, K = s·(pA − w·M) for B (cofactor 1); 65 bytes. Validates the peer's share first. */
export function spake2SharedK(role, w, s, peer) {
  if (role !== 'A' && role !== 'B') pairFail('bad-params', 'role')
  const q = decodePoint(peer)
  const k = affine(pmul(scalarOf(s, 'scalar'), padd(proj(q), pneg(pmul(scalarOf(w, 'w'), proj(role === 'A' ? PT_N : PT_M))))))
  if (!k) pairFail('bad-point', 'K is the point at infinity')
  return encodePoint(k)
}
/** TT = len(A)‖A ‖ len(B)‖B ‖ len(pA)‖pA ‖ len(pB)‖pB ‖ len(K)‖K ‖ len(w)‖w — len: 8-byte little-endian; w: 32 bytes big-endian. */
export function spake2Transcript(idA, idB, pA, pB, K, w) {
  const lp = (b) => Buffer.concat([le64(b.length), b])
  return Buffer.concat([lp(Buffer.from(idA)), lp(Buffer.from(idB)), lp(Buffer.from(pA)), lp(Buffer.from(pB)), lp(Buffer.from(K)), lp(be32(scalarOf(w, 'w')))])
}
/** Ke ‖ Ka = SHA-256(TT); KcA ‖ KcB = HKDF-SHA256(Ka, salt = nil, info = "ConfirmationKeys" ‖ AAD, 32). 16 bytes each. */
export function spake2KeySchedule(TT, aad) {
  const h = sha256(Buffer.from(TT))
  const kc = hkdf256(h.subarray(16), Buffer.alloc(0), Buffer.concat([utf8('ConfirmationKeys'), Buffer.from(aad)]), 32)
  return { Ke: h.subarray(0, 16), Ka: h.subarray(16), KcA: kc.subarray(0, 16), KcB: kc.subarray(16) }
}
/** Key confirmation message: HMAC-SHA256(Kc, TT), 32 bytes. */
export function spake2Mac(kc, TT) { return hmac256(Buffer.from(kc), Buffer.from(TT)) }

// ---- the pairing code --------------------------------------------------------------------------------------------
const CODE_RE = /^[0-9]{6}$/
const checkCode = (code) => { if (typeof code !== 'string' || !CODE_RE.test(code)) pairFail('bad-code', 'not 6 ASCII digits') }
/** A fresh code: 6 decimal digits, uniform over 000000–999999 (rejection sampling on 32 random bits). */
export function newPairCode() {
  for (;;) {
    const v = crypto.randomBytes(4).readUInt32BE(0)
    if (v < 4294000000) return String(v % 1000000).padStart(6, '0')
  }
}
/** "048213" → "048 213" (always ASCII digits, whatever the UI language). */
export function formatPairCode(code) { checkCode(code); return `${code.slice(0, 3)} ${code.slice(3)}` }
const ND_RE = /\p{Nd}/u, SEP_RE = /[\s\p{Pd}]/u
/** What the user typed → "048213", or null. NFKC first; any Unicode decimal digit counts (full-width, Arabic-Indic,
 *  Devanagari, …); white space and dashes are ignored; anything else, or not exactly 6 digits, gives null. */
export function parsePairCode(text) {
  if (typeof text !== 'string' || text.length > 64) return null
  let out = ''
  for (const ch of text.normalize('NFKC')) {
    if (ND_RE.test(ch)) {
      const cp = ch.codePointAt(0)
      let z = cp                             // Unicode encodes decimal digits in aligned runs of ten (0…9)
      while (z > 0 && ND_RE.test(String.fromCodePoint(z - 1))) z--
      out += String((cp - z) % 10)
      if (out.length > PAIR_CODE_DIGITS) return null
    } else if (!SEP_RE.test(ch)) return null
  }
  return out.length === PAIR_CODE_DIGITS ? out : null
}

// ---- Pocket's pairing context -------------------------------------------------------------------------------------
/** E2EE.md §3.7: did = b64u(SHA-256("pocket/v1 did" ‖ 0x00 ‖ sig ‖ kx)[0:12]). */
export function didOf(sig, kx) {
  return sha256(utf8('pocket/v1 did'), Buffer.from([0]), pubKey(sig, 'sig'), pubKey(kx, 'kx')).subarray(0, 12).toString('base64url')
}
function pubKey(v, what) {
  const b = bytesOf(v, 65)
  try { if (b) { decodePoint(b); return b } } catch { /* below */ }
  return pairFail('bad-params', `${what} is not a P-256 public key`)
}
function l16(s, what) {
  const b = typeof s === 'string' ? utf8(s) : null
  if (!b || b.length < 1 || b.length > 255 || b.toString('utf8') !== s) pairFail('bad-params', `${what} must be 1–255 bytes of UTF-8`)
  return Buffer.concat([Buffer.from([0, b.length]), b])
}
function ctxBase(p) {
  if (!p || typeof p !== 'object') pairFail('bad-params', 'params')
  if (!Number.isInteger(p.attempt) || p.attempt < 1 || p.attempt > 255) pairFail('bad-params', 'attempt must be 1–255')
  const g = bytesOf(p.genesis, 32)
  if (!g) pairFail('bad-params', 'genesis must be 32 bytes')
  return Buffer.concat([utf8(PAIR_LABEL), l16(p.acct, 'acct'), l16(p.pendingId, 'pendingId'), Buffer.from([p.attempt]), g])
}
/** ctx = "pocket-pair/1" ‖ L16(acct) ‖ L16(pendingId) ‖ attempt ‖ G ‖ sigA ‖ kxA ‖ sigB ‖ kxB — the confirmation AAD. */
export function pairCtx(p) {
  return Buffer.concat([ctxBase(p), pubKey(p.sigA, 'sigA'), pubKey(p.kxA, 'kxA'), pubKey(p.sigB, 'sigB'), pubKey(p.kxB, 'kxB')])
}
/** ctxW = the same without sigA ‖ kxA: everything B knows when it makes its offer. */
export function pairCtxW(p) { return Buffer.concat([ctxBase(p), pubKey(p.sigB, 'sigB'), pubKey(p.kxB, 'kxB')]) }
/** w = OS2IP(HKDF-SHA256(UTF8(code), salt = 32 zero bytes, info = "pocket-pair-w" ‖ ctxW, 48)) mod n; w = 0 fails. */
export function pairW(code, ctxW) {
  checkCode(code)
  const w = toBig(hkdf256(utf8(code), Buffer.alloc(32), Buffer.concat([utf8('pocket-pair-w'), Buffer.from(ctxW)]), 48)) % FN
  if (w === 0n) pairFail('bad-code', 'w = 0')
  return w
}
const idOf = (acct, sig, kx) => utf8(`${acct}/${didOf(sig, kx)}`)
function run(role, code, p, s, peer) {
  const ctxW = pairCtxW(p), ctx = pairCtx(p), w = pairW(code, ctxW)
  const mine = spake2Public(role, w, s), K = spake2SharedK(role, w, s, peer)
  const theirs = Buffer.from(bytesOf(peer, 65))
  const TT = spake2Transcript(idOf(p.acct, p.sigA, p.kxA), idOf(p.acct, p.sigB, p.kxB),
    role === 'A' ? mine : theirs, role === 'A' ? theirs : mine, K, w)
  const k = spake2KeySchedule(TT, ctx)
  return { mine, Ke: k.Ke, cA: spake2Mac(k.KcA, TT), cB: spake2Mac(k.KcB, TT) }
}
const macOf = (v) => bytesOf(v, 32)

// ---- the two roles -------------------------------------------------------------------------------------------------
const B_STATES = new WeakMap()               // handle → secrets; the handle itself carries nothing secret
/**
 * New device B: p = { acct, pendingId, attempt, genesis, sigB, kxB } (bytes or base64url).
 * Returns { pB, state }. Keep `state` in memory only, for this one attempt (never persist or log it).
 * opts.testScalar (bigint or 32 bytes) fixes y — test vectors only.
 */
export function startB(code, p, opts = {}) {
  checkCode(code)
  const ctxW = pairCtxW(p)                   // validates everything below
  const base = { acct: p.acct, pendingId: p.pendingId, attempt: p.attempt, genesis: bytesOf(p.genesis, 32), sigB: bytesOf(p.sigB, 65), kxB: bytesOf(p.kxB, 65) }
  const w = pairW(code, ctxW)
  const y = opts.testScalar === undefined ? randomScalar() : scalarOf(opts.testScalar, 'y')
  const pB = spake2Public('B', w, y)
  const state = Object.freeze({ role: 'B', pendingId: base.pendingId, attempt: base.attempt })
  B_STATES.set(state, { code, base, y, pB, used: false })
  return { pB, state }
}
/**
 * B, on the answer: a = { sigA, kxA } of the answering device, taken from the lock B validated (never from the answer).
 * Returns { ok: true, cB, Ke } — B pins the genesis and sends cB — or { ok: false, code: 'bad-point' | 'bad-confirm' }:
 * report the attempt as failed and start the next one with a new code. Each state answers once.
 */
export function finishB(state, a, pA, cA) {
  const st = B_STATES.get(state)
  if (!st) pairFail('bad-params', 'not a state from startB')
  if (st.used) pairFail('used', 'this attempt was already answered')
  st.used = true
  const p = { ...st.base, sigA: a?.sigA, kxA: a?.kxA }
  pairCtx(p)                                 // throws bad-params on our own inputs, before looking at the peer's
  const c = macOf(cA)
  let r
  try {
    if (!bytesOf(pA, 65)) pairFail('bad-point', 'not 65 bytes')
    r = run('B', st.code, p, st.y, pA)
  } catch (e) {
    if (e instanceof PairError && e.code === 'bad-point') return { ok: false, code: 'bad-point' }
    throw e
  }
  if (!c || !ctEqual(c, r.cA)) return { ok: false, code: 'bad-confirm' }
  return { ok: true, cB: r.cB, Ke: r.Ke }
}
/**
 * Approver A, after the user typed the code: p = { acct, pendingId, attempt, genesis, sigA, kxA, sigB, kxB } (A's own
 * keys and pinned genesis; B's keys from the pending entry, checked against its did). Throws PairError (bad-code,
 * bad-params, bad-point) — then A sends nothing for this attempt and reports it failed.
 * Returns { pA, cA, confirmB(cB) → { ok: true, Ke } | { ok: false, code: 'bad-confirm' } } (confirmB answers once).
 * opts.testScalar fixes x — test vectors only.
 */
export function answerA(code, p, pB, opts = {}) {
  checkCode(code)
  pairCtx(p)                                 // bad-code, then bad-params, then bad-point
  const x = opts.testScalar === undefined ? randomScalar() : scalarOf(opts.testScalar, 'x')
  if (!bytesOf(pB, 65)) pairFail('bad-point', 'not 65 bytes')
  const r = run('A', code, p, x, pB)
  let used = false
  return Object.freeze({
    pA: r.mine,
    cA: r.cA,
    confirmB(cB) {
      if (used) pairFail('used', 'already confirmed')
      used = true
      const c = macOf(cB)
      return c && ctEqual(c, r.cB) ? { ok: true, Ke: r.Ke } : { ok: false, code: 'bad-confirm' }
    },
  })
}

/** Internals for tests and ports (field and group arithmetic, the constants as affine points). */
export const p256 = Object.freeze({
  p: FP, n: FN, b: FB, G: GEN, M: PT_M, N: PT_N, INF,
  add: padd, neg: pneg, mul: pmul, affine, proj, onCurve, decompress, encodePoint, decodePoint, randomScalar, hkdf256,
})

// MIT License
//
// Copyright (c) 2026 the Pocket authors
//
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated
// documentation files (the "Software"), to deal in the Software without restriction, including without limitation the
// rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
// permit persons to whom the Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the
// Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
// WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
// COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
// OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
