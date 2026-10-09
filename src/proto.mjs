// Pocket relay — protocol primitives: encodings, P-256 signature checks, coordination documents, tickets,
// proof of possession, seals and blob framing (E2EE.md §3, §11, §12, §13).
//
// The relay never decrypts anything. Everything here is verification of public data plus the byte-level framing
// of ciphertext it stores. Node.js 22 built-ins only.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
import crypto from 'node:crypto'

// ---- errors -------------------------------------------------------------------------------------------------
export class RelayError extends Error {
  constructor(code, detail, extra) {
    super(detail ? `${code}: ${detail}` : code)
    this.code = code
    if (extra) this.extra = extra
  }
}
export const fail = (code, detail, extra) => { throw new RelayError(code, detail, extra) }

/** HTTP status for an error code (RELAY.md §14 plus the verification codes of E2EE.md). */
export const STATUS = {
  'bad-request': 400, mismatch: 400, 'bad-blob': 400, 'bad-format': 400, 'bad-json': 400, 'bad-b64u': 400,
  'bad-seal': 400, 'bad-utf8': 400,
  token: 401, 'bad-ticket': 401, expired: 401, 'bad-proof': 401, 'bad-nonce': 401, 'bad-sig': 401, stale: 401,
  'unknown-key': 401, 'key-not-valid': 401, 'wrong-aud': 401, 'bad-key': 401,
  denied: 403, revoked: 403, 'wrong-account': 403, 'bad-claim': 403,
  'not-found': 404,
  ver: 409, exists: 409, size: 409, claimed: 409,
  'too-large': 413,
  rate: 429, quota: 429,
  storage: 503, unclaimed: 503, full: 503,
}
export const statusOf = (code) => STATUS[code] ?? 400

// ---- encodings (E2EE.md §3.1) ---------------------------------------------------------------------------------
export const PFX = 'pocket/v1 '
const ZERO = Buffer.from([0])
const EMPTY = Buffer.alloc(0)
const B64U_RE = /^[A-Za-z0-9_-]*$/
const UTF8 = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true })

export const b64u = (buf) => Buffer.from(buf).toString('base64url')
/** Strict base64url: no padding, alphabet only, canonical trailing bits; optional exact byte length. */
export function unb64u(s, len) {
  if (typeof s !== 'string' || !B64U_RE.test(s) || s.length % 4 === 1) fail('bad-b64u')
  const b = Buffer.from(s, 'base64url')
  if (b.toString('base64url') !== s) fail('bad-b64u')
  if (len !== undefined && b.length !== len) fail('bad-b64u', `expected ${len} bytes`)
  return b
}
/** Decoded length of a base64url string without decoding it (the string must already be valid). */
export const b64uLen = (s) => Math.floor((s.length * 3) / 4)
export function fromUtf8(buf) { try { return UTF8.decode(buf) } catch { return fail('bad-utf8') } }
/** A JSON object from UTF-8 bytes (no BOM, object at the top level), with an optional byte limit. */
export function parseObj(buf, max) {
  if (max !== undefined && buf.length > max) fail('too-large')
  let v
  try { v = JSON.parse(fromUtf8(buf)) } catch (e) { if (e instanceof RelayError) throw e; fail('bad-json') }
  if (!v || typeof v !== 'object' || Array.isArray(v)) fail('bad-json')
  return v
}
export const u32be = (n) => { const b = Buffer.alloc(4); b.writeUInt32BE(n); return b }
export const isInt = (v, min = 0) => Number.isSafeInteger(v) && v >= min
export const isStr = (v, max = 4096) => typeof v === 'string' && v.length <= max

export const sha256 = (...parts) => crypto.createHash('sha256').update(parts.length === 1 ? parts[0] : Buffer.concat(parts)).digest()
export const sha256hex = (x) => crypto.createHash('sha256').update(x).digest('hex')

/** UTF8("pocket/v1 " + label) || 0x00 || U32BE(len h) || h || c  (E2EE.md §3.4) */
export const sigInput = (label, h, c = EMPTY) => Buffer.concat([Buffer.from(PFX + label, 'utf8'), ZERO, u32be(h.length), h, c])

// ---- P-256 (E2EE.md §3.2, §3.3) ---------------------------------------------------------------------------------
const P = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffffn
const N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n
const B = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604bn
const big = (buf) => (buf.length ? BigInt('0x' + buf.toString('hex')) : 0n)
const mod = (a, m) => { const r = a % m; return r < 0n ? r + m : r }

/** Uncompressed SEC1 point, 65 bytes, coordinates < p, on the curve. */
export function checkPub(pub) {
  if (!Buffer.isBuffer(pub) || pub.length !== 65 || pub[0] !== 4) fail('bad-key')
  const x = big(pub.subarray(1, 33)), y = big(pub.subarray(33))
  if (x >= P || y >= P) fail('bad-key')
  if (mod(y * y, P) !== mod(x * x * x - 3n * x + B, P)) fail('bad-key')
  return pub
}

// Public key objects are cached: tickets of the same device are verified over and over.
const KEY_CACHE = new Map()
const KEY_CACHE_MAX = 4096
function publicKeyOf(pub) {
  const id = pub.toString('base64url')
  let k = KEY_CACHE.get(id)
  if (k) return k
  checkPub(pub)
  k = crypto.createPublicKey({ key: { kty: 'EC', crv: 'P-256', x: b64u(pub.subarray(1, 33)), y: b64u(pub.subarray(33)) }, format: 'jwk' })
  if (KEY_CACHE.size >= KEY_CACHE_MAX) KEY_CACHE.delete(KEY_CACHE.keys().next().value)
  KEY_CACHE.set(id, k)
  return k
}
/** ECDSA P-256 / SHA-256 with r || s signatures (64 bytes); r and s must be in [1, n−1]. */
export function ecdsaVerify(pub, msg, sig) {
  if (!Buffer.isBuffer(sig) || sig.length !== 64) return false
  const r = big(sig.subarray(0, 32)), s = big(sig.subarray(32))
  if (r === 0n || s === 0n || r >= N || s >= N) return false
  let key
  try { key = publicKeyOf(pub) } catch { return false }
  try { return crypto.verify('sha256', msg, { key, dsaEncoding: 'ieee-p1363' }, sig) } catch { return false }
}

// ---- identifiers -----------------------------------------------------------------------------------------------
export const DID_RE = /^[A-Za-z0-9_-]{16}$/
export const KINDS = ['phone', 'computer']
/** A virtual address: dotted quad inside 100.64.0.0/10, no leading zeros. */
export function checkAddr(a) {
  const m = typeof a === 'string' && /^100\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(a)
  if (!m) return false
  const o = m.slice(1).map(Number)
  if (m.slice(1).some((s) => s.length > 1 && s[0] === '0') || o.some((x) => x > 255)) return false
  return o[0] >= 64 && o[0] <= 127
}

// ---- coordination documents, tickets, proofs (E2EE.md §12, §13) --------------------------------------------------
const MIN = 60_000, HOUR = 3_600_000
export const SKEW_MS = 5 * MIN

/** keys = [{kid, pub (b64u), use: [...], nbf, exp}] */
function coordKey(keys, kid, use, now) {
  const k = keys.find((x) => x.kid === kid)
  if (!k) fail('unknown-key')
  if (!Array.isArray(k.use) || !k.use.includes(use) || now < k.nbf - SKEW_MS || now > k.exp + SKEW_MS) fail('key-not-valid')
  return unb64u(k.pub, 65)
}
/** Signed document {p, s} under `label`, signed by a coordination key allowed to sign that label. */
export function verifyCoordDoc(label, doc, keys, now) {
  if (!doc || typeof doc !== 'object') fail('bad-format')
  const p = unb64u(doc.p), D = parseObj(p, 1048576)
  if (D.v !== 1 || D.t !== label) fail('bad-format')
  if (!ecdsaVerify(coordKey(keys, D.kid, label, now), sigInput(label, p), unb64u(doc.s, 64))) fail('bad-sig')
  return D
}
/** keys.json {p, sigs: [{kid, s}]} — accepted when one signature verifies with a key already trusted for `keys`. */
export function verifyKeysDoc(doc, trusted, now) {
  if (!doc || typeof doc !== 'object') fail('bad-format')
  const p = unb64u(doc.p), D = parseObj(p)
  if (D.v !== 1 || D.t !== 'keys' || !Array.isArray(D.keys)) fail('bad-format')
  const ok = (Array.isArray(doc.sigs) ? doc.sigs : []).some((x) => {
    try { return ecdsaVerify(coordKey(trusted, x.kid, 'keys', now), sigInput('keys', p), unb64u(x.s, 64)) } catch { return false }
  })
  if (!ok) fail('bad-sig')
  return D.keys.filter(validKeyRecord)
}
export function validKeyRecord(k) {
  if (!k || typeof k !== 'object' || !isStr(k.kid, 64) || !k.kid || !Array.isArray(k.use) || !isInt(k.nbf) || !isInt(k.exp)) return false
  try { checkPub(unb64u(k.pub, 65)) } catch { return false }
  return true
}
/** Compact ticket b64u(payload).b64u(sig) (E2EE.md §12.2). acct: '*' accepts any account. */
export function verifyTicket(ticket, { keys, aud, now, acct }) {
  const parts = typeof ticket === 'string' && ticket.length <= 8192 ? ticket.split('.') : []
  if (parts.length !== 2) fail('bad-ticket')
  const T = verifyCoordDoc('ticket', { p: parts[0], s: parts[1] }, keys, now)
  if (!isStr(T.aud, 64) || T.aud !== aud) fail('wrong-aud')
  if (!isInt(T.iat, 1) || !isInt(T.exp, 1) || T.exp <= T.iat || T.exp - T.iat > 24 * HOUR) fail('bad-ticket')
  if (now < T.iat - SKEW_MS || now > T.exp + SKEW_MS) fail('expired')
  if (acct !== undefined && acct !== '*' && T.acct !== acct) fail('wrong-account')
  if (!checkAddr(T.addr) || !DID_RE.test(T.dev ?? '') || !KINDS.includes(T.kind) || !Array.isArray(T.peers) || !T.peers.every(checkAddr)) fail('bad-ticket')
  if (!isStr(T.acct, 128) || !T.acct) fail('bad-ticket')
  checkPub(unb64u(T.sig, 65))
  return T
}
/** Proof of possession for a relay challenge (E2EE.md §13, RELAY.md §3). */
export function verifyRelayAuth({ ticket, a, s }, { keys, relayId, acct, nonce, now }) {
  const T = verifyTicket(ticket, { keys, aud: relayId, now, acct })
  const ab = unb64u(a), A = parseObj(ab, 4096)
  if (A.v !== 1 || A.t !== 'relay-auth' || A.relay !== relayId) fail('bad-proof')
  if (typeof nonce !== 'string' || A.nonce !== nonce) fail('bad-nonce')
  if (A.th !== b64u(sha256(Buffer.from(ticket, 'utf8')))) fail('bad-proof')
  if (!isInt(A.ts, 1) || Math.abs(now - A.ts) > SKEW_MS) fail('stale')
  if (!ecdsaVerify(unb64u(T.sig, 65), sigInput('relay-auth', ab), unb64u(s, 64))) fail('bad-sig')
  return T
}

// ---- seals (E2EE.md §3.5) ----------------------------------------------------------------------------------------
export const HEADER_MAX = 4096
/** One binary seal starting at `off`: U32BE(len h) || h || U32BE(len c) || c || s(64). Returns {h, c, s, next}. */
export function sealAt(buf, off = 0) {
  if (buf.length - off < 72) fail('bad-seal')
  const hl = buf.readUInt32BE(off)
  if (hl < 2 || hl > HEADER_MAX || off + 4 + hl + 4 + 64 > buf.length) fail('bad-seal')
  const cl = buf.readUInt32BE(off + 4 + hl)
  const end = off + 8 + hl + cl + 64
  if (end > buf.length) fail('bad-seal')
  return { h: buf.subarray(off + 4, off + 4 + hl), c: buf.subarray(off + 8 + hl, off + 8 + hl + cl), s: buf.subarray(end - 64, end), next: end }
}
/** Exactly one binary seal, nothing after it. */
export function parseSealBin(buf) {
  const r = sealAt(buf, 0)
  if (r.next !== buf.length) fail('bad-seal')
  return r
}
export const sealToBin = ({ h, c, s }) => Buffer.concat([u32be(h.length), h, u32be(c.length), c, s])

/**
 * The JSON form {h, c, s} of an envelope in a WebSocket frame. Checks shapes and sizes without decoding the
 * ciphertext twice; returns the header bytes (the relay may read routing fields from it) and the sizes.
 */
export function checkEnvelopeJson(env, { maxC = 1048576 + 16, maxH = HEADER_MAX } = {}) {
  if (!env || typeof env !== 'object' || Array.isArray(env)) fail('bad-request')
  const { h, c, s } = env
  if (typeof h !== 'string' || typeof c !== 'string' || typeof s !== 'string') fail('bad-request')
  if (h.length > Math.ceil((maxH * 4) / 3) + 4 || c.length > Math.ceil((maxC * 4) / 3) + 4) fail('too-large')
  const hb = unb64u(h)
  if (hb.length > maxH) fail('too-large')
  if (hb.length < 2) fail('bad-request')
  if (!B64U_RE.test(c) || c.length % 4 === 1) fail('bad-b64u')
  const cLen = b64uLen(c)
  if (cLen > maxC) fail('too-large')
  unb64u(s, 64)
  return { h: hb, cLen, bytes: hb.length + cLen + 64 }
}

// ---- blobs (E2EE.md §11.2) ---------------------------------------------------------------------------------------
export const BLOB_MAGIC = Buffer.from('PKB1', 'utf8')
export const BLOB_CHUNK = 65536
export const BLOB_PIECE = BLOB_CHUNK + 16
export const BLOB_HEADER = 22
export const blobSizeFor = (len) => BLOB_HEADER + len + 16 * Math.max(1, Math.ceil(len / BLOB_CHUNK))
export const BLOB_MAX_PLAIN = 100 * 1024 * 1024
export const BLOB_MAX = blobSizeFor(BLOB_MAX_PLAIN)
/** Is `bytes` the size of some PKB1 stream (22 + len + 16·max(1, ⌈len/65536⌉))? */
export function blobBytesValid(bytes) {
  if (!isInt(bytes, BLOB_HEADER + 16) || bytes > BLOB_MAX) return false
  const body = bytes - BLOB_HEADER
  const n = Math.ceil(body / BLOB_PIECE)
  const last = body - (n - 1) * BLOB_PIECE
  return last >= 16 && last <= BLOB_PIECE
}
/** The 22-byte header: magic, version 1, chunk size 2^16, blob id. */
export function checkBlobHeader(head, blobId) {
  return head.length >= BLOB_HEADER && head.subarray(0, 4).equals(BLOB_MAGIC) && head[4] === 1 && head[5] === 16 && head.subarray(6, 22).equals(blobId)
}
export const BLOB_ID_RE = /^[A-Za-z0-9_-]{22}$/
/** Blob ids are 16 random bytes in base64url (22 characters, canonical). */
export function parseBlobId(s) {
  if (!BLOB_ID_RE.test(s ?? '')) return null
  try { return unb64u(s, 16) } catch { return null }
}
