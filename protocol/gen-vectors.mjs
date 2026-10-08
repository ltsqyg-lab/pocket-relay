#!/usr/bin/env node
/*
 * Pocket protocol v1 — reference implementation and test-vector generator.
 *
 * Spec: E2EE.md (crypto), RELAY.md, COORD.md, ASR.md in this folder. Node.js >= 20, built-in modules only.
 *
 *   node docs/protocol/gen-vectors.mjs           rewrite vectors.json
 *   node docs/protocol/gen-vectors.mjs --check   rebuild in memory and require a byte-identical vectors.json, then
 *                                                verify every signature with Node's own ECDSA verifier and confirm
 *                                                every negative case fails with its expected error code
 *
 * Signatures in vectors.json come from a deterministic signer (RFC 6979, pure JS below) so the file is reproducible.
 * Products may sign with ordinary randomized ECDSA: only verification has to agree with these vectors.
 *
 * The functions in sections 1-9 are written to be read and ported. They are exported, so Node-based builders
 * (relay/, server/, asr/, agent/) can import this file in their own tests as an oracle; product code must still be
 * its own implementation and pass vectors.json.
 *
 * Every private key in this file is public test material. Never use any of it outside tests.
 */
import crypto from 'node:crypto'
import zlib from 'node:zlib'
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'

const HERE = path.dirname(fileURLToPath(import.meta.url))
const VECTORS_FILE = path.join(HERE, 'vectors.json')

// ============================================================================================================
// 0. errors
// ============================================================================================================
export class PocketError extends Error {
  constructor(code, detail) { super(detail ? `${code}: ${detail}` : code); this.code = code }
}
const fail = (code, detail) => { throw new PocketError(code, detail) }

// ============================================================================================================
// 1. encodings (E2EE.md §3.1)
// ============================================================================================================
export const utf8 = (s) => Buffer.from(s, 'utf8')
const UTF8 = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true })   // keeps a BOM so JSON.parse rejects it
export function fromUtf8(buf) { try { return UTF8.decode(buf) } catch { return fail('bad-utf8') } }
const B64U_RE = /^[A-Za-z0-9_-]*$/
export const b64u = (buf) => Buffer.from(buf).toString('base64url')
/** Strict base64url: no padding, alphabet only, canonical trailing bits; optional exact length in bytes. */
export function unb64u(s, len) {
  if (typeof s !== 'string' || !B64U_RE.test(s) || s.length % 4 === 1) fail('bad-b64u')
  const b = Buffer.from(s, 'base64url')
  if (b.toString('base64url') !== s) fail('bad-b64u')
  if (len !== undefined && b.length !== len) fail('bad-b64u', `expected ${len} bytes`)
  return b
}
export const u32be = (n) => { const b = Buffer.alloc(4); b.writeUInt32BE(n); return b }
export const u64be = (n) => { const b = Buffer.alloc(8); b.writeBigUInt64BE(BigInt(n)); return b }
/** Parse a JSON object from UTF-8 bytes (no BOM, object at top level), with an optional byte limit. */
export function parseJson(buf, max) {
  if (max !== undefined && buf.length > max) fail('too-large')
  const text = fromUtf8(buf)
  let v
  try { v = JSON.parse(text) } catch { fail('bad-json') }
  if (!v || typeof v !== 'object' || Array.isArray(v)) fail('bad-json')
  return v
}
const isInt = (v, min = 0) => Number.isSafeInteger(v) && v >= min
const isStr = (v, max = 4096) => typeof v === 'string' && v.length <= max

// ============================================================================================================
// 2. primitives (E2EE.md §3.2)
// ============================================================================================================
export const sha256 = (...parts) => crypto.createHash('sha256').update(Buffer.concat(parts)).digest()
export const hmac256 = (key, ...parts) => crypto.createHmac('sha256', key).update(Buffer.concat(parts)).digest()
export const hkdf256 = (ikm, salt, info, len = 32) => Buffer.from(crypto.hkdfSync('sha256', ikm, salt, info, len))

export function gcmSeal(key, nonce, aad, pt) {
  const c = crypto.createCipheriv('aes-256-gcm', key, nonce, { authTagLength: 16 })
  c.setAAD(aad)
  return Buffer.concat([c.update(pt), c.final(), c.getAuthTag()])
}
export function gcmOpen(key, nonce, aad, ct) {
  if (ct.length < 16) fail('bad-tag')
  const d = crypto.createDecipheriv('aes-256-gcm', key, nonce, { authTagLength: 16 })
  d.setAAD(aad)
  d.setAuthTag(ct.subarray(ct.length - 16))
  try { return Buffer.concat([d.update(ct.subarray(0, ct.length - 16)), d.final()]) } catch { return fail('bad-tag') }
}

export const deflate = (buf) => zlib.deflateRawSync(buf, { level: 6 })
/** Raw DEFLATE (RFC 1951) with a hard cap on the inflated size (zip-bomb guard). */
export function inflate(buf, max) {
  try { return zlib.inflateRawSync(buf, { maxOutputLength: max }) } catch (e) {
    if (e && (e.code === 'ERR_BUFFER_TOO_LARGE' || e instanceof RangeError)) fail('too-large')
    return fail('bad-zip')
  }
}

// ---- P-256 --------------------------------------------------------------------------------------------------
const P = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffffn
const N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n
const B = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604bn
const GX = 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296n
const GY = 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5n
const big = (buf) => (buf.length ? BigInt('0x' + buf.toString('hex')) : 0n)
const bytes32 = (v) => Buffer.from(v.toString(16).padStart(64, '0'), 'hex')
const mod = (a, m) => { const r = a % m; return r < 0n ? r + m : r }

/** Public keys are uncompressed SEC1 points (65 bytes). Reject anything not on the curve. */
export function checkPub(pub) {
  if (!Buffer.isBuffer(pub) || pub.length !== 65 || pub[0] !== 4) fail('bad-key')
  const x = big(pub.subarray(1, 33)), y = big(pub.subarray(33))
  if (x >= P || y >= P) fail('bad-key')
  if (mod(y * y, P) !== mod(x * x * x - 3n * x + B, P)) fail('bad-key')
  return pub
}
export function checkPriv(d) {
  if (!Buffer.isBuffer(d) || d.length !== 32) fail('bad-key')
  const v = big(d)
  if (v === 0n || v >= N) fail('bad-key')
  return d
}
export function pubOf(d) { const e = crypto.createECDH('prime256v1'); e.setPrivateKey(checkPriv(d)); return e.getPublicKey() }
const jwk = (pub) => ({ kty: 'EC', crv: 'P-256', x: b64u(pub.subarray(1, 33)), y: b64u(pub.subarray(33)) })
/** ECDSA P-256 / SHA-256, signature = r || s (32 + 32 bytes, IEEE P1363). Randomized (what products normally use). */
export function ecdsaSign(d, msg) {
  const key = crypto.createPrivateKey({ key: { ...jwk(pubOf(d)), d: b64u(d) }, format: 'jwk' })
  return crypto.sign('sha256', msg, { key, dsaEncoding: 'ieee-p1363' })
}
export function ecdsaVerify(pub, msg, sig) {
  if (!Buffer.isBuffer(sig) || sig.length !== 64) return false
  const r = big(sig.subarray(0, 32)), s = big(sig.subarray(32))
  if (r === 0n || s === 0n || r >= N || s >= N) return false
  try { checkPub(pub) } catch { return false }
  const key = crypto.createPublicKey({ key: jwk(pub), format: 'jwk' })
  return crypto.verify('sha256', msg, { key, dsaEncoding: 'ieee-p1363' }, sig)
}
/** ECDH P-256: the shared secret is the 32-byte big-endian x-coordinate. */
export function ecdh(d, pub) { const e = crypto.createECDH('prime256v1'); e.setPrivateKey(checkPriv(d)); return e.computeSecret(checkPub(pub)) }

// Deterministic ECDSA (RFC 6979 §3.2, SHA-256) in plain BigInt arithmetic — used only to make vectors reproducible.
function inv(a, m) {
  let r0 = mod(a, m), r1 = m, s0 = 1n, s1 = 0n
  while (r1) { const q = r0 / r1; [r0, r1] = [r1, r0 - q * r1]; [s0, s1] = [s1, s0 - q * s1] }
  if (r0 !== 1n) throw new Error('no inverse')
  return mod(s0, m)
}
function padd(a, b) {
  if (!a) return b
  if (!b) return a
  let l
  if (a[0] === b[0]) {
    if (mod(a[1] + b[1], P) === 0n) return null
    l = mod((3n * a[0] * a[0] - 3n) * inv(2n * a[1], P), P)
  } else l = mod((b[1] - a[1]) * inv(b[0] - a[0], P), P)
  const x = mod(l * l - a[0] - b[0], P)
  return [x, mod(l * (a[0] - x) - a[1], P)]
}
function pmul(k, pt) { let r = null; for (let a = pt; k > 0n; k >>= 1n, a = padd(a, a)) if (k & 1n) r = padd(r, a); return r }
export function ecdsaSignDeterministic(d, msg) {
  const x = big(checkPriv(d)), h1 = sha256(msg), z = big(h1)
  const xo = bytes32(x), ho = bytes32(mod(z, N))
  let V = Buffer.alloc(32, 1), K = Buffer.alloc(32, 0)
  K = hmac256(K, V, Buffer.from([0]), xo, ho); V = hmac256(K, V)
  K = hmac256(K, V, Buffer.from([1]), xo, ho); V = hmac256(K, V)
  for (;;) {
    V = hmac256(K, V)
    const k = big(V)
    if (k >= 1n && k < N) {
      const r = mod(pmul(k, [GX, GY])[0], N)
      if (r !== 0n) {
        const s = mod(inv(k, N) * (z + r * x), N)
        if (s !== 0n) return Buffer.concat([bytes32(r), bytes32(s)])
      }
    }
    K = hmac256(K, V, Buffer.from([0])); V = hmac256(K, V)
  }
}

// ============================================================================================================
// 3. labels, signatures, seals (E2EE.md §3.4-3.6)
// ============================================================================================================
export const PFX = 'pocket/v1 '
const Z = Buffer.from([0])
/** Everything that is signed: UTF8("pocket/v1 " + label) || 0x00 || U32BE(len(h)) || h || c   (c may be empty). */
export const sigInput = (label, h, c = Buffer.alloc(0)) => Buffer.concat([utf8(PFX + label), Z, u32be(h.length), h, c])

let SIGNER = ecdsaSign   // the generator swaps in the deterministic signer
const sign = (d, msg) => SIGNER(d, msg)

/** SEAL: key = HKDF-SHA256(ikm, salt = header.id (16 B), info = "pocket/v1 <label> key"); AES-256-GCM(nonce = header.nonce, AAD = header bytes). */
export const sealKey = (ikm, label, salt) => hkdf256(ikm, salt, utf8(`${PFX}${label} key`))
function idNonce(hBytes) {
  const h = parseJson(hBytes, 4096)
  return { id: unb64u(h.id, 16), nonce: unb64u(h.nonce, 12), h }
}
export function sealWith(ikm, label, hBytes, pt) { const { id, nonce } = idNonce(hBytes); return gcmSeal(sealKey(ikm, label, id), nonce, hBytes, pt) }
export function openWith(ikm, label, hBytes, c) { const { id, nonce } = idNonce(hBytes); return gcmOpen(sealKey(ikm, label, id), nonce, hBytes, c) }

/** A seal is three byte strings (h, c, s). JSON form for WebSocket / control messages, binary form for bulk HTTP. */
export const sealToJson = ({ h, c, s }) => ({ h: b64u(h), c: b64u(c), s: b64u(s) })
export const sealFromJson = (j) => ({ h: unb64u(j.h), c: unb64u(j.c), s: unb64u(j.s, 64) })
export const sealToBin = ({ h, c, s }) => Buffer.concat([u32be(h.length), h, u32be(c.length), c, s])
/** Parse one binary seal at `off`; returns { seal, next }. A seal stream is plain concatenation. */
export function sealFromBin(buf, off = 0) {
  if (buf.length - off < 72) fail('bad-seal')
  const hl = buf.readUInt32BE(off)
  if (hl < 2 || hl > 4096 || off + 4 + hl + 4 + 64 > buf.length) fail('bad-seal')
  const cl = buf.readUInt32BE(off + 4 + hl)
  const end = off + 8 + hl + cl + 64
  if (end > buf.length) fail('bad-seal')
  return { seal: { h: buf.subarray(off + 4, off + 4 + hl), c: buf.subarray(off + 8 + hl, off + 8 + hl + cl), s: buf.subarray(end - 64, end) }, next: end }
}
export function sealStream(buf) { const out = []; for (let off = 0; off < buf.length;) { const r = sealFromBin(buf, off); out.push(r.seal); off = r.next } return out }

/** Signed document {p, s}: p = payload bytes (JSON), s = ECDSA over sigInput(label, p). */
export function makeSigned(label, d, payload) {
  const p = Buffer.isBuffer(payload) ? payload : utf8(JSON.stringify(payload))
  return { p: b64u(p), s: b64u(sign(d, sigInput(label, p))) }
}

// ============================================================================================================
// 4. identifiers (E2EE.md §3.7, §4, §6.2, §8)
// ============================================================================================================
export const didOf = (sigPub, kxPub) => b64u(sha256(utf8(PFX + 'did'), Z, checkPub(sigPub), checkPub(kxPub)).subarray(0, 12))
export const kidOf = (key) => b64u(hmac256(key, utf8(PFX + 'kid')).subarray(0, 16))
export const namesKeyOf = (epoch1Key) => hkdf256(epoch1Key, Buffer.alloc(0), utf8(PFX + 'names'))
export const sessionKeyOf = (namesKey, sessionId, xv) =>
  b64u(hmac256(namesKey, utf8('sess'), Z, utf8(sessionId), Z, utf8(String(xv))).subarray(0, 16))
/** Six 11-bit indices from the first 66 bits of SHA-256("pocket/v1 sas" || 0x00 || genesisHash || sigPub || kxPub). */
export function sasIndices(genesisHash, sigPub, kxPub) {
  const v = big(sha256(utf8(PFX + 'sas'), Z, genesisHash, sigPub, kxPub).subarray(0, 9))
  return [61, 50, 39, 28, 17, 6].map((sh) => Number((v >> BigInt(sh)) & 0x7ffn))
}
export function checkAddr(a) {
  const m = typeof a === 'string' && /^100\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(a)
  if (!m) return false
  const o = m.slice(1).map(Number)
  if (m.slice(1).some((s) => s.length > 1 && s[0] === '0') || o.some((x) => x > 255)) return false
  return o[0] >= 64 && o[0] <= 127
}
const BAD_CHARS = /[\u0000-\u001f\u007f-\u009f؜‎‏‪-‮⁦-⁩]/
export const checkName = (s) => typeof s === 'string' && !BAD_CHARS.test(s) && [...s].length >= 1 && [...s].length <= 64

// ============================================================================================================
// 5. device lock (E2EE.md §5) and ACL (§7)
// ============================================================================================================
const KINDS = ['phone', 'computer']
const PLATFORMS = ['ios', 'android', 'mac', 'windows', 'linux']
const DID_RE = /^[A-Za-z0-9_-]{16}$/

export function checkDevice(d) {
  if (!d || typeof d !== 'object') fail('bad-device')
  const keys = Object.keys(d).sort().join(',')
  if (keys !== 'addr,admin,id,kind,kx,name,platform,sig') fail('bad-device')
  if (!KINDS.includes(d.kind) || !PLATFORMS.includes(d.platform) || !checkName(d.name) || !checkAddr(d.addr) || typeof d.admin !== 'boolean') fail('bad-device')
  let id
  try { id = didOf(unb64u(d.sig, 65), unb64u(d.kx, 65)) } catch { fail('bad-device') }
  if (d.id !== id) fail('bad-device')
  return d
}
export const emptyLockState = (acct) => ({ acct, seq: 0, head: null, genesis: null, devices: {}, acl: { phones: {}, computers: {} }, realms: {} })
const liveAdmins = (st) => Object.values(st.devices).filter((x) => !x.revoked && x.admin).length

function checkAcl(acl, devices) {
  if (!acl || typeof acl !== 'object' || Array.isArray(acl)) fail('bad-acl')
  if (Object.keys(acl).some((k) => k !== 'phones' && k !== 'computers')) fail('bad-acl')
  const phones = acl.phones ?? {}, computers = acl.computers ?? {}
  const isList = (v, kind) => v === '*' || (Array.isArray(v) && v.length <= 256 && v.every((x) => devices[x]?.kind === kind))
  for (const [id, r] of Object.entries(phones)) {
    if (devices[id]?.kind !== 'phone' || !r || typeof r !== 'object') fail('bad-acl')
    if (Object.keys(r).some((k) => k !== 'computers' && k !== 'control')) fail('bad-acl')
    if (!isList(r.computers, 'computer') || (r.control !== undefined && typeof r.control !== 'boolean')) fail('bad-acl')
  }
  for (const [id, r] of Object.entries(computers)) {
    if (devices[id]?.kind !== 'computer' || !r || typeof r !== 'object') fail('bad-acl')
    if (Object.keys(r).some((k) => k !== 'phones') || !isList(r.phones, 'phone')) fail('bad-acl')
  }
  return { phones, computers }
}

/** Apply one signed lock statement {p, s} to a state; returns the new state or throws PocketError(code). */
export function applyStatement(st, stmt) {
  if (!stmt || typeof stmt.p !== 'string' || typeof stmt.s !== 'string') fail('bad-format')
  const payload = unb64u(stmt.p), sig = unb64u(stmt.s, 64)
  const L = parseJson(payload, 16384)
  if (L.v !== 1 || L.t !== 'lock' || !isInt(L.seq, 1) || !isInt(L.ts, 1) || !DID_RE.test(L.by ?? '') || !L.op || typeof L.op !== 'object') fail('bad-format')
  if (L.acct !== st.acct) fail('bad-acct')
  if (L.seq !== st.seq + 1) fail('bad-seq')
  if (L.prev !== (st.head ? st.head.h : null)) fail('bad-prev')
  const op = L.op
  let signer
  if (st.seq === 0) {
    if (op.type !== 'genesis') fail('not-genesis')
    signer = checkDevice(op.device)
    if (L.by !== signer.id || signer.admin !== true) fail('bad-device')
  } else {
    if (op.type === 'genesis') fail('bad-op')
    signer = st.devices[L.by]
    if (!signer) fail('unknown-signer')
    if (signer.revoked) fail('revoked-signer')
  }
  if (!ecdsaVerify(unb64u(signer.sig), sigInput('lock', payload), sig)) fail('bad-sig')

  const ns = structuredClone(st)
  const addDevice = (dev, extra) => { ns.devices[dev.id] = { ...dev, addedAt: L.ts, addedBy: L.by, revoked: null, ...extra } }
  switch (op.type) {
    case 'genesis': {
      if (op.resetOf !== undefined && op.resetOf !== null) {
        const r = op.resetOf
        if (typeof r !== 'object' || !isStr(r.genesis, 43) || !isInt(r.seq, 1) || !isStr(r.h, 43)) fail('bad-op')
      }
      addDevice(signer, { sas: null })
      break
    }
    case 'add': {
      if (!signer.admin) fail('not-admin')
      const dev = checkDevice(op.device)
      if (typeof op.sas !== 'boolean') fail('bad-op')
      if (ns.devices[dev.id]) fail('dup-device')
      if (Object.values(ns.devices).some((x) => !x.revoked && x.addr === dev.addr)) fail('dup-addr')
      addDevice(dev, { sas: op.sas })
      break
    }
    case 'revoke': {
      const t = ns.devices[op.device]
      if (!t || t.revoked) fail('bad-target')
      if (!signer.admin && L.by !== op.device) fail('not-admin')
      if (op.reason !== undefined && !isStr(op.reason, 64)) fail('bad-op')
      t.revoked = { at: L.ts, by: L.by }
      if (liveAdmins(ns) < 1) fail('last-admin')
      break
    }
    case 'policy': {
      if (!signer.admin) fail('not-admin')
      ns.acl = checkAcl(op.acl, ns.devices)
      if (op.admins !== undefined) {
        if (!op.admins || typeof op.admins !== 'object') fail('bad-acl')
        for (const [id, v] of Object.entries(op.admins)) {
          if (!ns.devices[id] || ns.devices[id].revoked || typeof v !== 'boolean') fail('bad-acl')
          ns.devices[id].admin = v
        }
      }
      if (liveAdmins(ns) < 1) fail('last-admin')
      break
    }
    case 'realm': {
      if (L.by !== op.realm || signer.kind !== 'computer') fail('not-owner')
      const cur = ns.realms[op.realm]?.epoch ?? 0
      if (op.epoch !== cur + 1) fail('bad-epoch')
      if (!isStr(op.kid, 22)) fail('bad-op')
      unb64u(op.kid, 16)
      if (!['init', 'revoke', 'acl', 'rotate', 'reset'].includes(op.reason)) fail('bad-op')
      ns.realms[op.realm] = { epoch: op.epoch, kids: { ...(ns.realms[op.realm]?.kids ?? {}), [op.epoch]: op.kid } }
      break
    }
    default: fail('bad-op')
  }
  const h = b64u(sha256(payload))
  ns.seq = L.seq
  ns.head = { seq: L.seq, h }
  if (L.seq === 1) ns.genesis = h
  return ns
}
export function validateLog(acct, statements) { return statements.reduce((st, s) => applyStatement(st, s), emptyLockState(acct)) }
/** Does a (separately validated) new log's genesis declare itself a reset of the log we know? */
export function isResetOf(newGenesisStmt, known) {
  const L = parseJson(unb64u(newGenesisStmt.p))
  return L.op?.type === 'genesis' && L.op.resetOf?.genesis === known.genesis && L.acct === known.acct
}

/** ACL evaluation (E2EE.md §7.2). Only live phone -> live computer pairs ever have access. */
export function access(st, phoneId, computerId) {
  const p = st.devices[phoneId], c = st.devices[computerId]
  if (!p || !c || p.revoked || c.revoked || p.kind !== 'phone' || c.kind !== 'computer') return { read: false, control: false }
  const pr = st.acl.phones[phoneId], cr = st.acl.computers[computerId]
  const read = (!pr || pr.computers === '*' || pr.computers.includes(computerId)) && (!cr || cr.phones === '*' || cr.phones.includes(phoneId))
  return { read, control: read && (!pr || pr.control !== false) }
}

// ============================================================================================================
// 6. grants (E2EE.md §8.4)
// ============================================================================================================
export function makeGrant({ granter, ephPriv, recipient, realm, keys, id, nonce, ts }) {
  const ephPub = pubOf(ephPriv), rcptKx = unb64u(recipient.kx, 65)
  const header = { v: 1, t: 'grant', id: b64u(id), nonce: b64u(nonce), realm, to: recipient.id, toKx: recipient.kx, by: granter.id, ts,
    eph: b64u(ephPub), epochs: keys.map((k) => ({ epoch: k.epoch, kid: kidOf(k.key) })) }
  const h = utf8(JSON.stringify(header))
  const pt = utf8(JSON.stringify({ realm, keys: keys.map((k) => ({ epoch: k.epoch, key: b64u(k.key) })) }))
  const ikm = Buffer.concat([ecdh(ephPriv, rcptKx), ephPub, rcptKx])
  const c = sealWith(ikm, 'grant', h, pt)
  return { h, c, s: sign(granter.sigPriv, sigInput('grant', h, c)) }
}
/** Returns { realm, keys: {epoch: Buffer} }. `self` = { id, kx (b64u), kxPriv }. */
export function openGrant(g, { lock, self }) {
  const H = parseJson(g.h, 4096)
  if (H.v !== 1 || H.t !== 'grant' || !Array.isArray(H.epochs) || H.epochs.length < 1 || H.epochs.length > 1000) fail('bad-header')
  if (H.to !== self.id || H.toKx !== self.kx) fail('not-for-me')
  const by = lock.devices[H.by], realm = lock.devices[H.realm]
  if (!by) fail('unknown-sender')
  if (by.revoked) fail('revoked-sender')
  if (!realm || realm.revoked || realm.kind !== 'computer') fail('bad-realm')
  if (!(H.by === H.realm || (by.admin && access(lock, H.by, H.realm).read))) fail('denied')
  if (!ecdsaVerify(unb64u(by.sig), sigInput('grant', g.h, g.c), g.s)) fail('bad-sig')
  const eph = checkPub(unb64u(H.eph, 65)), myKx = unb64u(self.kx, 65)
  const ikm = Buffer.concat([ecdh(self.kxPriv, eph), eph, myKx])
  const pt = parseJson(openWith(ikm, 'grant', g.h, g.c), 1048576)
  if (pt.realm !== H.realm || !Array.isArray(pt.keys) || pt.keys.length !== H.epochs.length) fail('bad-grant')
  const kids = lock.realms[H.realm]?.kids ?? {}
  const out = {}
  pt.keys.forEach((k, i) => {
    const key = unb64u(k.key, 32)
    if (H.epochs[i].epoch !== k.epoch || H.epochs[i].kid !== kidOf(key) || kids[k.epoch] !== kidOf(key)) fail('bad-kid')
    out[k.epoch] = key
  })
  return { realm: H.realm, keys: out }
}

// ============================================================================================================
// 7. envelopes (E2EE.md §9) and stored objects (§10)
// ============================================================================================================
export const ENV_KINDS = ['cmd', 'rpc', 'res', 'evt']
export const ENV_MAX = 1048576           // ciphertext bytes (before base64url)
export const CMD_WINDOW_MS = 600000     // commands and rpcs older or newer than 10 minutes are refused
export function makeEnvelope({ sender, header, payload, key, zip = false }) {
  const h = utf8(JSON.stringify(zip ? { ...header, zip: 'deflate' } : header))
  let pt = Buffer.isBuffer(payload) ? payload : utf8(JSON.stringify(payload))
  if (zip) pt = deflate(pt)
  const c = sealWith(key, 'env', h, pt)
  return { h, c, s: sign(sender.sigPriv, sigInput('env', h, c)) }
}
/**
 * ctx = { lock, self (did), keyring: {realmDid: {epoch: key}}, now, lastSeq: Map(did -> seq), suspended?: Set(did) }
 * Verification order is normative (E2EE.md §9.3): nothing is decrypted before the signature and the ACL pass.
 */
export function openEnvelope(env, ctx) {
  const { h, c, s } = env
  if (h.length > 4096 || c.length > ENV_MAX + 16) fail('too-large')
  const H = parseJson(h)
  if (H.v !== 1 || H.t !== 'env' || !ENV_KINDS.includes(H.kind)) fail('bad-header')
  unb64u(H.id, 16); unb64u(H.nonce, 12)
  if (![H.from, H.to, H.realm].every((x) => typeof x === 'string') || !isInt(H.epoch, 1) || !isInt(H.seq, 1) || !isInt(H.ts, 1)) fail('bad-header')
  if (H.kind === 'res' ? typeof H.re !== 'string' : H.re !== undefined) fail('bad-header')
  if (H.zip !== undefined && H.zip !== 'deflate') fail('bad-header')
  const st = ctx.lock, sender = st.devices[H.from], me = st.devices[ctx.self]
  if (!sender) fail('unknown-sender')
  if (sender.revoked) fail('revoked-sender')
  if (ctx.suspended?.has(H.from)) fail('suspended-sender')
  if (!(H.to === ctx.self || (H.to === '*' && H.kind === 'evt'))) fail('not-for-me')
  if (!ecdsaVerify(unb64u(sender.sig), sigInput('env', h, c), s)) fail('bad-sig')
  if (H.kind === 'cmd' || H.kind === 'rpc') {
    if (me.kind !== 'computer' || H.realm !== ctx.self || sender.kind !== 'phone') fail('denied')
    const a = access(st, H.from, ctx.self)
    if (!(H.kind === 'cmd' ? a.control : a.read)) fail('denied')
  } else {
    if (H.from !== H.realm || sender.kind !== 'computer' || me.kind !== 'phone') fail('denied')
    if (!access(st, ctx.self, H.realm).read) fail('denied')
  }
  if (H.seq <= (ctx.lastSeq.get(H.from) ?? 0)) fail('replay')
  if ((H.kind === 'cmd' || H.kind === 'rpc') && Math.abs(ctx.now - H.ts) > CMD_WINDOW_MS) fail('stale')
  const key = ctx.keyring[H.realm]?.[H.epoch]
  if (!key) fail('no-key')
  let pt = openWith(key, 'env', h, c)
  if (H.zip) pt = inflate(pt, ENV_MAX)
  const payload = parseJson(pt, ENV_MAX)
  if (typeof payload.op !== 'string') fail('bad-payload')
  ctx.lastSeq.set(H.from, H.seq)          // commit replay state only after full success
  return { header: H, payload }
}

export const OBJ_KINDS = {
  info: { seq: false, max: 262144 },
  usage: { seq: false, max: 16384 },
  sess: { seq: false, max: 65536 },
  msg: { seq: true, max: 4194304 },
  lite: { seq: true, max: 1048576 },
}
export function makeObject({ owner, header, plaintext, key, zip = false }) {
  const h = utf8(JSON.stringify(zip ? { ...header, zip: 'deflate' } : header))
  let pt = Buffer.isBuffer(plaintext) ? plaintext : utf8(JSON.stringify(plaintext))
  if (zip) pt = deflate(pt)
  const c = sealWith(key, 'obj', h, pt)
  return { h, c, s: sign(owner.sigPriv, sigInput('obj', h, c)) }
}
/** ctx = { lock, keyring, expect: {realm, kind, key, seq?}, minVer? } */
export function openObject(obj, ctx) {
  const H = parseJson(obj.h, 4096)
  if (H.v !== 1 || H.t !== 'obj' || !OBJ_KINDS[H.kind]) fail('bad-header')
  unb64u(H.id, 16); unb64u(H.nonce, 12)
  const spec = OBJ_KINDS[H.kind]
  if (!isStr(H.key, 64) || !isInt(H.ver, 1) || !isInt(H.epoch, 1) || !isInt(H.ts, 1) || (spec.seq ? !isInt(H.seq, 1) : H.seq !== undefined)) fail('bad-header')
  if (H.zip !== undefined && H.zip !== 'deflate') fail('bad-header')
  const e = ctx.expect
  if (H.realm !== e.realm || H.kind !== e.kind || H.key !== e.key || (spec.seq && H.seq !== e.seq)) fail('wrong-object')
  const owner = ctx.lock.devices[H.realm]
  if (!owner || owner.kind !== 'computer') fail('bad-realm')
  if (owner.revoked) fail('revoked-sender')
  if (H.by !== H.realm) fail('not-owner')
  if (obj.c.length > spec.max + 16) fail('too-large')
  if (!ecdsaVerify(unb64u(owner.sig), sigInput('obj', obj.h, obj.c), obj.s)) fail('bad-sig')
  if (ctx.minVer !== undefined && H.ver < ctx.minVer) fail('rollback')
  const key = ctx.keyring[H.realm]?.[H.epoch]
  if (!key) fail('no-key')
  let pt = openWith(key, 'obj', obj.h, obj.c)
  if (H.zip) pt = inflate(pt, spec.max)
  if (pt.length > spec.max) fail('too-large')
  return { header: H, value: parseJson(pt) }
}

// ============================================================================================================
// 8. blobs (E2EE.md §11)
// ============================================================================================================
export const BLOB_MAGIC = utf8('PKB1')
export const BLOB_CHUNK = 65536
export const blobKeyOf = (fileKey, blobId) => hkdf256(fileKey, blobId, utf8(PFX + 'blob key'))
export const blobHeader = (blobId) => Buffer.concat([BLOB_MAGIC, Buffer.from([1, 16]), blobId])      // 22 bytes
export const blobNonce = (i, last) => Buffer.concat([u32be(last ? 1 : 0), u64be(i)])                   // 12 bytes
export function encryptBlob(fileKey, blobId, pt) {
  const k = blobKeyOf(fileKey, blobId), H = blobHeader(blobId)
  const n = Math.max(1, Math.ceil(pt.length / BLOB_CHUNK)), out = [H]
  for (let i = 0; i < n; i++) out.push(gcmSeal(k, blobNonce(i, i === n - 1), H, pt.subarray(i * BLOB_CHUNK, (i + 1) * BLOB_CHUNK)))
  return Buffer.concat(out)
}
export function decryptBlob(fileKey, blobId, ct) {
  if (ct.length < 22 + 16) fail('bad-blob')
  const H = ct.subarray(0, 22)
  if (!H.subarray(0, 4).equals(BLOB_MAGIC) || H[4] !== 1 || H[5] !== 16 || !H.subarray(6).equals(blobId)) fail('bad-blob')
  const k = blobKeyOf(fileKey, blobId), body = ct.subarray(22), full = BLOB_CHUNK + 16
  const n = Math.ceil(body.length / full)
  if (body.length - (n - 1) * full < 16) fail('bad-blob')
  const out = []
  for (let i = 0; i < n; i++) out.push(gcmOpen(k, blobNonce(i, i === n - 1), H, body.subarray(i * full, Math.min(body.length, (i + 1) * full))))
  return Buffer.concat(out)
}

// ============================================================================================================
// 9. coordination-signed documents, tickets, proof of possession (E2EE.md §12-13)
// ============================================================================================================
const MIN = 60000, HOUR = 3600000
export const SKEW_MS = 5 * MIN
/** keys = [{kid, pub (b64u), use: [...], nbf, exp}] */
function coordKey(keys, kid, use, now) {
  const k = keys.find((x) => x.kid === kid)
  if (!k) fail('unknown-key')
  if (!k.use.includes(use) || now < k.nbf - SKEW_MS || now > k.exp + SKEW_MS) fail('key-not-valid')
  return unb64u(k.pub, 65)
}
export function verifyCoordDoc(label, doc, keys, now) {
  const p = unb64u(doc.p), D = parseJson(p, 1048576)
  if (D.v !== 1 || D.t !== label) fail('bad-format')
  if (!ecdsaVerify(coordKey(keys, D.kid, label, now), sigInput(label, p), unb64u(doc.s, 64))) fail('bad-sig')
  return D
}
/** keys.json: {p, sigs: [{kid, s}]}; accepted when at least one signature verifies with a key we already trust. */
export function verifyKeysDoc(doc, trusted, now) {
  const p = unb64u(doc.p), D = parseJson(p)
  if (D.v !== 1 || D.t !== 'keys' || !Array.isArray(D.keys)) fail('bad-format')
  const ok = (doc.sigs ?? []).some((x) => {
    try { return ecdsaVerify(coordKey(trusted, x.kid, 'keys', now), sigInput('keys', p), unb64u(x.s, 64)) } catch { return false }
  })
  if (!ok) fail('bad-sig')
  return D.keys
}
export const ticketOf = (doc) => `${doc.p}.${doc.s}`
export function verifyTicket(ticket, { keys, aud, now, acct }) {
  const parts = typeof ticket === 'string' ? ticket.split('.') : []
  if (parts.length !== 2) fail('bad-ticket')
  const T = verifyCoordDoc('ticket', { p: parts[0], s: parts[1] }, keys, now)
  if (!isStr(T.aud, 64) || T.aud !== aud) fail('wrong-aud')
  if (!isInt(T.iat, 1) || !isInt(T.exp, 1) || T.exp <= T.iat || T.exp - T.iat > 24 * HOUR) fail('bad-ticket')
  if (now < T.iat - SKEW_MS || now > T.exp + SKEW_MS) fail('expired')
  if (acct !== undefined && acct !== '*' && T.acct !== acct) fail('wrong-account')
  if (!checkAddr(T.addr) || !DID_RE.test(T.dev ?? '') || !KINDS.includes(T.kind) || !Array.isArray(T.peers) || !T.peers.every(checkAddr)) fail('bad-ticket')
  checkPub(unb64u(T.sig, 65))
  return T
}
export function makeProof(label, d, fields) {
  const a = utf8(JSON.stringify({ v: 1, t: label, ...fields }))
  return { a: b64u(a), s: b64u(sign(d, sigInput(label, a))) }
}
/** Relay WebSocket / HTTP-session proof of possession (E2EE.md §13, RELAY.md §3). */
export function verifyRelayAuth({ ticket, a, s }, { keys, relayId, acct, nonce, now }) {
  const T = verifyTicket(ticket, { keys, aud: relayId, now, acct })
  const ab = unb64u(a), A = parseJson(ab, 4096)
  if (A.v !== 1 || A.t !== 'relay-auth' || A.relay !== relayId) fail('bad-proof')
  if (A.nonce !== nonce) fail('bad-nonce')
  if (A.th !== b64u(sha256(utf8(ticket)))) fail('bad-proof')
  if (!isInt(A.ts, 1) || Math.abs(now - A.ts) > SKEW_MS) fail('stale')
  if (!ecdsaVerify(unb64u(T.sig, 65), sigInput('relay-auth', ab), unb64u(s, 64))) fail('bad-sig')
  return T
}
/** ASR gateway proof of possession: binds the audio body (ASR.md §3). Nonce replay is checked by the caller. */
export function verifyAsrAuth({ ticket, a, s, body }, { keys, aud, now }) {
  const T = verifyTicket(ticket, { keys, aud, now })
  const ab = unb64u(a), A = parseJson(ab, 4096)
  if (A.v !== 1 || A.t !== 'asr-auth' || A.aud !== aud) fail('bad-proof')
  if (!isInt(A.ts, 1) || Math.abs(now - A.ts) > SKEW_MS) fail('stale')
  unb64u(A.nonce, 16)
  if (A.bodySha !== b64u(sha256(body))) fail('body-mismatch')
  if (!ecdsaVerify(unb64u(T.sig, 65), sigInput('asr-auth', ab), unb64u(s, 64))) fail('bad-sig')
  return { ticket: T, nonce: A.nonce }
}

/** Enrollment proof of possession (E2EE.md §13, COORD.md §4.1): binds the two enrolled public keys to the bearer token. */
export function verifyEnrollAuth({ a, s }, { token, sig, kx, now }) {
  const ab = unb64u(a), A = parseJson(ab, 4096)
  if (A.v !== 1 || A.t !== 'enroll-auth') fail('bad-proof')
  if (A.sig !== sig || A.kx !== kx) fail('bad-proof')
  if (A.th !== b64u(sha256(utf8(token)))) fail('bad-proof')
  if (!isInt(A.ts, 1) || Math.abs(now - A.ts) > SKEW_MS) fail('stale')
  if (!ecdsaVerify(checkPub(unb64u(sig, 65)), sigInput('enroll-auth', ab), unb64u(s, 64))) fail('bad-sig')
  return A
}

// ============================================================================================================
// 10. vector generation
// ============================================================================================================
const T0 = Date.UTC(2026, 9, 8)                                        // 2026-10-08T00:00:00Z
const ACCT = 'u_test0001'
function testScalar(label) {
  for (let i = 0; ; i++) { const d = sha256(utf8(`pocket test vector key/${label}/${i}`)); const v = big(d); if (v > 0n && v < N) return d }
}
function testBytes(label, n) {
  const out = []
  for (let i = 0, len = 0; len < n; i++, len += 32) out.push(sha256(utf8(`pocket test vector bytes/${label}/${i}`)))
  return Buffer.concat(out).subarray(0, n)
}
const pattern = (n) => { const b = Buffer.alloc(n); for (let i = 0; i < n; i++) b[i] = i % 251; return b }

const DEVICE_INFO = {
  phoneA: { kind: 'phone', platform: 'ios', name: 'iPhone A', addr: '100.64.0.11' },
  phoneB: { kind: 'phone', platform: 'android', name: 'Pixel B', addr: '100.64.0.12' },
  computerC: { kind: 'computer', platform: 'mac', name: 'MacBook C', addr: '100.64.0.21' },
  computerD: { kind: 'computer', platform: 'windows', name: 'PC D', addr: '100.64.0.22' },
  evil: { kind: 'phone', platform: 'ios', name: 'Evil', addr: '100.64.0.99' },
}
function testDevice(name) {
  const sigPriv = testScalar(`${name}/sig`), kxPriv = testScalar(`${name}/kx`), sigPub = pubOf(sigPriv), kxPub = pubOf(kxPriv)
  return { handle: name, sigPriv, kxPriv, sigPub, kxPub, id: didOf(sigPub, kxPub), sig: b64u(sigPub), kx: b64u(kxPub), ...DEVICE_INFO[name] }
}
const entry = (d, admin = true) => ({ id: d.id, kind: d.kind, platform: d.platform, name: d.name, addr: d.addr, sig: d.sig, kx: d.kx, admin })
function statement(st, by, op, over = {}, signKey = by.sigPriv) {
  const L = { v: 1, t: 'lock', acct: over.acct ?? st.acct, seq: over.seq ?? st.seq + 1, prev: 'prev' in over ? over.prev : (st.head ? st.head.h : null),
    ts: T0 + (st.seq + 1) * MIN, by: over.by ?? by.id, op }
  const p = utf8(JSON.stringify(L))
  return { p: b64u(p), s: b64u(sign(signKey, sigInput('lock', p))) }
}
const errorOf = (fn) => { try { fn(); return null } catch (e) { if (e instanceof PocketError) return e.code; throw e } }
const lockSummary = (st) => ({
  acct: st.acct, seq: st.seq, head: st.head, genesis: st.genesis,
  devices: Object.fromEntries(Object.entries(st.devices).map(([id, d]) => [id, { name: d.name, kind: d.kind, admin: d.admin, addr: d.addr, sas: d.sas, revoked: !!d.revoked }])),
  acl: st.acl, realms: st.realms,
})
const view = (s) => ({ h: b64u(s.h), hText: s.h.toString('utf8'), c: b64u(s.c), s: b64u(s.s) })
const fromView = (v) => ({ h: unb64u(v.h), c: unb64u(v.c), s: unb64u(v.s) })
const flip = (b, i = 0) => { const x = Buffer.from(b); x[i] ^= 1; return x }

function rfc6979SelfTest() {
  // RFC 6979 A.2.5: P-256, SHA-256, message "sample"
  const d = Buffer.from('c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721', 'hex')
  const sig = ecdsaSignDeterministic(d, utf8('sample')).toString('hex')
  const want = 'efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716' + 'f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8'
  if (sig !== want) throw new Error('RFC 6979 self-test failed')
  if (!ecdsaVerify(pubOf(d), utf8('sample'), Buffer.from(sig, 'hex'))) throw new Error('RFC 6979 vector does not verify')
  const t = testScalar('selftest'), [x, y] = pmul(big(t), [GX, GY])
  if (!Buffer.concat([Buffer.from([4]), bytes32(x), bytes32(y)]).equals(pubOf(t))) throw new Error('point arithmetic self-test failed')
  return { d: d.toString('hex'), msg: 'sample', sig }
}

function build() {
  const rfc6979 = rfc6979SelfTest()
  const wl = {}
  for (const [k, f] of [['english', 'bip39-english.txt'], ['chineseSimplified', 'bip39-chinese-simplified.txt']]) {
    const raw = fs.readFileSync(path.join(HERE, 'wordlists', f))
    const words = raw.toString('utf8').split('\n').filter(Boolean)
    if (words.length !== 2048 || new Set(words).size !== 2048) throw new Error(`bad word list ${f}`)
    wl[k] = { file: `wordlists/${f}`, sha256: sha256(raw).toString('hex'), words }
  }
  const D = Object.fromEntries(Object.keys(DEVICE_INFO).map((n) => [n, testDevice(n)]))
  const { phoneA, phoneB, computerC, computerD, evil } = D
  const coord1 = { kid: 'test-c1', priv: testScalar('coord/c1') }, coord2 = { kid: 'test-c2', priv: testScalar('coord/c2') }
  coord1.pub = pubOf(coord1.priv); coord2.pub = pubOf(coord2.priv)
  const KC1 = testBytes('realm/computerC/1', 32), KC2 = testBytes('realm/computerC/2', 32), KD1 = testBytes('realm/computerD/1', 32)

  // ---- lock chain -----------------------------------------------------------------------------------------
  const chain = [], states = []
  let st = emptyLockState(ACCT)
  const push = (by, op) => { const s = statement(st, by, op); st = applyStatement(st, s); chain.push(s); states.push(st) }
  push(phoneA, { type: 'genesis', device: entry(phoneA) })                                                  // 1
  push(phoneA, { type: 'add', device: entry(computerC), sas: true })                                        // 2
  push(computerC, { type: 'realm', realm: computerC.id, epoch: 1, kid: kidOf(KC1), reason: 'init' })        // 3
  push(computerC, { type: 'add', device: entry(phoneB), sas: true })                                        // 4
  push(phoneA, { type: 'add', device: entry(computerD), sas: false })                                       // 5
  push(computerD, { type: 'realm', realm: computerD.id, epoch: 1, kid: kidOf(KD1), reason: 'init' })        // 6
  push(phoneA, { type: 'policy', acl: { phones: { [phoneB.id]: { computers: [computerC.id], control: false } } }, admins: { [phoneB.id]: false } }) // 7
  push(phoneA, { type: 'revoke', device: phoneB.id, reason: 'lost' })                                       // 8
  push(computerC, { type: 'realm', realm: computerC.id, epoch: 2, kid: kidOf(KC2), reason: 'revoke' })      // 9
  const at = (n) => states[n - 1]
  const lockInvalid = []
  const bad = (name, prefix, make, expect) => {
    const base = prefix ? at(prefix) : emptyLockState(ACCT)
    const s = make(base)
    const got = errorOf(() => applyStatement(base, s))
    if (got !== expect) throw new Error(`lock vector ${name}: expected ${expect}, got ${got}`)
    lockInvalid.push({ name, prefix, statement: s, error: expect })
  }
  bad('first statement is not genesis', 0, (b) => statement(b, phoneA, { type: 'add', device: entry(phoneB), sas: true }), 'not-genesis')
  bad('genesis after the first statement', 1, (b) => statement(b, phoneB, { type: 'genesis', device: entry(phoneB) }), 'bad-op')
  bad('statement for another account', 1, (b) => statement(b, phoneA, { type: 'add', device: entry(phoneB), sas: true }, { acct: 'u_other0001' }), 'bad-acct')
  bad('sequence number skips', 2, (b) => statement(b, phoneA, { type: 'add', device: entry(phoneB), sas: true }, { seq: 5 }), 'bad-seq')
  bad('prev does not match head', 2, (b) => statement(b, phoneA, { type: 'add', device: entry(phoneB), sas: true }, { prev: b64u(sha256(utf8('x'))) }), 'bad-prev')
  bad('signature by a different key', 2, (b) => statement(b, phoneA, { type: 'add', device: entry(phoneB), sas: true }, {}, computerC.sigPriv), 'bad-sig')
  bad('signer is not in the lock', 2, (b) => statement(b, evil, { type: 'add', device: entry(phoneB), sas: true }), 'unknown-signer')
  bad('signer was revoked', 8, (b) => statement(b, phoneB, { type: 'add', device: entry(evil), sas: true }), 'revoked-signer')
  bad('non-admin adds a device', 7, (b) => statement(b, phoneB, { type: 'add', device: entry(evil), sas: true }), 'not-admin')
  bad('phone writes a realm epoch for a computer', 3, (b) => statement(b, phoneA, { type: 'realm', realm: computerC.id, epoch: 2, kid: kidOf(KC2), reason: 'rotate' }), 'not-owner')
  bad('realm epoch skips', 3, (b) => statement(b, computerC, { type: 'realm', realm: computerC.id, epoch: 3, kid: kidOf(KC2), reason: 'rotate' }), 'bad-epoch')
  bad('device added twice', 4, (b) => statement(b, phoneA, { type: 'add', device: entry(phoneB), sas: true }), 'dup-device')
  bad('address already in use', 2, (b) => statement(b, phoneA, { type: 'add', device: { ...entry(phoneB), addr: computerC.addr }, sas: true }), 'dup-addr')
  bad('device id does not match its keys', 2, (b) => statement(b, phoneA, { type: 'add', device: { ...entry(phoneB), id: evil.id }, sas: true }), 'bad-device')
  bad('policy names a computer as a phone', 4, (b) => statement(b, phoneA, { type: 'policy', acl: { phones: { [computerC.id]: { computers: '*' } } } }), 'bad-acl')
  bad('revoking the last admin', 1, (b) => statement(b, phoneA, { type: 'revoke', device: phoneA.id }), 'last-admin')
  const reset = statement(emptyLockState(ACCT), computerC, { type: 'genesis', device: entry(computerC), resetOf: { genesis: at(9).genesis, seq: 9, h: at(9).head.h } })
  if (!isResetOf(reset, at(9)) || errorOf(() => validateLog(ACCT, [reset]))) throw new Error('reset vector')

  // ---- ACL ------------------------------------------------------------------------------------------------
  const aclCases = []
  for (const [label, n] of [['after policy (statement 7)', 7], ['final (statement 9)', 9]]) {
    for (const p of [phoneA, phoneB]) for (const c of [computerC, computerD]) aclCases.push({ state: label, prefix: n, phone: p.handle, computer: c.handle, ...access(at(n), p.id, c.id) })
  }
  const aclDocs = []
  const devs4 = Object.fromEntries([phoneA, phoneB, computerC, computerD].map((d) => [d.id, { kind: d.kind, revoked: null }]))
  for (const acl of [
    { phones: {}, computers: {} },
    { phones: { [phoneA.id]: { computers: [computerD.id] } }, computers: {} },
    { phones: {}, computers: { [computerC.id]: { phones: [phoneB.id] } } },
    { phones: { [phoneB.id]: { computers: '*', control: false } }, computers: { [computerD.id]: { phones: '*' } } },
  ]) {
    const s = { devices: devs4, acl }
    aclDocs.push({ acl, results: [phoneA, phoneB].flatMap((p) => [computerC, computerD].map((c) => ({ phone: p.handle, computer: c.handle, ...access(s, p.id, c.id) }))) })
  }

  // ---- keyrings and identifiers ---------------------------------------------------------------------------
  const names = namesKeyOf(KC1)
  const sessions = [['5f1c2a5e-8f2b-4c55-9b7e-6c0d7a2b9e10', 4], ['019a6b2c-7d3e-7f00-8a1b-2c3d4e5f6a7b', 4], ['5f1c2a5e-8f2b-4c55-9b7e-6c0d7a2b9e10', 5]]
  const sas = [phoneB, computerC, computerD].map((d) => {
    const idx = sasIndices(unb64u(at(1).genesis, 32), d.sigPub, d.kxPub)
    return { device: d.handle, genesis: at(1).genesis, sig: d.sig, kx: d.kx, indices: idx, english: idx.map((i) => wl.english.words[i]), chineseSimplified: idx.map((i) => wl.chineseSimplified.words[i]) }
  })

  // ---- seals ----------------------------------------------------------------------------------------------
  const sealCases = ['env', 'obj'].map((label, i) => {
    const ikm = testBytes(`seal/${label}`, 32)
    const h = utf8(JSON.stringify({ v: 1, t: 'test', id: b64u(testBytes(`seal/${label}/id`, 16)), nonce: b64u(testBytes(`seal/${label}/nonce`, 12)) }))
    const pt = utf8(i ? '' : 'hello, pocket')
    return { label, ikm: b64u(ikm), h: b64u(h), hText: h.toString(), key: b64u(sealKey(ikm, label, unb64u(JSON.parse(h).id))), plaintext: b64u(pt), c: b64u(sealWith(ikm, label, h, pt)) }
  })

  // ---- envelopes ------------------------------------------------------------------------------------------
  const kr = (n) => ({ [computerC.id]: n >= 9 ? { 1: KC1, 2: KC2 } : { 1: KC1 }, [computerD.id]: { 1: KD1 } })
  const SEQ0 = T0 * 1024
  const envHeader = (o) => ({ v: 1, t: 'env', id: b64u(testBytes(`env/${o.tag}/id`, 16)), nonce: b64u(testBytes(`env/${o.tag}/nonce`, 12)),
    from: o.from.id, to: o.to === '*' ? '*' : o.to.id, realm: o.realm.id, epoch: o.epoch, seq: o.seq, ts: o.ts, kind: o.kind, ...(o.re ? { re: o.re } : {}),
    lock: { seq: 9, h: at(9).head.h } })
  const cmdPayload = { op: 'dispatch', sessionId: '5f1c2a5e-8f2b-4c55-9b7e-6c0d7a2b9e10', text: '把 README 翻译成英文', dispatchId: 'd_9k2m4x7q' }
  const envValid = [], envInvalid = []
  const keyFor = (realm, epoch) => kr(9)[realm.id][epoch]
  const mk = (o, payload, opts = {}) => makeEnvelope({ sender: opts.signer ?? o.from, header: envHeader(o), payload, key: opts.key ?? keyFor(o.realm, o.epoch), zip: !!opts.zip })
  const ctxOf = (c) => ({ lock: at(c.prefix), self: D[c.self].id, keyring: kr(c.prefix), now: c.now, lastSeq: new Map(Object.entries(c.lastSeq ?? {}).map(([n, v]) => [D[n].id, v])) })
  const cmdO = { tag: 'cmd', from: phoneA, to: computerC, realm: computerC, epoch: 2, seq: SEQ0 + 1, ts: T0 + 1000, kind: 'cmd' }
  const cmd = mk(cmdO, cmdPayload)
  const addEnv = (name, e, ctx, payload) => {
    const r = openEnvelope(e, ctxOf(ctx))
    if (JSON.stringify(r.payload) !== JSON.stringify(payload)) throw new Error(`envelope ${name}`)
    envValid.push({ name, context: ctx, envelope: view(e), payload })
  }
  addEnv('phone -> computer command', cmd, { prefix: 9, self: 'computerC', now: T0 + 3000, lastSeq: { phoneA: SEQ0 } }, cmdPayload)
  const evtPayload = { op: 'notify', kind: 'session_end', sessionId: cmdPayload.sessionId, state: 'done', title: '翻译 README', body: '已完成', agent: 'claude', host: 'MacBook C' }
  const evt = mk({ tag: 'evt', from: computerC, to: '*', realm: computerC, epoch: 2, seq: SEQ0 + 7, ts: T0 + 60000, kind: 'evt' }, evtPayload, { zip: true })
  addEnv('computer -> all phones event (deflate)', evt, { prefix: 9, self: 'phoneA', now: T0 + 61000 }, evtPayload)
  const resPayload = { op: 'result', ok: true, delivered: true, queued: false, sessionId: cmdPayload.sessionId }
  const res = mk({ tag: 'res', from: computerC, to: phoneA, realm: computerC, epoch: 2, seq: SEQ0 + 8, ts: T0 + 3500, kind: 'res', re: envHeader(cmdO).id }, resPayload)
  addEnv('computer -> phone result', res, { prefix: 9, self: 'phoneA', now: T0 + 4000 }, resPayload)
  const rpcPayload = { op: 'search', q: 'README' }
  addEnv('read-only phone may send rpc', mk({ tag: 'rpc-b', from: phoneB, to: computerC, realm: computerC, epoch: 1, seq: SEQ0 + 2, ts: T0 + 1000, kind: 'rpc' }, rpcPayload), { prefix: 7, self: 'computerC', now: T0 + 2000 }, rpcPayload)
  const envBad = (name, e, ctx, expect) => {
    const got = errorOf(() => openEnvelope(e, ctxOf(ctx)))
    if (got !== expect) throw new Error(`envelope vector ${name}: expected ${expect}, got ${got}`)
    envInvalid.push({ name, context: ctx, envelope: view(e), error: expect })
  }
  const okCtx = { prefix: 9, self: 'computerC', now: T0 + 3000, lastSeq: { phoneA: SEQ0 } }
  envBad('ciphertext modified', { ...cmd, c: flip(cmd.c, 3) }, okCtx, 'bad-sig')
  envBad('signature modified', { ...cmd, s: flip(cmd.s, 40) }, okCtx, 'bad-sig')
  envBad('header modified after signing', { ...cmd, h: utf8(cmd.h.toString().replace('"seq":', '"seq": ')) }, okCtx, 'bad-sig')
  envBad('addressed to another computer', mk({ ...cmdO, tag: 'cmd-d', to: computerD, realm: computerD, epoch: 1 }, cmdPayload), okCtx, 'not-for-me')
  envBad('replayed sequence number', cmd, { ...okCtx, lastSeq: { phoneA: SEQ0 + 1 } }, 'replay')
  envBad('command too old', cmd, { ...okCtx, now: T0 + 1000 + CMD_WINDOW_MS + 1 }, 'stale')
  envBad('sender not in the lock', mk({ ...cmdO, tag: 'cmd-evil', from: evil }, cmdPayload), okCtx, 'unknown-sender')
  envBad('sender revoked', mk({ ...cmdO, tag: 'cmd-b', from: phoneB, epoch: 1 }, cmdPayload), okCtx, 'revoked-sender')
  envBad('read-only phone sends a command', mk({ ...cmdO, tag: 'cmd-b7', from: phoneB, epoch: 1 }, cmdPayload), { prefix: 7, self: 'computerC', now: T0 + 3000 }, 'denied')
  envBad('phone sends an event', mk({ tag: 'evt-a', from: phoneA, to: '*', realm: computerC, epoch: 2, seq: SEQ0 + 3, ts: T0, kind: 'evt' }, evtPayload), { prefix: 9, self: 'computerC', now: T0 }, 'denied')
  envBad('unknown epoch', mk({ ...cmdO, tag: 'cmd-e3', epoch: 3 }, cmdPayload, { key: KC2 }), okCtx, 'no-key')
  envBad('encrypted under a key nobody granted', mk({ ...cmdO, tag: 'cmd-wrongkey' }, cmdPayload, { key: testBytes('wrong key', 32) }), okCtx, 'bad-tag')

  // ---- objects --------------------------------------------------------------------------------------------
  const sk = sessionKeyOf(names, sessions[0][0], sessions[0][1])
  const msg = { seq: 7, role: 'assistant', ts: T0 + 120000, blocks: [
    { kind: 'text', text: '翻译好了,截图在下面。' },
    { kind: 'tool', name: 'Write', brief: 'README.en.md', ok: true, ts: T0 + 110000, result: 'File written' },
    { kind: 'attachment', name: 'shot.png', mime: 'image/png', bytes: 5, sha: sha256(utf8('hello')).toString('hex'),
      blob: b64u(testBytes('blob/hello/id', 16)), key: b64u(testBytes('blob/hello/key', 32)) },
  ] }
  const objHeader = (o) => ({ v: 1, t: 'obj', id: b64u(testBytes(`obj/${o.tag}/id`, 16)), nonce: b64u(testBytes(`obj/${o.tag}/nonce`, 12)),
    realm: computerC.id, kind: o.kind, key: o.key, ...(o.seq ? { seq: o.seq } : {}), ver: o.ver, epoch: 2, by: (o.by ?? computerC).id, ts: T0 + 120000 })
  const msgObj = makeObject({ owner: computerC, header: objHeader({ tag: 'msg', kind: 'msg', key: sk, seq: 7, ver: 5 }), plaintext: msg, key: KC2, zip: true })
  const sessVal = { id: sessions[0][0], xv: 4, title: '翻译 README', agent: 'claude', host: 'MacBook C', state: 'done', lastSeq: 7, msgCount: 7, updatedAt: T0 + 120000, terminal: true, prompt: null }
  const sessObj = makeObject({ owner: computerC, header: objHeader({ tag: 'sess', kind: 'sess', key: sk, ver: 9 }), plaintext: sessVal, key: KC2 })
  const objValid = [], objInvalid = []
  const octx = (o) => ({ lock: at(o.prefix ?? 9), keyring: kr(9), expect: { realm: computerC.id, ...o.expect }, minVer: o.minVer })
  for (const [name, ob, c, value] of [['message object (deflate)', msgObj, { expect: { kind: 'msg', key: sk, seq: 7 } }, msg], ['session object', sessObj, { expect: { kind: 'sess', key: sk } }, sessVal]]) {
    if (JSON.stringify(openObject(ob, octx(c)).value) !== JSON.stringify(value)) throw new Error(`object ${name}`)
    objValid.push({ name, context: c, object: view(ob), value })
  }
  const objBad = (name, ob, c, expect) => {
    const got = errorOf(() => openObject(ob, octx(c)))
    if (got !== expect) throw new Error(`object vector ${name}: expected ${expect}, got ${got}`)
    objInvalid.push({ name, context: c, object: view(ob), error: expect })
  }
  const mctx = { expect: { kind: 'msg', key: sk, seq: 7 } }
  objBad('served under a different sequence number', msgObj, { expect: { kind: 'msg', key: sk, seq: 8 } }, 'wrong-object')
  objBad('older version than one already seen', msgObj, { ...mctx, minVer: 6 }, 'rollback')
  objBad('ciphertext modified', { ...msgObj, c: flip(msgObj.c, 10) }, mctx, 'bad-sig')
  objBad('written by a phone', makeObject({ owner: phoneA, header: objHeader({ tag: 'msg-a', kind: 'msg', key: sk, seq: 7, ver: 6, by: phoneA }), plaintext: msg, key: KC2 }), mctx, 'not-owner')
  objBad('inflates beyond the limit', makeObject({ owner: computerC, header: { ...objHeader({ tag: 'bomb', kind: 'lite', key: sk, seq: 7, ver: 1 }), zip: 'deflate' }, plaintext: deflate(Buffer.alloc(OBJ_KINDS.lite.max + 1, 0x20)), key: KC2 }), { expect: { kind: 'lite', key: sk, seq: 7 } }, 'too-large')

  // ---- grants ---------------------------------------------------------------------------------------------
  const grantValid = [], grantInvalid = []
  const g = (o) => makeGrant({ granter: o.by, ephPriv: testScalar(`grant/${o.tag}/eph`), recipient: o.to, realm: o.realm.id, keys: o.keys,
    id: testBytes(`grant/${o.tag}/id`, 16), nonce: testBytes(`grant/${o.tag}/nonce`, 12), ts: T0 + 600000 })
  const gctx = (prefix, who) => ({ lock: at(prefix), self: { id: D[who].id, kx: D[who].kx, kxPriv: D[who].kxPriv } })
  const g1 = g({ tag: 'c-to-a', by: computerC, to: phoneA, realm: computerC, keys: [{ epoch: 1, key: KC1 }, { epoch: 2, key: KC2 }] })
  const g2 = g({ tag: 'a-to-b', by: phoneA, to: phoneB, realm: computerC, keys: [{ epoch: 1, key: KC1 }] })
  for (const [name, gr, prefix, who, keys] of [['computer grants its keyring to a phone', g1, 9, 'phoneA', [KC1, KC2]], ['admin phone re-grants a realm key it holds', g2, 5, 'phoneB', [KC1]]]) {
    const r = openGrant(gr, gctx(prefix, who))
    if (keys.some((k, i) => !r.keys[i + 1].equals(k))) throw new Error(`grant ${name}`)
    grantValid.push({ name, context: { prefix, self: who }, grant: view(gr), ephPriv: b64u(testScalar(`grant/${name === 'computer grants its keyring to a phone' ? 'c-to-a' : 'a-to-b'}/eph`)), keys: Object.fromEntries(keys.map((k, i) => [i + 1, b64u(k)])) })
  }
  const grantBad = (name, gr, prefix, who, expect) => {
    const got = errorOf(() => openGrant(gr, gctx(prefix, who)))
    if (got !== expect) throw new Error(`grant vector ${name}: expected ${expect}, got ${got}`)
    grantInvalid.push({ name, context: { prefix, self: who }, grant: view(gr), error: expect })
  }
  grantBad('key does not match the lock commitment', g({ tag: 'badkid', by: computerC, to: phoneA, realm: computerC, keys: [{ epoch: 1, key: testBytes('not the realm key', 32) }] }), 9, 'phoneA', 'bad-kid')
  grantBad('non-admin phone grants', g({ tag: 'b-to-a', by: phoneB, to: phoneA, realm: computerC, keys: [{ epoch: 1, key: KC1 }] }), 7, 'phoneA', 'denied')
  grantBad('opened by the wrong device', g1, 9, 'computerD', 'not-for-me')
  grantBad('ciphertext modified', { ...g1, c: flip(g1.c, 5) }, 9, 'phoneA', 'bad-sig')

  // ---- blobs ----------------------------------------------------------------------------------------------
  const blobValid = [], blobInvalid = []
  for (const [name, pt] of [['empty', Buffer.alloc(0)], ['hello', utf8('hello')], ['one full chunk', pattern(65536)], ['one chunk and one byte', pattern(65537)], ['four chunks', pattern(200000)]]) {
    const fk = testBytes(`blob/${name}/key`, 32), id = testBytes(`blob/${name}/id`, 16), ct = encryptBlob(fk, id, pt)
    if (!decryptBlob(fk, id, ct).equals(pt)) throw new Error(`blob ${name}`)
    blobValid.push({ name, fileKey: b64u(fk), blobId: b64u(id), blobKey: b64u(blobKeyOf(fk, id)),
      plaintext: pt.length <= 64 ? { b64u: b64u(pt) } : { pattern: 'byte i = i mod 251', length: pt.length },
      plaintextSha256: sha256(pt).toString('hex'), ciphertextLength: ct.length, ciphertextSha256: sha256(ct).toString('hex'),
      ...(ct.length <= 256 ? { ciphertext: b64u(ct) } : { ciphertextHead: b64u(ct.subarray(0, 64)), ciphertextTail: b64u(ct.subarray(-64)) }) })
  }
  {
    const fk = testBytes('blob/four chunks/key', 32), id = testBytes('blob/four chunks/id', 16), ct = encryptBlob(fk, id, pattern(200000)), F = BLOB_CHUNK + 16
    const chunks = [0, 1, 2, 3].map((i) => ct.subarray(22 + i * F, 22 + (i + 1) * F))
    for (const [name, mutate, expect] of [
      ['last chunk dropped', (b) => b.subarray(0, 22 + 3 * F), 'bad-tag'],
      ['cut in the middle of a chunk', (b) => b.subarray(0, 22 + F + 1000), 'bad-tag'],
      ['chunks 1 and 2 swapped', () => Buffer.concat([ct.subarray(0, 22), chunks[0], chunks[2], chunks[1], chunks[3]]), 'bad-tag'],
      ['extra bytes appended', (b) => Buffer.concat([b, Buffer.alloc(16)]), 'bad-tag'],
      ['header names another blob', (b) => flip(b, 10), 'bad-blob'],
    ]) {
      const bad = mutate(ct), got = errorOf(() => decryptBlob(fk, id, bad))
      if (got !== expect) throw new Error(`blob vector ${name}: expected ${expect}, got ${got}`)
      blobInvalid.push({ name, of: 'four chunks', ciphertextLength: bad.length, ciphertextSha256: sha256(bad).toString('hex'), error: expect })
    }
  }

  // ---- coordination documents, tickets, proofs -------------------------------------------------------------
  const keyRec = (k, nbf, exp) => ({ kid: k.kid, pub: b64u(k.pub), use: ['keys', 'ticket', 'netmap', 'revocations', 'purge'], nbf, exp })
  const keys1 = [keyRec(coord1, T0 - 30 * 24 * HOUR, T0 + 365 * 24 * HOUR)]
  const keysDocPayload = { v: 1, t: 'keys', at: T0, keys: [...keys1, keyRec(coord2, T0, T0 + 730 * 24 * HOUR)] }
  const keysDoc = (() => { const s = makeSigned('keys', coord1.priv, keysDocPayload); return { p: s.p, sigs: [{ kid: coord1.kid, s: s.s }] } })()
  const allKeys = verifyKeysDoc(keysDoc, keys1, T0)
  const ticketPayload = { v: 1, t: 'ticket', kid: 'test-c2', iss: 'pocket.pocketcli.net', aud: 'hk1', acct: ACCT, dev: phoneA.id, addr: phoneA.addr, kind: 'phone',
    sig: phoneA.sig, peers: [computerC.addr, computerD.addr], iat: T0, exp: T0 + 6 * HOUR, quota: { dayMB: 200, monthMB: 2048 } }
  const ticket = ticketOf(makeSigned('ticket', coord2.priv, ticketPayload))
  verifyTicket(ticket, { keys: allKeys, aud: 'hk1', now: T0 + HOUR, acct: '*' })
  const ticketInvalid = []
  const tBad = (name, t, opts, expect) => {
    const got = errorOf(() => verifyTicket(t, { keys: allKeys, aud: 'hk1', now: T0 + HOUR, acct: '*', ...opts }))
    if (got !== expect) throw new Error(`ticket vector ${name}: expected ${expect}, got ${got}`)
    ticketInvalid.push({ name, ticket: t, options: opts, error: expect })
  }
  tBad('expired', ticket, { now: T0 + 6 * HOUR + SKEW_MS + 1 }, 'expired')
  tBad('for another relay', ticket, { aud: 'r_selfhosted1' }, 'wrong-aud')
  tBad('self-hosted relay bound to another account', ticket, { acct: 'u_other0001' }, 'wrong-account')
  tBad('payload modified', ticketOf({ p: b64u(utf8(JSON.stringify({ ...ticketPayload, peers: [...ticketPayload.peers, evil.addr] }))), s: ticket.split('.')[1] }), {}, 'bad-sig')
  tBad('unknown key id', ticketOf(makeSigned('ticket', coord2.priv, { ...ticketPayload, kid: 'test-c9' })), {}, 'unknown-key')
  tBad('lifetime over 24 hours', ticketOf(makeSigned('ticket', coord2.priv, { ...ticketPayload, exp: T0 + 25 * HOUR })), {}, 'bad-ticket')

  const nonce = b64u(testBytes('relay/nonce', 16))
  const auth = makeProof('relay-auth', phoneA.sigPriv, { relay: 'hk1', nonce, th: b64u(sha256(utf8(ticket))), ts: T0 + HOUR })
  const rctx = { keys: allKeys, relayId: 'hk1', acct: '*', nonce, now: T0 + HOUR + 2000 }
  verifyRelayAuth({ ticket, ...auth }, rctx)
  const relayAuthInvalid = []
  const raBad = (name, msg, c, expect) => {
    const got = errorOf(() => verifyRelayAuth(msg, { ...rctx, ...c }))
    if (got !== expect) throw new Error(`relay-auth vector ${name}: expected ${expect}, got ${got}`)
    relayAuthInvalid.push({ name, message: msg, context: c, error: expect })
  }
  raBad('answers an old challenge', { ticket, ...auth }, { nonce: b64u(testBytes('relay/other nonce', 16)) }, 'bad-nonce')
  raBad('stolen ticket, attacker key', { ticket, ...makeProof('relay-auth', evil.sigPriv, { relay: 'hk1', nonce, th: b64u(sha256(utf8(ticket))), ts: T0 + HOUR }) }, {}, 'bad-sig')
  raBad('proof made for another relay', { ticket, ...makeProof('relay-auth', phoneA.sigPriv, { relay: 'r_selfhosted1', nonce, th: b64u(sha256(utf8(ticket))), ts: T0 + HOUR }) }, {}, 'bad-proof')

  const asrTicket = ticketOf(makeSigned('ticket', coord2.priv, { ...ticketPayload, aud: 'asr:official', peers: [], quota: undefined }))
  const audio = pattern(3200)
  const asrProof = makeProof('asr-auth', phoneA.sigPriv, { aud: 'asr:official', ts: T0 + HOUR, nonce: b64u(testBytes('asr/nonce', 16)), bodySha: b64u(sha256(audio)) })
  const actx = { keys: allKeys, aud: 'asr:official', now: T0 + HOUR + 500 }
  verifyAsrAuth({ ticket: asrTicket, ...asrProof, body: audio }, actx)
  const asrBadBody = errorOf(() => verifyAsrAuth({ ticket: asrTicket, ...asrProof, body: pattern(3201) }, actx))
  if (asrBadBody !== 'body-mismatch') throw new Error('asr vector')

  const enrollToken = 'test-user-token-0001'
  const enrollFields = { th: b64u(sha256(utf8(enrollToken))), sig: phoneA.sig, kx: phoneA.kx, ts: T0 + HOUR }
  const enrollProof = makeProof('enroll-auth', phoneA.sigPriv, enrollFields)
  const ectxE = { token: enrollToken, sig: phoneA.sig, kx: phoneA.kx, now: T0 + HOUR + 1500 }
  verifyEnrollAuth(enrollProof, ectxE)
  const enrollAuthInvalid = []
  const eaBad = (name, msg, c, expect) => {
    const got = errorOf(() => verifyEnrollAuth(msg, { ...ectxE, ...c }))
    if (got !== expect) throw new Error(`enroll-auth vector ${name}: expected ${expect}, got ${got}`)
    enrollAuthInvalid.push({ name, message: msg, context: c, error: expect })
  }
  eaBad("someone else's public keys, signed with the attacker's key", makeProof('enroll-auth', evil.sigPriv, enrollFields), {}, 'bad-sig')
  eaBad('the same proof presented with another login token', enrollProof, { token: 'test-user-token-0002' }, 'bad-proof')
  eaBad('proof made for other keys', enrollProof, { sig: phoneB.sig, kx: phoneB.kx }, 'bad-proof')
  eaBad('older than five minutes', enrollProof, { now: T0 + HOUR + SKEW_MS + 1 }, 'stale')
  eaBad('a relay proof offered as an enrollment proof', makeProof('relay-auth', phoneA.sigPriv, enrollFields), {}, 'bad-proof')
  eaBad('enroll-auth payload signed under another label', (() => { const ab = utf8(JSON.stringify({ v: 1, t: 'enroll-auth', ...enrollFields })); return { a: b64u(ab), s: b64u(sign(phoneA.sigPriv, sigInput('relay-auth', ab))) } })(), {}, 'bad-sig')

  const netmapPayload = { v: 1, t: 'netmap', kid: 'test-c2', acct: ACCT, at: T0 + HOUR, ver: 42, self: phoneA.id,
    lock: { seq: 9, h: at(9).head.h, genesis: at(9).genesis },
    devices: [phoneA, computerC, computerD].map((d) => ({ id: d.id, addr: d.addr, kind: d.kind, platform: d.platform, name: d.name, sig: d.sig, kx: d.kx, status: 'active', online: d !== computerD, lastSeen: T0 + HOUR })),
    relay: { id: 'hk1', url: 'https://pocket.pocketcli.net/relay', region: 'hk', kind: 'official' },
    relays: [{ id: 'hk1', url: 'https://pocket.pocketcli.net/relay', region: 'hk', kind: 'official', state: 'verified' }],
    prefs: { listDays: 2 }, lang: 'zh', asr: { official: { url: 'https://pocket.pocketcli.net/asr', aud: 'asr:official' } } }
  const netmap = makeSigned('netmap', coord2.priv, netmapPayload)
  verifyCoordDoc('netmap', netmap, allKeys, T0 + HOUR)
  const revPayload = { v: 1, t: 'revocations', kid: 'test-c2', at: T0 + 2 * HOUR, acct: ACCT, since: 0, next: 2,
    items: [{ addr: phoneB.addr, dev: phoneB.id, nbf: Number.MAX_SAFE_INTEGER, gone: true, at: T0 + 2 * HOUR }, { addr: phoneA.addr, dev: phoneA.id, nbf: T0 + 2 * HOUR, at: T0 + 2 * HOUR }] }
  const revocations = makeSigned('revocations', coord2.priv, revPayload)
  verifyCoordDoc('revocations', revocations, allKeys, T0 + 2 * HOUR)
  const purge = makeSigned('purge', coord2.priv, { v: 1, t: 'purge', kid: 'test-c2', acct: ACCT, at: T0 + 3 * HOUR, relay: 'hk1' })
  verifyCoordDoc('purge', purge, allKeys, T0 + 3 * HOUR)
  const wrongLabel = errorOf(() => verifyCoordDoc('purge', { p: netmap.p, s: netmap.s }, allKeys, T0 + HOUR))
  if (wrongLabel !== 'bad-format') throw new Error('label confusion vector')

  // ---- assemble -------------------------------------------------------------------------------------------
  const seal1 = fromView(objValid[1].object)
  return {
    about: {
      spec: 'docs/protocol/E2EE.md (protocol v1)',
      generator: 'docs/protocol/gen-vectors.mjs (node gen-vectors.mjs --check must pass)',
      encoding: 'All byte strings are base64url without padding unless the field name says hex. *Text fields are the same bytes shown as UTF-8 for reading; the base64url field is normative.',
      signatures: 'ECDSA signatures here are deterministic (RFC 6979) so this file is reproducible. Implementations may sign with randomized ECDSA; they must verify these.',
      contexts: '`prefix` = how many statements of lock.chain to apply to get the lock state; device names refer to `devices`.',
      testOnly: 'All private keys below are public test material.',
      now: T0,
      account: ACCT,
    },
    wordlists: { english: { file: wl.english.file, sha256: wl.english.sha256 }, chineseSimplified: { file: wl.chineseSimplified.file, sha256: wl.chineseSimplified.sha256 } },
    encoding: {
      b64u: [[''], ['00'], ['ff'], ['0000'], ['fbff'], ['000102'], ['48656c6c6f']].map(([hex]) => ({ hex, b64u: b64u(Buffer.from(hex, 'hex')) })),
      b64uInvalid: ['AA==', 'A', 'AB', '+/8', 'AA\n', 'AAA ', 'AB=='].filter((s) => errorOf(() => unb64u(s)) === 'bad-b64u'),
      sigInput: { label: 'env', h: b64u(utf8('{}')), c: b64u(Buffer.from([1, 2])), bytesHex: sigInput('env', utf8('{}'), Buffer.from([1, 2])).toString('hex') },
      sealJson: view(seal1),
      sealBinaryHex: sealToBin(seal1).toString('hex'),
      sealStreamOfTwoHex: Buffer.concat([sealToBin(seal1), sealToBin(seal1)]).toString('hex'),
    },
    hkdf: [
      { name: 'RFC 5869 A.1', ikm: b64u(Buffer.alloc(22, 0x0b)), salt: b64u(Buffer.from('000102030405060708090a0b0c', 'hex')), info: b64u(Buffer.from('f0f1f2f3f4f5f6f7f8f9', 'hex')), length: 42,
        okmHex: hkdf256(Buffer.alloc(22, 0x0b), Buffer.from('000102030405060708090a0b0c', 'hex'), Buffer.from('f0f1f2f3f4f5f6f7f8f9', 'hex'), 42).toString('hex') },
      { name: 'pocket names key (empty salt)', ikm: b64u(KC1), salt: '', info: b64u(utf8(PFX + 'names')), length: 32, okmHex: names.toString('hex') },
    ],
    ecdsa: {
      rfc6979: { ...rfc6979, note: 'RFC 6979 A.2.5 (P-256, SHA-256, "sample"); hex; the generator refuses to run if it does not reproduce this' },
      invalidSignatures: [
        { name: 'r = 0', sig: b64u(Buffer.concat([Buffer.alloc(32), bytes32(1n)])) },
        { name: 's = n', sig: b64u(Buffer.concat([bytes32(1n), bytes32(N)])) },
        { name: 'DER-encoded instead of raw', sig: b64u(Buffer.from('3006020101020101', 'hex')) },
      ].map((x) => ({ ...x, pub: phoneA.sig, message: b64u(utf8('anything')), valid: false })),
      invalidPublicKeys: [
        { name: 'compressed point', pub: b64u(Buffer.concat([Buffer.from([2]), phoneA.sigPub.subarray(1, 33)])) },
        { name: 'not on the curve', pub: b64u(Buffer.concat([phoneA.sigPub.subarray(0, 64), Buffer.from([phoneA.sigPub[64] ^ 1])])) },
        { name: 'x >= p', pub: b64u(Buffer.concat([Buffer.from([4]), bytes32(P), phoneA.sigPub.subarray(33)])) },
      ].filter((x) => errorOf(() => checkPub(unb64u(x.pub))) === 'bad-key'),
    },
    devices: Object.fromEntries(Object.values(D).map((d) => [d.handle, { id: d.id, kind: d.kind, platform: d.platform, name: d.name, addr: d.addr,
      sigPriv: b64u(d.sigPriv), sig: d.sig, kxPriv: b64u(d.kxPriv), kx: d.kx }])),
    ecdh: [[phoneA, computerC], [computerC, phoneA], [phoneB, computerD]].map(([a, b]) => ({ priv: a.handle + '.kxPriv', pub: b.handle + '.kx', shared: b64u(ecdh(a.kxPriv, b.kxPub)) })),
    realmKeys: { computerC: { 1: b64u(KC1), 2: b64u(KC2) }, computerD: { 1: b64u(KD1) } },
    kid: [KC1, KC2, KD1].map((k) => ({ key: b64u(k), kid: kidOf(k) })),
    names: { realm: 'computerC', epoch1Key: b64u(KC1), namesKey: b64u(names), sessions: sessions.map(([id, xv]) => ({ sessionId: id, xv, sk: sessionKeyOf(names, id, xv) })) },
    sas,
    seal: sealCases,
    lock: {
      account: ACCT,
      chain,
      chainText: chain.map((s) => unb64u(s.p).toString('utf8')),
      states: states.map(lockSummary),
      invalid: lockInvalid,
      reset: { statement: reset, resetsGenesis: at(9).genesis, newGenesis: b64u(sha256(unb64u(reset.p))) },
    },
    acl: { fromChain: aclCases, documents: aclDocs },
    envelope: { valid: envValid, invalid: envInvalid },
    object: { valid: objValid, invalid: objInvalid },
    grant: { valid: grantValid, invalid: grantInvalid },
    blob: { valid: blobValid, invalid: blobInvalid },
    coord: {
      keys: { private: { [coord1.kid]: b64u(coord1.priv), [coord2.kid]: b64u(coord2.priv) }, pinned: keys1, document: keysDoc, documentText: unb64u(keysDoc.p).toString('utf8') },
      ticket: { valid: { ticket, payload: ticketPayload, aud: 'hk1', now: T0 + HOUR }, invalid: ticketInvalid },
      relayAuth: { valid: { message: { ticket, ...auth }, context: { relayId: 'hk1', acct: '*', nonce, now: rctx.now } }, invalid: relayAuthInvalid },
      asrAuth: { ticket: asrTicket, proof: asrProof, body: { pattern: 'byte i = i mod 251', length: 3200 }, now: actx.now, aud: 'asr:official', badBodyLength: 3201, badBodyError: 'body-mismatch' },
      enrollAuth: { valid: { message: enrollProof, context: ectxE, fields: enrollFields }, invalid: enrollAuthInvalid },
      netmap: { doc: netmap, payload: netmapPayload },
      revocations: { doc: revocations, payload: revPayload },
      purge: { doc: purge, payload: parseJson(unb64u(purge.p)) },
      labelConfusion: { note: 'a netmap document checked as a purge order must fail', error: 'bad-format' },
    },
  }
}

// ============================================================================================================
// 11. --check: independent re-verification of the stored file
// ============================================================================================================
function check(v) {
  let n = 0
  const ok = (cond, what) => { if (!cond) throw new Error(`check failed: ${what}`); n++ }
  const dev = (name) => v.devices[name]
  const ids = Object.fromEntries(Object.entries(v.devices).map(([k, d]) => [k, d.id]))
  // keys and identifiers
  for (const d of Object.values(v.devices)) {
    ok(pubOf(unb64u(d.sigPriv, 32)).equals(unb64u(d.sig, 65)) && pubOf(unb64u(d.kxPriv, 32)).equals(unb64u(d.kx, 65)), `keys of ${d.name}`)
    ok(didOf(unb64u(d.sig), unb64u(d.kx)) === d.id, `did of ${d.name}`)
  }
  for (const x of v.ecdh) ok(ecdh(unb64u(dev(x.priv.split('.')[0]).kxPriv), unb64u(dev(x.pub.split('.')[0]).kx)).equals(unb64u(x.shared)), 'ecdh')
  for (const x of v.ecdsa.invalidSignatures) ok(!ecdsaVerify(unb64u(x.pub), unb64u(x.message), unb64u(x.sig)), x.name)
  ok(ecdsaVerify(pubOf(Buffer.from(v.ecdsa.rfc6979.d, 'hex')), utf8('sample'), Buffer.from(v.ecdsa.rfc6979.sig, 'hex')), 'rfc6979 verifies')
  // every stored lock statement must verify with Node's verifier and rebuild the stored states
  let st = emptyLockState(v.lock.account)
  v.lock.chain.forEach((s, i) => { st = applyStatement(st, s); ok(JSON.stringify(lockSummary(st)) === JSON.stringify(v.lock.states[i]), `lock state ${i + 1}`) })
  const states = v.lock.chain.reduce((acc, s) => [...acc, applyStatement(acc.at(-1) ?? emptyLockState(v.lock.account), s)], [])
  const at = (k) => (k ? states[k - 1] : emptyLockState(v.lock.account))
  for (const b of v.lock.invalid) ok(errorOf(() => applyStatement(at(b.prefix), b.statement)) === b.error, `lock: ${b.name}`)
  ok(errorOf(() => validateLog(v.lock.account, [v.lock.reset.statement])) === null && isResetOf(v.lock.reset.statement, at(9)), 'lock reset')
  for (const c of v.acl.fromChain) { const a = access(at(c.prefix), ids[c.phone], ids[c.computer]); ok(a.read === c.read && a.control === c.control, `acl ${c.phone}/${c.computer}`) }
  // envelopes / objects / grants with stored bytes
  const keyring = (prefix) => ({ [ids.computerC]: prefix >= 9 ? { 1: unb64u(v.realmKeys.computerC[1]), 2: unb64u(v.realmKeys.computerC[2]) } : { 1: unb64u(v.realmKeys.computerC[1]) }, [ids.computerD]: { 1: unb64u(v.realmKeys.computerD[1]) } })
  const ectx = (c) => ({ lock: at(c.prefix), self: ids[c.self], keyring: keyring(c.prefix), now: c.now, lastSeq: new Map(Object.entries(c.lastSeq ?? {}).map(([k, s]) => [ids[k], s])) })
  for (const e of v.envelope.valid) ok(JSON.stringify(openEnvelope(fromView(e.envelope), ectx(e.context)).payload) === JSON.stringify(e.payload), `envelope: ${e.name}`)
  for (const e of v.envelope.invalid) ok(errorOf(() => openEnvelope(fromView(e.envelope), ectx(e.context))) === e.error, `envelope: ${e.name}`)
  const octx = (c) => ({ lock: at(c.prefix ?? 9), keyring: keyring(9), expect: { realm: ids.computerC, ...c.expect }, minVer: c.minVer })
  for (const o of v.object.valid) ok(JSON.stringify(openObject(fromView(o.object), octx(o.context)).value) === JSON.stringify(o.value), `object: ${o.name}`)
  for (const o of v.object.invalid) ok(errorOf(() => openObject(fromView(o.object), octx(o.context))) === o.error, `object: ${o.name}`)
  const gself = (c) => ({ lock: at(c.prefix), self: { id: ids[c.self], kx: dev(c.self).kx, kxPriv: unb64u(dev(c.self).kxPriv) } })
  for (const x of v.grant.valid) { const r = openGrant(fromView(x.grant), gself(x.context)); ok(Object.entries(x.keys).every(([e, k]) => r.keys[e].equals(unb64u(k))), `grant: ${x.name}`) }
  for (const x of v.grant.invalid) ok(errorOf(() => openGrant(fromView(x.grant), gself(x.context))) === x.error, `grant: ${x.name}`)
  // coordination documents
  const keys = verifyKeysDoc(v.coord.keys.document, v.coord.keys.pinned, v.about.now)
  const t = v.coord.ticket
  ok(verifyTicket(t.valid.ticket, { keys, aud: t.valid.aud, now: t.valid.now, acct: '*' }).dev === ids.phoneA, 'ticket')
  for (const x of t.invalid) ok(errorOf(() => verifyTicket(x.ticket, { keys, aud: 'hk1', now: t.valid.now, acct: '*', ...x.options })) === x.error, `ticket: ${x.name}`)
  const ra = v.coord.relayAuth
  ok(verifyRelayAuth(ra.valid.message, { keys, ...ra.valid.context }).addr === dev('phoneA').addr, 'relay auth')
  for (const x of ra.invalid) ok(errorOf(() => verifyRelayAuth(x.message, { keys, ...ra.valid.context, ...x.context })) === x.error, `relay auth: ${x.name}`)
  const asr = v.coord.asrAuth
  ok(verifyAsrAuth({ ticket: asr.ticket, ...asr.proof, body: pattern(asr.body.length) }, { keys, aud: asr.aud, now: asr.now }).ticket.dev === ids.phoneA, 'asr auth')
  ok(errorOf(() => verifyAsrAuth({ ticket: asr.ticket, ...asr.proof, body: pattern(asr.badBodyLength) }, { keys, aud: asr.aud, now: asr.now })) === asr.badBodyError, 'asr auth body')
  const ea = v.coord.enrollAuth
  ok(verifyEnrollAuth(ea.valid.message, ea.valid.context).sig === dev('phoneA').sig, 'enroll auth')
  for (const x of ea.invalid) ok(errorOf(() => verifyEnrollAuth(x.message, { ...ea.valid.context, ...x.context })) === x.error, `enroll auth: ${x.name}`)
  for (const [label, x, when] of [['netmap', v.coord.netmap, v.coord.netmap.payload.at], ['revocations', v.coord.revocations, v.coord.revocations.payload.at], ['purge', v.coord.purge, v.coord.purge.payload.at]]) ok(verifyCoordDoc(label, x.doc, keys, when).t === label, label)
  ok(errorOf(() => verifyCoordDoc('purge', v.coord.netmap.doc, keys, v.about.now)) === 'bad-format', 'label confusion')
  return n
}

// ============================================================================================================
// main
// ============================================================================================================
function main() {
  SIGNER = ecdsaSignDeterministic
  const text = JSON.stringify(build(), null, 2) + '\n'
  if (process.argv.includes('--check')) {
    const stored = fs.readFileSync(VECTORS_FILE, 'utf8')
    if (stored !== text) { console.error('vectors.json differs from what this generator produces now (run without --check to rewrite it)'); process.exit(1) }
    SIGNER = ecdsaSign                       // from here on nothing is signed; verification uses Node's ECDSA
    const n = check(JSON.parse(stored))
    console.log(`vectors.json OK: byte-identical rebuild, ${n} independent checks passed`)
  } else {
    fs.writeFileSync(VECTORS_FILE, text)
    console.log(`wrote ${path.relative(process.cwd(), VECTORS_FILE)} (${text.length} bytes)`)
  }
}
if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) main()
