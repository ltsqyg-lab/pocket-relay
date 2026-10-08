// The relay's own crypto against the shared vectors (docs/protocol/vectors.json): every valid case passes,
// every invalid case fails with the expected error code.
import test from 'node:test'
import crypto from 'node:crypto'
import assert from 'node:assert/strict'
import { vectors as v } from './helpers.mjs'
import * as P from '../src/proto.mjs'

const codeOf = (fn) => { try { fn(); return null } catch (e) { if (e instanceof P.RelayError) return e.code; throw e } }
const hex = (s) => Buffer.from(s, 'hex')

test('base64url: canonical round trips and strict rejections', () => {
  for (const x of v.encoding.b64u) {
    assert.equal(P.b64u(hex(x.hex)), x.b64u)
    assert.deepEqual(P.unb64u(x.b64u), hex(x.hex))
  }
  for (const s of v.encoding.b64uInvalid) assert.equal(codeOf(() => P.unb64u(s)), 'bad-b64u', JSON.stringify(s))
})

test('SigInput bytes', () => {
  const x = v.encoding.sigInput
  assert.equal(P.sigInput(x.label, P.unb64u(x.h), P.unb64u(x.c)).toString('hex'), x.bytesHex)
})

test('seal encodings: JSON, binary and a stream of two describe the same bytes', () => {
  const j = v.encoding.sealJson
  const bin = hex(v.encoding.sealBinaryHex)
  const s = P.parseSealBin(bin)
  assert.equal(P.b64u(s.h), j.h)
  assert.equal(P.b64u(s.c), j.c)
  assert.equal(P.b64u(s.s), j.s)
  assert.deepEqual(P.sealToBin({ h: P.unb64u(j.h), c: P.unb64u(j.c), s: P.unb64u(j.s) }), bin)
  const stream = hex(v.encoding.sealStreamOfTwoHex)
  const a = P.sealAt(stream, 0), b = P.sealAt(stream, a.next)
  assert.equal(b.next, stream.length)
  assert.equal(codeOf(() => P.parseSealBin(stream)), 'bad-seal', 'a stream is not one seal')
  assert.equal(codeOf(() => P.parseSealBin(bin.subarray(0, bin.length - 1))), 'bad-seal', 'truncated')
  const env = P.checkEnvelopeJson({ h: j.h, c: j.c, s: j.s })
  assert.equal(env.cLen, P.unb64u(j.c).length)
})

test('ECDSA: RFC 6979 sample verifies; malformed signatures and public keys are rejected', () => {
  const r = v.ecdsa.rfc6979
  const e = crypto.createECDH('prime256v1'); e.setPrivateKey(hex(r.d))
  const pub = e.getPublicKey()
  assert.ok(P.ecdsaVerify(pub, Buffer.from(r.msg), hex(r.sig)))
  for (const x of v.ecdsa.invalidSignatures) assert.equal(P.ecdsaVerify(P.unb64u(x.pub), P.unb64u(x.message), P.unb64u(x.sig)), false, x.name)
  for (const x of v.ecdsa.invalidPublicKeys) assert.equal(codeOf(() => P.checkPub(Buffer.from(x.pub, 'base64url'))), 'bad-key', x.name)
})

test('coordination keys document, tickets, relay proofs, signed documents', () => {
  const c = v.coord
  const keys = P.verifyKeysDoc(c.keys.document, c.keys.pinned, v.about.now)
  assert.deepEqual(keys.map((k) => k.kid), ['test-c1', 'test-c2'])
  assert.equal(codeOf(() => P.verifyKeysDoc(c.keys.document, [{ ...c.keys.pinned[0], kid: 'other' }], v.about.now)), 'bad-sig', 'unknown signer')
  // tickets
  const T = P.verifyTicket(c.ticket.valid.ticket, { keys, aud: c.ticket.valid.aud, now: c.ticket.valid.now, acct: '*' })
  assert.equal(T.dev, v.devices.phoneA.id)
  for (const x of c.ticket.invalid) {
    assert.equal(codeOf(() => P.verifyTicket(x.ticket, { keys, aud: 'hk1', now: c.ticket.valid.now, acct: '*', ...x.options })), x.error, x.name)
  }
  // relay proofs
  const ra = c.relayAuth
  assert.equal(P.verifyRelayAuth(ra.valid.message, { keys, ...ra.valid.context }).addr, v.devices.phoneA.addr)
  for (const x of ra.invalid) assert.equal(codeOf(() => P.verifyRelayAuth(x.message, { keys, ...ra.valid.context, ...x.context })), x.error, x.name)
  // signed documents under their own label only
  for (const [label, x] of [['netmap', c.netmap], ['revocations', c.revocations], ['purge', c.purge]]) {
    assert.equal(P.verifyCoordDoc(label, x.doc, keys, x.payload.at).t, label)
  }
  assert.equal(codeOf(() => P.verifyCoordDoc('purge', c.netmap.doc, keys, v.about.now)), c.labelConfusion.error)
  assert.equal(codeOf(() => P.verifyCoordDoc('revocations', c.purge.doc, keys, v.about.now)), 'bad-format')
  // a key used outside its validity window or for a label it may not sign
  const narrow = keys.map((k) => ({ ...k, use: ['keys'] }))
  assert.equal(codeOf(() => P.verifyTicket(c.ticket.valid.ticket, { keys: narrow, aud: 'hk1', now: c.ticket.valid.now, acct: '*' })), 'key-not-valid')
})

test('blob framing: valid stream sizes and headers; a header naming another blob', () => {
  for (const b of v.blob.valid) {
    assert.ok(P.blobBytesValid(b.ciphertextLength), `${b.name}: ${b.ciphertextLength}`)
    if (b.ciphertext) assert.ok(P.checkBlobHeader(P.unb64u(b.ciphertext).subarray(0, 22), P.unb64u(b.blobId)), b.name)
    assert.equal(P.blobSizeFor(Buffer.from(b.plaintext?.b64u ?? '', 'base64url').length || b.plaintextLength || 0) > 0, true)
  }
  const one = v.blob.valid.find((b) => b.ciphertext)
  const other = Buffer.alloc(16, 7)
  assert.equal(P.checkBlobHeader(P.unb64u(one.ciphertext).subarray(0, 22), other), false, 'header names another blob')
  for (const n of [0, 1, 65535, 65536, 65537, 200000, 100 * 1024 * 1024]) assert.ok(P.blobBytesValid(P.blobSizeFor(n)), `size for ${n}`)
  for (const bad of [0, 22, 37, 22 + 65552 + 1, 22 + 65552 + 15, P.BLOB_MAX + 1]) assert.equal(P.blobBytesValid(bad), false, `not a PKB1 size: ${bad}`)
})
