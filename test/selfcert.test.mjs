// The self-signed certificate (selfcert.mjs): what is inside, that TLS works with it, pins, files on disk; a cross-check
// with the openssl command line when there is one.
import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import tls from 'node:tls'
import crypto from 'node:crypto'
import { execFileSync } from 'node:child_process'
import { makeSelfSigned, pinOf, ensureSelfSigned, normalizeHost, certIsFor, hostOfCert, isPin, NO_HOST_CN } from '../src/selfcert.mjs'
import { pinnedSocket } from './helpers.mjs'

const DAY = 86_400_000
const made = []
const tmp = () => { const d = fs.mkdtempSync(path.join(os.tmpdir(), 'pocket-relay-test-')); made.push(d); return d }
test.after(() => { for (const d of made) fs.rmSync(d, { recursive: true, force: true }) })
const hasOpenssl = (() => { try { execFileSync('openssl', ['version'], { stdio: 'pipe' }); return true } catch { return false } })()

/** The DER elements of a certificate we care about, read back with a minimal parser (independent of the writer). */
function der(buf) {
  const read = (b, off) => {
    const tag = b[off]
    let len = b[off + 1], hdr = 2
    if (len & 0x80) { const n = len & 0x7f; len = 0; for (let i = 0; i < n; i++) len = len * 256 + b[off + 2 + i]; hdr = 2 + n }
    return { tag, start: off + hdr, end: off + hdr + len, body: b.subarray(off + hdr, off + hdr + len) }
  }
  const kids = (el, b) => { const out = []; for (let o = el.start; o < el.end;) { const k = read(b, o); out.push(k); o = k.end } return out }
  const cert = read(buf, 0)
  const [tbs, alg, sig] = kids(cert, buf)
  return { cert, tbs, alg, sig, tbsKids: kids(tbs, buf), kids: (el) => kids(el, buf) }
}

test('a certificate for an IPv4 address: v3, P-256, ecdsa-with-SHA256, CN and SAN, CA:FALSE, serverAuth, 10 years', () => {
  const t0 = Date.now()
  const m = makeSelfSigned({ host: '203.0.113.7' })
  const x = new crypto.X509Certificate(m.certPem)
  assert.equal(x.subject, 'CN=203.0.113.7')
  assert.equal(x.issuer, x.subject, 'self-issued')
  assert.equal(x.subjectAltName, 'IP Address:203.0.113.7')
  assert.equal(x.ca, false)
  assert.deepEqual(x.keyUsage, ['1.3.6.1.5.5.7.3.1'], 'extended key usage: serverAuth')
  assert.equal(x.publicKey.asymmetricKeyType, 'ec')
  assert.equal(x.publicKey.asymmetricKeyDetails.namedCurve, 'prime256v1')
  assert.ok(x.checkPrivateKey(crypto.createPrivateKey(m.keyPem)), 'key and certificate are a pair')
  assert.ok(x.verify(x.publicKey), 'signed with its own key')
  assert.equal(x.checkIP('203.0.113.7'), '203.0.113.7')
  assert.equal(x.checkIP('203.0.113.8'), undefined)
  // validity: from a day ago, 10 years
  const from = Date.parse(x.validFrom), to = Date.parse(x.validTo)
  assert.ok(Math.abs(from - (t0 - DAY)) < 5000, 'notBefore = now − 1 day')
  assert.ok(Math.abs(to - from - 3650 * DAY) < 1000, 'valid 3650 days')
  // serial: 16 bytes, positive (top bit clear), non-zero first byte
  assert.match(x.serialNumber, /^[0-7][0-9A-F]{31}$/)
  assert.notEqual(x.serialNumber.slice(0, 2), '00')
  // pin = sha256 of the DER, lower-case hex; from PEM, from DER, from the X509Certificate, as Node's fingerprint
  assert.ok(isPin(m.pin))
  assert.equal(m.pin, 'sha256:' + crypto.createHash('sha256').update(x.raw).digest('hex'))
  assert.equal(m.pin, pinOf(m.certPem))
  assert.equal(m.pin, pinOf(x.raw))
  assert.equal(m.pin, pinOf(x))
  assert.equal(m.pin, 'sha256:' + x.fingerprint256.replace(/:/g, '').toLowerCase())
  // the DER itself: version [0] = 2, signature algorithm without parameters, critical basicConstraints / keyUsage
  const d = der(x.raw)
  assert.equal(d.tbsKids[0].tag, 0xa0)
  assert.deepEqual([...d.tbsKids[0].body], [0x02, 0x01, 0x02], 'version v3')
  assert.equal(d.tbsKids[1].body.length, 16, '16-byte serial')
  assert.deepEqual([...d.alg.body], [0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02], 'ecdsa-with-SHA256, no parameters')
  assert.deepEqual(d.tbsKids[2].body, d.alg.body, 'same algorithm inside and outside')
  const exts = d.kids(d.kids(d.tbsKids[7])[0])
  const extIds = exts.map((e) => d.kids(e)[0].body.toString('hex'))
  assert.deepEqual(extIds, ['551d13', '551d0f', '551d25', '551d11'], 'basicConstraints, keyUsage, extKeyUsage, subjectAltName')
  const crit = exts.map((e) => d.kids(e)[1].tag === 0x01)
  assert.deepEqual(crit, [true, true, false, false])
  const ku = d.kids(exts[1])[2].body
  assert.deepEqual([...ku], [0x03, 0x02, 0x07, 0x80], 'keyUsage = digitalSignature only')
  const san = d.kids(exts[3])[1].body
  assert.deepEqual([...san], [0x30, 0x06, 0x87, 0x04, 203, 0, 113, 7], 'SAN iPAddress 203.0.113.7')
})

test('IPv6 and DNS hosts; a certificate without host; far dates use GeneralizedTime', () => {
  for (const host of ['2001:DB8::1', '[2001:db8:0:0:0:0:0:1]']) {
    const x = new crypto.X509Certificate(makeSelfSigned({ host }).certPem)
    assert.equal(x.subject, 'CN=2001:db8::1')
    assert.equal(x.checkIP('2001:db8::1'), '2001:db8::1')
    assert.equal(hostOfCert(x), '2001:db8::1')
    assert.ok(certIsFor(x, '[2001:db8::1]'))
  }
  const v4mapped = new crypto.X509Certificate(makeSelfSigned({ host: '::ffff:198.51.100.4' }).certPem)
  assert.ok(v4mapped.checkIP('::ffff:198.51.100.4'))
  const dns = new crypto.X509Certificate(makeSelfSigned({ host: 'Relay.Example.COM.' }).certPem)
  assert.equal(dns.subject, 'CN=relay.example.com')
  assert.equal(dns.subjectAltName, 'DNS:relay.example.com')
  assert.equal(dns.checkHost('relay.example.com'), 'relay.example.com')
  assert.ok(certIsFor(dns, 'relay.example.com') && !certIsFor(dns, 'other.example.com') && !certIsFor(dns, '203.0.113.7'))
  const idn = new crypto.X509Certificate(makeSelfSigned({ host: '中继.example' }).certPem)
  assert.equal(idn.subjectAltName, 'DNS:xn--fiqv10j.example')
  const none = new crypto.X509Certificate(makeSelfSigned({ host: null }).certPem)
  assert.equal(none.subject, `CN=${NO_HOST_CN}`)
  assert.equal(none.subjectAltName, undefined)
  assert.ok(certIsFor(none, null) && !certIsFor(none, '203.0.113.7'))
  const far = new crypto.X509Certificate(makeSelfSigned({ host: '198.51.100.1', notBefore: Date.UTC(2049, 11, 31), days: 3650 }).certPem)
  assert.equal(new Date(far.validFrom).getUTCFullYear(), 2049, 'UTCTime')
  assert.equal(new Date(far.validTo).getUTCFullYear(), 2059, 'GeneralizedTime from 2050')
  for (const bad of ['', 'fe80::1%en0', 'a b', 'under_score.example', '-x.example', 'x'.repeat(64) + '.example', '1.2.3.4.5', '[::1']) {
    assert.throws(() => normalizeHost(bad), `${bad} is refused`)
  }
  assert.deepEqual(['203.0.113.7', '2001:db8::1', 'relay.example.com'].map((h) => normalizeHost(h).kind), ['ipv4', 'ipv6', 'dns'])
})

test('TLS: a server with it works; a client that checks the pin connects, a wrong pin is refused; Node accepts it as an exact trust anchor', async (t) => {
  const m = makeSelfSigned({ host: '127.0.0.1' })
  const server = tls.createServer({ key: m.keyPem, cert: m.certPem }, (s) => s.end('hello'))
  await new Promise((r) => server.listen(0, '127.0.0.1', r))
  t.after(() => server.close())
  const url = `https://127.0.0.1:${server.address().port}`
  const sock = await pinnedSocket(url, m.pin)
  const got = await new Promise((r) => { let b = ''; sock.on('data', (d) => { b += d }); sock.on('end', () => r(b)) })
  assert.equal(got, 'hello')
  await assert.rejects(pinnedSocket(url, 'sha256:' + '0'.repeat(64)), (e) => e.code === 'PIN_MISMATCH' && e.got === m.pin)
  // without the pin, a normal client refuses it (not from a CA)
  await assert.rejects(new Promise((resolve, reject) => { const c = tls.connect({ host: '127.0.0.1', port: server.address().port }, resolve); c.on('error', reject) }),
    (e) => /self.signed|unable to verify|DEPTH_ZERO/i.test(String(e.code) + e.message))
  // trusting exactly this certificate (ca:) works too, host name check included
  const authorized = await new Promise((resolve, reject) => {
    const c = tls.connect({ host: '127.0.0.1', port: server.address().port, ca: m.certPem }, () => { resolve(c.authorized); c.destroy() })
    c.on('error', reject)
  })
  assert.equal(authorized, true)
})

test('ensureSelfSigned: files 0600 in a 0700 directory, reused across restarts, new only for a new host or a broken pair', () => {
  const dir = path.join(tmp(), 'tls')
  const a = ensureSelfSigned({ dir, host: '203.0.113.7' })
  assert.equal(a.created, true)
  assert.equal(a.reason, 'missing')
  assert.equal(fs.statSync(dir).mode & 0o777, 0o700)
  for (const f of [a.keyFile, a.certFile]) assert.equal(fs.statSync(f).mode & 0o777, 0o600, f)
  assert.equal(path.basename(a.keyFile), 'self-key.pem')
  assert.equal(path.basename(a.certFile), 'self-cert.pem')
  const b = ensureSelfSigned({ dir, host: '203.0.113.7' })
  assert.equal(b.created, false)
  assert.equal(b.pin, a.pin, 'same certificate after a restart')
  assert.equal(ensureSelfSigned({ dir, host: null }).pin, a.pin, 'address unknown: keep what is there')
  assert.equal(ensureSelfSigned({ dir, host: '[::ffff:203.0.113.7]' }).created, true, 'another host (even the same IPv4 written as IPv6) → new certificate')
  const c = ensureSelfSigned({ dir, host: '198.51.100.9' })
  assert.equal(c.reason, 'host-changed')
  assert.notEqual(c.pin, a.pin)
  assert.equal(new crypto.X509Certificate(fs.readFileSync(c.certFile)).checkIP('198.51.100.9'), '198.51.100.9')
  // a key that does not belong to the certificate (crash between the two writes), a broken file, an expiring certificate
  fs.writeFileSync(c.keyFile, makeSelfSigned({ host: '198.51.100.9' }).keyPem)
  assert.equal(ensureSelfSigned({ dir, host: '198.51.100.9' }).reason, 'not-a-pair')
  fs.writeFileSync(c.certFile, 'garbage')
  assert.equal(ensureSelfSigned({ dir, host: '198.51.100.9' }).reason, 'unreadable')
  const later = Date.now() + 3640 * DAY
  assert.equal(ensureSelfSigned({ dir, host: '198.51.100.9', now: later }).reason, 'expiring')
  // no host yet: a certificate without SAN, replaced once the host is known
  const dir2 = path.join(tmp(), 'tls')
  const n = ensureSelfSigned({ dir: dir2, host: null })
  assert.equal(n.host, null)
  assert.equal(ensureSelfSigned({ dir: dir2, host: '203.0.113.50' }).reason, 'host-changed')
})

test('pinOf: the first certificate of a chain; refuses what is not a certificate', () => {
  const leaf = makeSelfSigned({ host: '203.0.113.7' }), other = makeSelfSigned({ host: '198.51.100.1' })
  assert.equal(pinOf(leaf.certPem + other.certPem), leaf.pin)
  assert.equal(pinOf(Buffer.from(leaf.certPem)), leaf.pin)
  assert.throws(() => pinOf('not a certificate'))
  assert.ok(!isPin('SHA256:' + 'a'.repeat(64)) && !isPin('sha256:' + 'A'.repeat(64)) && !isPin('sha256:' + 'a'.repeat(63)))
})

test('openssl reads it the same way', { skip: !hasOpenssl && 'no openssl command' }, () => {
  const dir = tmp()
  for (const [host, sanText] of [['203.0.113.7', 'IP Address:203.0.113.7'], ['2001:db8::1', 'IP Address:2001:DB8:0:0:0:0:0:1'], ['relay.example.com', 'DNS:relay.example.com']]) {
    const m = makeSelfSigned({ host })
    const f = path.join(dir, 'c.pem')
    fs.writeFileSync(f, m.certPem)
    const text = execFileSync('openssl', ['x509', '-in', f, '-noout', '-text'], { encoding: 'utf8' })
    for (const want of ['Version: 3 (0x2)', 'Signature Algorithm: ecdsa-with-SHA256', `Subject: CN=${host === 'relay.example.com' ? host : host.replace('2001:db8::1', '2001:db8::1')}`,
      'X509v3 Basic Constraints: critical', 'CA:FALSE', 'X509v3 Key Usage: critical', 'Digital Signature', 'TLS Web Server Authentication', sanText]) {
      assert.ok(text.replace(/\s+/g, ' ').includes(want.replace(/\s+/g, ' ')), `openssl output has ${want}\n${text}`)
    }
    const fp = execFileSync('openssl', ['x509', '-in', f, '-noout', '-fingerprint', '-sha256'], { encoding: 'utf8' })
    assert.equal('sha256:' + fp.split('=')[1].trim().replace(/:/g, '').toLowerCase(), m.pin)
    execFileSync('openssl', ['asn1parse', '-in', f], { stdio: 'pipe' })     // strict DER parse
    const kf = path.join(dir, 'k.pem')
    fs.writeFileSync(kf, m.keyPem)
    const pubFromKey = execFileSync('openssl', ['pkey', '-in', kf, '-pubout'], { encoding: 'utf8' })
    const pubFromCert = execFileSync('openssl', ['x509', '-in', f, '-noout', '-pubkey'], { encoding: 'utf8' })
    assert.equal(pubFromKey, pubFromCert, 'openssl agrees the key belongs to the certificate')
  }
})
