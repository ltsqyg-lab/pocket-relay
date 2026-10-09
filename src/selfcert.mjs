// Self-signed TLS certificate for a server that is reached by its IP address (or by a name without a certificate
// from a public CA), the way Tailscale's derper does it: an ECDSA P-256 key and an X.509 v3 certificate signed with
// that same key, valid 10 years. Clients do not check it against any certificate authority; they pin it:
//
//   pin = "sha256:" + lower-case hex SHA-256 of the leaf certificate's DER          (RELAY.md §12.1)
//
// Zero dependencies: the DER is written here and node:crypto signs it. Self-contained on purpose (no imports from
// the rest of the relay) so other Pocket servers can copy this file unchanged.
//
//   makeSelfSigned({ host, notBefore?, days? })  → { keyPem, certPem, pin }   a new key and certificate (nothing on disk)
//   pinOf(certPemOrDer)                          → "sha256:<64 hex>"         of the first certificate in a PEM, or of DER
//   ensureSelfSigned({ dir, host })              → { keyPem, certPem, pin, host, created, reason, keyFile, certFile }
//                                                  <dir>/self-key.pem + self-cert.pem (0600), reused across restarts;
//                                                  a new pair only when missing, broken, expiring or made for another host
//   normalizeHost(host)                          → { kind: "ipv4" | "ipv6" | "dns", name }   (throws on anything else)
//
// Not a CA certificate (CA:FALSE, keyUsage digitalSignature only): x509.verify(x509.publicKey) is true, but OpenSSL's
// X509_check_issued (Node's x509.checkIssued(itself)) and LibreSSL's `openssl verify -CAfile` refuse it as its own
// issuer, since keyCertSign is missing (RFC 5280 allows it only with CA:TRUE). Node's TLS client accepts it as an
// exact trust anchor (`ca: certPem`); pinned clients compare the pin and need neither.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
import crypto from 'node:crypto'
import fs from 'node:fs'
import net from 'node:net'
import path from 'node:path'
import { domainToASCII } from 'node:url'

const DAY = 86_400_000
export const PIN_RE = /^sha256:[0-9a-f]{64}$/
export const isPin = (s) => typeof s === 'string' && PIN_RE.test(s)
/** Common name of a certificate made before the server knew its public address (no subjectAltName at all). */
export const NO_HOST_CN = 'pocket-self-signed'

// ---- DER (X.690) ----------------------------------------------------------------------------------------------------
function derLen(n) {
  if (n < 0x80) return Buffer.from([n])
  const bytes = []
  for (let v = n; v > 0; v = Math.floor(v / 256)) bytes.unshift(v & 0xff)
  return Buffer.from([0x80 | bytes.length, ...bytes])
}
const tlv = (tag, body) => Buffer.concat([Buffer.from([tag]), derLen(body.length), body])
const seq = (...items) => tlv(0x30, Buffer.concat(items))
const set = (...items) => tlv(0x31, Buffer.concat(items))
const explicit = (n, body) => tlv(0xa0 | n, body)
const octets = (buf) => tlv(0x04, buf)
const bitString = (buf, unusedBits = 0) => tlv(0x03, Buffer.concat([Buffer.from([unusedBits]), buf]))
const utf8String = (s) => tlv(0x0c, Buffer.from(s, 'utf8'))
const boolTrue = () => tlv(0x01, Buffer.from([0xff]))
/** A non-negative INTEGER from big-endian magnitude bytes, minimally encoded. */
function uint(buf) {
  let i = 0
  while (i < buf.length - 1 && buf[i] === 0) i++
  const b = buf.subarray(i)
  return tlv(0x02, b[0] & 0x80 ? Buffer.concat([Buffer.from([0]), b]) : b)
}
function oid(dotted) {
  const arcs = dotted.split('.').map(Number)
  const out = [40 * arcs[0] + arcs[1]]
  for (const a of arcs.slice(2)) {
    const enc = [a & 0x7f]
    for (let v = Math.floor(a / 128); v > 0; v = Math.floor(v / 128)) enc.unshift(0x80 | (v & 0x7f))
    out.push(...enc)
  }
  return tlv(0x06, Buffer.from(out))
}
/** RFC 5280 §4.1.2.5: UTCTime through 2049, GeneralizedTime from 2050; whole seconds, "Z". */
function time(ms) {
  const d = new Date(Math.floor(ms / 1000) * 1000)
  const p = (n, w = 2) => String(n).padStart(w, '0')
  const y = d.getUTCFullYear()
  const rest = p(d.getUTCMonth() + 1) + p(d.getUTCDate()) + p(d.getUTCHours()) + p(d.getUTCMinutes()) + p(d.getUTCSeconds()) + 'Z'
  return y >= 1950 && y < 2050 ? tlv(0x17, Buffer.from(p(y % 100) + rest, 'ascii')) : tlv(0x18, Buffer.from(p(y, 4) + rest, 'ascii'))
}

const OID = {
  ecdsaWithSha256: '1.2.840.10045.4.3.2',
  commonName: '2.5.4.3',
  basicConstraints: '2.5.29.19',
  keyUsage: '2.5.29.15',
  extKeyUsage: '2.5.29.37',
  subjectAltName: '2.5.29.17',
  serverAuth: '1.3.6.1.5.5.7.3.1',
}

// ---- hosts ----------------------------------------------------------------------------------------------------------
function ipv6Bytes(canonical) {
  const [l, r = null] = canonical.split('::')
  const L = l ? l.split(':') : []
  const R = r === null ? [] : r ? r.split(':') : []
  const groups = r === null ? L : [...L, ...Array(8 - L.length - R.length).fill('0'), ...R]
  if (groups.length !== 8 || !groups.every((g) => /^[0-9a-f]{1,4}$/.test(g))) throw new Error(`bad IPv6 address ${canonical}`)
  const b = Buffer.alloc(16)
  groups.forEach((g, i) => b.writeUInt16BE(parseInt(g, 16), i * 2))
  return b
}

/** An IPv4 address, an IPv6 address (brackets optional, no zone) or a DNS name, in canonical form. */
export function normalizeHost(host) {
  if (typeof host !== 'string' || !host || host.length > 255) throw new Error('host must be an IP address or a DNS name')
  const h = host.trim().replace(/^\[(.*)\]$/, '$1')
  if (h.includes('%')) throw new Error(`host ${JSON.stringify(host)}: IPv6 zone ids are not allowed`)
  if (net.isIPv4(h)) {
    const parts = h.split('.').map(Number)
    return { kind: 'ipv4', name: parts.join('.'), bytes: Buffer.from(parts) }
  }
  if (net.isIPv6(h)) {
    const name = new URL(`http://[${h}]/`).hostname.slice(1, -1)    // lower case, "::" compressed, no dotted quad
    return { kind: 'ipv6', name, bytes: ipv6Bytes(name) }
  }
  const name = domainToASCII(h.toLowerCase()).replace(/\.$/, '')
  if (!name || name.length > 253 || !/^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$/.test(name)) {
    throw new Error(`host ${JSON.stringify(host)} is neither an IP address nor a DNS name`)
  }
  return { kind: 'dns', name }
}

// ---- certificates ---------------------------------------------------------------------------------------------------
const toPem = (der) => `-----BEGIN CERTIFICATE-----\n${der.toString('base64').match(/.{1,64}/g).join('\n')}\n-----END CERTIFICATE-----\n`

/**
 * A new ECDSA P-256 key and a self-signed X.509 v3 certificate for `host` (IPv4, IPv6 or DNS name; null = no
 * subjectAltName, for a server that does not know its address yet). Subject and issuer CN = the host; SAN = the IP
 * address or the DNS name; basicConstraints CA:FALSE; keyUsage digitalSignature; extKeyUsage serverAuth; a random
 * positive 16-byte serial; signed ecdsa-with-SHA256. Valid from `notBefore` (default: now − 1 day) for `days`
 * (default 3650).
 */
export function makeSelfSigned({ host, notBefore, days = 3650 } = {}) {
  const h = host == null ? null : normalizeHost(host)
  const nb = Number.isFinite(notBefore) ? notBefore : Date.now() - DAY
  if (!(Number.isFinite(days) && days > 0 && days <= 36500)) throw new Error('days must be between 1 and 36500')
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' })
  const serial = crypto.randomBytes(16)
  serial[0] = (serial[0] & 0x7f) || 0x01            // positive, and a non-zero first byte keeps it exactly 16 bytes
  const cn = h ? h.name : NO_HOST_CN
  const name = seq(set(seq(oid(OID.commonName), utf8String(cn))))
  const sigAlg = seq(oid(OID.ecdsaWithSha256))     // parameters absent (RFC 5758 §3.2)
  const ext = (id, critical, value) => seq(oid(id), ...(critical ? [boolTrue()] : []), octets(value))
  const exts = [
    ext(OID.basicConstraints, true, seq()),                                      // cA DEFAULT FALSE
    ext(OID.keyUsage, true, bitString(Buffer.from([0x80]), 7)),                  // digitalSignature
    ext(OID.extKeyUsage, false, seq(oid(OID.serverAuth))),
  ]
  if (h) exts.push(ext(OID.subjectAltName, false, seq(h.kind === 'dns' ? tlv(0x82, Buffer.from(h.name, 'ascii')) : tlv(0x87, h.bytes))))
  const tbs = seq(
    explicit(0, uint(Buffer.from([2]))),           // version v3
    uint(serial),
    sigAlg,
    name,                                          // issuer = subject: self-signed
    seq(time(nb), time(nb + days * DAY)),
    name,
    publicKey.export({ type: 'spki', format: 'der' }),
    explicit(3, seq(...exts)),
  )
  const sig = crypto.sign('sha256', tbs, privateKey)   // DER Ecdsa-Sig-Value
  const der = seq(tbs, sigAlg, bitString(sig))
  return { keyPem: privateKey.export({ type: 'pkcs8', format: 'pem' }), certPem: toPem(der), pin: pinOf(der) }
}

/** Pin of a certificate: "sha256:" + hex SHA-256 of its DER. PEM input: the first certificate (the leaf of a chain). */
export function pinOf(certPemOrDer) {
  const x = certPemOrDer instanceof crypto.X509Certificate ? certPemOrDer : new crypto.X509Certificate(certPemOrDer)
  return 'sha256:' + crypto.createHash('sha256').update(x.raw).digest('hex')
}

/** Does this certificate name exactly `host` in its subjectAltName (null host: a certificate without SAN)? */
export function certIsFor(x509, host) {
  if (host == null) return !x509.subjectAltName
  const h = typeof host === 'string' ? normalizeHost(host) : host
  if (h.kind === 'dns') return x509.checkHost(h.name, { subject: 'never', wildcards: false }) === h.name
  return x509.checkIP(h.name) !== undefined
}

function writeAtomic(file, text, mode) {
  const tmp = `${file}.tmp-${process.pid}-${crypto.randomBytes(4).toString('hex')}`
  fs.writeFileSync(tmp, text, { mode })
  try { fs.chmodSync(tmp, mode) } catch { /* not ours to change */ }
  fs.renameSync(tmp, file)
}

/**
 * The key and certificate in `dir` (self-key.pem, self-cert.pem; mode 0600, directory 0700), created when missing,
 * unreadable, not a pair, expiring within 30 days, or made for another host. `host` null means "address not known":
 * any existing pair is kept, otherwise one without subjectAltName is made (it is replaced once the host is known).
 */
export function ensureSelfSigned({ dir, host = null, now = Date.now(), days = 3650 }) {
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 })
  const keyFile = path.join(dir, 'self-key.pem'), certFile = path.join(dir, 'self-cert.pem')
  const want = host == null ? null : normalizeHost(host)
  let reason = 'missing'
  try {
    const keyPem = fs.readFileSync(keyFile, 'utf8'), certPem = fs.readFileSync(certFile, 'utf8')
    const x = new crypto.X509Certificate(certPem)
    if (!x.checkPrivateKey(crypto.createPrivateKey(keyPem))) reason = 'not-a-pair'
    else if (Date.parse(x.validTo) - now < 30 * DAY) reason = 'expiring'
    else if (want && !certIsFor(x, want)) reason = 'host-changed'
    else return { keyPem, certPem, pin: pinOf(x), host: want?.name ?? hostOfCert(x), created: false, reason: null, keyFile, certFile }
  } catch (e) { reason = e?.code === 'ENOENT' ? 'missing' : 'unreadable' }
  const made = makeSelfSigned({ host: want?.name ?? null, notBefore: now - DAY, days })
  writeAtomic(keyFile, made.keyPem, 0o600)        // key first: a crash in between leaves a mismatch, caught next time
  writeAtomic(certFile, made.certPem, 0o600)
  return { ...made, host: want?.name ?? null, created: true, reason, keyFile, certFile }
}

/** The single host a certificate made here is for (null when it has no subjectAltName). */
export function hostOfCert(x509) {
  const san = x509.subjectAltName
  if (!san) return null
  const first = san.split(', ')[0]
  if (first.startsWith('DNS:')) return first.slice(4)
  if (first.startsWith('IP Address:')) return normalizeHost(first.slice(11)).name
  return null
}
