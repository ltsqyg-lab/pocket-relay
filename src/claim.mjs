// Running a relay without a domain (RELAY.md §12.1), the way Tailscale's derper runs on a bare IP address: the relay
// makes its own certificate, finds its public address, and prints one line for its owner to paste into the Pocket App
//
//   pocket-relay://<host>:<port>?pin=sha256:<hex>&claim=<code>
//
// No path: devices reach a relay at the root of its host and port. The pin is the SHA-256 of the relay's certificate (devices check nothing else). The claim code (32 random bytes)
// lets the first caller who knows it — coordination, with the line the owner pasted — bind the relay to a relay id and
// an account (POST /v1/claim). It exists only in this server's output and in files readable by the relay's user.
//
// Files in the data directory (all mode 0600):
//   tls/self-key.pem, tls/self-cert.pem   the self-signed key and certificate (selfcert.mjs)
//   claim.json     {claim, at}               while not claimed
//   binding.json   {relayId, account, at}    once claimed
//   public.json    {host, at}                the public address coordination reported (GET <coord>/v2/whoami)
//   connect.txt    the line above (with the claim code only while not claimed)
//
// SPDX-License-Identifier: AGPL-3.0-or-later
import crypto from 'node:crypto'
import fs from 'node:fs'
import net from 'node:net'
import path from 'node:path'
import tls from 'node:tls'
import { normalizeHost, pinOf, isPin } from './selfcert.mjs'

export const CLAIM_RE = /^[A-Za-z0-9_-]{43}$/          // base64url of 32 bytes, no padding
export const RELAY_ID_RE = /^[A-Za-z0-9_:.-]{1,64}$/
export const SCHEME = 'pocket-relay:'

export function claimFiles(dataDir) {
  const tlsDir = path.join(dataDir, 'tls')
  return {
    tlsDir, selfKey: path.join(tlsDir, 'self-key.pem'), selfCert: path.join(tlsDir, 'self-cert.pem'),
    claim: path.join(dataDir, 'claim.json'), binding: path.join(dataDir, 'binding.json'),
    public: path.join(dataDir, 'public.json'), connect: path.join(dataDir, 'connect.txt'),
  }
}

export function writeFileAtomic(file, text, mode = 0o600) {
  fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 })
  const tmp = `${file}.tmp-${process.pid}-${crypto.randomBytes(4).toString('hex')}`
  fs.writeFileSync(tmp, text, { mode })
  try { fs.chmodSync(tmp, mode) } catch { /* not ours to change */ }
  fs.renameSync(tmp, file)
}
/** A JSON object from a file; null when the file does not exist or does not hold one. */
function readJsonFile(file) {
  let text
  try { text = fs.readFileSync(file, 'utf8') } catch (e) { if (e.code === 'ENOENT') return null; throw e }
  try { const j = JSON.parse(text); return j && typeof j === 'object' && !Array.isArray(j) ? j : null } catch { return null }
}
const rm = (file) => { try { fs.unlinkSync(file) } catch (e) { if (e.code !== 'ENOENT') throw e } }

// ---- binding and claim code ------------------------------------------------------------------------------------------
export const validAccount = (a) => typeof a === 'string' && a.length > 0 && a.length <= 128 && a !== '*' && !/[\u0000-\u001f\u007f]/.test(a)

/** The binding a claim wrote ({relayId, account, at}), or null. */
export function readBinding(dataDir) {
  const j = readJsonFile(claimFiles(dataDir).binding)
  if (!j || typeof j.relayId !== 'string' || !RELAY_ID_RE.test(j.relayId) || !validAccount(j.account)) return null
  return { relayId: j.relayId, account: j.account, at: Number.isSafeInteger(j.at) ? j.at : 0 }
}
export function writeBinding(dataDir, { relayId, account, at = Date.now() }) {
  writeFileAtomic(claimFiles(dataDir).binding, JSON.stringify({ relayId, account, at }) + '\n')
}
export function removeBinding(dataDir) { rm(claimFiles(dataDir).binding) }

export function readClaim(dataDir) {
  const j = readJsonFile(claimFiles(dataDir).claim)
  return j && typeof j.claim === 'string' && CLAIM_RE.test(j.claim) ? j.claim : null
}
/** A new claim code, replacing any earlier one. */
export function newClaim(dataDir, now = Date.now()) {
  const claim = crypto.randomBytes(32).toString('base64url')
  writeFileAtomic(claimFiles(dataDir).claim, JSON.stringify({ claim, at: now }) + '\n')
  return claim
}
export function ensureClaim(dataDir, now = Date.now()) {
  const old = readClaim(dataDir)
  return old ? { claim: old, created: false } : { claim: newClaim(dataDir, now), created: true }
}
export function removeClaim(dataDir) { rm(claimFiles(dataDir).claim) }

/** Constant-time comparison of a presented claim code with the stored one (hashes first: equal lengths, no early exit). */
export function claimMatches(presented, stored) {
  if (typeof presented !== 'string' || typeof stored !== 'string' || !stored) return false
  const h = (s) => crypto.createHash('sha256').update(s, 'utf8').digest()
  return crypto.timingSafeEqual(h(presented), h(stored)) && presented.length === stored.length
}

// ---- the connection line ---------------------------------------------------------------------------------------------
/**
 * A host of a line: IPv4, IPv6 or a DNS name — but not a name the system resolver would read as an IPv4 address
 * (`127.1`, `0x7f.1`: a custom scheme keeps them as names, inet_aton does not), and no top-level label of digits.
 */
function lineHost(host) {
  const h = normalizeHost(host)
  if (h.kind === 'dns' && /^(0x[0-9a-f]*|[0-9]+)$/.test(h.name.split('.').pop())) throw new Error(`host ${JSON.stringify(host)} looks like an IP address but is not one`)
  return h
}

/** pocket-relay://<host>:<port>?pin=…&claim=…  (IPv6 in brackets; pin and claim only when given). */
export function formatConnect({ host, port, pin = null, claim = null }) {
  const h = lineHost(host)
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('port must be 1..65535')
  if (pin != null && !isPin(pin)) throw new Error('pin must be "sha256:" + 64 lower-case hex digits')
  if (claim != null && !CLAIM_RE.test(claim)) throw new Error('claim must be 43 base64url characters')
  if (pin == null && h.kind !== 'dns') throw new Error('a line for an IP address needs a pin')
  const q = [pin && `pin=${pin}`, claim && `claim=${claim}`].filter(Boolean)
  return `pocket-relay://${h.kind === 'ipv6' ? `[${h.name}]` : h.name}:${port}${q.length ? '?' + q.join('&') : ''}`
}

/**
 * Parse a connection line: {host, kind, port, pin, claim, url} where url is the relay's https base URL. Throws. Like
 * the App: no path (one trailing slash is tolerated), a pin for IP addresses, parameters it does not know are ignored
 * (later additions), `pin` and `claim` at most once.
 */
export function parseConnect(line) {
  let u
  try { u = new URL(String(line).trim()) } catch { throw new Error('not a pocket-relay:// line') }
  if (u.protocol !== SCHEME) throw new Error('not a pocket-relay:// line')
  if (u.username || u.password || u.hash) throw new Error('unexpected user name or fragment')
  if (u.pathname !== '' && u.pathname !== '/') throw new Error('unexpected path')
  const h = lineHost(u.hostname)
  const port = Number(u.port)
  if (!u.port || !Number.isInteger(port) || port < 1 || port > 65535) throw new Error('the port is missing')
  for (const k of ['pin', 'claim']) if (u.searchParams.getAll(k).length > 1) throw new Error(`${k} given twice`)
  const pin = u.searchParams.get('pin'), claim = u.searchParams.get('claim')
  if (pin !== null && !isPin(pin)) throw new Error('bad pin')
  if (pin === null && h.kind !== 'dns') throw new Error('a line for an IP address needs a pin')
  if (claim !== null && !CLAIM_RE.test(claim)) throw new Error('bad claim code')
  const hostPart = h.kind === 'ipv6' ? `[${h.name}]` : h.name
  return { host: h.name, kind: h.kind, port, pin, claim, url: `https://${hostPart}:${port}` }
}

/** The address devices use, from `publicUrl` ({host, port, path}), or null when it is not configured. */
export function configuredAddress(cfg) {
  if (!cfg.publicUrl) return null
  const u = new URL(cfg.publicUrl)
  return { host: normalizeHost(u.hostname).name, port: u.port ? Number(u.port) : 443, path: u.pathname.replace(/\/+$/, ''), from: 'config' }
}
export function readPublic(dataDir) {
  const j = readJsonFile(claimFiles(dataDir).public)
  try { return j && typeof j.host === 'string' ? { host: normalizeHost(j.host).name, at: j.at ?? 0 } : null } catch { return null }
}
export function writePublic(dataDir, host, now = Date.now()) {
  writeFileAtomic(claimFiles(dataDir).public, JSON.stringify({ host, at: now }) + '\n')
}

/** Ask coordination which address this server's requests come from: GET <coordUrl>/v2/whoami → {ip}. */
export async function whoami({ coordUrl, fetchImpl = globalThis.fetch, timeoutMs = 10_000 }) {
  const r = await fetchImpl(`${coordUrl}/v2/whoami`, { signal: AbortSignal.timeout(timeoutMs), redirect: 'error', headers: { accept: 'application/json' } })
  if (!r.ok) throw new Error(`HTTP ${r.status}`)
  const text = await r.text()
  if (text.length > 4096) throw new Error('answer too large')
  let ip
  try { ip = JSON.parse(text)?.ip } catch { throw new Error('answer is not JSON') }
  if (typeof ip !== 'string' || !net.isIP(ip.replace(/^\[|\]$/g, ''))) throw new Error('answer has no IP address')
  return normalizeHost(ip).name
}

/** Not an address the rest of the internet can reach (private, loopback, link-local, CGNAT, documentation…). */
export function nonPublicIp(ip) {
  const h = normalizeHost(ip)
  if (h.kind === 'dns') return false
  if (h.kind === 'ipv4') {
    const [a, b] = h.bytes
    return a === 0 || a === 10 || a === 127 || (a === 100 && b >= 64 && b < 128) || (a === 169 && b === 254) || (a === 172 && b >= 16 && b < 32) ||
      (a === 192 && b === 168) || a >= 224
  }
  const b = h.bytes
  const v4 = b.subarray(0, 10).every((x) => x === 0) && b[10] === 0xff && b[11] === 0xff
  if (v4) return nonPublicIp([...b.subarray(12)].join('.'))
  return b.every((x, i) => (i < 15 ? x === 0 : x <= 1)) || (b[0] & 0xfe) === 0xfc || (b[0] === 0xfe && (b[1] & 0xc0) === 0x80) || b[0] === 0xff ||
    (b[0] === 0x20 && b[1] === 0x01 && b[2] === 0x0d && b[3] === 0xb8)
}

// ---- certificates given in the configuration -------------------------------------------------------------------------
let ROOTS = null
const splitPem = (pem) => String(pem).match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g) ?? []

/**
 * Does this certificate (a PEM chain, leaf first) chain to a root in Node's bundled CA store and cover `host` (any
 * host with `anyHost`)? Then
 * devices can check it like any website and it is not pinned: a CA certificate is renewed every few weeks or months
 * and a pin would break at the first renewal.
 */
export function publiclyTrusted(pem, host, { roots = null, now = Date.now(), anyHost = false } = {}) {
  try {
    const certs = splitPem(pem).map((p) => new crypto.X509Certificate(p))
    if (!certs.length) return false
    const leaf = certs[0]
    if (Date.parse(leaf.validTo) < now || Date.parse(leaf.validFrom) > now) return false
    if (!anyHost) {
      const h = normalizeHost(host)
      if (h.kind === 'dns' ? !leaf.checkHost(h.name) : !leaf.checkIP(h.name)) return false
    }
    const anchors = roots ? roots.map((r) => new crypto.X509Certificate(r)) : (ROOTS ??= tls.rootCertificates.map((r) => new crypto.X509Certificate(r)))
    let cur = leaf
    for (let depth = 0; depth < 8; depth++) {
      if (anchors.some((a) => cur.checkIssued(a) && cur.verify(a.publicKey))) return true
      const next = certs.find((c) => c !== cur && cur.checkIssued(c) && cur.verify(c.publicKey))
      if (!next) return false
      cur = next
    }
    return false
  } catch { return false }
}

// ---- what to tell the owner ------------------------------------------------------------------------------------------
/**
 * The connection line as it stands, from the configuration and the files in the data directory (the relay calls this
 * after every change; `connect-string` calls it on its own). `port` overrides the listening port (an ephemeral port in
 * tests). Returns {line, pin, claim, bound, host, port, path, publicCa} or {line: null, why}.
 */
export function connectInfo({ cfg, port = null, now = Date.now() }) {
  const F = claimFiles(cfg.dataDir)
  const bound = cfg.relayId ? { relayId: cfg.relayId, account: cfg.account } : readBinding(cfg.dataDir)
  let addr = configuredAddress(cfg)
  if (!addr && cfg.tlsMode !== 'off') {
    const pub = readPublic(cfg.dataDir)
    if (pub) addr = { host: pub.host, port: port ?? cfg.listen.port, path: '', from: 'whoami' }
  }
  if (!addr) return { line: null, bound, why: cfg.tlsMode === 'off' ? 'no-public-url' : 'no-address' }
  // the line has no path: devices reach a relay at the root of its host and port
  if (addr.path) return { line: null, bound, why: 'path', path: addr.path }
  let pin = null, publicCa = false
  try {
    if (cfg.tlsMode === 'self') pin = pinOf(fs.readFileSync(F.selfCert, 'utf8'))
    else if (cfg.tlsMode === 'files') {
      const pem = fs.readFileSync(cfg.tls.cert, 'utf8')
      pin = pinOf(pem)
      // not pinned only for a DNS name: a line for an IP address always carries a pin (the App requires one)
      publicCa = normalizeHost(addr.host).kind === 'dns' && publiclyTrusted(pem, addr.host, { now })
    }
  } catch { return { line: null, bound, why: 'no-certificate' } }
  if (pin === null && normalizeHost(addr.host).kind !== 'dns') return { line: null, bound, why: 'proxy-ip' }
  const claim = bound ? null : readClaim(cfg.dataDir)
  if (!bound && !claim) return { line: null, bound, why: 'no-claim' }
  const line = formatConnect({ host: addr.host, port: addr.port, pin: publicCa ? null : pin, claim })
  return { line, pin, publicCa, claim, bound, host: addr.host, port: addr.port, path: addr.path, from: addr.from }
}

/** The text printed to standard output: the line, where to paste it, which port to open. */
export function connectBlock(info, { file = null, claimed = false } = {}) {
  const bar = '='.repeat(78)
  const out = [bar]
  if (!info.bound) {
    out.push('Pocket relay: ready to be added (not claimed yet).',
      'In the Pocket app: Settings → Relay → Add your own relay, then paste this line:',
      '在 Pocket App:我的 → 中继 → 添加自建中继,粘贴这一行:')
  } else {
    out.push(claimed ? `Pocket relay: claimed (relay ${info.bound.relayId}). 已认领。` : `Pocket relay: relay ${info.bound.relayId}.`,
      'Connection line (no claim code: this relay is already claimed):', '连接串(已认领,不带认领码):')
  }
  out.push('', `    ${info.line}`, '')
  if (info.publicCa) out.push(`Certificate from a public CA: devices check it like a website, no pin needed (its pin is ${info.pin}).`)
  out.push(`Open TCP port ${info.port} to the internet in this server's firewall / cloud security group.`,
    `在服务器防火墙 / 云服务器安全组里放行 TCP ${info.port} 端口。`)
  if (file) out.push(`Also in ${file}. Print it again: node src/main.mjs connect-string (Docker: docker exec <container> node src/main.mjs connect-string)`)
  out.push(bar, '')
  return out.join('\n')
}

/** Why there is no line yet, for people (English + Chinese). */
export function noLineText(why, { cfg, port = null, error = null, retrySeconds = null } = {}) {
  port ??= cfg.listen.port
  if (why === 'no-address') {
    return [`Pocket relay: could not find this server's public IP address${error ? ` (${cfg.coord.url}/v2/whoami: ${error})` : ''}.`,
      `Set it yourself and restart: RELAY_PUBLIC_URL=https://<public IP>:${port}${retrySeconds ? ` (trying again in ${retrySeconds} s)` : ''}`,
      `找不到本机的公网 IP;请设置 RELAY_PUBLIC_URL=https://<公网 IP>:${port} 后重启。`, ''].join('\n')
  }
  if (why === 'no-public-url') {
    return ['Pocket relay: behind a reverse proxy (tls off): set publicUrl (RELAY_PUBLIC_URL) to the https address devices use, e.g. https://relay.example.com',
      '在反向代理后面运行:请把 publicUrl(RELAY_PUBLIC_URL)设成设备访问用的 https 地址。', ''].join('\n')
  }
  if (why === 'path') {
    return [`Pocket relay: publicUrl has a path (${cfg.publicUrl}); the Pocket App adds relays only at the root of a host and port.`,
      'Serve the relay at the root of its own host name or port (e.g. https://relay.example.com), or let it terminate TLS itself (tls "auto", port 8443).',
      'publicUrl 带了路径;Pocket App 只能添加挂在主机 + 端口根路径上的中继:给它单独的域名或端口,或者让它自己做 TLS(默认 8443 端口)。', ''].join('\n')
  }
  if (why === 'proxy-ip') {
    return ['Pocket relay: behind a proxy (tls off) with an IP address in publicUrl: devices need a pin for an IP address, and a proxy\'s certificate is not',
      'known here. Give publicUrl a domain name with a certificate from a public CA, or let the relay terminate TLS itself (tls "auto").',
      '在代理后面却用 IP 地址:按 IP 连接要钉证书指纹,中继拿不到代理的证书。publicUrl 请用有公共证书的域名,或者让中继自己做 TLS。', ''].join('\n')
  }
  if (why === 'no-certificate') return 'Pocket relay: the TLS certificate is missing or unreadable; start the relay first (it makes its certificate on start).\n'
  if (why === 'no-claim') return 'Pocket relay: no claim code yet; start the relay first, or run: node src/main.mjs reset-claim\n'
  return `Pocket relay: no connection line (${why}).\n`
}
