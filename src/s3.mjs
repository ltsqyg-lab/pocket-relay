// S3-compatible object storage with AWS Signature Version 4 presigned URLs (RELAY.md §9). Works with AWS S3,
// Cloudflare R2, MinIO, Tencent COS and Aliyun OSS (their S3-compatible endpoints).
//
// SPDX-License-Identifier: AGPL-3.0-or-later
import crypto from 'node:crypto'

const hmac = (key, s) => crypto.createHmac('sha256', key).update(s, 'utf8').digest()
const hexHash = (s) => crypto.createHash('sha256').update(s, 'utf8').digest('hex')
/** RFC 3986 encoding as SigV4 wants it (unreserved: A-Z a-z 0-9 - _ . ~). */
export const rfc3986 = (s) => encodeURIComponent(s).replace(/[!'()*]/g, (c) => '%' + c.charCodeAt(0).toString(16).toUpperCase())
const encodePath = (p) => p.split('/').map(rfc3986).join('/')
export const amzDate = (t) => new Date(t).toISOString().replace(/[-:]/g, '').replace(/\.\d{3}/, '')   // 20130524T000000Z

/**
 * Presign a request. `url` is the object URL (no query); `headers` are extra headers to sign (lower-case names,
 * e.g. {'content-length': '123'}); `host` is always signed. Payload: UNSIGNED-PAYLOAD.
 */
export function presign({ method, url, region, accessKey, secretKey, expires, now, headers = {}, service = 's3', query = {} }) {
  const u = new URL(url)
  const t = amzDate(now)
  const date = t.slice(0, 8)
  const scope = `${date}/${region}/${service}/aws4_request`
  const hdrs = { host: u.host, ...Object.fromEntries(Object.entries(headers).map(([k, v]) => [k.toLowerCase(), String(v).trim()])) }
  const signed = Object.keys(hdrs).sort()
  const q = {
    ...query,
    'X-Amz-Algorithm': 'AWS4-HMAC-SHA256',
    'X-Amz-Credential': `${accessKey}/${scope}`,
    'X-Amz-Date': t,
    'X-Amz-Expires': String(expires),
    'X-Amz-SignedHeaders': signed.join(';'),
  }
  const canonicalQuery = Object.keys(q).sort().map((k) => `${rfc3986(k)}=${rfc3986(q[k])}`).join('&')
  const canonicalPath = encodePath(decodeURIComponent(u.pathname)) || '/'
  const canonicalRequest = [method, canonicalPath, canonicalQuery, signed.map((k) => `${k}:${hdrs[k]}\n`).join(''), signed.join(';'), 'UNSIGNED-PAYLOAD'].join('\n')
  const stringToSign = ['AWS4-HMAC-SHA256', t, scope, hexHash(canonicalRequest)].join('\n')
  const kSigning = hmac(hmac(hmac(hmac('AWS4' + secretKey, date), region), service), 'aws4_request')
  const signature = crypto.createHmac('sha256', kSigning).update(stringToSign, 'utf8').digest('hex')
  return `${u.origin}${canonicalPath}?${canonicalQuery}&X-Amz-Signature=${signature}`
}

export class S3Backend {
  /** cfg: {name, when, endpoint, region, bucket, accessKeyEnv, secretKeyEnv, pathStyle, prefix} */
  constructor(cfg, { env = process.env, now = Date.now, fetchImpl = globalThis.fetch } = {}) {
    this.name = cfg.name
    this.when = cfg.when ?? 'default'
    this.region = cfg.region
    this.bucket = cfg.bucket
    this.prefix = cfg.prefix ?? ''
    this.pathStyle = !!cfg.pathStyle
    this.accessKey = env[cfg.accessKeyEnv] || ''
    this.secretKey = env[cfg.secretKeyEnv] || ''
    const e = new URL(cfg.endpoint)
    this.origin = this.pathStyle ? e.origin : `${e.protocol}//${cfg.bucket}.${e.host}`
    this.now = now
    this.fetch = fetchImpl
    this.healthy = !!(this.accessKey && this.secretKey)
    this.checkedAt = 0
  }

  keyOf(realm, blobId) { return `${this.prefix}${realm}/${blobId}` }
  urlOf(key) { return this.pathStyle ? `${this.origin}/${this.bucket}/${key}` : `${this.origin}/${key}` }
  sign(method, key, expires, headers = {}) {
    return presign({ method, url: this.urlOf(key), region: this.region, accessKey: this.accessKey, secretKey: this.secretKey, expires, now: this.now(), headers })
  }
  presignPut(key, bytes, expires = 3600) { return { url: this.sign('PUT', key, expires, { 'content-length': String(bytes) }), headers: { 'Content-Length': String(bytes) } } }
  presignGet(key, expires = 600) { return this.sign('GET', key, expires) }

  async head(key) {
    const r = await this.fetch(this.sign('HEAD', key, 300), { method: 'HEAD', signal: AbortSignal.timeout(15_000), redirect: 'error' })
    return { status: r.status, size: r.ok ? Number(r.headers.get('content-length')) : null }
  }
  async del(key) {
    const r = await this.fetch(this.sign('DELETE', key, 300), { method: 'DELETE', signal: AbortSignal.timeout(15_000), redirect: 'error' })
    if (!(r.ok || r.status === 404)) throw new Error(`delete: HTTP ${r.status}`)
  }
  /** Reachability probe: a HEAD of a key that need not exist; 200 / 404 mean the bucket answers. */
  async probe() {
    this.checkedAt = this.now()
    if (!this.accessKey || !this.secretKey) { this.healthy = false; return false }
    try {
      const r = await this.head(`${this.prefix}.probe`)
      this.healthy = r.status === 200 || r.status === 404
    } catch { this.healthy = false }
    return this.healthy
  }
}
