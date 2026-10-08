#!/usr/bin/env node
// A fake S3-compatible store for the relay's tests and the local lab: path-style buckets, AWS SigV4 presigned query
// authentication with UNSIGNED-PAYLOAD (signatures and expiry are checked), PUT / GET (Range) / HEAD / DELETE.
//
//   node test/fake-s3.mjs --port 18650 [--host 127.0.0.1] [--keys-file keys.json]   (keys: {"<access key>": "<secret>"})
//
// SPDX-License-Identifier: AGPL-3.0-or-later
import http from 'node:http'
import fs from 'node:fs'
import { pathToFileURL } from 'node:url'
import { presign } from '../src/s3.mjs'

export function startFakeS3({ port = 0, host = '127.0.0.1', keys = {}, log = () => {} } = {}) {
  const objects = new Map()     // "bucket/key" -> Buffer
  const state = { down: false, requests: [] }
  const server = http.createServer((req, res) => {
    const chunks = []
    req.on('data', (c) => chunks.push(c))
    req.on('end', () => {
      const body = Buffer.concat(chunks)
      const u = new URL(req.url, `http://${req.headers.host}`)
      state.requests.push({ method: req.method, path: u.pathname, auth: req.headers.authorization ?? null, range: req.headers.range ?? null })
      if (state.down) { res.writeHead(503); return res.end() }
      const err = (code, status) => { res.writeHead(status, { 'Content-Type': 'application/xml' }); res.end(`<?xml version="1.0"?><Error><Code>${code}</Code></Error>`) }
      // ---- authentication: presigned query string, SigV4 --------------------------------------------------------
      const q = u.searchParams
      if (q.get('X-Amz-Algorithm') !== 'AWS4-HMAC-SHA256') return err('AccessDenied', 403)
      const [ak, date, region, service] = String(q.get('X-Amz-Credential') || '').split('/')
      const secret = keys[ak]
      if (!secret || service !== 's3') return err('InvalidAccessKeyId', 403)
      const t = q.get('X-Amz-Date') || ''
      const m = /^(\d{4})(\d{2})(\d{2})T(\d{2})(\d{2})(\d{2})Z$/.exec(t)
      if (!m || date !== t.slice(0, 8)) return err('AuthorizationQueryParametersError', 400)
      const at = Date.UTC(+m[1], +m[2] - 1, +m[3], +m[4], +m[5], +m[6])
      const expires = Number(q.get('X-Amz-Expires'))
      if (!(expires > 0) || Date.now() > at + expires * 1000) return err('AccessDenied', 403)
      const signedNames = String(q.get('X-Amz-SignedHeaders') || '').split(';')
      if (!signedNames.includes('host')) return err('AccessDenied', 403)
      const headers = {}
      for (const n of signedNames) if (n !== 'host') headers[n] = req.headers[n] ?? ''
      const extra = {}
      for (const [k, v] of q) if (!k.startsWith('X-Amz-')) extra[k] = v
      const expect = presign({ method: req.method, url: `http://${req.headers.host}${u.pathname}`, region, accessKey: ak, secretKey: secret, expires, now: at, headers, query: extra })
      if (new URL(expect).searchParams.get('X-Amz-Signature') !== q.get('X-Amz-Signature')) return err('SignatureDoesNotMatch', 403)
      // ---- object operations ----------------------------------------------------------------------------------
      const id = decodeURIComponent(u.pathname.slice(1))
      if (!id.includes('/')) return err('InvalidRequest', 400)
      if (req.method === 'PUT') {
        if (String(body.length) !== req.headers['content-length']) return err('IncompleteBody', 400)
        objects.set(id, body); log(`PUT ${id} ${body.length}`)
        res.writeHead(200, { ETag: '"x"' }); return res.end()
      }
      const obj = objects.get(id)
      if (req.method === 'DELETE') { objects.delete(id); res.writeHead(204); return res.end() }
      if (!obj) return err('NoSuchKey', 404)
      if (req.method === 'HEAD') { res.writeHead(200, { 'Content-Length': String(obj.length) }); return res.end() }
      if (req.method === 'GET') {
        const r = /^bytes=(\d*)-(\d*)$/.exec(req.headers.range || '')
        if (r) {
          let s = r[1] === '' ? Math.max(0, obj.length - Number(r[2])) : Number(r[1])
          let e = r[1] === '' ? obj.length - 1 : r[2] === '' ? obj.length - 1 : Math.min(Number(r[2]), obj.length - 1)
          if (s > e) { res.writeHead(416); return res.end() }
          res.writeHead(206, { 'Content-Length': String(e - s + 1), 'Content-Range': `bytes ${s}-${e}/${obj.length}` })
          return res.end(obj.subarray(s, e + 1))
        }
        res.writeHead(200, { 'Content-Length': String(obj.length) }); return res.end(obj)
      }
      return err('MethodNotAllowed', 405)
    })
  })
  return new Promise((resolve) => server.listen(port, host, () => {
    const a = server.address()
    resolve({ url: `http://${host}:${a.port}`, port: a.port, objects, state, stop: () => new Promise((r) => { server.closeAllConnections?.(); server.close(() => r()) }) })
  }))
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const arg = (n, d) => { const i = process.argv.indexOf(n); return i >= 0 ? process.argv[i + 1] : d }
  const keys = arg('--keys-file') ? JSON.parse(fs.readFileSync(arg('--keys-file'), 'utf8')) : {}
  const s = await startFakeS3({ port: Number(arg('--port', '18650')), host: arg('--host', '127.0.0.1'), keys, log: (l) => console.log(new Date().toISOString(), l) })
  console.log(`fake S3 listening on ${s.url} (${Object.keys(keys).length} access keys)`)
}
