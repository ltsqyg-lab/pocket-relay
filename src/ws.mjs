// Minimal RFC 6455 WebSocket server side (text frames carrying JSON), no dependencies.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
import crypto from 'node:crypto'

const WS_GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11'
const MAX_FRAGS = 1024
const WRITE_BUFFER_MAX = 16 * 1024 * 1024

/**
 * Finish an HTTP upgrade and return a connection object:
 *   ws.send(obj) · ws.close(code, reason) · ws.ping() · ws.onMessage(obj) · ws.onClose(code) · ws.alive · ws.lastSeen
 * Oversized messages close with `tooLargeCode`, binary or non-JSON messages with `malformedCode`.
 */
export function upgrade(req, socket, head, { maxMessage = 2 * 1024 * 1024, tooLargeCode = 4413, malformedCode = 4400 } = {}) {
  const key = req.headers['sec-websocket-key']
  if (!key || req.headers['sec-websocket-version'] !== '13' || String(req.headers.upgrade || '').toLowerCase() !== 'websocket') {
    socket.end('HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n')
    return null
  }
  const accept = crypto.createHash('sha1').update(key + WS_GUID).digest('base64')
  socket.write('HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n' +
    `Sec-WebSocket-Accept: ${accept}\r\n\r\n`)
  socket.setNoDelay(true)
  socket.setTimeout(0)
  if (head && head.length) socket.unshift(head)
  return attach(socket, { maxMessage, tooLargeCode, malformedCode })
}

function attach(socket, { maxMessage, tooLargeCode, malformedCode }) {
  const ws = {
    alive: true,
    lastSeen: Date.now(),
    closeCode: 0,
    onMessage: () => {},
    onClose: () => {},
    send(obj) {
      if (!ws.alive) return false
      return rawSend(0x1, Buffer.from(typeof obj === 'string' ? obj : JSON.stringify(obj), 'utf8'))
    },
    close(code = 1000, reason = '') {
      if (!ws.alive) return
      const r = Buffer.from(String(reason).slice(0, 100), 'utf8')
      const b = Buffer.alloc(2 + r.length); b.writeUInt16BE(code); r.copy(b, 2)
      ws.closeCode = code
      rawSend(0x8, b)
      end(code)
    },
    ping() { rawSend(0x9, Buffer.alloc(0)) },
    get buffered() { return socket.writableLength },
  }
  function rawSend(op, payload) {
    if (socket.destroyed || !socket.writable) return false
    if (socket.writableLength > WRITE_BUFFER_MAX) { end(1008); return false }
    let header
    if (payload.length < 126) header = Buffer.from([0x80 | op, payload.length])
    else if (payload.length < 65536) { header = Buffer.alloc(4); header[0] = 0x80 | op; header[1] = 126; header.writeUInt16BE(payload.length, 2) }
    else { header = Buffer.alloc(10); header[0] = 0x80 | op; header[1] = 127; header.writeBigUInt64BE(BigInt(payload.length), 2) }
    socket.write(header)
    return socket.write(payload)
  }
  function end(code) {
    if (!ws.alive) return
    ws.alive = false
    if (!ws.closeCode) ws.closeCode = code || 1006
    try { socket.end() } catch { /* already gone */ }
    setTimeout(() => { try { socket.destroy() } catch { /* already gone */ } }, 2000).unref()
    try { ws.onClose(ws.closeCode) } catch { /* handler errors must not escape */ }
  }

  // Frames are reassembled by accounting for chunks and concatenating once per complete frame.
  let pending = [], pendingLen = 0, need = 0
  let fragOp = 0, frags = [], fragLen = 0
  socket.on('data', (chunk) => {
    if (!ws.alive) return
    ws.lastSeen = Date.now()
    pending.push(chunk)
    pendingLen += chunk.length
    if (pendingLen < need) return
    const buf = pending.length === 1 ? pending[0] : Buffer.concat(pending, pendingLen)
    pending = []; pendingLen = 0; need = 0
    let pos = 0
    while (ws.alive) {
      const avail = buf.length - pos
      if (avail < 2) break
      const b0 = buf[pos], b1 = buf[pos + 1]
      const fin = (b0 & 0x80) !== 0
      if (b0 & 0x70) return ws.close(1002, 'rsv')
      const op = b0 & 0x0f
      const masked = (b1 & 0x80) !== 0
      let len = b1 & 0x7f, off = 2
      if (len === 126) { if (avail < 4) break; len = buf.readUInt16BE(pos + 2); off = 4 }
      else if (len === 127) {
        if (avail < 10) break
        const L = buf.readBigUInt64BE(pos + 2)
        if (L > BigInt(maxMessage)) return ws.close(tooLargeCode, 'too-large')
        len = Number(L); off = 10
      }
      if (!masked) return ws.close(1002, 'unmasked')
      const ctrl = op >= 0x8
      if (ctrl && (!fin || len > 125)) return ws.close(1002, 'control')
      if (!ctrl) {
        if (op === 0x1 || op === 0x2) { if (frags.length) return ws.close(1002, 'interleaved'); fragOp = op }
        else if (op !== 0x0 || !frags.length && !fragOp) return ws.close(1002, 'opcode')
        if (fragLen + len > maxMessage) return ws.close(tooLargeCode, 'too-large')
        if (frags.length >= MAX_FRAGS) return ws.close(tooLargeCode, 'too-large')
      }
      const hdr = off + 4
      if (avail < hdr + len) { need = hdr + len; break }
      const mask = buf.subarray(pos + off, pos + off + 4)
      const payload = Buffer.allocUnsafe(len)
      for (let i = 0; i < len; i++) payload[i] = buf[pos + hdr + i] ^ mask[i & 3]
      pos += hdr + len
      if (op === 0x8) {
        const code = payload.length >= 2 ? payload.readUInt16BE(0) : 1005
        try { rawSend(0x8, payload.subarray(0, 2)) } catch { /* gone */ }
        return end(code)
      }
      if (op === 0x9) { rawSend(0xa, payload); continue }
      if (op === 0xa) continue
      if (ctrl) return ws.close(1002, 'opcode')
      frags.push(payload)
      fragLen += len
      if (!fin) continue
      const whole = frags.length === 1 ? frags[0] : Buffer.concat(frags, fragLen)
      const kind = fragOp
      frags = []; fragLen = 0; fragOp = 0
      if (kind !== 0x1) return ws.close(malformedCode, 'binary')
      let msg
      try { msg = JSON.parse(whole.toString('utf8')) } catch { return ws.close(malformedCode, 'json') }
      if (!msg || typeof msg !== 'object' || Array.isArray(msg)) return ws.close(malformedCode, 'json')
      try { ws.onMessage(msg) } catch (e) { console.error('[ws] handler error', e?.stack || e) }
    }
    if (ws.alive && pos < buf.length) {
      const rest = buf.subarray(pos)
      pending = [rest.length < 65536 && buf.length > 1048576 ? Buffer.from(rest) : rest]
      pendingLen = rest.length
    }
  })
  socket.on('error', () => end(1006))
  socket.on('close', () => end(1006))
  return ws
}
