// Operational log (RELAY.md §11): time, relay id, account, address, operation, sizes, status, latency, client IP.
// Never: envelope / object / blob bytes, seal headers, tickets, tokens, nonces, presigned URLs, Authorization headers.
// Callers pass only those safe fields; this module additionally drops any field whose name suggests a secret.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

const FORBIDDEN = /^(ticket|token|nonce|url|auth|authorization|env|seal|h|c|s|a|sig|body|key|secret|presigned|claim)$/i
const SAFE_VALUE = /^[\w .:@*/+,=()\-[\]'"]{0,200}$/u

/** relayId: a string, or a function (a relay that is claimed while running changes its id). */
export function createLogger({ relayId, format = 'text', sink = (line) => process.stdout.write(line + '\n'), now = Date.now } = {}) {
  const rid = () => (typeof relayId === 'function' ? relayId() : relayId)
  function clean(fields) {
    const out = {}
    for (const [k, v] of Object.entries(fields || {})) {
      if (v === undefined || v === null || FORBIDDEN.test(k)) continue
      if (typeof v === 'number' || typeof v === 'boolean') out[k] = v
      else {
        const s = String(v)
        out[k] = SAFE_VALUE.test(s) ? s : s.replace(/[^\w .:@*/+,=()\-[\]]/gu, '?').slice(0, 200)
      }
    }
    return out
  }
  function write(level, op, fields) {
    const f = clean(fields)
    const t = new Date(now()).toISOString()
    if (format === 'json') sink(JSON.stringify({ t, level, relay: rid(), op, ...f }))
    else sink(`${t} ${level} ${rid()} ${op}${Object.entries(f).map(([k, v]) => ` ${k}=${typeof v === 'string' && /\s/.test(v) ? JSON.stringify(v) : v}`).join('')}`)
  }
  return {
    info: (op, fields) => write('info', op, fields),
    warn: (op, fields) => write('warn', op, fields),
    error: (op, fields) => write('error', op, fields),
  }
}
