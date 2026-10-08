#!/usr/bin/env node
// Pocket relay entry point.
//   node src/main.mjs [--config relay.json]   start (or RELAY_CONFIG=…; every value can also come from RELAY_* variables)
//   node src/main.mjs --health                liveness probe for containers: asks this relay's /v1/health on loopback
//   node src/main.mjs --version
//
// SPDX-License-Identifier: AGPL-3.0-or-later
import fs from 'node:fs'
import http from 'node:http'
import https from 'node:https'
import { loadConfig, ConfigError } from './config.mjs'

const args = process.argv.slice(2)
const { createRelay, VERSION } = await import('./relay.mjs')
if (args.includes('--version')) { console.log(`pocket-relay ${VERSION}`); process.exit(0) }

const ci = args.indexOf('--config')
let file = ci >= 0 ? args[ci + 1] : process.env.RELAY_CONFIG || null
if (!file && fs.existsSync('/etc/pocket-relay/relay.json')) file = '/etc/pocket-relay/relay.json'

let cfg
try { cfg = loadConfig({ file }) } catch (e) {
  if (e instanceof ConfigError) { console.error(`pocket-relay: ${e.message}`); process.exit(78) }
  throw e
}

if (args.includes('--health')) health()
else await run()

function health() {
  const mod = cfg.tls ? https : http
  const req = mod.get({ host: '127.0.0.1', port: cfg.listen.port, path: '/v1/health', rejectUnauthorized: false, timeout: 4000 },
    (res) => process.exit(res.statusCode === 200 ? 0 : 1))
  req.on('error', () => process.exit(1))
  req.on('timeout', () => { req.destroy(); process.exit(1) })
}

// Last line of defence: an exception thrown in some callback must not drop every user's connection with it. Log it
// with its stack and keep serving; more than 20 in a minute means the state is broken, so exit and let the supervisor
// restart the relay (red team 2026-10-08: one such throw used to end the process).
let fatalBurst = []
function fatal(kind, e) {
  console.error(JSON.stringify({ t: new Date().toISOString(), level: 'error', op: kind, error: String(e?.stack || e).slice(0, 2000) }))
  const t = Date.now()
  fatalBurst = fatalBurst.filter((x) => t - x < 60_000)
  fatalBurst.push(t)
  if (fatalBurst.length > 20) { console.error('pocket-relay: too many unexpected errors in a minute, exiting'); process.exit(1) }
}

async function run() {
  process.on('uncaughtException', (e) => fatal('uncaught-exception', e))
  process.on('unhandledRejection', (e) => fatal('unhandled-rejection', e))
  const relay = await createRelay(cfg)
  const addr = await relay.listen()
  relay.log.info('started', { version: VERSION, account: cfg.account, port: addr.port, tls: !!cfg.tls, store: cfg.blobs.store })
  let stopping = false
  const stop = async (sig) => {
    if (stopping) return
    stopping = true
    relay.log.info('stopping', { signal: sig })
    await relay.close()
    process.exit(0)
  }
  process.on('SIGTERM', () => stop('SIGTERM'))
  process.on('SIGINT', () => stop('SIGINT'))
}
