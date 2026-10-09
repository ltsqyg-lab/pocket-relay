#!/usr/bin/env node
// Pocket relay entry point.
//   node src/main.mjs [--config relay.json]   start (or RELAY_CONFIG=…; every value can also come from RELAY_* variables)
//   node src/main.mjs connect-string          print the line to paste into the Pocket App again (RELAY.md §12.1)
//   node src/main.mjs reset-claim             unbind this relay and make a new claim code (a running relay notices)
//   node src/main.mjs --health                liveness probe for containers: asks this relay's /v1/info on loopback
//   node src/main.mjs --version
//
// SPDX-License-Identifier: AGPL-3.0-or-later
import fs from 'node:fs'
import http from 'node:http'
import https from 'node:https'
import { loadConfig, ConfigError } from './config.mjs'
import { claimFiles, connectInfo, connectBlock, noLineText, newClaim, readBinding, removeBinding, writeFileAtomic } from './claim.mjs'

const args = process.argv.slice(2)
const { createRelay, VERSION } = await import('./relay.mjs')
if (args.includes('--version')) { console.log(`pocket-relay ${VERSION}`); process.exit(0) }
const COMMANDS = ['connect-string', 'reset-claim']
const command = args.find((a) => COMMANDS.includes(a)) ?? null
const unknown = args.find((a, i) => !a.startsWith('--') && !COMMANDS.includes(a) && args[i - 1] !== '--config')
if (unknown) { console.error(`pocket-relay: unknown command ${JSON.stringify(unknown)} (commands: ${COMMANDS.join(', ')})`); process.exit(64) }

const ci = args.indexOf('--config')
let file = ci >= 0 ? args[ci + 1] : process.env.RELAY_CONFIG || null
if (!file && fs.existsSync('/etc/pocket-relay/relay.json')) file = '/etc/pocket-relay/relay.json'

let cfg
try { cfg = loadConfig({ file }) } catch (e) {
  if (e instanceof ConfigError) { console.error(`pocket-relay: ${e.message}`); process.exit(78) }
  throw e
}

if (args.includes('--health')) health()
else if (command === 'connect-string') connectString()
else if (command === 'reset-claim') resetClaim()
else await run()

function health() {
  const mod = cfg.tlsMode === 'off' ? http : https
  const host = ['0.0.0.0', '::', '127.0.0.1', '::1', 'localhost'].includes(cfg.listen.host) ? '127.0.0.1' : cfg.listen.host
  // /v1/info answers in every state, also before the relay is claimed (then /v1/health is 503 `unclaimed`)
  const req = mod.get({ host, port: cfg.listen.port, path: '/v1/info', rejectUnauthorized: false, timeout: 4000 },
    (res) => process.exit(res.statusCode === 200 ? 0 : 1))
  req.on('error', () => process.exit(1))
  req.on('timeout', () => { req.destroy(); process.exit(1) })
}

function connectString() {
  const info = connectInfo({ cfg })
  if (!info.line) { process.stderr.write(noLineText(info.why, { cfg })); process.exit(1) }
  process.stdout.write(connectBlock(info, { file: claimFiles(cfg.dataDir).connect }))
}

function resetClaim() {
  if (cfg.relayId) {
    console.error('pocket-relay: relayId and account come from the configuration; remove them from it (and the RELAY_RELAY_ID / RELAY_ACCOUNT variables) to claim this relay from the Pocket App instead.')
    process.exit(1)
  }
  if (!fs.existsSync(cfg.dataDir)) { console.error(`pocket-relay: no data directory ${cfg.dataDir}; start the relay first.`); process.exit(1) }
  const was = readBinding(cfg.dataDir)
  newClaim(cfg.dataDir)                // the new code first, then the binding goes: a running relay never sees neither
  removeBinding(cfg.dataDir)
  console.log(was ? `Unbound from relay ${was.relayId} (account ${was.account}). A running relay notices within a few seconds and closes its connections.`
    : 'New claim code made; the old one no longer works.')
  const info = connectInfo({ cfg })
  if (!info.line) { process.stderr.write(noLineText(info.why, { cfg })); return }
  writeFileAtomic(claimFiles(cfg.dataDir).connect, info.line + '\n', 0o600)
  process.stdout.write(connectBlock(info, { file: claimFiles(cfg.dataDir).connect }))
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
  let relay, addr
  try {
    relay = await createRelay(cfg)
    addr = await relay.listen()
  } catch (e) {
    // the two mistakes people make when running it by hand: a data directory they cannot write, a port in use
    if (['EACCES', 'EPERM', 'EROFS'].includes(e?.code) && !e.syscall?.startsWith('listen')) {
      console.error(`pocket-relay: cannot write the data directory ${cfg.dataDir} (${e.code}); choose another one with RELAY_DATA_DIR=<directory>`)
      process.exit(78)
    }
    if (e?.code === 'EADDRINUSE' || e?.code === 'EACCES') {
      console.error(`pocket-relay: cannot listen on ${cfg.listen.host}:${cfg.listen.port} (${e.code}); choose another port with RELAY_LISTEN_PORT=<port>`)
      process.exit(78)
    }
    throw e
  }
  const st = relay.state
  relay.log.info('started', { version: VERSION, state: st.bound ? 'claimed' : 'unclaimed', account: cfg.account, port: addr.port, tls: cfg.tlsMode,
    pin: st.pin, host: st.publicHost, store: cfg.blobs.store })
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
