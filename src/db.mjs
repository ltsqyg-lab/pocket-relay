// Relay index: SQLite (node:sqlite) for identities seen, revocation cut-offs, realms, objects, queued envelopes,
// blobs, presigned uploads handed out, traffic counters and each account's newest ticket quota (RELAY.md §8.1).
// Object and blob bodies live in files next to it.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
import fs from 'node:fs'
import path from 'node:path'

// node:sqlite prints an ExperimentalWarning on Node 22; it is stable enough for this use and the warning is noise
// in a service log. Only that one warning is filtered.
const origEmit = process.emitWarning
process.emitWarning = function (w, ...rest) {
  const msg = typeof w === 'string' ? w : w?.message
  if (msg && /SQLite is an experimental feature/.test(msg)) return
  return origEmit.call(process, w, ...rest)
}
const { DatabaseSync } = await import('node:sqlite')

const SCHEMA = `
CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS idents (addr TEXT PRIMARY KEY, acct TEXT NOT NULL, dev TEXT NOT NULL, kind TEXT NOT NULL, last_seen INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS idents_acct ON idents (acct);
CREATE TABLE IF NOT EXISTS cutoffs (addr TEXT PRIMARY KEY, dev TEXT, acct TEXT, nbf INTEGER NOT NULL, gone INTEGER NOT NULL DEFAULT 0, at INTEGER NOT NULL, keep_until INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS realms (realm TEXT PRIMARY KEY, acct TEXT NOT NULL, rev INTEGER NOT NULL DEFAULT 0, purged_rev INTEGER NOT NULL DEFAULT 0);
CREATE INDEX IF NOT EXISTS realms_acct ON realms (acct);
CREATE TABLE IF NOT EXISTS objects (
  realm TEXT NOT NULL, kind TEXT NOT NULL, key TEXT NOT NULL, seq INTEGER NOT NULL DEFAULT 0,
  ver INTEGER NOT NULL, bytes INTEGER NOT NULL, at INTEGER NOT NULL, last_read INTEGER NOT NULL, rev INTEGER NOT NULL,
  del INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (realm, kind, key, seq));
CREATE INDEX IF NOT EXISTS objects_rev ON objects (realm, rev);
CREATE TABLE IF NOT EXISTS queue (
  q INTEGER PRIMARY KEY AUTOINCREMENT, rcpt TEXT NOT NULL, acct TEXT NOT NULL, sender TEXT NOT NULL, fid TEXT NOT NULL,
  env TEXT NOT NULL, bytes INTEGER NOT NULL, at INTEGER NOT NULL, expires INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS queue_rcpt ON queue (rcpt, q);
CREATE INDEX IF NOT EXISTS queue_exp ON queue (expires);
CREATE TABLE IF NOT EXISTS blobs (
  realm TEXT NOT NULL, blob TEXT NOT NULL, acct TEXT NOT NULL, bytes INTEGER NOT NULL, store TEXT NOT NULL, backend TEXT,
  uploader TEXT NOT NULL, state TEXT NOT NULL, created INTEGER NOT NULL, expires INTEGER, last_read INTEGER,
  PRIMARY KEY (realm, blob));
CREATE INDEX IF NOT EXISTS blobs_acct ON blobs (acct);
CREATE INDEX IF NOT EXISTS blobs_state ON blobs (state, expires);
CREATE TABLE IF NOT EXISTS presigns (realm TEXT NOT NULL, blob TEXT NOT NULL, backend TEXT NOT NULL, at INTEGER NOT NULL, PRIMARY KEY (realm, blob, backend));
CREATE INDEX IF NOT EXISTS presigns_at ON presigns (at);
CREATE TABLE IF NOT EXISTS traffic (acct TEXT NOT NULL, period TEXT NOT NULL, bytes INTEGER NOT NULL, PRIMARY KEY (acct, period));
CREATE TABLE IF NOT EXISTS acct_quota (acct TEXT PRIMARY KEY, iat INTEGER NOT NULL, quota TEXT);
CREATE TABLE IF NOT EXISTS rev_cursor (acct TEXT PRIMARY KEY, cursor INTEGER NOT NULL, at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS purges (id TEXT PRIMARY KEY, at INTEGER NOT NULL);
`

export class Store {
  constructor(dataDir) {
    this.dir = dataDir
    fs.mkdirSync(dataDir, { recursive: true, mode: 0o700 })
    for (const d of ['o', 'b', 'tmp']) fs.mkdirSync(path.join(dataDir, d), { recursive: true, mode: 0o700 })
    const file = path.join(dataDir, 'relay.db')
    this.db = new DatabaseSync(file)
    try { fs.chmodSync(file, 0o600) } catch { /* not ours to change */ }
    this.db.exec('PRAGMA journal_mode = WAL; PRAGMA synchronous = NORMAL; PRAGMA foreign_keys = OFF; PRAGMA busy_timeout = 5000;')
    this.db.exec(SCHEMA)
    this.st = {}
    const p = (name, sql) => { this.st[name] = this.db.prepare(sql) }
    p('metaGet', 'SELECT v FROM meta WHERE k = ?')
    p('metaSet', 'INSERT INTO meta (k, v) VALUES (?, ?) ON CONFLICT (k) DO UPDATE SET v = excluded.v')
    // identities
    p('identGet', 'SELECT * FROM idents WHERE addr = ?')
    p('identPut', `INSERT INTO idents (addr, acct, dev, kind, last_seen) VALUES (?, ?, ?, ?, ?)
      ON CONFLICT (addr) DO UPDATE SET acct = excluded.acct, dev = excluded.dev, kind = excluded.kind, last_seen = excluded.last_seen`)
    p('identTouch', 'UPDATE idents SET last_seen = ? WHERE addr = ?')
    p('identsOfAcct', 'SELECT * FROM idents WHERE acct = ?')
    p('identDel', 'DELETE FROM idents WHERE addr = ?')
    p('identsOld', 'DELETE FROM idents WHERE last_seen < ?')
    // cut-offs
    p('cutAll', 'SELECT * FROM cutoffs')
    p('cutPut', `INSERT INTO cutoffs (addr, dev, acct, nbf, gone, at, keep_until) VALUES (?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT (addr) DO UPDATE SET dev = excluded.dev, acct = excluded.acct, nbf = excluded.nbf, gone = excluded.gone, at = excluded.at, keep_until = excluded.keep_until`)
    p('cutDel', 'DELETE FROM cutoffs WHERE addr = ?')
    p('cutOld', 'SELECT addr FROM cutoffs WHERE keep_until < ?')
    // realms
    p('realmGet', 'SELECT * FROM realms WHERE realm = ?')
    p('realmAdd', 'INSERT INTO realms (realm, acct, rev, purged_rev) VALUES (?, ?, 0, 0) ON CONFLICT (realm) DO NOTHING')
    p('realmBump', 'UPDATE realms SET rev = rev + 1 WHERE realm = ? RETURNING rev')
    p('realmPurged', 'UPDATE realms SET purged_rev = MAX(purged_rev, ?) WHERE realm = ?')
    p('realmDel', 'DELETE FROM realms WHERE realm = ?')
    p('realmsOfAcct', 'SELECT realm FROM realms WHERE acct = ?')
    // objects
    p('objGet', 'SELECT * FROM objects WHERE realm = ? AND kind = ? AND key = ? AND seq = ?')
    p('objPut', `INSERT INTO objects (realm, kind, key, seq, ver, bytes, at, last_read, rev, del) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0)
      ON CONFLICT (realm, kind, key, seq) DO UPDATE SET ver = excluded.ver, bytes = excluded.bytes, at = excluded.at,
        last_read = excluded.last_read, rev = excluded.rev, del = 0`)
    p('objTomb', `INSERT INTO objects (realm, kind, key, seq, ver, bytes, at, last_read, rev, del) VALUES (?, ?, ?, ?, ?, 0, ?, ?, ?, 1)
      ON CONFLICT (realm, kind, key, seq) DO UPDATE SET ver = excluded.ver, bytes = 0, at = excluded.at, last_read = excluded.last_read, rev = excluded.rev, del = 1`)
    p('objDelRow', 'DELETE FROM objects WHERE realm = ? AND kind = ? AND key = ? AND seq = ?')
    p('objSeqs', 'SELECT seq, ver FROM objects WHERE realm = ? AND kind = ? AND key = ? AND seq > 0 AND del = 0')
    p('objTouch', 'UPDATE objects SET last_read = ? WHERE realm = ? AND kind = ? AND key = ? AND seq = ?')
    p('objChanges', `SELECT kind, key, seq, ver, bytes, at, rev, del FROM objects WHERE realm = ? AND rev > ? ORDER BY rev LIMIT ?`)
    p('objExisting', `SELECT kind, key, seq, ver, bytes, at, rev, del FROM objects WHERE realm = ? AND rev > ? AND del = 0 ORDER BY rev LIMIT ?`)
    p('objHeads', `SELECT key, MAX(seq) AS last, COUNT(*) AS count FROM objects WHERE realm = ? AND kind = ? AND del = 0 AND seq > 0 GROUP BY key ORDER BY key`)
    p('objKeyHeads', `SELECT key, ver FROM objects WHERE realm = ? AND kind = ? AND del = 0 AND seq = 0 ORDER BY key`)
    p('objRange', `SELECT seq, ver, bytes, last_read FROM objects WHERE realm = ? AND kind = 'msg' AND key = ? AND seq > ? AND del = 0 ORDER BY seq LIMIT ?`)
    p('objLast', `SELECT MAX(seq) AS last FROM objects WHERE realm = ? AND kind = ? AND key = ? AND del = 0 AND seq > 0`)
    p('objOfRealm', 'SELECT kind, key, seq, del FROM objects WHERE realm = ?')
    p('objDelRealm', 'DELETE FROM objects WHERE realm = ?')
    p('objCountRealm', 'SELECT COUNT(*) AS n FROM objects WHERE realm = ? AND del = 0')
    // stored bytes of an account's objects (RELAY.md §8.3; deletion markers have 0 bytes)
    p('objBytesOfAcct', 'SELECT COALESCE(SUM(o.bytes), 0) AS b FROM realms r JOIN objects o ON o.realm = r.realm WHERE r.acct = ? AND o.del = 0')
    // stale = neither written nor read since the cut-off; the session list, info and usage of a computer seen in the
    // last week are kept (RELAY.md §8.2)
    p('objStale', `SELECT realm, kind, key, seq FROM objects WHERE del = 0 AND at < ? AND last_read < ?
      AND NOT (kind IN ('sess', 'info', 'usage') AND realm IN (SELECT addr FROM idents WHERE last_seen >= ?)) LIMIT 2000`)
    p('objOldTombs', `SELECT realm, kind, key, seq, rev FROM objects WHERE del = 1 AND at < ? LIMIT 5000`)
    // queue
    p('qAdd', 'INSERT INTO queue (rcpt, acct, sender, fid, env, bytes, at, expires) VALUES (?, ?, ?, ?, ?, ?, ?, ?)')
    p('qStats', 'SELECT COUNT(*) AS n, COALESCE(SUM(bytes), 0) AS b FROM queue WHERE rcpt = ?')
    p('qFor', 'SELECT q, sender, env, at FROM queue WHERE rcpt = ? AND expires > ? ORDER BY q LIMIT ?')
    p('qAck', 'DELETE FROM queue WHERE q = ? AND rcpt = ?')
    p('qExpired', 'SELECT q, rcpt, sender, fid FROM queue WHERE expires <= ? ORDER BY q LIMIT 1000')
    p('qDel', 'DELETE FROM queue WHERE q = ?')
    p('qDelFor', 'DELETE FROM queue WHERE rcpt = ?')
    p('qDelAcct', 'DELETE FROM queue WHERE acct = ?')
    // blobs
    p('blobGet', 'SELECT * FROM blobs WHERE realm = ? AND blob = ?')
    p('blobReserve', `INSERT INTO blobs (realm, blob, acct, bytes, store, backend, uploader, state, created, expires, last_read)
      VALUES (?, ?, ?, ?, ?, ?, ?, 'reserved', ?, ?, NULL)`)
    p('blobReplaceReservation', `UPDATE blobs SET bytes = ?, store = ?, backend = ?, uploader = ?, created = ?, expires = ? WHERE realm = ? AND blob = ? AND state = 'reserved'`)
    p('blobCommit', `UPDATE blobs SET state = 'ready', store = ?, backend = ?, expires = NULL, created = ? WHERE realm = ? AND blob = ?`)
    p('blobDel', 'DELETE FROM blobs WHERE realm = ? AND blob = ?')
    p('blobTouch', 'UPDATE blobs SET last_read = ? WHERE realm = ? AND blob = ?')
    p('blobsOfRealm', 'SELECT * FROM blobs WHERE realm = ?')
    p('blobsOfAcct', 'SELECT * FROM blobs WHERE acct = ?')
    p('blobStoreUsed', `SELECT COALESCE(SUM(bytes), 0) AS b FROM blobs WHERE acct = ? AND state != 'dead'`)
    p('blobExpiredRes', `SELECT * FROM blobs WHERE state = 'reserved' AND expires < ? LIMIT 1000`)
    p('blobStale', `SELECT * FROM blobs WHERE state = 'ready' AND COALESCE(last_read, created) < ? LIMIT 1000`)
    p('blobDead', `SELECT * FROM blobs WHERE state = 'dead' LIMIT 1000`)
    p('blobMarkDead', `UPDATE blobs SET state = 'dead' WHERE realm = ? AND blob = ?`)
    p('blobActiveRes', `SELECT COUNT(*) AS n FROM blobs WHERE uploader = ? AND state = 'reserved' AND created > ?`)
    // presigned PUTs handed out, watched for a day: an upload that lands after its blob row is gone is deleted (§9)
    p('presignPut', `INSERT INTO presigns (realm, blob, backend, at) VALUES (?, ?, ?, ?) ON CONFLICT (realm, blob, backend) DO UPDATE SET at = excluded.at`)
    p('presignDue', 'SELECT realm, blob, backend, at FROM presigns WHERE at < ? ORDER BY at LIMIT ?')
    p('presignDel', 'DELETE FROM presigns WHERE realm = ? AND blob = ? AND backend = ?')
    // traffic, revocation cursors, purges
    p('trafAdd', `INSERT INTO traffic (acct, period, bytes) VALUES (?, ?, ?) ON CONFLICT (acct, period) DO UPDATE SET bytes = bytes + excluded.bytes`)
    p('trafGet', 'SELECT bytes FROM traffic WHERE acct = ? AND period = ?')
    p('trafDelAcct', 'DELETE FROM traffic WHERE acct = ?')
    p('trafOld', 'DELETE FROM traffic WHERE period < ?')
    // the newest ticket seen per account: its quota applies to every device of the account (RELAY.md §8.3)
    p('acctQuotaGet', 'SELECT iat, quota FROM acct_quota WHERE acct = ?')
    p('acctQuotaPut', `INSERT INTO acct_quota (acct, iat, quota) VALUES (?, ?, ?)
      ON CONFLICT (acct) DO UPDATE SET iat = excluded.iat, quota = excluded.quota WHERE excluded.iat > acct_quota.iat`)
    p('acctQuotaDel', 'DELETE FROM acct_quota WHERE acct = ?')
    p('curGet', 'SELECT cursor FROM rev_cursor WHERE acct = ?')
    p('curSet', 'INSERT INTO rev_cursor (acct, cursor, at) VALUES (?, ?, ?) ON CONFLICT (acct) DO UPDATE SET cursor = excluded.cursor, at = excluded.at')
    p('purgeSeen', 'SELECT at FROM purges WHERE id = ?')
    p('purgeAdd', 'INSERT OR IGNORE INTO purges (id, at) VALUES (?, ?)')
    p('purgeOld', 'DELETE FROM purges WHERE at < ?')
    p('identAccts', 'SELECT DISTINCT acct FROM idents')
    p('acctsWithData', `SELECT DISTINCT acct FROM realms UNION SELECT DISTINCT acct FROM blobs UNION SELECT DISTINCT acct FROM queue`)
  }

  run(name, ...args) { return this.st[name].run(...args) }
  get(name, ...args) { return this.st[name].get(...args) }
  all(name, ...args) { return this.st[name].all(...args) }

  tx(fn) {
    this.db.exec('BEGIN IMMEDIATE')
    try { const r = fn(); this.db.exec('COMMIT'); return r } catch (e) { try { this.db.exec('ROLLBACK') } catch { /* already rolled back */ } throw e }
  }

  meta(k, v) {
    if (v === undefined) return this.get('metaGet', k)?.v ?? null
    this.run('metaSet', k, String(v))
  }

  close() { try { this.db.close() } catch { /* closed */ } }
}
