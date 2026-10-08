#!/bin/sh
# Local lab relays (BUILD-PLAN §2):
#   official relay   hk1           https://127.0.0.1:18600   account "*", blobs in the fake S3 (cn-ip rule: 127.0.0.0/8 → bucket lab-cn)
#   self-hosted      r_selfhost01  https://127.0.0.1:18610   bound to one account, blobs on its own disk
#   fake S3                        http://127.0.0.1:18650
#
#   relay/scripts/dev.sh start | stop | status | logs
#   relay/scripts/dev.sh self <relayId> <account>     restart the self-hosted relay bound to that relay id and account
#
# Trust: coordination keys from $LAB/coord-keys.json (written by server/lab-v2.sh); without it a lab key is generated
# here ($LAB/relay/lab-coord.json) and only tickets signed with that key are accepted. TLS: a 127.0.0.1 certificate
# signed by the lab CA $LAB/ca/ca.crt (created here if the coordination lab has not made one). Clients trust it only
# in lab mode (node: NODE_EXTRA_CA_CERTS=$LAB/ca/ca.crt).
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
RELAY=$(cd "$HERE/.." && pwd)
REPO=$(cd "$RELAY/.." && pwd)
LAB=${POCKET_LAB:-$RELAY/.lab}
RUN=$LAB/relay
CA=$LAB/ca
mkdir -p "$RUN"

die() { echo "dev.sh: $*" >&2; exit 1; }
pid_alive() { [ -f "$1" ] && kill -0 "$(cat "$1")" 2>/dev/null; }

ensure_ca() {
  mkdir -p "$CA"; chmod 700 "$CA"
  if [ ! -f "$CA/ca.crt" ] || [ ! -f "$CA/ca.key" ]; then
    openssl ecparam -name prime256v1 -genkey -noout -out "$CA/ca.key" 2>/dev/null
    chmod 600 "$CA/ca.key"
    openssl req -x509 -new -key "$CA/ca.key" -sha256 -days 365 -subj "/CN=Pocket e2ee lab CA" -out "$CA/ca.crt" 2>/dev/null
    echo "created lab CA $CA/ca.crt"
  fi
  # a leaf for the relays (127.0.0.1 + localhost), renewed when missing or older than 20 days
  if [ ! -f "$CA/relay.crt" ] || [ -n "$(find "$CA/relay.crt" -mtime +20 2>/dev/null)" ]; then
    openssl ecparam -name prime256v1 -genkey -noout -out "$CA/relay.key" 2>/dev/null
    chmod 600 "$CA/relay.key"
    openssl req -new -key "$CA/relay.key" -subj "/CN=127.0.0.1" -out "$RUN/relay.csr" 2>/dev/null
    printf 'subjectAltName=IP:127.0.0.1,DNS:localhost\nextendedKeyUsage=serverAuth\nbasicConstraints=CA:FALSE\n' > "$RUN/relay.ext"
    openssl x509 -req -in "$RUN/relay.csr" -CA "$CA/ca.crt" -CAkey "$CA/ca.key" -set_serial "0x$(openssl rand -hex 8)" \
      -days 30 -sha256 -extfile "$RUN/relay.ext" -out "$CA/relay.crt" 2>/dev/null
    rm -f "$RUN/relay.csr" "$RUN/relay.ext"
  fi
}

ensure_keys() {
  if [ -f "$LAB/coord-keys.json" ]; then PINNED_FILE=$LAB/coord-keys.json; COORD_URL=$(node -e 'try{const j=require(process.argv[1]);process.stdout.write(j.url||"")}catch{}' "$LAB/coord-lab.json"); return; fi
  PINNED_FILE=$RUN/lab-coord-pinned.json; COORD_URL=""
  if [ ! -f "$RUN/lab-coord.json" ]; then
    node --input-type=module -e '
      import crypto from "node:crypto"; import fs from "node:fs"
      const { privateKey, publicKey } = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" })
      const j = publicKey.export({ format: "jwk" })
      const pub = Buffer.concat([Buffer.from([4]), Buffer.from(j.x, "base64url"), Buffer.from(j.y, "base64url")]).toString("base64url")
      const now = Date.now()
      fs.writeFileSync(process.argv[1], JSON.stringify({ kid: "lab-relay", priv: privateKey.export({ format: "jwk" }).d, pub }, null, 1), { mode: 0o600 })
      fs.writeFileSync(process.argv[2], JSON.stringify([{ kid: "lab-relay", pub, use: ["keys","ticket","netmap","revocations","purge"], nbf: now - 60000, exp: now + 365*86400000 }], null, 1))
    ' "$RUN/lab-coord.json" "$PINNED_FILE"
    echo "no coordination lab keys yet: generated $RUN/lab-coord.json (lab only)"
  fi
}

ensure_s3() {
  if [ ! -f "$RUN/s3-keys.json" ]; then
    AK="LAB$(openssl rand -hex 6 | tr a-z A-Z)"; SK=$(openssl rand -hex 20)
    umask 077; printf '{"%s":"%s"}\n' "$AK" "$SK" > "$RUN/s3-keys.json"; umask 022
  fi
  printf '127.0.0.0/8\n::1/128\n' > "$RUN/cn-ip.txt"
}

write_configs() {
  PINNED=$(cat "$PINNED_FILE")
  if [ -n "$COORD_URL" ]; then COORD_JSON="\"$COORD_URL\""; else COORD_JSON=null; fi
  SELF_ID=r_selfhost01; SELF_ACCT=u_lab_self
  [ -f "$RUN/self.env" ] && . "$RUN/self.env"
  cat > "$RUN/hk1.json" <<EOF
{ "relayId": "hk1", "account": "*", "publicUrl": "https://127.0.0.1:18600",
  "listen": { "host": "127.0.0.1", "port": 18600 },
  "tls": { "cert": "$CA/relay.crt", "key": "$CA/relay.key" },
  "coord": { "url": $COORD_JSON, "pinnedKeys": $PINNED, "pollSeconds": 30 },
  "dataDir": "$RUN/hk1",
  "blobs": { "store": "s3", "cnIpFile": "$RUN/cn-ip.txt", "backends": [
    { "name": "cn", "when": "cn-ip", "endpoint": "http://127.0.0.1:18650", "region": "lab-1", "bucket": "lab-cn",
      "accessKeyEnv": "RELAY_S3_LAB_KEY", "secretKeyEnv": "RELAY_S3_LAB_SECRET", "pathStyle": true, "prefix": "pocket/" },
    { "name": "default", "when": "default", "endpoint": "http://127.0.0.1:18650", "region": "lab-1", "bucket": "lab-hk",
      "accessKeyEnv": "RELAY_S3_LAB_KEY", "secretKeyEnv": "RELAY_S3_LAB_SECRET", "pathStyle": true, "prefix": "pocket/" } ] },
  "quota": { "useTicketQuota": true }
}
EOF
  cat > "$RUN/self.json" <<EOF
{ "relayId": "$SELF_ID", "account": "$SELF_ACCT", "publicUrl": "https://127.0.0.1:18610",
  "listen": { "host": "127.0.0.1", "port": 18610 },
  "tls": { "cert": "$CA/relay.crt", "key": "$CA/relay.key" },
  "coord": { "url": $COORD_JSON, "pinnedKeys": $PINNED, "pollSeconds": 30 },
  "dataDir": "$RUN/self",
  "blobs": { "store": "disk" }
}
EOF
}

start_one() {   # name config
  if pid_alive "$RUN/$1.pid"; then echo "$1 already running (pid $(cat "$RUN/$1.pid"))"; return; fi
  AK=$(node -e 'const j=require(process.argv[1]);process.stdout.write(Object.keys(j)[0])' "$RUN/s3-keys.json")
  SK=$(node -e 'const j=require(process.argv[1]);process.stdout.write(Object.values(j)[0])' "$RUN/s3-keys.json")
  RELAY_S3_LAB_KEY=$AK RELAY_S3_LAB_SECRET=$SK NODE_EXTRA_CA_CERTS=$CA/ca.crt \
    nohup node "$RELAY/src/main.mjs" --config "$2" < /dev/null >> "$RUN/$1.log" 2>&1 &
  echo $! > "$RUN/$1.pid"
}

start_s3() {
  if pid_alive "$RUN/s3.pid"; then return; fi
  nohup node "$RELAY/test/fake-s3.mjs" --port 18650 --keys-file "$RUN/s3-keys.json" < /dev/null >> "$RUN/s3.log" 2>&1 &
  echo $! > "$RUN/s3.pid"
}

wait_up() {   # url
  i=0
  while [ $i -lt 40 ]; do
    if curl -sf -m 2 --noproxy '*' --cacert "$CA/ca.crt" "$1/v1/health" >/dev/null 2>&1; then return 0; fi
    i=$((i + 1)); sleep 0.25
  done
  return 1
}

stop_one() { if pid_alive "$RUN/$1.pid"; then kill "$(cat "$RUN/$1.pid")" 2>/dev/null || true; fi; rm -f "$RUN/$1.pid"; }

case "${1:-start}" in
  start)
    ensure_ca; ensure_keys; ensure_s3; write_configs
    start_s3; start_one hk1 "$RUN/hk1.json"; start_one self "$RUN/self.json"
    wait_up https://127.0.0.1:18600 || die "hk1 did not come up; see $RUN/hk1.log"
    wait_up https://127.0.0.1:18610 || die "self-hosted relay did not come up; see $RUN/self.log"
    echo "relays up: hk1 https://127.0.0.1:18600 (account *), $(node -e 'const j=require(process.argv[1]);process.stdout.write(j.relayId+" https://127.0.0.1:18610 (account "+j.account+")")' "$RUN/self.json"), fake S3 http://127.0.0.1:18650"
    echo "coordination keys: $PINNED_FILE; CA: $CA/ca.crt; logs: $RUN/*.log"
    ;;
  self)
    [ $# -eq 3 ] || die "usage: dev.sh self <relayId> <account>"
    printf 'SELF_ID=%s\nSELF_ACCT=%s\n' "$2" "$3" > "$RUN/self.env"
    stop_one self; sleep 0.5
    ensure_ca; ensure_keys; ensure_s3; write_configs
    start_one self "$RUN/self.json"
    wait_up https://127.0.0.1:18610 || die "self-hosted relay did not come up; see $RUN/self.log"
    echo "self-hosted relay $2 for account $3 on https://127.0.0.1:18610"
    ;;
  stop) stop_one hk1; stop_one self; stop_one s3; echo "stopped" ;;
  status)
    for n in hk1 self s3; do if pid_alive "$RUN/$n.pid"; then echo "$n: running (pid $(cat "$RUN/$n.pid"))"; else echo "$n: stopped"; fi; done
    ;;
  logs) tail -n 40 "$RUN/hk1.log" "$RUN/self.log" 2>/dev/null ;;
  *) die "usage: dev.sh start | stop | status | logs | self <relayId> <account>" ;;
esac
