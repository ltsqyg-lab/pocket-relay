# Pocket protocol

| Document | What it covers |
|---|---|
| [E2EE.md](E2EE.md) | Cryptography: device keys, the device lock, verification words, realms and grants, envelopes, stored objects, attachments, coordination-signed documents |
| [RELAY.md](RELAY.md) | The relay (this repository) |
| [COORD.md](COORD.md) | The coordination server API that devices use (accounts, devices, the lock, tickets, revocations) |
| [ASR.md](ASR.md) | The speech gateway ([pocket-asr](https://github.com/ltsqyg-lab/pocket-asr)) |
| [vectors.json](vectors.json) | Test vectors; `node gen-vectors.mjs --check` rebuilds them and runs the independent checks |
| [pake.mjs](pake.mjs) | Pairing-code reference implementation (SPAKE2 over P-256, RFC 9382); `node --test pake.test.mjs` |
