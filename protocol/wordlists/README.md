# Word lists for verification words (SAS)

These two files are the BIP-39 word lists, copied unchanged from
<https://github.com/bitcoin/bips/tree/master/bip-0039> (BIP-39 is published under the MIT License;
authors: Marek Palatinus, Pavol Rusnak, Aaron Voisine, Sean Bowe).

| File | Entries | SHA-256 of the file |
|---|---|---|
| `bip39-english.txt` | 2048 lowercase English words | `2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda` |
| `bip39-chinese-simplified.txt` | 2048 single simplified Chinese characters | `5c5942792bd8340cb8b27cd592f1015edf56a8c5b26276ee18a482428e7c5726` |

Each file is UTF-8, one entry per line, line N (0-based) = index N, with a trailing newline.
Implementations MUST ship byte-identical copies and SHOULD check the SHA-256 at build or test time.

Pocket uses them only to display the **verification words** described in `../E2EE.md` §6.
The words are a fingerprint of public keys: they are not a password, not a recovery phrase,
and never need to be written down. The UI must say so (some users know these lists from crypto wallets).
