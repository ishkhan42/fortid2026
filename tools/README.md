# Offline analysis tools

These tools were authored or adapted by project contributors during local,
offline CTF analysis. The retained code is our own analysis tooling; no
organizer source, handouts, challenge inputs, third-party code, binaries,
caches, credentials, flags, or target-specific identifiers are included.
Dependencies are named, not vendored. Entry points operate on caller-supplied
local files, text, or standard input and make no network requests.

## ELF call-graph fingerprints

`elf_fingerprint.py` reads sized function symbols from an ELF64 x86-64 `.text`
section and summarizes direct calls plus immediate values used by memory `xor`
and `not` instructions. It writes per-function structural and semantic hashes
and duplicate counts. This is a heuristic for comparing binary structure, not a
decompiler or proof of semantic equivalence. Indirect calls are not followed;
recursive direct-call graphs are reported as errors.

Dependencies: Python 3.10+, `pyelftools`, and `capstone`.

```sh
python -m pip install pyelftools capstone
python tools/elf_fingerprint.py ./local-program --output /tmp/program.fingerprints.json
python tools/elf_fingerprint.py ./local-program --symbol-regex 'parser_.*'
```

The default output is `<binary>.fingerprints.json`; `--output` chooses another
local path. Function selection uses Python regular-expression search and
defaults to every named, sized function in `.text`.

## PMAF image renderer

`pmaf_render.py` applies a local PMAF v1 stream to a local starting image and
writes an RGB PNG. The format contains a 40-byte header and keyed 8-byte
operations; the native C core uses incremental 4-connected component tracking
for repeated fills. The script builds `pmaf_renderer.c` as a shared library in
the system temporary directory on first use, keyed by the source hash. It does
not modify the input files or require challenge-specific directory names.

Dependencies: Python 3.10+, NumPy, Pillow, and a C11 compiler available as `cc`
(or the executable named by `CC`).

```sh
python -m pip install numpy Pillow
python tools/pmaf_render.py ./start.png ./operations.pmaf ./rendered.png
```

The Python API is also available as `render(start_png, pmaf_bytes)`, returning
an `(height, width, 3)` `uint8` NumPy array.

## QR overlay SAT search

`qr_overlay_sat.py` searches for a shared 21×21 module matrix whose two
caller-supplied uppercase alphanumeric messages remain within the modeled
version-1 QR error-correction limits under a selected reflection/rotation.
It varies both QR masks and can optionally pin corresponding module
coordinates with `--anchor ROW,COLUMN`. This is a specialized SAT model, not a
general QR encoder; each SAT call has time and conflict budgets, so finding no
model is not proof that no overlay exists. The `.npz` output contains the
module matrix and selected data suffixes.

Dependencies: Python 3.10+, NumPy, `qrcode`, `python-sat`, and `pycryptosat`
(the `CryptoMinisat` backend). Matrix construction uses `qrcode` encoder
internals and may need adaptation if that library changes those internals.

```sh
python tools/qr_overlay_sat.py "A" "B" --output /tmp/overlay.npz --reflection yes --rotations 1 --time-budget 0.25
```

Try `--help` for error-correction, transform, anchor, and solver-budget options.


## Offline wallet derivation

`wallet_derive.py` derives an Ethereum-style address from a caller-supplied
phrase using BIP39 NFKD/PBKDF2 seed derivation and BIP32 secp256k1 child-key
derivation. It defaults to `m/44'/60'/0'/0/0`; `--path` accepts another BIP32
path. It does not validate the phrase against a BIP39 word list or checksum.
The address is computed locally with Keccak-256; no RPC, explorer, or wallet
service is used. Private keys are never printed or written.

Use this for offline analysis only, not as a signing wallet or audited key
manager: the pure-Python elliptic-curve arithmetic is not constant-time.

Dependency: Python 3.10+ and `pycryptodome`.

```sh
python -m pip install pycryptodome
python tools/wallet_derive.py                       # hidden interactive phrase prompt
cat /path/to/local-phrase.txt | python tools/wallet_derive.py
python tools/wallet_derive.py --phrase-file /path/to/local-phrase.txt --path "m/44'/60'/0'/0/0"
python tools/wallet_derive.py --phrase-file /path/to/local-phrase.txt --expected-address "$EXPECTED_ADDRESS"
```

Use only a phrase you control; do not put a real phrase in shell history or
share it with anyone. `--passphrase-prompt` requests an optional BIP39
passphrase through a hidden prompt. The supplied phrase and expected address are
not stored by this tool.

## Verification during archival cleanup

The retained command-line tools were exercised offline on 2026-10-12:

- ELF analysis processed 5,030 functions in the local reference binary and reproduced known selector subtree-XOR invariants.
- PMAF part 01 rendered pixel-for-pixel identically to the retained reference image. Larger parts and runtime performance are not certified by that check.
- Wallet derivation matched a standard public mnemonic test vector without emitting private keys.
- The QR search produced an overlay for distinct messages `A` and `B`; an independent OpenCV decoder read both messages in the corresponding transformed views. An identity-view `HELLO` example also decoded correctly. A longer distinct-message search was interrupted without a result; no success or impossibility is asserted for it.

The observed environment used `qrcode` 8.2, `python-sat` 1.9.dev15, and
`pycryptosat` 5.17.0. These checks do not establish correctness for every
input, library version, or model.
