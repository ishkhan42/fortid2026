#!/usr/bin/env python3
"""Derive an Ethereum-style address from a BIP39-style phrase, fully offline.

This computes the BIP39 PBKDF2 seed and BIP32 secp256k1 child key at a
caller-supplied path. It intentionally does not validate a mnemonic word list
or checksum and never prints or writes private key material.
"""

from __future__ import annotations

import argparse
import getpass
import hashlib
import hmac
from pathlib import Path
import re
import struct
import sys
import unicodedata

_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
_G = (
    0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
)
_HARDENED = 0x80000000


def add_points(left: tuple[int, int] | None,
               right: tuple[int, int] | None) -> tuple[int, int] | None:
    if left is None:
        return right
    if right is None:
        return left
    x1, y1 = left
    x2, y2 = right
    if x1 == x2 and (y1 + y2) % _P == 0:
        return None
    if left == right:
        slope = (3 * x1 * x1 * pow(2 * y1, -1, _P)) % _P
    else:
        slope = ((y2 - y1) * pow(x2 - x1, -1, _P)) % _P
    x3 = (slope * slope - x1 - x2) % _P
    return x3, (slope * (x1 - x3) - y1) % _P


def multiply(scalar: int, point: tuple[int, int] = _G) -> tuple[int, int] | None:
    scalar %= _N
    result = None
    addend: tuple[int, int] | None = point
    while scalar:
        if scalar & 1:
            result = add_points(result, addend)
        addend = add_points(addend, addend)
        scalar >>= 1
    return result


def parse_path(path: str) -> list[int]:
    parts = path.split("/")
    if not parts or parts[0] != "m":
        raise ValueError("derivation path must start with 'm'")
    result = []
    for part in parts[1:]:
        hardened = part.endswith(("'", "h", "H"))
        number = part[:-1] if hardened else part
        if not number.isdecimal():
            raise ValueError(f"invalid derivation path component: {part!r}")
        index = int(number)
        if index >= _HARDENED:
            raise ValueError("path indices must be less than 2^31")
        result.append(index | (_HARDENED if hardened else 0))
    return result


def derive_private_key(seed: bytes, path: list[int]) -> int:
    digest = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
    key = int.from_bytes(digest[:32], "big")
    chain_code = digest[32:]
    if not 0 < key < _N:
        raise ValueError("invalid BIP32 master key")

    for index in path:
        if index >= _HARDENED:
            data = b"\x00" + key.to_bytes(32, "big")
        else:
            public = multiply(key)
            if public is None:
                raise ValueError("invalid BIP32 parent key")
            x, y = public
            prefix = b"\x02" if y % 2 == 0 else b"\x03"
            data = prefix + x.to_bytes(32, "big")
        digest = hmac.new(
            chain_code, data + struct.pack(">I", index), hashlib.sha512
        ).digest()
        left = int.from_bytes(digest[:32], "big")
        key = (left + key) % _N
        if left >= _N or key == 0:
            raise ValueError(f"invalid BIP32 child at index {index}")
        chain_code = digest[32:]
    return key


def keccak256(data: bytes) -> bytes:
    try:
        from Crypto.Hash import keccak
    except ImportError as error:
        raise RuntimeError(
            "Ethereum Keccak requires pycryptodome; install it with "
            "'python -m pip install pycryptodome'"
        ) from error
    hasher = keccak.new(digest_bits=256)
    hasher.update(data)
    return hasher.digest()


def ethereum_address(private_key: int) -> str:
    public = multiply(private_key)
    if public is None:
        raise ValueError("private key does not produce a public point")
    x, y = public
    uncompressed = x.to_bytes(32, "big") + y.to_bytes(32, "big")
    return keccak256(uncompressed)[-20:].hex()


def phrase_seed(phrase: str, passphrase: str) -> bytes:
    normalized_phrase = unicodedata.normalize("NFKD", " ".join(phrase.split()))
    normalized_passphrase = unicodedata.normalize("NFKD", passphrase)
    return hashlib.pbkdf2_hmac(
        "sha512",
        normalized_phrase.encode("utf-8"),
        ("mnemonic" + normalized_passphrase).encode("utf-8"),
        2048,
        dklen=64,
    )


def read_phrase(phrase_file: Path | None) -> str:
    if phrase_file is not None:
        return phrase_file.read_text(encoding="utf-8")
    if sys.stdin.isatty():
        return getpass.getpass("Mnemonic phrase: ")
    return sys.stdin.read()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--path", default="m/44'/60'/0'/0/0",
        help="BIP32 derivation path (default: m/44'/60'/0'/0/0)",
    )
    parser.add_argument(
        "--phrase-file", type=Path,
        help="read the phrase from a local UTF-8 file; otherwise use prompt/stdin",
    )
    parser.add_argument(
        "--passphrase-prompt", action="store_true",
        help="prompt securely for a BIP39 passphrase (default: empty)",
    )
    parser.add_argument(
        "--expected-address",
        help="compare the derived address with a caller-supplied address",
    )
    args = parser.parse_args()

    expected = None
    if args.expected_address is not None:
        expected = args.expected_address.removeprefix("0x").lower()
        if not re.fullmatch(r"[0-9a-f]{40}", expected):
            parser.error("--expected-address must be a 20-byte hexadecimal address")
    try:
        path = parse_path(args.path)
    except ValueError as error:
        parser.error(str(error))

    phrase = read_phrase(args.phrase_file)
    passphrase = (
        getpass.getpass("BIP39 passphrase: ") if args.passphrase_prompt else ""
    )
    key = derive_private_key(phrase_seed(phrase, passphrase), path)
    address = ethereum_address(key)
    print(f"0x{address}")
    if expected is None:
        return 0
    matched = address == expected
    print("match" if matched else "no match")
    return 0 if matched else 1


if __name__ == "__main__":
    raise SystemExit(main())
