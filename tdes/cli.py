"""Command line interface for encrypting and decrypting files with 3DES in CBC mode."""
from __future__ import annotations

import argparse
import pathlib
import sys
from typing import Optional, Sequence

from .des import BLOCK_SIZE_BYTES, build_triple_des, decrypt_cbc, encrypt_cbc


def _parse_hex_bytes(value: str, *, expected_lengths: Optional[tuple[int, ...]] = None) -> bytes:
    stripped = value.replace(" ", "")
    if len(stripped) % 2 != 0:
        raise argparse.ArgumentTypeError("Hex string must contain an even number of characters")
    try:
        data = bytes.fromhex(stripped)
    except ValueError as exc:  # pragma: no cover - defensive programming
        raise argparse.ArgumentTypeError(f"Invalid hexadecimal data: {value}") from exc

    if expected_lengths is not None and len(data) not in expected_lengths:
        lengths = ", ".join(str(num) for num in expected_lengths)
        raise argparse.ArgumentTypeError(f"Value must decode to {lengths} bytes")
    return data


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Encrypt or decrypt files using a pure-Python implementation of 3DES "
            "with CBC mode and PKCS#7 padding."
        )
    )
    parser.add_argument("mode", choices=["encrypt", "decrypt"], help="operation to perform")
    parser.add_argument("input", type=pathlib.Path, help="path to the input file")
    parser.add_argument("output", type=pathlib.Path, help="path for the resulting file")
    parser.add_argument(
        "--key",
        required=True,
        type=lambda value: _parse_hex_bytes(value, expected_lengths=(16, 24)),
        help="3DES key encoded as 32 or 48 hexadecimal characters (16 or 24 bytes)",
    )
    parser.add_argument(
        "--iv",
        required=True,
        type=lambda value: _parse_hex_bytes(value, expected_lengths=(BLOCK_SIZE_BYTES,)),
        help="Initialization vector encoded as 16 hexadecimal characters (8 bytes)",
    )
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_argument_parser()
    args = parser.parse_args(argv)

    key_bytes: bytes = args.key
    iv: bytes = args.iv

    cipher = build_triple_des(key_bytes)

    try:
        data = args.input.read_bytes()
    except FileNotFoundError:
        parser.error(f"Input file not found: {args.input}")
    except OSError as exc:
        parser.error(f"Failed to read input file: {exc}")

    if args.mode == "encrypt":
        result = encrypt_cbc(data, cipher, iv)
    else:
        try:
            result = decrypt_cbc(data, cipher, iv)
        except ValueError as exc:
            parser.error(str(exc))
            return 2

    try:
        args.output.write_bytes(result)
    except OSError as exc:
        parser.error(f"Failed to write output file: {exc}")

    return 0


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    sys.exit(main())
