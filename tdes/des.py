"""Implementation of DES and Triple DES block ciphers with CBC support."""
from __future__ import annotations

from dataclasses import dataclass
from typing import List, Sequence

BLOCK_SIZE_BYTES = 8

# Permutation tables and constants for DES.
IP = [
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7,
]

IP_INV = [
    40, 8, 48, 16, 56, 24, 64, 32,
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41, 9, 49, 17, 57, 25,
]

EXPANSION = [
    32, 1, 2, 3, 4, 5,
    4, 5, 6, 7, 8, 9,
    8, 9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29,
    28, 29, 30, 31, 32, 1,
]

P_BOX = [
    16, 7, 20, 21,
    29, 12, 28, 17,
    1, 15, 23, 26,
    5, 18, 31, 10,
    2, 8, 24, 14,
    32, 27, 3, 9,
    19, 13, 30, 6,
    22, 11, 4, 25,
]

S_BOXES = [
    [
        [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
        [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
        [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
        [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13],
    ],
    [
        [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
        [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
        [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
        [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9],
    ],
    [
        [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
        [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
        [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
        [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12],
    ],
    [
        [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
        [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
        [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
        [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14],
    ],
    [
        [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
        [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
        [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
        [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3],
    ],
    [
        [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
        [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
        [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
        [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13],
    ],
    [
        [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
        [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
        [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
        [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12],
    ],
    [
        [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
        [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
        [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
        [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11],
    ],
]

PC1 = [
    57, 49, 41, 33, 25, 17, 9,
    1, 58, 50, 42, 34, 26, 18,
    10, 2, 59, 51, 43, 35, 27,
    19, 11, 3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15,
    7, 62, 54, 46, 38, 30, 22,
    14, 6, 61, 53, 45, 37, 29,
    21, 13, 5, 28, 20, 12, 4,
]

PC2 = [
    14, 17, 11, 24, 1, 5,
    3, 28, 15, 6, 21, 10,
    23, 19, 12, 4, 26, 8,
    16, 7, 27, 20, 13, 2,
    41, 52, 31, 37, 47, 55,
    30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53,
    46, 42, 50, 36, 29, 32,
]

SHIFTS = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]


def _permute(value: int, table: Sequence[int], input_bits: int) -> int:
    result = 0
    for position in table:
        result = (result << 1) | ((value >> (input_bits - position)) & 1)
    return result


def _left_rotate(value: int, shift: int, bit_width: int) -> int:
    mask = (1 << bit_width) - 1
    shift %= bit_width
    return ((value << shift) & mask) | (value >> (bit_width - shift))


def _sbox_substitution(value: int) -> int:
    result = 0
    for i in range(8):
        chunk = (value >> (42 - 6 * i)) & 0x3F
        row = ((chunk & 0x20) >> 4) | (chunk & 0x01)
        column = (chunk >> 1) & 0x0F
        sbox_value = S_BOXES[i][row][column]
        result = (result << 4) | sbox_value
    return result


def _feistel(right: int, subkey: int) -> int:
    expanded = _permute(right, EXPANSION, 32)
    mixed = expanded ^ subkey
    substituted = _sbox_substitution(mixed)
    return _permute(substituted, P_BOX, 32)


def _bytes_to_int(block: bytes) -> int:
    return int.from_bytes(block, byteorder="big")


def _int_to_bytes(value: int, length: int) -> bytes:
    return value.to_bytes(length, byteorder="big")


def _xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def _generate_subkeys(key: bytes) -> List[int]:
    if len(key) != BLOCK_SIZE_BYTES:
        raise ValueError("DES key must be exactly 8 bytes long")

    key_int = _bytes_to_int(key)
    permuted = _permute(key_int, PC1, 64)
    c = (permuted >> 28) & ((1 << 28) - 1)
    d = permuted & ((1 << 28) - 1)

    subkeys: List[int] = []
    for shift in SHIFTS:
        c = _left_rotate(c, shift, 28)
        d = _left_rotate(d, shift, 28)
        combined = (c << 28) | d
        subkey = _permute(combined, PC2, 56)
        subkeys.append(subkey)
    return subkeys


@dataclass
class DESBlockCipher:
    """DES block cipher implementation operating on 8-byte blocks."""

    key: bytes

    def __post_init__(self) -> None:
        self.subkeys = _generate_subkeys(self.key)

    def encrypt_block(self, block: bytes) -> bytes:
        if len(block) != BLOCK_SIZE_BYTES:
            raise ValueError("Block size must be 8 bytes")

        block_int = _bytes_to_int(block)
        permuted = _permute(block_int, IP, 64)
        left = (permuted >> 32) & 0xFFFFFFFF
        right = permuted & 0xFFFFFFFF

        for subkey in self.subkeys:
            new_left = right
            new_right = left ^ _feistel(right, subkey)
            left, right = new_left, new_right

        preoutput = (right << 32) | left
        encrypted = _permute(preoutput, IP_INV, 64)
        return _int_to_bytes(encrypted, BLOCK_SIZE_BYTES)

    def decrypt_block(self, block: bytes) -> bytes:
        if len(block) != BLOCK_SIZE_BYTES:
            raise ValueError("Block size must be 8 bytes")

        block_int = _bytes_to_int(block)
        permuted = _permute(block_int, IP, 64)
        left = (permuted >> 32) & 0xFFFFFFFF
        right = permuted & 0xFFFFFFFF

        for subkey in reversed(self.subkeys):
            new_left = right
            new_right = left ^ _feistel(right, subkey)
            left, right = new_left, new_right

        preoutput = (right << 32) | left
        decrypted = _permute(preoutput, IP_INV, 64)
        return _int_to_bytes(decrypted, BLOCK_SIZE_BYTES)


@dataclass
class TripleDES:
    """Triple DES cipher in EDE mode using three independent keys."""

    key1: bytes
    key2: bytes
    key3: bytes

    def __post_init__(self) -> None:
        self.des1 = DESBlockCipher(self.key1)
        self.des2 = DESBlockCipher(self.key2)
        self.des3 = DESBlockCipher(self.key3)

    def encrypt_block(self, block: bytes) -> bytes:
        block = self.des1.encrypt_block(block)
        block = self.des2.decrypt_block(block)
        block = self.des3.encrypt_block(block)
        return block

    def decrypt_block(self, block: bytes) -> bytes:
        block = self.des3.decrypt_block(block)
        block = self.des2.encrypt_block(block)
        block = self.des1.decrypt_block(block)
        return block


def pad_pkcs7(data: bytes, block_size: int = BLOCK_SIZE_BYTES) -> bytes:
    padding_len = block_size - (len(data) % block_size)
    if padding_len == 0:
        padding_len = block_size
    return data + bytes([padding_len] * padding_len)


def unpad_pkcs7(data: bytes, block_size: int = BLOCK_SIZE_BYTES) -> bytes:
    if not data or len(data) % block_size != 0:
        raise ValueError("Invalid padded data length")
    padding_len = data[-1]
    if padding_len < 1 or padding_len > block_size:
        raise ValueError("Invalid PKCS#7 padding")
    if data[-padding_len:] != bytes([padding_len] * padding_len):
        raise ValueError("Invalid PKCS#7 padding bytes")
    return data[:-padding_len]


def encrypt_cbc(plaintext: bytes, cipher: TripleDES, iv: bytes) -> bytes:
    if len(iv) != BLOCK_SIZE_BYTES:
        raise ValueError("IV must be 8 bytes long for DES CBC mode")

    padded = pad_pkcs7(plaintext, BLOCK_SIZE_BYTES)
    blocks = [padded[i : i + BLOCK_SIZE_BYTES] for i in range(0, len(padded), BLOCK_SIZE_BYTES)]

    result = bytearray()
    previous = iv
    for block in blocks:
        xored = _xor_bytes(block, previous)
        encrypted = cipher.encrypt_block(xored)
        result.extend(encrypted)
        previous = encrypted
    return bytes(result)


def decrypt_cbc(ciphertext: bytes, cipher: TripleDES, iv: bytes) -> bytes:
    if len(iv) != BLOCK_SIZE_BYTES:
        raise ValueError("IV must be 8 bytes long for DES CBC mode")
    if len(ciphertext) % BLOCK_SIZE_BYTES != 0:
        raise ValueError("Ciphertext is not a multiple of the block size")

    blocks = [ciphertext[i : i + BLOCK_SIZE_BYTES] for i in range(0, len(ciphertext), BLOCK_SIZE_BYTES)]

    result = bytearray()
    previous = iv
    for block in blocks:
        decrypted = cipher.decrypt_block(block)
        plaintext_block = _xor_bytes(decrypted, previous)
        result.extend(plaintext_block)
        previous = block

    return unpad_pkcs7(bytes(result), BLOCK_SIZE_BYTES)


def build_triple_des(key: bytes) -> TripleDES:
    if len(key) not in (16, 24):
        raise ValueError("3DES key must be 16 or 24 bytes long")
    if len(key) == 16:
        key += key[:8]
    return TripleDES(key[:8], key[8:16], key[16:24])


__all__ = [
    "DESBlockCipher",
    "TripleDES",
    "build_triple_des",
    "encrypt_cbc",
    "decrypt_cbc",
    "pad_pkcs7",
    "unpad_pkcs7",
]
