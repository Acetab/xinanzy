import unittest

from tdes.des import (
    BLOCK_SIZE_BYTES,
    DESBlockCipher,
    build_triple_des,
    decrypt_cbc,
    encrypt_cbc,
)


class DESTestCase(unittest.TestCase):
    def test_single_des_known_vector(self) -> None:
        key = bytes.fromhex("133457799BBCDFF1")
        plaintext = bytes.fromhex("0123456789ABCDEF")
        expected_ciphertext = bytes.fromhex("85E813540F0AB405")

        cipher = DESBlockCipher(key)
        self.assertEqual(cipher.encrypt_block(plaintext), expected_ciphertext)
        self.assertEqual(cipher.decrypt_block(expected_ciphertext), plaintext)

    def test_triple_des_degenerates_to_des_with_identical_keys(self) -> None:
        base_key = bytes.fromhex("133457799BBCDFF1")
        triple_key = base_key * 3
        block = bytes.fromhex("0123456789ABCDEF")

        des_cipher = DESBlockCipher(base_key)
        triple_cipher = build_triple_des(triple_key)

        ciphertext = triple_cipher.encrypt_block(block)
        self.assertEqual(ciphertext, des_cipher.encrypt_block(block))
        self.assertEqual(triple_cipher.decrypt_block(ciphertext), block)
        self.assertEqual(triple_cipher.decrypt_block(ciphertext), des_cipher.decrypt_block(ciphertext))

    def test_cbc_roundtrip(self) -> None:
        key = bytes(range(1, 25))
        iv = bytes(range(BLOCK_SIZE_BYTES))
        plaintext = b"Triple DES CBC mode with PKCS#7 padding!"

        cipher = build_triple_des(key)
        ciphertext = encrypt_cbc(plaintext, cipher, iv)
        recovered = decrypt_cbc(ciphertext, cipher, iv)

        self.assertEqual(recovered, plaintext)


if __name__ == "__main__":
    unittest.main()
