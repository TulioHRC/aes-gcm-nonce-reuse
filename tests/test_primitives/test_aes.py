import unittest

from src.primitives.aes import AES128, encrypt_block, key_expansion

# FIPS 197, Appendix B: AES-128 worked example.
FIPS_KEY = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
FIPS_PLAINTEXT = bytes.fromhex("00112233445566778899aabbccddeeff")
FIPS_CIPHERTEXT = bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a")

# FIPS 197, Appendix A.1: the expanded key schedule's first and last round keys
# (the schedule starts with the raw key, and both are independently exercised
# end-to-end by test_fips197_encryption_vector).
FIPS_ROUND_KEY_0 = FIPS_KEY
FIPS_ROUND_KEY_10 = bytes.fromhex("13111d7fe3944a17f307a78b4d2b30c5")


class TestAES128KnownAnswer(unittest.TestCase):
    def test_fips197_encryption_vector(self):
        self.assertEqual(encrypt_block(FIPS_KEY, FIPS_PLAINTEXT), FIPS_CIPHERTEXT)

    def test_key_expansion_round_key_0(self):
        round_keys = key_expansion(FIPS_KEY)
        flat = bytes(b for word in round_keys[0] for b in word)
        self.assertEqual(flat, FIPS_ROUND_KEY_0)

    def test_key_expansion_round_key_10(self):
        round_keys = key_expansion(FIPS_KEY)
        flat = bytes(b for word in round_keys[10] for b in word)
        self.assertEqual(flat, FIPS_ROUND_KEY_10)

    def test_key_expansion_produces_eleven_round_keys(self):
        round_keys = key_expansion(FIPS_KEY)
        self.assertEqual(len(round_keys), 11)
        for round_key in round_keys:
            self.assertEqual(len(round_key), 4)
            for word in round_key:
                self.assertEqual(len(word), 4)

    def test_rejects_wrong_key_length(self):
        with self.assertRaises(ValueError):
            encrypt_block(b"\x00" * 15, FIPS_PLAINTEXT)

    def test_rejects_wrong_block_length(self):
        with self.assertRaises(ValueError):
            encrypt_block(FIPS_KEY, b"\x00" * 15)


class TestAES128Class(unittest.TestCase):
    def test_wrapper_matches_functional_api(self):
        cipher = AES128(FIPS_KEY)
        self.assertEqual(cipher.encrypt_block(FIPS_PLAINTEXT), FIPS_CIPHERTEXT)

    def test_wrapper_reuses_expanded_key_across_calls(self):
        cipher = AES128(FIPS_KEY)
        first = cipher.encrypt_block(FIPS_PLAINTEXT)
        second = cipher.encrypt_block(FIPS_PLAINTEXT)
        self.assertEqual(first, second)
        self.assertEqual(first, FIPS_CIPHERTEXT)

    def test_different_keys_give_different_ciphertexts(self):
        cipher_a = AES128(FIPS_KEY)
        cipher_b = AES128(bytes(16))
        self.assertNotEqual(
            cipher_a.encrypt_block(FIPS_PLAINTEXT), cipher_b.encrypt_block(FIPS_PLAINTEXT)
        )


class TestAES128DifferentialAgainstReferenceLibrary(unittest.TestCase):
    """Cross-check against `cryptography`'s AES if it happens to be installed.

    This differential test is optional (see requirements.txt); it is
    skipped rather than failing when the reference library is absent.
    """

    def test_random_blocks_match_reference(self):
        try:
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        except ImportError:
            self.skipTest("optional 'cryptography' reference library not installed")

        import os

        for _ in range(100):
            key = os.urandom(16)
            block = os.urandom(16)
            mine = encrypt_block(key, block)
            encryptor = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
            reference = encryptor.update(block) + encryptor.finalize()
            self.assertEqual(mine, reference)


if __name__ == "__main__":
    unittest.main()
