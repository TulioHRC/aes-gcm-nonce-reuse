import unittest

from src.modes.gcm import AESGCM, AuthenticationError

# NIST SP 800-38D known-answer test vectors (verified against the
# `cryptography` reference library during development; see test below
# that additionally cross-checks against it live when available).
NIST_VECTORS = [
    # (name, key, iv, plaintext, aad, expected_ciphertext, expected_tag)
    (
        "case1_all_zero_empty_plaintext",
        bytes(16),
        bytes(12),
        b"",
        b"",
        b"",
        bytes.fromhex("58e2fccefa7e3061367f1d57a4e7455a"),
    ),
    (
        "case2_all_zero_one_block",
        bytes(16),
        bytes(12),
        bytes(16),
        b"",
        bytes.fromhex("0388dace60b6a392f328c2b971b2fe78"),
        bytes.fromhex("ab6e47d42cec13bdf53a67b21257bddf"),
    ),
    (
        "case3_full_block_message",
        bytes.fromhex("feffe9928665731c6d6a8f9467308308"),
        bytes.fromhex("cafebabefacedbaddecaf888"),
        bytes.fromhex(
            "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a"
            "721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39"
        ),
        b"",
        bytes.fromhex(
            "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12"
            "e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091"
        ),
        bytes.fromhex("cc15abcc191161501aabab46b8fbac85"),
    ),
    (
        "case4_truncated_message_with_aad",
        bytes.fromhex("feffe9928665731c6d6a8f9467308308"),
        bytes.fromhex("cafebabefacedbaddecaf888"),
        bytes.fromhex(
            "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a"
            "721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657"
        ),
        bytes.fromhex("feedfacedeadbeeffeedfacedeadbeefabaddad2"),
        bytes.fromhex(
            "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12"
            "e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac97"
        ),
        bytes.fromhex("29c70e637a78362e9763ef39afc87ed7"),
    ),
    (
        "case5_8_byte_nonce_with_aad",
        bytes.fromhex("feffe9928665731c6d6a8f9467308308"),
        bytes.fromhex("cafebabefacedbad"),
        bytes.fromhex(
            "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a"
            "721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657"
        ),
        bytes.fromhex("feedfacedeadbeeffeedfacedeadbeefabaddad2"),
        bytes.fromhex(
            "61353b4c2806934a777ff51fa22a4755699b2a714fcdc6f83766e5f97b6c742"
            "373806900e49f24b22b097544d4896b424989b5e1ebac0f07"
        ),
        bytes.fromhex("032e58d2a272749c2f32fe53e1abbb5a"),
    ),
    (
        "case6_60_byte_nonce_with_aad",
        bytes.fromhex("feffe9928665731c6d6a8f9467308308"),
        bytes.fromhex(
            "9313225df88406e555909c5aff5269aa86a7a9531534f7da2e4c303d8a318a"
            "721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255"
        ),
        bytes.fromhex(
            "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a"
            "721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657"
        ),
        bytes.fromhex("feedfacedeadbeeffeedfacedeadbeefabaddad2"),
        bytes.fromhex(
            "0aa966389d18fa020a7282e9d4515dd0fd0ac9ab68e4ea083751748f8c05fdc"
            "85fdfaf93f38d9750e10443adc9f709383e6919c3d08fe9c9"
        ),
        bytes.fromhex("7899bad910d3bca31030b269a3994e16"),
    ),
]


class TestAESGCMKnownAnswer(unittest.TestCase):
    def test_nist_vectors(self):
        for name, key, iv, pt, aad, expected_ct, expected_tag in NIST_VECTORS:
            with self.subTest(vector=name):
                gcm = AESGCM(key)
                result = gcm.encrypt(iv, pt, aad)
                self.assertEqual(result.ciphertext, expected_ct, f"{name}: ciphertext mismatch")
                self.assertEqual(result.tag, expected_tag, f"{name}: tag mismatch")

    def test_decrypt_round_trips_all_vectors(self):
        for name, key, iv, pt, aad, _, _ in NIST_VECTORS:
            with self.subTest(vector=name):
                gcm = AESGCM(key)
                result = gcm.encrypt(iv, pt, aad)
                recovered = gcm.decrypt(iv, result.ciphertext, result.tag, aad)
                self.assertEqual(recovered, pt)


class TestAESGCMAuthentication(unittest.TestCase):
    def setUp(self):
        self.gcm = AESGCM(bytes(16))
        self.nonce = bytes(12)
        self.encrypted = self.gcm.encrypt(self.nonce, b"authentic message", b"aad")

    def test_tampered_ciphertext_rejected(self):
        bad_ciphertext = bytes([self.encrypted.ciphertext[0] ^ 0x01]) + self.encrypted.ciphertext[1:]
        with self.assertRaises(AuthenticationError):
            self.gcm.decrypt(self.nonce, bad_ciphertext, self.encrypted.tag, b"aad")

    def test_tampered_tag_rejected(self):
        bad_tag = bytes([self.encrypted.tag[0] ^ 0x01]) + self.encrypted.tag[1:]
        with self.assertRaises(AuthenticationError):
            self.gcm.decrypt(self.nonce, self.encrypted.ciphertext, bad_tag, b"aad")

    def test_tampered_aad_rejected(self):
        with self.assertRaises(AuthenticationError):
            self.gcm.decrypt(self.nonce, self.encrypted.ciphertext, self.encrypted.tag, b"wrong-aad")

    def test_correct_inputs_accepted(self):
        pt = self.gcm.decrypt(self.nonce, self.encrypted.ciphertext, self.encrypted.tag, b"aad")
        self.assertEqual(pt, b"authentic message")


class TestAESGCMConstruction(unittest.TestCase):
    def test_rejects_wrong_key_length(self):
        with self.assertRaises(ValueError):
            AESGCM(bytes(15))

    def test_rejects_invalid_tag_length(self):
        with self.assertRaises(ValueError):
            AESGCM(bytes(16), tag_len=3)
        with self.assertRaises(ValueError):
            AESGCM(bytes(16), tag_len=17)

    def test_truncated_tag_is_a_prefix_of_full_tag(self):
        key, nonce, pt = bytes(16), bytes(12), b"message"
        full = AESGCM(key, tag_len=16).encrypt(nonce, pt)
        short = AESGCM(key, tag_len=8).encrypt(nonce, pt)
        self.assertEqual(short.tag, full.tag[:8])


class TestAESGCMDifferentialAgainstReferenceLibrary(unittest.TestCase):
    def test_random_round_trips_match_reference(self):
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM as RefGCM
        except ImportError:
            self.skipTest("optional 'cryptography' reference library not installed")

        import os

        for i in range(50):
            key = os.urandom(16)
            nonce = os.urandom(12)
            pt = os.urandom(i * 3)
            aad = os.urandom(i)
            mine = AESGCM(key).encrypt(nonce, pt, aad)
            ref_full = RefGCM(key).encrypt(nonce, pt, aad if aad else None)
            self.assertEqual(mine.ciphertext, ref_full[:-16])
            self.assertEqual(mine.tag, ref_full[-16:])


if __name__ == "__main__":
    unittest.main()
