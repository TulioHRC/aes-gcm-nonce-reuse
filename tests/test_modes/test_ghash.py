import unittest

from src.modes.ghash import ghash
from src.primitives.aes import AES128
from src.primitives.gf128 import GF128Element, GF128_ZERO


class TestGhash(unittest.TestCase):
    def test_zero_key_gives_zero_hash(self):
        """GHASH_0(A, C) == 0 for any A, C: every Horner step multiplies by H=0."""
        result = ghash(GF128_ZERO, b"associated data", b"some ciphertext bytes")
        self.assertEqual(result, bytes(16))

    def test_output_is_16_bytes(self):
        h = GF128Element(bytes(range(16)))
        for aad_len, ct_len in [(0, 0), (1, 0), (0, 1), (7, 23), (16, 16), (33, 50)]:
            result = ghash(h, bytes(aad_len), bytes(ct_len))
            self.assertEqual(len(result), 16)

    def test_sensitive_to_ciphertext_changes(self):
        h = GF128Element(bytes(range(1, 17)))
        base = ghash(h, b"", b"\x00" * 32)
        changed = ghash(h, b"", b"\x01" + b"\x00" * 31)
        self.assertNotEqual(base, changed)

    def test_sensitive_to_aad_changes(self):
        h = GF128Element(bytes(range(1, 17)))
        base = ghash(h, b"aad-one", b"ciphertext")
        changed = ghash(h, b"aad-two", b"ciphertext")
        self.assertNotEqual(base, changed)

    def test_matches_nist_sp800_38d_test_case_2(self):
        """Derive H and the GHASH output from the full NIST SP 800-38D Test
        Case 2 GCM vector (verified against the `cryptography` library in
        test_gcm.py), confirming the GHASH building block in isolation."""
        key = bytes(16)
        ciphertext = bytes.fromhex("0388dace60b6a392f328c2b971b2fe78")
        tag = bytes.fromhex("ab6e47d42cec13bdf53a67b21257bddf")
        j0 = bytes(12) + b"\x00\x00\x00\x01"

        cipher = AES128(key)
        h = GF128Element(cipher.encrypt_block(bytes(16)))
        mask = cipher.encrypt_block(j0)

        s = ghash(h, b"", ciphertext)
        recovered_tag = bytes(a ^ b for a, b in zip(s, mask))
        self.assertEqual(recovered_tag, tag)


if __name__ == "__main__":
    unittest.main()
