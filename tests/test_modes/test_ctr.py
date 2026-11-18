import unittest

from src.modes.ctr import ctr_encrypt, incr_32
from src.primitives.aes import AES128


class TestIncr32(unittest.TestCase):
    def test_increments_low_32_bits(self):
        block = bytes(12) + b"\x00\x00\x00\x01"
        self.assertEqual(incr_32(block), bytes(12) + b"\x00\x00\x00\x02")

    def test_leaves_prefix_untouched(self):
        block = bytes(range(12)) + b"\x00\x00\x00\x05"
        result = incr_32(block)
        self.assertEqual(result[:12], bytes(range(12)))

    def test_wraps_mod_2_32(self):
        block = bytes(12) + b"\xff\xff\xff\xff"
        self.assertEqual(incr_32(block), bytes(12) + b"\x00\x00\x00\x00")

    def test_rejects_wrong_length(self):
        with self.assertRaises(ValueError):
            incr_32(bytes(15))


class TestCtrEncrypt(unittest.TestCase):
    def setUp(self):
        self.cipher = AES128(bytes(16))
        self.icb = bytes(16)

    def test_self_inverse(self):
        plaintext = b"The quick brown fox jumps over the lazy dog!!!"
        ciphertext = ctr_encrypt(self.cipher, self.icb, plaintext)
        recovered = ctr_encrypt(self.cipher, self.icb, ciphertext)
        self.assertEqual(recovered, plaintext)

    def test_handles_partial_final_block(self):
        plaintext = b"exactly 20 bytes!!!!"
        self.assertEqual(len(plaintext), 20)
        ciphertext = ctr_encrypt(self.cipher, self.icb, plaintext)
        self.assertEqual(len(ciphertext), 20)
        self.assertEqual(ctr_encrypt(self.cipher, self.icb, ciphertext), plaintext)

    def test_handles_empty_input(self):
        self.assertEqual(ctr_encrypt(self.cipher, self.icb, b""), b"")

    def test_different_counters_give_different_keystream(self):
        plaintext = bytes(16)
        ct1 = ctr_encrypt(self.cipher, self.icb, plaintext)
        ct2 = ctr_encrypt(self.cipher, incr_32(self.icb), plaintext)
        self.assertNotEqual(ct1, ct2)


if __name__ == "__main__":
    unittest.main()
