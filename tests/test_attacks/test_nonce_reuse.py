import os
import unittest

from src.attacks.nonce_reuse import CollidingCiphertext, build_difference_polynomial
from src.attacks.root_finding import find_roots
from src.modes.gcm import AESGCM
from src.primitives.gf128 import GF128Element


def _encrypt(gcm: AESGCM, nonce: bytes, pt: bytes, aad: bytes) -> CollidingCiphertext:
    ct = gcm.encrypt(nonce, pt, aad)
    return CollidingCiphertext(aad=aad, ciphertext=ct.ciphertext, tag=ct.tag)


class TestBuildDifferencePolynomial(unittest.TestCase):
    def test_true_h_is_always_a_root(self):
        """The core guarantee of the forbidden attack: whatever else is in
        the polynomial's root set, the true GHASH key must be among them."""
        for trial in range(15):
            key = os.urandom(16)
            nonce = os.urandom(12)
            gcm = AESGCM(key)

            first = _encrypt(gcm, nonce, os.urandom(1 + trial * 7), os.urandom(trial))
            second = _encrypt(gcm, nonce, os.urandom(1 + trial * 3), os.urandom(trial + 1))

            g = build_difference_polynomial(first, second)
            roots = find_roots(g)

            h_true = GF128Element(gcm.h_subkey)
            with self.subTest(trial=trial):
                self.assertIn(h_true, roots)

    def test_handles_messages_of_different_lengths(self):
        key = os.urandom(16)
        nonce = os.urandom(12)
        gcm = AESGCM(key)

        first = _encrypt(gcm, nonce, os.urandom(5), b"")
        second = _encrypt(gcm, nonce, os.urandom(200), os.urandom(30))

        g = build_difference_polynomial(first, second)
        self.assertFalse(g.is_zero())
        roots = find_roots(g)
        self.assertIn(GF128Element(gcm.h_subkey), roots)

    def test_identical_messages_give_zero_polynomial(self):
        """Encrypting the exact same (aad, plaintext) twice under the same
        nonce yields identical ciphertext and tag, so the difference is 0."""
        key = os.urandom(16)
        nonce = os.urandom(12)
        gcm = AESGCM(key)
        pt, aad = os.urandom(40), os.urandom(5)

        first = _encrypt(gcm, nonce, pt, aad)
        second = _encrypt(gcm, nonce, pt, aad)

        g = build_difference_polynomial(first, second)
        self.assertTrue(g.is_zero())


if __name__ == "__main__":
    unittest.main()
