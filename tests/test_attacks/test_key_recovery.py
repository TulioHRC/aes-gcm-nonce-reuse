import os
import unittest

from src.attacks.key_recovery import (
    narrow_to_unique_key,
    recover_key_material,
    recover_mask,
)
from src.attacks.nonce_reuse import CollidingCiphertext, build_difference_polynomial
from src.attacks.root_finding import find_roots
from src.modes.gcm import AESGCM
from src.primitives.gf128 import GF128Element


def _encrypt(gcm: AESGCM, nonce: bytes, pt: bytes, aad: bytes) -> CollidingCiphertext:
    ct = gcm.encrypt(nonce, pt, aad)
    return CollidingCiphertext(aad=aad, ciphertext=ct.ciphertext, tag=ct.tag)


class TestRecoverMask(unittest.TestCase):
    def test_true_h_recovers_true_mask(self):
        key = os.urandom(16)
        nonce = os.urandom(12)
        gcm = AESGCM(key)
        sample = _encrypt(gcm, nonce, os.urandom(30), os.urandom(4))

        true_mask = gcm.cipher.encrypt_block(nonce + b"\x00\x00\x00\x01")
        self.assertEqual(recover_mask(GF128Element(gcm.h_subkey), sample), true_mask)


class TestNarrowToUniqueKey(unittest.TestCase):
    def test_single_candidate_returned_without_verifiers(self):
        h = GF128Element(os.urandom(16))
        self.assertEqual(narrow_to_unique_key([h], baseline_sample=None, extra_verifiers=[]), h)

    def test_empty_candidates_raises(self):
        with self.assertRaises(ValueError):
            narrow_to_unique_key([], baseline_sample=None, extra_verifiers=[])

    def test_multiple_candidates_without_verifiers_raises(self):
        h1, h2 = GF128Element(1), GF128Element(2)
        with self.assertRaises(ValueError):
            narrow_to_unique_key([h1, h2], baseline_sample=None, extra_verifiers=[])


class TestEndToEndKeyRecovery(unittest.TestCase):
    def test_recovers_true_h_and_mask_across_many_trials(self):
        multi_candidate_trials = 0

        for trial in range(25):
            key = os.urandom(16)
            nonce = os.urandom(12)
            gcm = AESGCM(key)

            first = _encrypt(gcm, nonce, os.urandom(80), os.urandom(9))
            second = _encrypt(gcm, nonce, os.urandom(64), os.urandom(5))
            independent_verifier = _encrypt(gcm, nonce, os.urandom(90), os.urandom(3))

            g = build_difference_polynomial(first, second)
            roots = find_roots(g)
            if len(roots) > 1:
                multi_candidate_trials += 1

            material = recover_key_material(roots, first, [independent_verifier])

            with self.subTest(trial=trial):
                self.assertEqual(material.h_subkey, GF128Element(gcm.h_subkey))
                true_mask = gcm.cipher.encrypt_block(nonce + b"\x00\x00\x00\x01")
                self.assertEqual(material.mask, true_mask)

        # Sanity check that this test suite actually exercises the
        # multi-candidate disambiguation path and isn't accidentally
        # trivial (every polynomial happening to have exactly one root).
        self.assertGreater(multi_candidate_trials, 0)


if __name__ == "__main__":
    unittest.main()
