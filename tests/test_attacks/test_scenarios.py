import os
import unittest

from src.demo.scenarios import run
from src.modes.gcm import AESGCM, AuthenticationError


class TestFinancialTamperingScenario(unittest.TestCase):
    def test_full_scenario_forges_an_accepted_transaction(self):
        key = os.urandom(16)
        nonce = os.urandom(12)
        victim = AESGCM(key)

        result = run(
            victim=victim,
            nonce=nonce,
            genuine_pt=b"Transfer 10 USD to Alice",
            genuine_aad=b"txn-header",
            replayed_pt=os.urandom(50),
            replayed_aad=os.urandom(5),
            independent_pt=os.urandom(70),
            independent_aad=os.urandom(4),
            tamper_offset=0,
            tampered_pt=b"Transfer 99 USD to Alice",
        )

        self.assertTrue(result.h_subkey_correct)
        self.assertTrue(result.mask_correct)
        self.assertGreaterEqual(result.num_root_candidates, 1)

        recovered = victim.decrypt(
            nonce, result.forged.ciphertext, result.forged.tag, result.forged.aad
        )
        self.assertEqual(recovered, result.tampered_plaintext)

    def test_mismatched_patch_length_raises(self):
        key = os.urandom(16)
        nonce = os.urandom(12)
        victim = AESGCM(key)

        with self.assertRaises(ValueError):
            run(
                victim=victim,
                nonce=nonce,
                genuine_pt=b"short",
                genuine_aad=b"",
                replayed_pt=os.urandom(20),
                replayed_aad=b"",
                independent_pt=os.urandom(20),
                independent_aad=b"",
                tamper_offset=0,
                tampered_pt=b"a much longer replacement",
            )

    def test_wrong_nonce_rejects_the_forgery(self):
        key = os.urandom(16)
        nonce = os.urandom(12)
        victim = AESGCM(key)

        result = run(
            victim=victim,
            nonce=nonce,
            genuine_pt=b"Transfer 10 USD to Alice",
            genuine_aad=b"txn-header",
            replayed_pt=os.urandom(50),
            replayed_aad=os.urandom(5),
            independent_pt=os.urandom(70),
            independent_aad=os.urandom(4),
            tamper_offset=0,
            tampered_pt=b"Transfer 99 USD to Alice",
        )

        other_nonce = os.urandom(12)
        while other_nonce == nonce:
            other_nonce = os.urandom(12)

        with self.assertRaises(AuthenticationError):
            victim.decrypt(
                other_nonce, result.forged.ciphertext, result.forged.tag, result.forged.aad
            )


if __name__ == "__main__":
    unittest.main()
