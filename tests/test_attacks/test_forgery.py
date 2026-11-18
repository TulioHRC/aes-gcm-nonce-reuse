import os
import unittest

from src.attacks.forgery import forge_ciphertext, forge_tag, tamper_ciphertext
from src.attacks.key_recovery import RecoveredKeyMaterial, recover_mask
from src.attacks.nonce_reuse import CollidingCiphertext
from src.modes.gcm import AESGCM
from src.primitives.gf128 import GF128Element


def _victim_and_material():
    key = os.urandom(16)
    nonce = os.urandom(12)
    gcm = AESGCM(key)
    h_subkey = GF128Element(gcm.h_subkey)
    mask = gcm.cipher.encrypt_block(nonce + b"\x00\x00\x00\x01")
    return gcm, nonce, RecoveredKeyMaterial(h_subkey=h_subkey, mask=mask)


class TestForgeTag(unittest.TestCase):
    def test_forged_tag_matches_victim_computed_tag(self):
        gcm, nonce, material = _victim_and_material()
        aad, ciphertext = os.urandom(5), os.urandom(48)

        forged_tag = forge_tag(material, aad, ciphertext)
        # The victim doesn't have an "encrypt this exact ciphertext" API, but
        # decrypt() recomputes the tag the same way encrypt() would have, so
        # accepting it here *is* the proof the forged tag is indistinguishable
        # from a real one produced under the master key.
        gcm.decrypt(nonce, ciphertext, forged_tag, aad)  # must not raise


class TestForgeCiphertext(unittest.TestCase):
    def test_arbitrary_forged_message_is_accepted_by_victim(self):
        gcm, nonce, material = _victim_and_material()
        forged = forge_ciphertext(material, b"attacker-aad", b"anything the attacker wants" * 3)

        # No exception == authentication accepted without the master key.
        gcm.decrypt(nonce, forged.ciphertext, forged.tag, forged.aad)

    def test_forged_tag_is_rejected_under_a_different_nonce(self):
        gcm, nonce, material = _victim_and_material()
        forged = forge_ciphertext(material, b"aad", b"payload")

        other_nonce = os.urandom(12)
        while other_nonce == nonce:
            other_nonce = os.urandom(12)

        from src.modes.gcm import AuthenticationError

        with self.assertRaises(AuthenticationError):
            gcm.decrypt(other_nonce, forged.ciphertext, forged.tag, forged.aad)


class TestTamperCiphertext(unittest.TestCase):
    def test_known_plaintext_region_can_be_rewritten(self):
        gcm, nonce, material = _victim_and_material()
        original_pt = b"Transfer 10 USD to Alice"
        original_aad = b"routing-header"
        original = gcm.encrypt(nonce, original_pt, original_aad)

        forged_pt = b"Transfer 99 USD to Alice"
        self.assertEqual(len(forged_pt), len(original_pt))
        patch = bytes(a ^ b for a, b in zip(original_pt, forged_pt))

        tampered = tamper_ciphertext(material, original_aad, original.ciphertext, 0, patch)
        recovered_pt = gcm.decrypt(nonce, tampered.ciphertext, tampered.tag, tampered.aad)

        self.assertEqual(recovered_pt, forged_pt)

    def test_patch_out_of_bounds_raises(self):
        gcm, nonce, material = _victim_and_material()
        original = gcm.encrypt(nonce, b"short message", b"")

        with self.assertRaises(ValueError):
            tamper_ciphertext(material, b"", original.ciphertext, 5, b"\x00" * 100)

    def test_untampered_bytes_are_unaffected(self):
        gcm, nonce, material = _victim_and_material()
        original_pt = os.urandom(32)
        original = gcm.encrypt(nonce, original_pt, b"")

        patch = bytes([0xFF])  # flip a single byte
        tampered = tamper_ciphertext(material, b"", original.ciphertext, 4, patch)
        recovered = gcm.decrypt(nonce, tampered.ciphertext, tampered.tag, b"")

        self.assertEqual(recovered[:4], original_pt[:4])
        self.assertEqual(recovered[5:], original_pt[5:])
        self.assertNotEqual(recovered[4], original_pt[4])


if __name__ == "__main__":
    unittest.main()
