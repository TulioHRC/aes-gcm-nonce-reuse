"""A practical attack scenario: tampering with a financial transaction that
was accidentally encrypted twice under the same (key, nonce) pair.

This module packages the full attack pipeline (nonce_reuse -> root_finding
-> key_recovery -> forgery) into a single `run` function the CLI can call,
modeling a situation like a buggy client that resets its nonce counter
after a crash and re-sends a similar packet under the same nonce it used
before the crash.
"""

from dataclasses import dataclass

from src.attacks.forgery import ForgedCiphertext, tamper_ciphertext
from src.attacks.key_recovery import RecoveredKeyMaterial, recover_key_material
from src.attacks.nonce_reuse import CollidingCiphertext, build_difference_polynomial
from src.attacks.root_finding import find_roots
from src.modes.gcm import AESGCM
from src.primitives.gf128 import GF128Element


@dataclass(frozen=True)
class ScenarioResult:
    """Everything a caller (e.g. the CLI) needs to narrate the attack."""

    num_root_candidates: int
    recovered_key_material: RecoveredKeyMaterial
    h_subkey_correct: bool
    mask_correct: bool
    original_plaintext: bytes
    tampered_plaintext: bytes
    forged: ForgedCiphertext


def run(
    victim: AESGCM,
    nonce: bytes,
    genuine_pt: bytes,
    genuine_aad: bytes,
    replayed_pt: bytes,
    replayed_aad: bytes,
    independent_pt: bytes,
    independent_aad: bytes,
    tamper_offset: int,
    tampered_pt: bytes,
) -> ScenarioResult:
    """Simulate: the victim reuses `nonce` for two messages (a bug), an
    attacker observes both plus one more message under the same nonce, and
    uses them to forge a modified version of the first message that the
    victim's own decryptor will accept as authentic.
    """
    first = _collide(victim, nonce, genuine_pt, genuine_aad)
    second = _collide(victim, nonce, replayed_pt, replayed_aad)
    independent = _collide(victim, nonce, independent_pt, independent_aad)

    g = build_difference_polynomial(first, second)
    candidates = find_roots(g)

    material = recover_key_material(candidates, first, [independent])

    true_h = GF128Element(victim.h_subkey)
    true_mask = victim.cipher.encrypt_block(nonce + b"\x00\x00\x00\x01")

    if len(tampered_pt) != len(genuine_pt):
        raise ValueError("tampered_pt must be the same length as genuine_pt for an in-place patch")
    patch = bytes(a ^ b for a, b in zip(genuine_pt, tampered_pt))

    forged = tamper_ciphertext(material, genuine_aad, first.ciphertext, tamper_offset, patch)

    return ScenarioResult(
        num_root_candidates=len(candidates),
        recovered_key_material=material,
        h_subkey_correct=material.h_subkey == true_h,
        mask_correct=material.mask == true_mask,
        original_plaintext=genuine_pt,
        tampered_plaintext=tampered_pt,
        forged=forged,
    )


def _collide(gcm: AESGCM, nonce: bytes, pt: bytes, aad: bytes) -> CollidingCiphertext:
    ct = gcm.encrypt(nonce, pt, aad)
    return CollidingCiphertext(aad=aad, ciphertext=ct.ciphertext, tag=ct.tag)
