"""Universal tag forgery: the payoff of the nonce-reuse attack.

Once `key_recovery.recover_key_material` has produced the true GHASH key H
and the one-time mask E_k(J0) for a given (key, nonce) pair, computing a
valid tag for *any* ciphertext/AAD under that same nonce needs no further
knowledge of the master key k:

    T* = GHASH_H(A*, C*) XOR E_k(J0)

This lets an attacker who intercepts two colliding ciphertexts either
tamper with one of them (same nonce, modified ciphertext, same AAD) or
author an entirely new authenticated message of their choosing, and have
it accepted by a verifier holding only the master key k.
"""

from dataclasses import dataclass

from src.attacks.key_recovery import RecoveredKeyMaterial
from src.modes.ghash import ghash


@dataclass(frozen=True)
class ForgedCiphertext:
    """A ciphertext/tag pair, authentic by GCM's rules, produced without k."""

    aad: bytes
    ciphertext: bytes
    tag: bytes


def forge_tag(key_material: RecoveredKeyMaterial, aad: bytes, ciphertext: bytes) -> bytes:
    """Compute a valid GCM tag for (aad, ciphertext) under the reused nonce,
    using only the recovered (H, mask) pair — never the master key k."""
    s = ghash(key_material.h_subkey, aad, ciphertext)
    return bytes(a ^ b for a, b in zip(s, key_material.mask))


def forge_ciphertext(
    key_material: RecoveredKeyMaterial, aad: bytes, ciphertext: bytes
) -> ForgedCiphertext:
    """Package an attacker-chosen (aad, ciphertext) with its forged tag."""
    tag = forge_tag(key_material, aad, ciphertext)
    return ForgedCiphertext(aad=aad, ciphertext=ciphertext, tag=tag)


def tamper_ciphertext(
    key_material: RecoveredKeyMaterial,
    original_aad: bytes,
    original_ciphertext: bytes,
    patch_offset: int,
    patch: bytes,
) -> ForgedCiphertext:
    """Flip arbitrary bytes of an intercepted ciphertext (same AAD, same
    nonce) and re-forge a tag that the victim's decryptor will accept.

    Since CTR-mode ciphertext bytes are just keystream XOR plaintext, the
    attacker does not need to know the keystream to change the plaintext:
    XOR-ing the known `patch` directly onto the ciphertext flips the
    corresponding plaintext bits to whatever the attacker wants, and the
    recovered (H, mask) pair lets them re-forge a matching tag without
    ever touching the master key.
    """
    if patch_offset < 0 or patch_offset + len(patch) > len(original_ciphertext):
        raise ValueError("Patch does not fit within the original ciphertext")

    tampered = bytearray(original_ciphertext)
    for i, patch_byte in enumerate(patch):
        tampered[patch_offset + i] ^= patch_byte

    return forge_ciphertext(key_material, original_aad, bytes(tampered))
