"""Disambiguating the true GHASH key H and recovering the one-time mask.

`root_finding.find_roots` returns every candidate root of the difference
polynomial built from a *single* colliding pair (first, second) — usually
more than one, since most roots of g(X) are algebraic artifacts, not the
true key. Critically, checking a candidate root against `first` or
`second` *individually* proves nothing: by construction of g(X), every one
of its roots satisfies GHASH_h(first) XOR GHASH_h(second) == T1 XOR T2, so
the masks recovered from `first` and `second` always agree with each
other, for every candidate, true or false.

Disambiguation therefore requires a genuinely independent third ciphertext
encrypted under the same reused nonce. Only the true H reproduces the same
recovered mask from that independent sample as it does from the original
pair; false roots agree on the original pair (tautologically) but diverge
on anything new, with probability roughly 2^-128 of a false collision.
"""

from dataclasses import dataclass
from typing import Sequence

from src.attacks.nonce_reuse import CollidingCiphertext
from src.modes.ghash import ghash
from src.primitives.gf128 import GF128Element


@dataclass(frozen=True)
class RecoveredKeyMaterial:
    """Everything the attacker needs to forge ciphertexts under the reused nonce."""

    h_subkey: GF128Element
    mask: bytes  # E_k(J0), the one-time pad that blinds the tag


def recover_mask(h_subkey: GF128Element, sample: CollidingCiphertext) -> bytes:
    """Compute the candidate one-time mask E_k(J0) = T XOR GHASH_H(A, C)."""
    s = ghash(h_subkey, sample.aad, sample.ciphertext)
    return bytes(a ^ b for a, b in zip(s, sample.tag))


def narrow_to_unique_key(
    candidates: Sequence[GF128Element],
    baseline_sample: CollidingCiphertext,
    extra_verifiers: Sequence[CollidingCiphertext],
) -> GF128Element:
    """Identify the single true H out of `candidates`.

    `baseline_sample` must be one of the two ciphertexts that produced
    `candidates` (either side of the colliding pair). `extra_verifiers`
    must be *independent* ciphertexts encrypted under the same reused
    nonce — NOT `baseline_sample`'s pair partner, since that pairing is
    tautologically consistent for every root (see module docstring).

    A candidate survives a verifier round only if the mask it implies via
    `baseline_sample` matches the mask it implies via that verifier.
    """
    if not candidates:
        raise ValueError("No candidate roots given; nothing to narrow")

    surviving = list(candidates)
    if len(surviving) == 1:
        return surviving[0]

    if not extra_verifiers:
        raise ValueError(
            "Multiple candidate roots remain; at least one ciphertext that is "
            "independent of the colliding pair (same reused nonce) is "
            "required to disambiguate H"
        )

    for verifier in extra_verifiers:
        if len(surviving) == 1:
            break
        surviving = [
            h
            for h in surviving
            if recover_mask(h, baseline_sample) == recover_mask(h, verifier)
        ]

    if len(surviving) != 1:
        raise RuntimeError(
            f"Could not uniquely identify H: {len(surviving)} candidates remain "
            "after all verifier samples; provide another colliding ciphertext"
        )
    return surviving[0]


def recover_key_material(
    candidates: Sequence[GF128Element],
    baseline_sample: CollidingCiphertext,
    extra_verifiers: Sequence[CollidingCiphertext] = (),
) -> RecoveredKeyMaterial:
    """End-to-end: pick out the true H, then compute the mask it implies."""
    h = narrow_to_unique_key(candidates, baseline_sample, extra_verifiers)
    mask = recover_mask(h, baseline_sample)
    return RecoveredKeyMaterial(h_subkey=h, mask=mask)
