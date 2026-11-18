"""The Joux "forbidden attack": setting up the key-recovery equation.

When two messages are encrypted under AES-GCM with the *same* (key, nonce)
pair, both tags are blinded by the identical one-time mask E_k(J0):

    T  = GHASH_H(A,  C)  XOR E_k(J0)
    T' = GHASH_H(A', C') XOR E_k(J0)

Adding the two equations cancels the mask entirely:

    T XOR T' = GHASH_H(A, C) XOR GHASH_H(A', C')

The right-hand side, written out via Horner's rule with the unknown key H
left symbolic as a variable X, is a polynomial g(X) of degree at most
max(blocks in message 1, blocks in message 2). The true H is guaranteed to
be one of its roots in GF(2^128) — see `root_finding.find_roots`.
"""

from dataclasses import dataclass

from src.algebra.poly import Polynomial
from src.modes.ghash import ghash_blocks
from src.primitives.gf128 import GF128Element


@dataclass(frozen=True)
class CollidingCiphertext:
    """One side of a nonce-reuse collision: an AEAD output under a reused nonce."""

    aad: bytes
    ciphertext: bytes
    tag: bytes


def _symbolic_ghash(aad: bytes, ciphertext: bytes) -> Polynomial:
    """Replay GHASH's Horner accumulation with H left as the polynomial
    variable X, i.e. build S(X) such that S(H) == GHASH_H(aad, ciphertext)."""
    acc = Polynomial.zero()
    for block in ghash_blocks(aad, ciphertext):
        acc = (acc + Polynomial.constant(GF128Element(block))).shifted(1)
    return acc


def build_difference_polynomial(
    first: CollidingCiphertext, second: CollidingCiphertext
) -> Polynomial:
    """Build g(X) = GHASH_X(A,C) + GHASH_X(A',C') + (T + T'), whose roots in
    GF(2^128) include the true authentication key H (NIST SP 800-38D GHASH key).
    """
    s1 = _symbolic_ghash(first.aad, first.ciphertext)
    s2 = _symbolic_ghash(second.aad, second.ciphertext)
    tag_difference = Polynomial.constant(GF128Element(first.tag) + GF128Element(second.tag))
    return s1 + s2 + tag_difference
