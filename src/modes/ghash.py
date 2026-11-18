"""GHASH universal hash function (NIST SP 800-38D, Sec 6.4).

GHASH_H(A, C) processes the associated data A and ciphertext C in 16-byte
blocks (zero-padding each to a full block), accumulating via Horner's rule
in GF(2^128) under the hash subkey H, and finishes with a length block
encoding bit-lengths of A and C as two 64-bit big-endian integers.
"""

from src.primitives.gf128 import GF128Element, GF128_ZERO

BLOCK_SIZE = 16


def _pad_to_block(data: bytes) -> bytes:
    """Zero-pad `data` on the right up to the next multiple of 16 bytes."""
    remainder = len(data) % BLOCK_SIZE
    if remainder == 0:
        return data
    return data + b"\x00" * (BLOCK_SIZE - remainder)


def _blocks(data: bytes):
    padded = _pad_to_block(data)
    for offset in range(0, len(padded), BLOCK_SIZE):
        yield padded[offset: offset + BLOCK_SIZE]


def ghash_blocks(aad: bytes, ciphertext: bytes):
    """Yield the exact sequence of 16-byte blocks GHASH folds in, in order:
    padded AAD blocks, then padded ciphertext blocks, then the length block.

    Exposed (not prefixed `_`) so `src.attacks.nonce_reuse` can replay the
    same Horner accumulation symbolically, with H left as an unknown X.
    """
    yield from _blocks(aad)
    yield from _blocks(ciphertext)
    yield (len(aad) * 8).to_bytes(8, "big") + (len(ciphertext) * 8).to_bytes(8, "big")


def ghash(h: GF128Element, aad: bytes, ciphertext: bytes) -> bytes:
    """Compute GHASH_H(A, C) and return it as 16 raw bytes."""
    acc = GF128_ZERO
    for block in ghash_blocks(aad, ciphertext):
        acc = (acc + GF128Element(block)) * h
    return acc.to_bytes()
