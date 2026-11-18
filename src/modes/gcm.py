"""AES-GCM: the full authenticated encryption construction (NIST SP 800-38D).

    E_k(J0) = one-time mask used to blind the authentication tag
    H        = E_k(0^128), the GHASH authentication subkey
    C        = CTR_k(J0 + 1, P)                     (encryption)
    T        = GHASH_H(A, C) XOR E_k(J0)            (authentication tag)

The nonce-reuse attack this project implements depends on E_k(J0) and H
being *reused* across two encryptions under the same (key, nonce) pair —
exactly the invariant this module's `encrypt` makes visible by accepting
the nonce as an explicit argument rather than generating it internally.
"""

from dataclasses import dataclass

from src.primitives.aes import AES128
from src.modes.ctr import ctr_encrypt, incr_32
from src.modes.ghash import ghash

BLOCK_SIZE = 16
DEFAULT_TAG_LEN = 16


class AuthenticationError(Exception):
    """Raised when a GCM ciphertext fails tag verification on decryption."""


@dataclass(frozen=True)
class GCMCiphertext:
    """The output of an AES-GCM encryption: ciphertext plus authentication tag."""

    ciphertext: bytes
    tag: bytes


def _xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def compute_j0(h_subkey: bytes, nonce: bytes) -> bytes:
    """Compute the pre-counter block J0 (NIST SP 800-38D, Sec 7.1)."""
    if len(nonce) == 12:
        return nonce + b"\x00\x00\x00\x01"
    # Arbitrary-length nonce: J0 = GHASH_H(IV) with the "ciphertext" slot = IV,
    # empty associated data, per the spec's s = GHASH_H({}, IV) definition.
    return ghash(_as_gf128(h_subkey), b"", nonce)


def _as_gf128(h_subkey: bytes):
    from src.primitives.gf128 import GF128Element

    return GF128Element(h_subkey)


class AESGCM:
    """AES-128-GCM authenticated encryption, built from the primitives above."""

    def __init__(self, key: bytes, tag_len: int = DEFAULT_TAG_LEN):
        if len(key) != 16:
            raise ValueError(f"AES-128-GCM key must be 16 bytes, got {len(key)}")
        if not (4 <= tag_len <= 16):
            raise ValueError(f"Tag length must be between 4 and 16 bytes, got {tag_len}")

        self.cipher = AES128(key)
        self.tag_len = tag_len
        self.h_subkey = self.cipher.encrypt_block(b"\x00" * BLOCK_SIZE)

    def _mask_and_j0(self, nonce: bytes) -> tuple[bytes, bytes]:
        j0 = compute_j0(self.h_subkey, nonce)
        mask = self.cipher.encrypt_block(j0)
        return j0, mask

    def encrypt(self, nonce: bytes, plaintext: bytes, aad: bytes = b"") -> GCMCiphertext:
        """Encrypt `plaintext` under `nonce`, authenticating `aad` alongside it."""
        j0, mask = self._mask_and_j0(nonce)
        ciphertext = ctr_encrypt(self.cipher, incr_32(j0), plaintext)
        full_tag = _xor_bytes(ghash(_as_gf128(self.h_subkey), aad, ciphertext), mask)
        return GCMCiphertext(ciphertext=ciphertext, tag=full_tag[: self.tag_len])

    def decrypt(self, nonce: bytes, ciphertext: bytes, tag: bytes, aad: bytes = b"") -> bytes:
        """Verify `tag` and decrypt `ciphertext`; raises AuthenticationError on mismatch."""
        j0, mask = self._mask_and_j0(nonce)
        full_tag = _xor_bytes(ghash(_as_gf128(self.h_subkey), aad, ciphertext), mask)
        expected_tag = full_tag[: self.tag_len]

        if not _constant_time_eq(expected_tag, tag):
            raise AuthenticationError("GCM tag verification failed")

        return ctr_encrypt(self.cipher, incr_32(j0), ciphertext)


def _constant_time_eq(a: bytes, b: bytes) -> bool:
    if len(a) != len(b):
        return False
    diff = 0
    for x, y in zip(a, b):
        diff |= x ^ y
    return diff == 0
