"""Counter (CTR) mode, as used internally by AES-GCM (NIST SP 800-38D, Sec 6.5).

GCM's counter is a 128-bit block split as [96-bit nonce/prefix || 32-bit counter],
where only the low 32 bits increment (wrapping modulo 2^32); the top 96 bits of
the counter block stay fixed for the whole message. This is the "incr_32"
operation from the spec, distinct from a generic full-128-bit increment.
"""

from src.primitives.aes import AES128

BLOCK_SIZE = 16


def incr_32(block: bytes) -> bytes:
    """Increment the rightmost 32 bits of a 16-byte block, wrapping mod 2^32."""
    if len(block) != BLOCK_SIZE:
        raise ValueError(f"CTR block must be {BLOCK_SIZE} bytes, got {len(block)}")
    prefix, counter = block[:12], block[12:]
    next_counter = ((int.from_bytes(counter, "big") + 1) & 0xFFFFFFFF).to_bytes(4, "big")
    return prefix + next_counter


def _xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def ctr_encrypt(cipher: AES128, icb: bytes, data: bytes) -> bytes:
    """Encrypt (or decrypt, since CTR is self-inverse) `data` under GCM's CTR mode.

    `icb` is the initial counter block J0+1-style starting block (already
    positioned at the first keystream block the caller wants); each successive
    16-byte chunk of `data` is XORed with E_k(counter), and the counter's low
    32 bits increment between blocks per `incr_32`.
    """
    if len(icb) != BLOCK_SIZE:
        raise ValueError(f"Initial counter block must be {BLOCK_SIZE} bytes, got {len(icb)}")

    out = bytearray()
    counter = icb
    for offset in range(0, len(data), BLOCK_SIZE):
        chunk = data[offset: offset + BLOCK_SIZE]
        keystream = cipher.encrypt_block(counter)
        out.extend(_xor_bytes(chunk, keystream[: len(chunk)]))
        counter = incr_32(counter)
    return bytes(out)
