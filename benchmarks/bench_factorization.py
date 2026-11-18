"""Benchmark: key-recovery runtime vs. message length (polynomial degree).

The attack's cost is dominated by `root_finding.find_roots`: the modular
exponentiation X^(2^128) mod g(X) is always 128 squarings regardless of
degree, but each squaring/reduction step costs O(deg(g)^2) field
multiplications, and the recursive Cantor-Zassenhaus splitting afterwards
adds further O(deg(g)^2) work per level. This benchmark measures wall-clock
time to go from two colliding ciphertexts to a fully recovered key as the
number of ciphertext blocks (and hence deg(g)) grows.

Run with:
    python3 benchmarks/bench_factorization.py
"""

import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.attacks.key_recovery import recover_key_material  # noqa: E402
from src.attacks.nonce_reuse import CollidingCiphertext, build_difference_polynomial  # noqa: E402
from src.attacks.root_finding import find_roots  # noqa: E402
from src.modes.gcm import AESGCM  # noqa: E402

BLOCK_SIZE = 16


def _collide(gcm: AESGCM, nonce: bytes, pt: bytes, aad: bytes) -> CollidingCiphertext:
    ct = gcm.encrypt(nonce, pt, aad)
    return CollidingCiphertext(aad=aad, ciphertext=ct.ciphertext, tag=ct.tag)


def run_one(num_blocks: int) -> dict:
    key = os.urandom(16)
    nonce = os.urandom(12)
    gcm = AESGCM(key)

    message_len = num_blocks * BLOCK_SIZE
    first = _collide(gcm, nonce, os.urandom(message_len), b"")
    second = _collide(gcm, nonce, os.urandom(message_len), b"")
    verifier = _collide(gcm, nonce, os.urandom(message_len), b"")

    t0 = time.perf_counter()
    g = build_difference_polynomial(first, second)
    t_build = time.perf_counter() - t0

    t0 = time.perf_counter()
    candidates = find_roots(g)
    t_roots = time.perf_counter() - t0

    t0 = time.perf_counter()
    material = recover_key_material(candidates, first, [verifier])
    t_disambiguate = time.perf_counter() - t0

    true_h = gcm.h_subkey
    return {
        "blocks": num_blocks,
        "degree": g.degree(),
        "num_candidates": len(candidates),
        "build_s": t_build,
        "roots_s": t_roots,
        "disambiguate_s": t_disambiguate,
        "total_s": t_build + t_roots + t_disambiguate,
        "correct": material.h_subkey.to_bytes() == true_h,
    }


def main() -> None:
    block_counts = [1, 2, 4, 8, 16, 32]
    print(f"{'blocks':>8} {'degree':>7} {'cands':>6} {'build(s)':>10} "
          f"{'roots(s)':>10} {'disamb(s)':>10} {'total(s)':>10} {'ok':>4}")
    print("-" * 72)

    for n in block_counts:
        result = run_one(n)
        print(
            f"{result['blocks']:>8} {result['degree']:>7} {result['num_candidates']:>6} "
            f"{result['build_s']:>10.4f} {result['roots_s']:>10.4f} "
            f"{result['disambiguate_s']:>10.4f} {result['total_s']:>10.4f} "
            f"{'yes' if result['correct'] else 'NO':>4}"
        )


if __name__ == "__main__":
    main()
