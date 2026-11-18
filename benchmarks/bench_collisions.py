"""Benchmark: how often a single colliding pair already pins down a unique
key, and how many extra independent ciphertexts are needed when it doesn't.

`find_roots` on the difference polynomial from one colliding pair returns
every root in GF(2^128) — usually just the true H, but occasionally a
handful of spurious candidates (bounded by deg(g), which equals the number
of 16-byte blocks in the longer message). This benchmark reports, over many
random trials per message size, the distribution of candidate-root counts
and confirms a single extra independent ciphertext is (almost) always
enough to disambiguate.

Run with:
    python3 benchmarks/bench_collisions.py
"""

import os
import sys
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.attacks.key_recovery import narrow_to_unique_key  # noqa: E402
from src.attacks.nonce_reuse import CollidingCiphertext, build_difference_polynomial  # noqa: E402
from src.attacks.root_finding import find_roots  # noqa: E402
from src.modes.gcm import AESGCM  # noqa: E402
from src.primitives.gf128 import GF128Element  # noqa: E402

BLOCK_SIZE = 16


def _collide(gcm: AESGCM, nonce: bytes, pt: bytes, aad: bytes) -> CollidingCiphertext:
    ct = gcm.encrypt(nonce, pt, aad)
    return CollidingCiphertext(aad=aad, ciphertext=ct.ciphertext, tag=ct.tag)


def run_trials(num_blocks: int, trials: int) -> dict:
    candidate_counts = Counter()
    verifiers_needed = []
    disambiguation_failures = 0

    message_len = num_blocks * BLOCK_SIZE
    for _ in range(trials):
        key = os.urandom(16)
        nonce = os.urandom(12)
        gcm = AESGCM(key)

        first = _collide(gcm, nonce, os.urandom(message_len), b"")
        second = _collide(gcm, nonce, os.urandom(message_len), b"")

        g = build_difference_polynomial(first, second)
        candidates = find_roots(g)
        candidate_counts[len(candidates)] += 1

        if len(candidates) == 1:
            verifiers_needed.append(0)
            continue

        # Feed independent verifiers one at a time until disambiguated,
        # to measure how many extra ciphertexts the attack realistically needs.
        verifiers = []
        resolved = False
        for attempt in range(1, 4):
            verifiers.append(_collide(gcm, nonce, os.urandom(message_len), b""))
            try:
                h = narrow_to_unique_key(candidates, first, verifiers)
                verifiers_needed.append(attempt)
                resolved = True
                if h != GF128Element(gcm.h_subkey):
                    disambiguation_failures += 1
                break
            except RuntimeError:
                continue
        if not resolved:
            disambiguation_failures += 1
            verifiers_needed.append(float("inf"))

    return {
        "num_blocks": num_blocks,
        "candidate_counts": dict(candidate_counts),
        "avg_verifiers_needed": sum(v for v in verifiers_needed if v != float("inf"))
        / max(1, sum(1 for v in verifiers_needed if v != float("inf"))),
        "disambiguation_failures": disambiguation_failures,
        "trials": trials,
    }


def main() -> None:
    block_counts = [1, 2, 4, 8]
    trials_per_size = 30

    for n in block_counts:
        result = run_trials(n, trials_per_size)
        print(f"\nmessage size = {result['num_blocks']} block(s), "
              f"{result['trials']} trials")
        print(f"  candidate-root-count distribution: {result['candidate_counts']}")
        print(f"  avg extra ciphertexts needed to disambiguate: "
              f"{result['avg_verifiers_needed']:.2f}")
        print(f"  disambiguation failures: {result['disambiguation_failures']}")


if __name__ == "__main__":
    main()
