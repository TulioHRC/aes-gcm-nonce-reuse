"""Root extraction over GF(2^128) for the Joux forbidden-attack (Layer 4).

Finding the roots of the difference polynomial g(X) built in
`nonce_reuse.py` is the crux of recovering the GHASH key H: H is
guaranteed to be *one* of g(X)'s roots in GF(2^128). We isolate the
roots in two stages:

1. `h(X) = gcd(g(X), X^(2^128) - X)` extracts the product of g(X)'s
   distinct linear factors (every field element satisfies a^(2^128) = a,
   so X^(2^128) - X is exactly the product of (X - a) over all a in the
   field).
2. Cantor-Zassenhaus equal-degree splitting (specialized to
   characteristic 2 via the trace map) breaks h(X) apart into its
   individual linear factors, each of the form (X - root).
"""

import random
from typing import List

from src.algebra.poly import Polynomial, gcd, pow_mod
from src.primitives.gf128 import GF128Element

FIELD_BITS = 128
FIELD_SIZE = 1 << FIELD_BITS


def find_roots(poly: Polynomial) -> List[GF128Element]:
    """Return every distinct root of `poly` that lies in GF(2^128)."""
    if poly.is_zero():
        raise ValueError("The zero polynomial has every field element as a root")
    if poly.degree() <= 0:
        return []

    x = Polynomial.monomial(1)
    x_to_field_size = pow_mod(x, FIELD_SIZE, poly)   # X^(2^128) mod poly(X)
    difference = x_to_field_size + x                 # X^(2^128) - X (char 2: - is +)

    squarefree_linear_part = gcd(difference, poly)
    linear_factors = _split_into_linear_factors(squarefree_linear_part)

    # A monic linear factor is (X - root) = (X + root) in char 2, i.e. X^1 + root*X^0.
    return [factor.coeff_at(0) for factor in linear_factors]


def _split_into_linear_factors(h: Polynomial) -> List[Polynomial]:
    """Recursively split a squarefree product of linear factors into its pieces."""
    if h.degree() <= 0:
        return []
    if h.degree() == 1:
        return [h.monic()]

    while True:
        candidate_factor = _random_split_attempt(h)
        if candidate_factor is not None:
            break

    cofactor, remainder = h.divmod(candidate_factor)
    assert remainder.is_zero(), "gcd-derived factor must divide h exactly"

    return _split_into_linear_factors(candidate_factor.monic()) + _split_into_linear_factors(
        cofactor.monic()
    )


def _random_split_attempt(h: Polynomial) -> "Polynomial | None":
    """One trial of trace-based equal-degree splitting; None means 'try again'."""
    degree = h.degree()
    random_coeffs = [GF128Element(random.getrandbits(FIELD_BITS)) for _ in range(degree)]
    t = Polynomial(random_coeffs)
    if t.is_zero():
        return None

    # Trace(T) = sum_{i=0}^{127} T(X)^(2^i) mod h(X). Squaring a polynomial's
    # representative mod h implements the Frobenius endomorphism step by step.
    trace = Polynomial.zero()
    term = t % h
    for _ in range(FIELD_BITS):
        trace = trace + term
        term = (term * term) % h

    factor = gcd(trace, h)
    if factor.is_zero() or factor.degree() == 0 or factor.degree() == degree:
        return None
    return factor
