"""Univariate polynomials over GF(2^128), for the nonce-reuse cryptanalysis layer.

A polynomial is represented as a tuple of GF128Element coefficients, ordered
from the constant term up: coeffs[i] is the coefficient of X^i. This module
provides the ring operations (add, mul, divmod, gcd) and the modular
exponentiation needed to isolate roots of the difference polynomial built in
`src.attacks.nonce_reuse` — the heart of the Joux forbidden-attack recovery
of the GHASH key H.
"""

from typing import List, Sequence, Tuple

from src.primitives.gf128 import GF128Element, GF128_ONE, GF128_ZERO


class Polynomial:
    """A polynomial with coefficients in GF(2^128), stored lowest-degree first."""

    __slots__ = ("coeffs",)

    def __init__(self, coeffs: Sequence[GF128Element]):
        self.coeffs: Tuple[GF128Element, ...] = _strip_trailing_zeros(tuple(coeffs))

    @classmethod
    def zero(cls) -> "Polynomial":
        return cls([])

    @classmethod
    def constant(cls, c: GF128Element) -> "Polynomial":
        return cls([c])

    @classmethod
    def monomial(cls, degree: int, coeff: GF128Element = GF128_ONE) -> "Polynomial":
        """Build coeff * X^degree."""
        return cls([GF128_ZERO] * degree + [coeff])

    def degree(self) -> int:
        """Degree of the polynomial; the zero polynomial has degree -1 by convention."""
        return len(self.coeffs) - 1

    def is_zero(self) -> bool:
        return len(self.coeffs) == 0

    def leading_coeff(self) -> GF128Element:
        if self.is_zero():
            return GF128_ZERO
        return self.coeffs[-1]

    def coeff_at(self, i: int) -> GF128Element:
        if i < 0 or i >= len(self.coeffs):
            return GF128_ZERO
        return self.coeffs[i]

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Polynomial):
            return NotImplemented
        return self.coeffs == other.coeffs

    def __add__(self, other: "Polynomial") -> "Polynomial":
        n = max(len(self.coeffs), len(other.coeffs))
        return Polynomial([self.coeff_at(i) + other.coeff_at(i) for i in range(n)])

    # Subtraction is identical to addition in characteristic 2.
    __sub__ = __add__

    def __mul__(self, other: "Polynomial") -> "Polynomial":
        if self.is_zero() or other.is_zero():
            return Polynomial.zero()

        result = [GF128_ZERO] * (self.degree() + other.degree() + 1)
        for i, a in enumerate(self.coeffs):
            if a == GF128_ZERO:
                continue
            for j, b in enumerate(other.coeffs):
                if b == GF128_ZERO:
                    continue
                result[i + j] = result[i + j] + (a * b)
        return Polynomial(result)

    def shifted(self, k: int = 1) -> "Polynomial":
        """Multiply by X^k: prepend k zero coefficients (cheaper than a full multiply)."""
        if self.is_zero() or k == 0:
            return self
        return Polynomial([GF128_ZERO] * k + list(self.coeffs))

    def scalar_mul(self, c: GF128Element) -> "Polynomial":
        if c == GF128_ZERO:
            return Polynomial.zero()
        return Polynomial([a * c for a in self.coeffs])

    def monic(self) -> "Polynomial":
        """Return this polynomial scaled so its leading coefficient is 1."""
        if self.is_zero():
            return self
        return self.scalar_mul(self.leading_coeff().inv())

    def divmod(self, divisor: "Polynomial") -> Tuple["Polynomial", "Polynomial"]:
        """Polynomial long division: returns (quotient, remainder) with
        self = quotient * divisor + remainder and deg(remainder) < deg(divisor)."""
        if divisor.is_zero():
            raise ZeroDivisionError("Polynomial division by zero polynomial")

        remainder: List[GF128Element] = list(self.coeffs)
        divisor_deg = divisor.degree()
        inv_lead = divisor.leading_coeff().inv()

        quotient_deg = self.degree() - divisor_deg
        quotient = [GF128_ZERO] * max(quotient_deg + 1, 0)

        for shift in range(quotient_deg, -1, -1):
            cur_deg = shift + divisor_deg
            if cur_deg >= len(remainder):
                continue
            coeff = remainder[cur_deg] * inv_lead
            if coeff == GF128_ZERO:
                continue
            quotient[shift] = coeff
            for j, dc in enumerate(divisor.coeffs):
                remainder[shift + j] = remainder[shift + j] + (coeff * dc)

        return Polynomial(quotient), Polynomial(remainder)

    def __mod__(self, other: "Polynomial") -> "Polynomial":
        _, r = self.divmod(other)
        return r

    def __repr__(self) -> str:
        if self.is_zero():
            return "Polynomial(0)"
        terms = " + ".join(f"({c})*X^{i}" for i, c in enumerate(self.coeffs))
        return f"Polynomial({terms})"


def _strip_trailing_zeros(coeffs: Tuple[GF128Element, ...]) -> Tuple[GF128Element, ...]:
    end = len(coeffs)
    while end > 0 and coeffs[end - 1] == GF128_ZERO:
        end -= 1
    return coeffs[:end]


def gcd(a: Polynomial, b: Polynomial) -> Polynomial:
    """Monic greatest common divisor of two polynomials via the Euclidean algorithm."""
    while not b.is_zero():
        a, b = b, a % b
    return a.monic() if not a.is_zero() else a


def pow_mod(base: Polynomial, exponent: int, modulus: Polynomial) -> Polynomial:
    """Compute base^exponent mod modulus via repeated squaring."""
    result = Polynomial.constant(GF128_ONE)
    base = base % modulus
    while exponent > 0:
        if exponent & 1:
            result = (result * base) % modulus
        base = (base * base) % modulus
        exponent >>= 1
    return result
