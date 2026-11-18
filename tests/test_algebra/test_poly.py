import random
import unittest

from src.algebra.poly import Polynomial, gcd, pow_mod
from src.primitives.gf128 import GF128Element, GF128_ONE, GF128_ZERO


def rand_elem() -> GF128Element:
    return GF128Element(random.getrandbits(128))


class TestPolynomialBasics(unittest.TestCase):
    def test_zero_polynomial_degree_is_minus_one(self):
        self.assertEqual(Polynomial.zero().degree(), -1)
        self.assertTrue(Polynomial.zero().is_zero())

    def test_strips_trailing_zero_coefficients(self):
        p = Polynomial([GF128_ONE, GF128_ZERO, GF128_ZERO])
        self.assertEqual(p.degree(), 0)

    def test_monomial_construction(self):
        p = Polynomial.monomial(3, GF128_ONE)
        self.assertEqual(p.degree(), 3)
        self.assertEqual(p.coeff_at(3), GF128_ONE)
        self.assertEqual(p.coeff_at(0), GF128_ZERO)

    def test_shifted_multiplies_by_x_power(self):
        p = Polynomial([GF128_ONE])  # constant 1
        shifted = p.shifted(3)
        self.assertEqual(shifted, Polynomial.monomial(3, GF128_ONE))

    def test_addition_is_coefficientwise_xor(self):
        a = Polynomial([GF128_ONE, rand_elem()])
        self.assertEqual(a + a, Polynomial.zero())

    def test_multiplication_distributes_over_addition(self):
        random.seed(0)
        a = Polynomial([rand_elem() for _ in range(3)])
        b = Polynomial([rand_elem() for _ in range(2)])
        c = Polynomial([rand_elem() for _ in range(4)])
        lhs = a * (b + c)
        rhs = (a * b) + (a * c)
        self.assertEqual(lhs, rhs)

    def test_square_of_linear_factor(self):
        one = GF128_ONE
        linear = Polynomial([one, one])  # X + 1
        squared = linear * linear
        expected = Polynomial([one, GF128_ZERO, one])  # X^2 + 1 (char 2)
        self.assertEqual(squared, expected)

    def test_monic_normalizes_leading_coefficient(self):
        random.seed(1)
        c = rand_elem()
        while c == GF128_ZERO:
            c = rand_elem()
        p = Polynomial([rand_elem(), c])
        self.assertEqual(p.monic().leading_coeff(), GF128_ONE)


class TestPolynomialDivision(unittest.TestCase):
    def test_exact_division_zero_remainder(self):
        one = GF128_ONE
        linear = Polynomial([one, one])  # X + 1
        product = linear * linear  # X^2 + 1
        quotient, remainder = product.divmod(linear)
        self.assertEqual(quotient, linear)
        self.assertTrue(remainder.is_zero())

    def test_division_identity_holds_for_random_polynomials(self):
        random.seed(2)
        for _ in range(20):
            degree_a = random.randint(2, 8)
            degree_b = random.randint(1, degree_a)
            a = Polynomial([rand_elem() for _ in range(degree_a + 1)]).monic()
            b = Polynomial([rand_elem() for _ in range(degree_b + 1)]).monic()
            q, r = a.divmod(b)
            self.assertTrue(r.is_zero() or r.degree() < b.degree())
            self.assertEqual((q * b) + r, a)

    def test_division_by_zero_raises(self):
        with self.assertRaises(ZeroDivisionError):
            Polynomial([GF128_ONE]).divmod(Polynomial.zero())


class TestGcd(unittest.TestCase):
    def test_gcd_of_coprime_linear_factors_is_one(self):
        random.seed(3)
        r1, r2 = rand_elem(), rand_elem()
        while r2 == r1:
            r2 = rand_elem()
        p1 = Polynomial([r1, GF128_ONE])  # X + r1
        p2 = Polynomial([r2, GF128_ONE])  # X + r2
        g = gcd(p1, p2)
        self.assertEqual(g.degree(), 0)

    def test_gcd_recovers_shared_factor(self):
        random.seed(4)
        shared = Polynomial([rand_elem(), GF128_ONE])  # X + r
        extra_a = Polynomial([rand_elem(), GF128_ONE])
        extra_b = Polynomial([rand_elem(), GF128_ONE])
        a = shared * extra_a
        b = shared * extra_b
        g = gcd(a, b)
        self.assertEqual(g, shared.monic())


class TestPowMod(unittest.TestCase):
    def test_small_exponentiation(self):
        x = Polynomial.monomial(1)
        modulus = Polynomial([GF128_ONE, GF128_ONE])  # X + 1, so X ≡ 1 mod (X+1)
        result = pow_mod(x, 5, modulus)
        self.assertEqual(result, Polynomial.constant(GF128_ONE))

    def test_matches_repeated_multiplication(self):
        random.seed(5)
        base = Polynomial([rand_elem(), rand_elem()])
        modulus = Polynomial([rand_elem(), rand_elem(), GF128_ONE]).monic()
        expected = Polynomial.constant(GF128_ONE)
        for _ in range(6):
            expected = (expected * base) % modulus
        self.assertEqual(pow_mod(base, 6, modulus), expected)


if __name__ == "__main__":
    unittest.main()
