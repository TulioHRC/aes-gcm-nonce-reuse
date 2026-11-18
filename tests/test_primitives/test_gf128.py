import unittest

from src.primitives.gf128 import GF128Element, GF128_ONE, GF128_ZERO


class TestGF128FieldAxioms(unittest.TestCase):
    """Exercise GF(2^128) as an actual field: identities, inverses, distributivity."""

    def setUp(self):
        self.a = GF128Element(bytes(range(16)))
        self.b = GF128Element(bytes(range(16, 32)))
        self.c = GF128Element(0x0123456789ABCDEF0123456789ABCDEF)

    def test_addition_is_xor_and_self_inverse(self):
        self.assertEqual(self.a + self.a, GF128_ZERO)
        self.assertEqual(self.a + GF128_ZERO, self.a)

    def test_addition_commutative_and_associative(self):
        self.assertEqual(self.a + self.b, self.b + self.a)
        self.assertEqual((self.a + self.b) + self.c, self.a + (self.b + self.c))

    def test_multiplicative_identity(self):
        self.assertEqual(self.a * GF128_ONE, self.a)
        self.assertEqual(GF128_ONE * self.a, self.a)

    def test_multiplication_by_zero(self):
        self.assertEqual(self.a * GF128_ZERO, GF128_ZERO)

    def test_multiplication_commutative(self):
        self.assertEqual(self.a * self.b, self.b * self.a)

    def test_distributivity(self):
        lhs = self.a * (self.b + self.c)
        rhs = (self.a * self.b) + (self.a * self.c)
        self.assertEqual(lhs, rhs)

    def test_inverse_round_trip(self):
        for element in (self.a, self.b, self.c, GF128_ONE):
            self.assertEqual(element * element.inv(), GF128_ONE)

    def test_inverse_of_zero_raises(self):
        with self.assertRaises(ZeroDivisionError):
            GF128_ZERO.inv()

    def test_division_is_inverse_of_multiplication(self):
        product = self.a * self.b
        self.assertEqual(product / self.b, self.a)

    def test_bytes_round_trip(self):
        raw = self.a.to_bytes()
        self.assertEqual(len(raw), 16)
        self.assertEqual(GF128Element(raw), self.a)

    def test_rejects_wrong_length_bytes(self):
        with self.assertRaises(ValueError):
            GF128Element(b"\x00" * 15)

    def test_constant_values(self):
        self.assertEqual(GF128_ZERO.to_int(), 0)
        self.assertEqual(GF128_ONE.to_int(), 1 << 127)


if __name__ == "__main__":
    unittest.main()
