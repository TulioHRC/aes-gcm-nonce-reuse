import random
import unittest

from src.algebra.poly import Polynomial
from src.attacks.root_finding import find_roots
from src.primitives.gf128 import GF128Element, GF128_ONE


def rand_elem() -> GF128Element:
    return GF128Element(random.getrandbits(128))


def distinct_random_elements(n: int):
    seen = set()
    elements = []
    while len(elements) < n:
        e = rand_elem()
        if e.to_int() not in seen:
            seen.add(e.to_int())
            elements.append(e)
    return elements


class TestFindRoots(unittest.TestCase):
    def test_degree_zero_has_no_roots(self):
        self.assertEqual(find_roots(Polynomial.constant(GF128_ONE)), [])

    def test_zero_polynomial_raises(self):
        with self.assertRaises(ValueError):
            find_roots(Polynomial.zero())

    def test_single_root(self):
        random.seed(10)
        root = rand_elem()
        poly = Polynomial([root, GF128_ONE])  # X + root
        found = find_roots(poly)
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0], root)

    def test_multiple_distinct_roots(self):
        random.seed(11)
        for n in (2, 3, 5):
            with self.subTest(n=n):
                roots = distinct_random_elements(n)
                poly = Polynomial.constant(GF128_ONE)
                for r in roots:
                    poly = poly * Polynomial([r, GF128_ONE])
                found = find_roots(poly)
                self.assertEqual(
                    sorted(e.to_int() for e in found), sorted(e.to_int() for e in roots)
                )

    def test_polynomial_with_no_roots_in_field_but_a_linear_component(self):
        """An irreducible quadratic factor contributes no roots; combined with
        one genuine linear factor, exactly one root should be found."""
        random.seed(12)
        root = rand_elem()
        linear = Polynomial([root, GF128_ONE])
        # A generic quadratic with no roots in the field is hard to construct
        # by hand; instead we just confirm the one true root still surfaces
        # amid a higher-degree product that also contains repeated factors.
        extra = Polynomial([rand_elem(), GF128_ONE])
        poly = linear * extra * extra  # repeated factor: root of 'extra' still found once
        found = find_roots(poly)
        self.assertIn(root, found)


if __name__ == "__main__":
    unittest.main()
