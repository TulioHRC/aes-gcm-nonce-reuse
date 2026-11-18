"""Finite Field GF(2^128) arithmetic conforming to NIST SP 800-38D (Galois/Counter Mode).

In NIST SP 800-38D, the field is defined via the irreducible polynomial:
    f(x) = x^128 + x^7 + x^2 + x + 1

Elements are represented as 16-byte strings or 128-bit integers.
NIST GCM uses a specific bit-reflection convention:
A bit string a_0 a_1 ... a_127 corresponds to the polynomial:
    A(x) = a_0 + a_1 x + a_2 x^2 + ... + a_127 x^127.
Bit 0 (the most significant bit of the first byte) is the coefficient of x^0 = 1,
and Bit 127 (the least significant bit of the last byte) is the coefficient of x^127.

When shifting polynomials, multiplying by x corresponds to a right shift of the bit string,
with reduction polynomial R = 0xE1000000000000000000000000000000.
"""

from typing import Union

# Reduction constant R = 11100001 || 0^120
# Represents x^128 + x^7 + x^2 + x + 1 when reduced on right-shift overflow
R_INT = 0xE1000000000000000000000000000000
MASK128 = (1 << 128) - 1


class GF128Element:
    """An element of the Galois Field GF(2^128) under GCM representation."""

    __slots__ = ("val",)

    def __init__(self, val: Union[int, bytes, bytearray, "GF128Element"]):
        if isinstance(val, GF128Element):
            self.val = val.val
        elif isinstance(val, int):
            self.val = val & MASK128
        elif isinstance(val, (bytes, bytearray)):
            if len(val) != 16:
                raise ValueError(f"GF(2^128) element from bytes requires exactly 16 bytes, got {len(val)}")
            self.val = int.from_bytes(val, byteorder="big")
        else:
            raise TypeError(f"Cannot initialize GF128Element with type {type(val)}")

    def to_bytes(self) -> bytes:
        return self.val.to_bytes(16, byteorder="big")

    def to_int(self) -> int:
        return self.val

    def __eq__(self, other: object) -> bool:
        if isinstance(other, GF128Element):
            return self.val == other.val
        if isinstance(other, int):
            return self.val == (other & MASK128)
        if isinstance(other, (bytes, bytearray)):
            return self.to_bytes() == other
        return False

    def __add__(self, other: Union["GF128Element", int, bytes]) -> "GF128Element":
        o = other if isinstance(other, GF128Element) else GF128Element(other)
        return GF128Element(self.val ^ o.val)

    def __sub__(self, other: Union["GF128Element", int, bytes]) -> "GF128Element":
        return self.__add__(other)

    def __mul__(self, other: Union["GF128Element", int, bytes]) -> "GF128Element":
        """Multiplication in GF(2^128) using the GCM algorithm (NIST SP 800-38D, Sec 5.2)."""
        o = other if isinstance(other, GF128Element) else GF128Element(other)
        x = self.val
        y = o.val
        z = 0
        v = x

        for i in range(128):
            # Check bit i of y from left to right (bit 127 - i)
            if (y >> (127 - i)) & 1:
                z ^= v
            if v & 1:
                v = (v >> 1) ^ R_INT
            else:
                v >>= 1

        return GF128Element(z)

    def inv(self) -> "GF128Element":
        """Multiplicative inverse in GF(2^128) via Fermat's Little Theorem: a^(2^128 - 2)."""
        if self.val == 0:
            raise ZeroDivisionError("Cannot invert zero element in GF(2^128)")

        # Exponent is 2^128 - 2
        exp = (1 << 128) - 2
        res = GF128Element(1 << 127)  # Multiplicative identity 1 is x^0, bit 0 is MSB = 1 << 127
        base = self

        while exp > 0:
            if exp & 1:
                res = res * base
            base = base * base
            exp >>= 1

        return res

    def __truediv__(self, other: Union["GF128Element", int, bytes]) -> "GF128Element":
        o = other if isinstance(other, GF128Element) else GF128Element(other)
        return self * o.inv()

    def __repr__(self) -> str:
        return f"GF128Element(0x{self.val:032x})"

    def __str__(self) -> str:
        return f"0x{self.val:032x}"


# Standard Identities
GF128_ZERO = GF128Element(0)
# In NIST bit notation, 1 corresponds to x^0, represented with MSB=1
GF128_ONE = GF128Element(1 << 127)
