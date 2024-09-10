# Copyright (c) 2017, 2020 Pieter Wuille
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.

"""Reference implementation for Bech32/Bech32m and segwit addresses."""

from micropython import const
from trezorcrypto import bech32
from typing import TYPE_CHECKING

bech32_decode = bech32.decode  # reexported


if TYPE_CHECKING:
    from enum import IntEnum
    from typing import Sequence, TypeVar

    A = TypeVar("A")
    B = TypeVar("B")
    C = TypeVar("C")
    # usage: OptionalTuple[int, list[int]] is either (None, None) or (someint, somelist)
    # but not (None, somelist)
    OptionalTuple2 = tuple[None, None] | tuple[A, B]
else:
    IntEnum = object


class Encoding(IntEnum):
    """Enumeration type to list the various supported encodings."""

    BECH32 = const(1)
    BECH32M = const(2)


CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
_BECH32M_CONST = const(0x2BC830A3)
CHARSET_REV = {char: idx for idx, char in enumerate(CHARSET)}


def bech32_polymod(values: list[int]) -> int:
    """Internal function that computes the Bech32 checksum."""
    generator = [0x3B6A_57B2, 0x2650_8E6D, 0x1EA1_19FA, 0x3D42_33DD, 0x2A14_62B3]
    chk = 1
    for value in values:
        top = chk >> 25
        chk = (chk & 0x1FF_FFFF) << 5 ^ value
        for i in range(5):
            chk ^= generator[i] if ((top >> i) & 1) else 0
    return chk


def bech32_hrp_expand(hrp: str) -> list[int]:
    """Expand the HRP into values for checksum computation."""
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]


def _bech32_create_checksum(hrp: str, data: list[int], spec: Encoding) -> list[int]:
    """Compute the checksum values given HRP and data."""
    values = bech32_hrp_expand(hrp) + data
    const = _BECH32M_CONST if spec == Encoding.BECH32M else 1
    polymod = bech32_polymod(values + [0, 0, 0, 0, 0, 0]) ^ const
    return [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]


def bech32_encode(hrp: str, data: list[int], spec: Encoding) -> str:
    """Compute a Bech32 string given HRP and data values."""
    combined = data + _bech32_create_checksum(hrp, data, spec)
    return hrp + "1" + "".join([CHARSET[d] for d in combined])


def convertbits(
    data: Sequence[int], frombits: int, tobits: int, arbitrary_input: bool = True
) -> list[int]:
    """General power-of-2 base conversion.

    The `arbitrary_input` parameter specifies what happens when the total length
    of input bits is not a multiple of `tobits`.
    If True (default), the overflowing bits are zero-padded to the right.
    If False, the input must must be a valid output of `convertbits()` in the opposite
    direction.
    Namely:
    (a) the overflow must only be the zero padding
    (b) length of the overflow is less than `frombits`, meaning that there is no
        additional all-zero `frombits`-sized group at the end.
    If both conditions hold, the all-zero overflow is discarded.
    Otherwise a ValueError is raised.
    """
    acc = 0
    bits = 0
    ret = []
    maxv = (1 << tobits) - 1
    max_acc = (1 << (frombits + tobits - 1)) - 1
    for value in data:
        if value < 0 or (value >> frombits):
            raise ValueError  # input value does not match `frombits` size
        acc = ((acc << frombits) | value) & max_acc
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)

    if arbitrary_input:
        if bits:
            # append remaining bits, zero-padded from right
            ret.append((acc << (tobits - bits)) & maxv)
    elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
        # (1) either there is a superfluous group at end of input, and/or
        # (2) the remainder is nonzero
        raise ValueError

    return ret

def reverse_convertbits(
    data: Sequence[int], frombits: int, tobits: int
) -> list[int]:
    acc = 0
    bits = 0
    ret = []
    maxv = (1 << frombits) - 1
    for value in data:
        if value < 0 or (value >> tobits):
            raise ValueError  # input value does not match `tobits` size
        acc = ((acc << tobits) | value) & ((1 << (frombits + tobits)) - 1)
        bits += tobits
        while bits >= frombits:
            bits -= frombits
            ret.append((acc >> bits) & maxv)
    return ret


def mintlayer_bech32_decode(bech32_str):
    if not (1 <= len(bech32_str) <= 90):
        raise ValueError("Invalid length of Bech32 string")

    if not (bech32_str.lower() == bech32_str or bech32_str.upper() == bech32_str):
        raise ValueError("Mixed case in Bech32 string")

    if "1" not in bech32_str:
        raise ValueError("Missing separator in Bech32 string")

    if bech32_str.index("1") == 0 or bech32_str.index("1") == len(bech32_str) - 1:
        raise ValueError("Invalid position of separator in Bech32 string")

    hrp, data = bech32_str.rsplit("1", 1)
    hrp = hrp.lower()
    data = data.lower()

    for char in data:
        if char not in CHARSET:
            raise ValueError("Invalid character in data part")

    decoded = []
    for char in data:
        decoded.append(CHARSET_REV[char])

    # if not bech32_verify_checksum(hrp, decoded):
    #     raise ValueError("Invalid checksum")

    return hrp, decoded[:-6]

def mintlayer_decode_address_to_bytes(address: str | None) -> bytes:
    if address is None:
        return bytes()

    _, data = mintlayer_bech32_decode(address)
    data = reverse_convertbits(data, 8, 5)
    return bytes(data)


def decode(hrp: str, addr: str) -> OptionalTuple2[int, bytes]:
    """Decode a segwit address."""
    from trezorcrypto import bech32

    try:
        hrpgot, data, spec = bech32.decode(addr)
        decoded = bytes(convertbits(data[1:], 5, 8, False))
    except ValueError:
        return (None, None)
    if hrpgot != hrp:
        return (None, None)
    if not 2 <= len(decoded) <= 40:
        return (None, None)
    if data[0] > 16:
        return (None, None)
    if data[0] == 0 and len(decoded) not in (20, 32):
        return (None, None)
    if (
        data[0] == 0
        and spec != Encoding.BECH32
        or data[0] != 0
        and spec != Encoding.BECH32M
    ):
        return (None, None)
    return (data[0], decoded)


def encode(hrp: str, witver: int, witprog: bytes) -> str | None:
    """Encode a segwit address."""
    data = convertbits(witprog, 8, 5)
    spec = Encoding.BECH32 if witver == 0 else Encoding.BECH32M
    ret = bech32_encode(hrp, [witver] + data, spec)
    if decode(hrp, ret) == (None, None):
        return None
    return ret
