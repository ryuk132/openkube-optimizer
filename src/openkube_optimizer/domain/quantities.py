"""Bounded, exact Kubernetes CPU/memory quantity conversion.

No Decimal arithmetic depends on the caller's decimal context. Errors contain
only fixed messages, never supplied quantities. This is not an SDK adapter.
"""

import re
from decimal import Decimal

MAX_QUANTITY_CHARACTERS = 128
MAX_CPU_CORES = Decimal("1000000")
MAX_MEMORY_BYTES = 2**60
# A fixed parser expansion guard, not an analysis setting. Together with the
# input-length bound it keeps all intermediate integers below 300 digits.
MAX_EXPONENT_MAGNITUDE = 128

_QUANTITY = re.compile(
    r"([+-]?)([0-9]+(?:\.[0-9]*)?|\.[0-9]+)"
    r"([eE][+-]?[0-9]+|[numkMGTPE]|[KMGTPE]i)?"
)
_DECIMAL_POWERS = {
    "": 0,
    "n": -9,
    "u": -6,
    "m": -3,
    "k": 3,
    "M": 6,
    "G": 9,
    "T": 12,
    "P": 15,
    "E": 18,
}
_BINARY_POWERS = {"Ki": 10, "Mi": 20, "Gi": 30, "Ti": 40, "Pi": 50, "Ei": 60}


def validate_cpu(value: object) -> None:
    """Require already-normalized, bounded decimal cores."""
    if (
        type(value) is not Decimal
        or not value.is_finite()
        or value < 0
        or value > MAX_CPU_CORES
    ):
        raise ValueError("Invalid CPU quantity")


def validate_memory(value: object) -> None:
    """Require already-normalized, bounded whole bytes (not bool)."""
    if type(value) is not int or not 0 <= value <= MAX_MEMORY_BYTES:
        raise ValueError("Invalid memory quantity")


def _parts(text: str) -> tuple[int, int]:
    """Return a nonnegative coefficient and a bounded power of ten."""
    if type(text) is not str or not 1 <= len(text) <= MAX_QUANTITY_CHARACTERS:
        raise ValueError("Invalid quantity")
    match = _QUANTITY.fullmatch(text)
    if match is None:
        raise ValueError("Invalid quantity")
    sign, number, suffix = match.groups()
    whole, dot, fraction = number.partition(".")
    coefficient = int(whole + fraction)
    if sign == "-" and coefficient != 0:
        raise ValueError("Invalid quantity")
    power = -len(fraction) if dot else 0
    suffix = suffix or ""
    if suffix in _BINARY_POWERS:
        coefficient *= 2 ** _BINARY_POWERS[suffix]
    elif suffix in _DECIMAL_POWERS:
        power += _DECIMAL_POWERS[suffix]
    else:
        exponent = int(suffix[1:])
        if abs(exponent) > MAX_EXPONENT_MAGNITUDE:
            raise ValueError("Invalid quantity exponent")
        power += exponent
    return coefficient, power


def parse_cpu(text: str) -> Decimal:
    """Convert a quantity to exact decimal cores without float rounding."""
    coefficient, power = _parts(text)
    value = Decimal((0, tuple(int(digit) for digit in str(coefficient)), power))
    validate_cpu(value)
    return value


def parse_memory(text: str) -> int:
    """Convert to bytes, rounding a nonnegative fraction upward, never down."""
    coefficient, power = _parts(text)
    value: int
    if power >= 0:
        value = coefficient * 10**power
    else:
        divisor = 10 ** (-power)
        value = (coefficient + divisor - 1) // divisor
    validate_memory(value)
    return value
