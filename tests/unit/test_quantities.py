"""Synthetic quantity cases: exact conversion, bounds, and safe failures."""

from decimal import Decimal, Inexact, Rounded, localcontext
from typing import cast

import pytest

from openkube_optimizer.domain.quantities import (
    MAX_CPU_CORES,
    MAX_MEMORY_BYTES,
    parse_cpu,
    parse_memory,
)


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("0", "0"),
        ("-0", "0"),
        ("+0.5", "0.5"),
        ("250m", "0.250"),
        ("1n", "0.000000001"),
        ("25u", "0.000025"),
        ("1e-3", "0.001"),
        ("1E+3", "1000"),
        (".5", "0.5"),
        ("1.", "1"),
        ("1Ki", "1024"),
        ("1000000", "1000000"),
        ("1e-128", "1e-128"),
        ("0.123456789012345678901234567890123", "0.123456789012345678901234567890123"),
    ],
)
def test_exact_cpu_conversion(text: str, expected: str) -> None:
    assert parse_cpu(text) == Decimal(expected)
    assert type(parse_cpu(text)) is Decimal


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("0", 0),
        ("-0", 0),
        ("0.4", 1),
        ("400m", 1),
        ("1.0", 1),
        ("1.2", 2),
        ("1n", 1),
        ("1e-128", 1),
        ("1k", 1000),
        ("1M", 1000000),
        ("128Mi", 134217728),
        ("1.5Ki", 1536),
        ("0.1Ki", 103),
        ("1Gi", 2**30),
        ("1Ti", 2**40),
        ("1Pi", 2**50),
        ("1Ei", MAX_MEMORY_BYTES),
        ("1E", 10**18),
        ("129e6", 129000000),
        ("1152921504606846975.1", MAX_MEMORY_BYTES),
    ],
)
def test_memory_conversion_rounds_up(text: str, expected: int) -> None:
    assert parse_memory(text) == expected
    assert type(parse_memory(text)) is int


def test_conversion_ignores_decimal_context_precision_and_traps() -> None:
    with localcontext() as context:
        context.prec = 2
        context.traps[Inexact] = True
        context.traps[Rounded] = True
        assert parse_cpu("12345678901234567890123456789e-28") == Decimal(
            "1.2345678901234567890123456789"
        )
        assert parse_memory("1152921504606846975.0000000000000001") == MAX_MEMORY_BYTES


@pytest.mark.parametrize(
    "text",
    [
        "",
        " ",
        " 1",
        "1 ",
        "1\n",
        "NaN",
        "sNaN",
        "Infinity",
        "-1",
        "-0.1n",
        "1_000",
        "1,000",
        "1..2",
        ".",
        "1e",
        "1e+",
        "1e1m",
        "1mi",
        "1K",
        "1ki",
        "1KB",
        "1e-129",
        "1e129",
        "0e99999999999999999999999999999",
        "1e" + "9" * 126,
        "0" * 129,
        "１",
        "١",
        "1\x00",
    ],
)
def test_malformed_or_unbounded_inputs_are_rejected(text: str) -> None:
    for parser in (parse_cpu, parse_memory):
        with pytest.raises(ValueError, match="^Invalid quantity"):
            parser(text)


@pytest.mark.parametrize("value", [None, 1, True, 0.5, Decimal("1"), b"1", object()])
def test_parser_rejects_wrong_types(value: object) -> None:
    for parser in (parse_cpu, parse_memory):
        with pytest.raises(ValueError, match="^Invalid quantity$"):
            parser(cast(str, value))


def test_quantity_length_boundary() -> None:
    text = "0" * 127 + "1"
    assert parse_cpu(text) == Decimal(1)
    assert parse_memory(text) == 1
    assert parse_cpu("0e128") == 0
    assert parse_memory("0e128") == 0


def test_upper_bounds_apply_after_exact_normalization() -> None:
    assert parse_cpu("1000k") == MAX_CPU_CORES
    for text in ("1000000.000000001", "1e128"):
        with pytest.raises(ValueError, match="^Invalid CPU quantity$"):
            parse_cpu(text)
    for text in ("1152921504606846976.0001", "2Ei", "1e128"):
        with pytest.raises(ValueError, match="^Invalid memory quantity$"):
            parse_memory(text)


def test_errors_do_not_echo_quantity_canaries() -> None:
    canary = "synthetic-private-quantity-canary"
    for parser in (parse_cpu, parse_memory):
        with pytest.raises(ValueError) as caught:
            parser(canary)
        assert canary not in str(caught.value)
        assert canary not in repr(caught.value)
