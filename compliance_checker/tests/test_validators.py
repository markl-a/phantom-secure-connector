"""Tests for the checksum validators (Luhn PAN + Taiwan national-ID).

These cover the two arithmetic checks the regex rule files document as out of
scope for the regex-only mechanism. The fixtures reuse the exact synthetic
identifiers that already appear in the rule-file tests so the validators stay
consistent with the rest of the suite.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from compliance_checker.validators import (  # noqa: E402
    luhn_valid,
    tw_national_id_valid,
)


# --------------------------------- Luhn -------------------------------------
# Known-valid public test PANs (the standard network sandbox numbers also used
# in compliance_checker/tests/test_pci_twpii.py).
VALID_PANS = [
    "4111111111111111",       # Visa
    "4111 1111 1111 1111",    # Visa, grouped with spaces (raw matched span)
    "4111-1111-1111-1111",    # Visa, grouped with hyphens
    "378282246310005",        # American Express
    "5555555555554444",       # Mastercard
    "6011111111111117",       # Discover
    "3530111333300000",       # JCB
]

INVALID_PANS = [
    "4111111111111112",       # Visa prefix, wrong check digit
    "1234567812345678",       # looks card-shaped, fails Luhn
    "5555555555554445",       # Mastercard prefix, wrong check digit
]


@pytest.mark.parametrize("pan", VALID_PANS)
def test_luhn_accepts_known_valid_pans(pan):
    assert luhn_valid(pan) is True


@pytest.mark.parametrize("pan", INVALID_PANS)
def test_luhn_rejects_wrong_check_digit(pan):
    assert luhn_valid(pan) is False


def test_luhn_rejects_non_pan_characters():
    # A letter inside the span means it is not a bare PAN: must NOT be accepted
    # by silently stripping the letter (which would pass "4111...abcd").
    assert luhn_valid("4111-abcd") is False
    assert luhn_valid("not a number") is False


def test_luhn_rejects_too_short():
    assert luhn_valid("") is False
    assert luhn_valid("7") is False        # single digit, no check possible
    assert luhn_valid("   ") is False      # separators only, zero digits


def test_luhn_ignores_only_space_and_hyphen_separators():
    # Same digits, three group formats, all must agree.
    assert luhn_valid("378282246310005") is True
    assert luhn_valid("3782 822463 10005") is True
    assert luhn_valid("3782-822463-10005") is True


def test_luhn_rejects_non_str_with_typeerror():
    for bad in (None, 4111111111111111, 4.0, ["4111"], {"pan": "4111"}):
        with pytest.raises(TypeError):
            luhn_valid(bad)  # type: ignore[arg-type]


# ----------------------------- TW national ID -------------------------------
# A123456789 is the synthetic ID used across the existing suite — it is a
# checksum-VALID Taiwan national ID. F131104093 is another valid synthetic one
# with a different region letter (F) to exercise the letter table.
VALID_TW_IDS = [
    "A123456789",
    "F131104093",
    "a123456789",   # lowercase normalised to uppercase
    " A123456789 ",  # surrounding whitespace stripped (raw matched span)
]

INVALID_TW_IDS = [
    "A234567890",   # correct shape, wrong check digit
    "B142706539",   # correct shape, wrong check digit
    "A12345678",    # too short (9 chars)
    "A1234567890",  # too long (11 chars)
    "A323456789",   # gender digit not 1 or 2
    "1123456789",   # leading char not a letter
    "AABCDEFGHI",   # non-digit body
    "",             # empty
]


@pytest.mark.parametrize("value", VALID_TW_IDS)
def test_tw_id_accepts_checksum_valid(value):
    assert tw_national_id_valid(value) is True


@pytest.mark.parametrize("value", INVALID_TW_IDS)
def test_tw_id_rejects_invalid(value):
    assert tw_national_id_valid(value) is False


def test_tw_id_letter_table_is_not_alphabetical():
    # I/O/W have non-sequential codes (34/35/32). Guard a real, valid ID for
    # each so a future "fix" that re-alphabetises the table is caught. These are
    # checksum-valid by construction against the weighted modulo-10 algorithm.
    assert tw_national_id_valid("I229999974") is True
    assert tw_national_id_valid("O100000013") is True
    assert tw_national_id_valid("W100000029") is True


def test_tw_id_rejects_non_str_with_typeerror():
    for bad in (None, 123456789, 4.0, ["A123456789"], {"id": "A123456789"}):
        with pytest.raises(TypeError):
            tw_national_id_valid(bad)  # type: ignore[arg-type]
