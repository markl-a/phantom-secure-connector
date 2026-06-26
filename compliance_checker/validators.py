"""Checksum validators for identifiers the regex rule mechanism cannot verify.

The TOML rule files in ``rules/`` are deliberately regex-only (see the header
comments in ``pci-dss.toml`` and ``tw-pii.toml``). A regex can match the SHAPE
of a credit-card PAN or a Taiwan national-ID, but it cannot run the arithmetic
checksum that separates a real identifier from a number that merely looks like
one. That gap is the documented "Tier 2" work; this module supplies the
arithmetic so callers can post-filter regex matches and cut false positives.

These are pure functions — no I/O, no globals, no PHI retained — so they are
safe to call on untrusted input and trivial to test. They are intentionally
NOT wired into the default scan path: tightening a live scan could change the
violation count for existing callers, and the rule files document that the scan
is "scheme prefix + length only". A caller who WANTS the tighter behaviour
opts in via :func:`filter_luhn_valid` (see ``checker``-level helpers) or by
calling these predicates directly.

Public API:
    luhn_valid(number)            -> bool   # credit-card PAN (Luhn / mod-10)
    tw_national_id_valid(value)   -> bool   # Taiwan 身分證字號 checksum
"""
from __future__ import annotations

from typing import Final

__all__ = ["luhn_valid", "tw_national_id_valid"]


def luhn_valid(number: str) -> bool:
    """Return ``True`` iff ``number`` passes the Luhn (mod-10) checksum.

    The Luhn algorithm is the check-digit scheme used by all major card
    networks (Visa / Mastercard / Amex / JCB / Discover). It does NOT prove a
    card is real or active — only that the digit sequence is internally
    consistent — but it eliminates the bulk of false positives where a regex
    matched an ordinary 13-19 digit number that is not a card at all.

    Non-digit separators commonly seen in card data (spaces and hyphens, e.g.
    ``"4111 1111 1111 1111"``) are ignored so a caller can pass the raw matched
    span straight through. Any OTHER non-digit character makes the input
    invalid: a token like ``"4111-abcd"`` is not a PAN, and silently stripping
    letters would wrongly accept it. An empty string, a lone digit, or a value
    with fewer than two digits is rejected (a PAN is always >= 12 digits, but
    we keep the floor at 2 so this stays a general-purpose Luhn predicate).

    Parameters
    ----------
    number:
        Candidate card number. ``str`` only; a non-``str`` raises ``TypeError``
        rather than silently coercing — a buggy caller must fail loudly, never
        have an unexpected object slip through as "invalid" and hide a leak.
    """
    if not isinstance(number, str):
        raise TypeError(
            f"luhn_valid() expects str, got {type(number).__name__}"
        )

    digits: list[int] = []
    for ch in number:
        if ch.isdigit():
            digits.append(int(ch))
        elif ch in " -":
            continue  # tolerate the standard PAN group separators
        else:
            return False  # any other char => not a bare PAN

    if len(digits) < 2:
        return False

    total = 0
    # Double every second digit counting from the RIGHTMOST (the check digit
    # itself is not doubled). Subtract 9 from any product > 9 (equivalent to
    # summing the two decimal digits of the product).
    for index, digit in enumerate(reversed(digits)):
        if index % 2 == 1:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
    return total % 10 == 0


# Taiwan national-ID letter -> two-digit code table (城市/區域代碼). This is the
# OFFICIAL mapping; it is NOT alphabetical (e.g. I=34, O=35, W=32) because the
# letters were assigned by household-registration region, not by sort order.
_TW_LETTER_CODE: Final[dict[str, int]] = {
    "A": 10, "B": 11, "C": 12, "D": 13, "E": 14, "F": 15, "G": 16, "H": 17,
    "I": 34, "J": 18, "K": 19, "L": 20, "M": 21, "N": 22, "O": 35, "P": 23,
    "Q": 24, "R": 25, "S": 26, "T": 27, "U": 28, "V": 29, "W": 32, "X": 30,
    "Y": 31, "Z": 33,
}

# Weights applied to the 11 expanded digits (letter -> 2 digits, then the 9
# numeric chars). The leading letter-code digit is weight 1, its second digit
# weight 9, the body digits 8..2, and the final check digit weight 1.
_TW_WEIGHTS: Final[tuple[int, ...]] = (1, 9, 8, 7, 6, 5, 4, 3, 2, 1, 1)


def tw_national_id_valid(value: str) -> bool:
    """Return ``True`` iff ``value`` is a checksum-valid Taiwan national ID.

    Format: one uppercase letter, then a gender digit (1 = male, 2 = female),
    then 8 numeric digits — the last of which is a check digit. The regex rule
    ``[A-Z][12]\\d{8}`` matches this SHAPE; this function additionally runs the
    official weighted-modulo-10 checksum, so a value like ``"A234567890"``
    (correct shape, wrong check digit) is correctly rejected.

    Input is normalised to uppercase and surrounding whitespace is stripped so
    a caller can pass a raw matched span. Anything that does not match the
    canonical shape (wrong length, bad letter, gender digit not 1/2, non-digit
    body) returns ``False`` rather than raising — this is a predicate over
    arbitrary scanned text, so malformed input is simply "not a valid ID".

    A non-``str`` argument raises ``TypeError`` (same fail-loud contract as
    :func:`luhn_valid`).
    """
    if not isinstance(value, str):
        raise TypeError(
            f"tw_national_id_valid() expects str, got {type(value).__name__}"
        )

    s = value.strip().upper()
    if len(s) != 10:
        return False
    letter, gender, body = s[0], s[1], s[2:]
    if letter not in _TW_LETTER_CODE:
        return False
    if gender not in ("1", "2"):
        return False
    if not body.isdigit():
        return False

    code = _TW_LETTER_CODE[letter]
    expanded = [code // 10, code % 10] + [int(c) for c in s[1:]]
    total = sum(d * w for d, w in zip(expanded, _TW_WEIGHTS))
    return total % 10 == 0
