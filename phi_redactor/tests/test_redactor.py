"""Tests for the regex PHI redactor. 8 real-ish examples, all stdlib."""
from __future__ import annotations

import sys
from pathlib import Path

# Add project root to path so `import phi_redactor` works when pytest is run
# from any cwd.
ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from phi_redactor.redactor import redact  # noqa: E402


def test_ssn_redacted():
    text = "Patient SSN 123-45-6789 on file."
    clean, m = redact(text)
    assert "123-45-6789" not in clean
    assert "[SSN_1]" in clean
    assert m.items["[SSN_1]"] == "123-45-6789"


def test_tw_national_id():
    text = "身分證 A123456789 已建檔"
    clean, m = redact(text)
    assert "A123456789" not in clean
    assert "[TW_ID_1]" in clean


def test_email_and_phone_taiwan_mobile():
    text = "Contact alice@example.com or 0912-345-678 for follow-up."
    clean, m = redact(text)
    assert "alice@example.com" not in clean
    assert "0912-345-678" not in clean
    assert "[EMAIL_1]" in clean and "[TW_PHONE_M_1]" in clean


def test_mrn_and_dob_iso():
    text = "Record MRN-A123456 DOB 1990-01-15 admitted today."
    clean, m = redact(text)
    assert "MRN-A123456" not in clean
    assert "1990-01-15" not in clean
    assert "[MRN_1]" in clean
    assert "[DOB_ISO_1]" in clean


def test_dob_chinese_form():
    text = "張先生 1985 年 03 月 22 日 出生"
    clean, m = redact(text)
    assert "1985" not in clean.replace("[DOB_ZH_1]", "")
    assert "[DOB_ZH_1]" in clean


def test_round_trip_restore():
    text = "Email bob@x.org SSN 999-00-1111 MRN-Z9 phone 02-1234-5678"
    clean, m = redact(text, mode="replace")
    assert m.restore(clean) == text


def test_mask_mode_preserves_length():
    text = "SSN 123-45-6789 done."
    clean, m = redact(text, mode="mask")
    # SSN span "123-45-6789" length 11 → 11 stars.
    assert "***********" in clean
    # Mask mode leaves no reversible mapping.
    assert m.items == {}


def test_idempotent_token_for_same_value():
    # Same SSN twice → same token, not [SSN_1] + [SSN_2].
    text = "SSN 123-45-6789 again 123-45-6789."
    clean, m = redact(text)
    assert clean.count("[SSN_1]") == 2
    assert "[SSN_2]" not in clean


def test_no_phi_passthrough():
    text = "The weather is nice today."
    clean, m = redact(text)
    assert clean == text
    assert m.items == {}
