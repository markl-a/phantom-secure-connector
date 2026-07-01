"""Tests for compliance_checker: HIPAA + GDPR scans of fake CSV / JSON."""
from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from compliance_checker.checker import (  # noqa: E402
    Violation,
    filter_luhn_valid,
    load_standard,
    scan_file,
    scan_records,
)


def test_load_hipaa_rules_18_total():
    rs = load_standard("hipaa")
    assert rs.standard == "HIPAA"
    assert len(rs.rules) == 18


def test_load_gdpr_rules_nonempty():
    rs = load_standard("gdpr")
    assert rs.standard == "GDPR"
    assert len(rs.rules) >= 5


def test_hipaa_flags_csv_with_ssn_and_mrn(tmp_path: Path):
    csv_path = tmp_path / "patients.csv"
    csv_path.write_text(
        "name,ssn,mrn,zip\n"
        "Alice Smith,123-45-6789,MRN-A12345,02134\n"
        "Bob Jones,987-65-4321,MRN-B99999,94016\n",
        encoding="utf-8",
    )
    rs = load_standard("hipaa")
    vio = scan_file(csv_path, rs)
    rule_ids = {v.rule_id for v in vio}
    assert "hipaa_07_ssn" in rule_ids
    assert "hipaa_08_mrn" in rule_ids
    # Two SSNs across two rows.
    assert sum(1 for v in vio if v.rule_id == "hipaa_07_ssn") == 2


def test_gdpr_flags_email_and_health_keyword(tmp_path: Path):
    csv_path = tmp_path / "users.csv"
    csv_path.write_text(
        "email,notes\n"
        "alice@example.com,diagnosis of diabetes\n"
        "bob@example.org,routine checkup\n",
        encoding="utf-8",
    )
    rs = load_standard("gdpr")
    vio = scan_file(csv_path, rs)
    rule_ids = {v.rule_id for v in vio}
    assert "gdpr_email" in rule_ids
    assert "gdpr_special_health_kw" in rule_ids


def test_json_scan_walks_nested():
    rs = load_standard("hipaa")
    obj = {
        "patients": [
            {"name": "Alice Smith", "ssn": "111-22-3333"},
            {"name": "Bob Jones", "contact": {"email": "b@x.org"}},
        ]
    }
    with tempfile.NamedTemporaryFile(
        "w", suffix=".json", delete=False, encoding="utf-8"
    ) as fh:
        json.dump(obj, fh)
        p = Path(fh.name)
    try:
        vio = scan_file(p, rs)
        assert any(v.rule_id == "hipaa_07_ssn" for v in vio)
        assert any(v.rule_id == "hipaa_06_email" for v in vio)
    finally:
        p.unlink()


def test_scan_records_clean_data_no_violations():
    rs = load_standard("hipaa")
    records = [{"col": "perfectly safe text"}, {"col": "no PHI here"}]
    vio = scan_records(records, rs)
    assert vio == []


# --------------------------- CLI exit-code contract --------------------------
from compliance_checker.checker import _cli  # noqa: E402


def test_cli_returns_1_on_violations(tmp_path: Path, capsys):
    csv_path = tmp_path / "v.csv"
    csv_path.write_text("email\nalice@example.com\n", encoding="utf-8")
    rc = _cli(["--standard", "hipaa", str(csv_path)])
    assert rc == 1
    out = capsys.readouterr().out
    assert "Violations: 1" in out


def test_cli_returns_0_on_clean(tmp_path: Path):
    csv_path = tmp_path / "clean.csv"
    csv_path.write_text("col\nperfectly safe text\n", encoding="utf-8")
    rc = _cli(["--standard", "hipaa", str(csv_path)])
    assert rc == 0


def test_cli_json_output_is_valid(tmp_path: Path, capsys):
    csv_path = tmp_path / "v.csv"
    csv_path.write_text("ssn\n123-45-6789\n", encoding="utf-8")
    # --show-matches to inspect the raw matched value in the structured record.
    rc = _cli([
        "--standard", "hipaa", "--json", "--show-matches", str(csv_path),
    ])
    assert rc == 1
    out = capsys.readouterr().out
    parsed = json.loads(out)
    assert isinstance(parsed, list) and parsed
    assert parsed[0]["rule_id"] == "hipaa_07_ssn"
    assert parsed[0]["matched"] == "123-45-6789"


def test_cli_unknown_standard_exits_cleanly_no_traceback(
    tmp_path: Path, capsys
):
    """An unknown --standard must produce a clean error + nonzero exit, NOT an
    uncaught FileNotFoundError traceback dumped at the user."""
    csv_path = tmp_path / "x.csv"
    csv_path.write_text("a\nb\n", encoding="utf-8")
    rc = _cli(["--standard", "does_not_exist", str(csv_path)])
    assert rc == 2
    err = capsys.readouterr().err
    assert "does_not_exist" in err or "unknown" in err.lower()


def test_cli_missing_file_exits_cleanly(tmp_path: Path, capsys):
    rc = _cli(["--standard", "hipaa", str(tmp_path / "nope.csv")])
    assert rc == 2
    err = capsys.readouterr().err
    assert err.strip()  # a human-readable message, not empty


def test_cli_unsupported_filetype_exits_cleanly(tmp_path: Path, capsys):
    bad = tmp_path / "data.txt"
    bad.write_text("hello", encoding="utf-8")
    rc = _cli(["--standard", "hipaa", str(bad)])
    assert rc == 2
    err = capsys.readouterr().err
    assert "unsupported" in err.lower() or ".txt" in err


# ----------------- PHI-safe export: redact matched by default ----------------
from compliance_checker.checker import Violation  # noqa: E402


def test_violation_to_dict_redacts_matched_by_default():
    """A compliance VIOLATION report feeds downstream (logs, tickets, the
    phantom ecosystem). The raw matched PHI must NOT be the default export —
    HIPAA 'minimum necessary' / GDPR data minimisation. to_dict() masks the
    matched value by default; the raw value is opt-in."""
    v = Violation(
        rule_id="hipaa_07_ssn", rule_label="SSN", standard="HIPAA",
        location="row=0 col=ssn", matched="123-45-6789",
    )
    d = v.to_dict()
    assert d["matched"] != "123-45-6789"
    assert "123-45-6789" not in json.dumps(d)
    # Fully masked, length-preserved — no partial fragments survive.
    assert d["matched"] == "*" * len("123-45-6789")
    # The structure / non-PHI fields are intact.
    assert d["rule_id"] == "hipaa_07_ssn"
    assert d["location"] == "row=0 col=ssn"


def test_violation_export_fully_masks_composite_match_no_fragment_leak():
    """A composite rule match (e.g. a URL embedding an email) must be FULLY
    masked in the default export — not partially redacted, which would leave
    the domain/path scaffolding (still identifying) exposed. The whole matched
    span is masked. Regression for the partial-mask leak.
    """
    v = Violation(
        rule_id="hipaa_14_url", rule_label="URL", standard="HIPAA",
        location="row=0 col=link",
        matched="https://portal.example/u/alice@example.com/record",
    )
    d = v.to_dict()
    blob = json.dumps(d)
    for fragment in ("portal", "example", "record", "alice", "https"):
        assert fragment not in blob
    assert set(d["matched"]) == {"*"}


def test_violation_to_dict_can_reveal_raw_on_explicit_opt_in():
    v = Violation(
        rule_id="hipaa_07_ssn", rule_label="SSN", standard="HIPAA",
        location="row=0 col=ssn", matched="123-45-6789",
    )
    d = v.to_dict(show_matches=True)
    assert d["matched"] == "123-45-6789"


def test_cli_json_redacts_matched_by_default(tmp_path: Path, capsys):
    csv_path = tmp_path / "v.csv"
    csv_path.write_text("ssn\n123-45-6789\n", encoding="utf-8")
    rc = _cli(["--standard", "hipaa", "--json", str(csv_path)])
    assert rc == 1
    out = capsys.readouterr().out
    # No raw PHI in the default JSON export.
    assert "123-45-6789" not in out
    parsed = json.loads(out)
    assert parsed[0]["rule_id"] == "hipaa_07_ssn"


def test_cli_json_show_matches_reveals_raw(tmp_path: Path, capsys):
    csv_path = tmp_path / "v.csv"
    csv_path.write_text("ssn\n123-45-6789\n", encoding="utf-8")
    rc = _cli([
        "--standard", "hipaa", "--json", "--show-matches", str(csv_path),
    ])
    assert rc == 1
    out = capsys.readouterr().out
    assert "123-45-6789" in out


def test_cli_text_redacts_matched_by_default(tmp_path: Path, capsys):
    csv_path = tmp_path / "v.csv"
    csv_path.write_text("ssn\n123-45-6789\n", encoding="utf-8")
    rc = _cli(["--standard", "hipaa", str(csv_path)])
    assert rc == 1
    out = capsys.readouterr().out
    # The human-readable report also must not print raw PHI by default.
    assert "123-45-6789" not in out


def test_cli_html_report_e2e_masks_pii_and_escapes(tmp_path):
    raw_email = "patient@example.com"
    csv_path = tmp_path / "rec.csv"
    # Column header carries an HTML-injection payload to prove escaping;
    # the cell value is a HIPAA email match to prove masking.
    csv_path.write_text("no<script>te\n" + raw_email + "\n", encoding="utf-8")
    out_path = tmp_path / "report.html"
    rc = _cli(["--standard", "hipaa", "--format", "html",
               "--html-out", str(out_path), str(csv_path)])
    assert rc == 1  # violations present
    report = out_path.read_text(encoding="utf-8")
    # self-contained, no external assets
    assert "<style>" in report
    assert "http://" not in report and "https://" not in report
    assert "<script>" not in report  # no XSS: payload was escaped
    assert "&lt;script&gt;" in report  # escaped form present
    assert "HIPAA" in report  # standard name rendered
    # PII masked by default: raw value absent, full-length mask present
    assert raw_email not in report
    assert "*" * len(raw_email) in report


def _pan_violation(matched: str) -> Violation:
    return Violation(
        rule_id="pci_dss_01_pan", rule_label="PAN", standard="PCI-DSS",
        location="row=0 col=card", matched=matched,
    )


def test_filter_luhn_valid_drops_pan_shaped_match_failing_checksum():
    # Visa test PAN with the last digit flipped — 16 digits (PAN-shaped) but
    # fails the Luhn checksum, so it's the false positive the filter targets.
    bad_pan = _pan_violation("4111111111111112")
    assert filter_luhn_valid([bad_pan]) == []


def test_filter_luhn_valid_keeps_pan_shaped_match_passing_checksum():
    # Standard Visa test number — checksum-valid.
    good_pan = _pan_violation("4111111111111111")
    assert filter_luhn_valid([good_pan]) == [good_pan]


def test_filter_luhn_valid_passes_non_pan_shaped_violations_through():
    # Fewer than 12 digits (a 9-digit SSN) — not PAN-shaped, so it passes
    # through unchanged regardless of whether it would pass Luhn.
    ssn = Violation(
        rule_id="hipaa_07_ssn", rule_label="SSN", standard="HIPAA",
        location="row=0 col=ssn", matched="123-45-6789",
    )
    assert filter_luhn_valid([ssn]) == [ssn]


def test_filter_luhn_valid_passes_non_pan_but_long_violations_through():
    # Violations from non-PAN rules that happen to have >=12 digits (e.g. Taiwan NHI
    # card numbers or international phone numbers) must pass through unchanged.
    nhi = Violation(
        rule_id="tw_nhi_card", rule_label="Taiwan NHI card number (健保卡號)", standard="TW-PII",
        location="row=0 col=nhi", matched="健保卡號: 123456789012",
    )
    phone = Violation(
        rule_id="gdpr_phone_intl", rule_label="International phone number", standard="GDPR",
        location="row=0 col=phone", matched="+44 1234 567890",
    )
    account = Violation(
        rule_id="hipaa_10_account", rule_label="Account number", standard="HIPAA",
        location="row=0 col=acct", matched="ACCT-123456789012",
    )
    assert filter_luhn_valid([nhi, phone, account]) == [nhi, phone, account]
