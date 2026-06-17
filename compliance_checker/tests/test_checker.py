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
    rc = _cli(["--standard", "hipaa", "--json", str(csv_path)])
    assert rc == 1
    out = capsys.readouterr().out
    parsed = json.loads(out)
    assert isinstance(parsed, list) and parsed
    assert parsed[0]["rule_id"] == "hipaa_07_ssn"
    # No raw matched value should be absent from the structured record.
    assert parsed[0]["matched"] == "123-45-6789"


def test_cli_unknown_standard_exits_cleanly_no_traceback(tmp_path: Path, capsys):
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
