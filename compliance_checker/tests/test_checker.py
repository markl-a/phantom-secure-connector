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
