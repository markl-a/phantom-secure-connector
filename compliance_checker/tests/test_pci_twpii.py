"""Tests for PCI-DSS and Taiwan PII rule files using synthetic data."""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from compliance_checker.checker import _cli, load_standard, scan_file  # noqa: E402


def test_load_pci_dss_rules():
    rs = load_standard("pci-dss")
    assert rs.standard == "PCI-DSS"
    assert "pci_visa" in {rule.id for rule in rs.rules}


def test_load_tw_pii_rules():
    rs = load_standard("tw-pii")
    assert rs.standard == "TW-PII"
    assert "tw_national_id" in {rule.id for rule in rs.rules}


def test_pci_and_twpii_scan_csv_e2e(tmp_path: Path):
    csv_path = tmp_path / "synthetic.csv"
    csv_path.write_text(
        "name,card,amex,twid,mobile\n"
        "Alice,4111 1111 1111 1111,378282246310005,A123456789,0912-345-678\n",
        encoding="utf-8",
    )

    pci_vio = scan_file(csv_path, load_standard("pci-dss"))
    pci_rule_ids = {v.rule_id for v in pci_vio}
    assert {"pci_visa", "pci_amex"}.issubset(pci_rule_ids)

    tw_vio = scan_file(csv_path, load_standard("tw-pii"))
    tw_rule_ids = {v.rule_id for v in tw_vio}
    assert {"tw_national_id", "tw_mobile"}.issubset(tw_rule_ids)


def test_cli_json_masks_pci_matches_by_default(tmp_path: Path, capsys):
    csv_path = tmp_path / "synthetic.csv"
    csv_path.write_text(
        "card\n4111 1111 1111 1111\n",
        encoding="utf-8",
    )

    rc = _cli(["--standard", "pci-dss", "--json", str(csv_path)])

    assert rc == 1
    out = capsys.readouterr().out
    assert "4111111111111111" not in out
    assert "4111 1111 1111 1111" not in out


def test_cli_json_masks_twpii_matches_by_default(tmp_path: Path, capsys):
    csv_path = tmp_path / "synthetic.csv"
    csv_path.write_text(
        "twid\nA123456789\n",
        encoding="utf-8",
    )

    rc = _cli(["--standard", "tw-pii", "--json", str(csv_path)])

    assert rc == 1
    out = capsys.readouterr().out
    assert "A123456789" not in out


def test_keyword_anchored_rules_do_not_overmatch_ordinary_data(tmp_path: Path):
    csv_path = tmp_path / "ordinary.csv"
    csv_path.write_text(
        "order_id,zip,price,pin\n"
        "12345678,02134,29.99,1234\n",
        encoding="utf-8",
    )

    pci_rule_ids = {
        v.rule_id for v in scan_file(csv_path, load_standard("pci-dss"))
    }
    assert "pci_cvv" not in pci_rule_ids
    assert "pci_expiry" not in pci_rule_ids

    tw_rule_ids = {
        v.rule_id for v in scan_file(csv_path, load_standard("tw-pii"))
    }
    assert "tw_ban" not in tw_rule_ids
    assert "tw_nhi_card" not in tw_rule_ids
