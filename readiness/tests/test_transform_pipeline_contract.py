from __future__ import annotations

import csv
import json
from pathlib import Path

from readiness.transform_pipeline import RAW_SYNTHETIC_VALUES, write_transform_pipeline_bundle


def _write_source(path: Path) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=[
                "patient",
                "ssn",
                "email",
                "phone",
                "internal_note",
                "consent_flag",
                "age_band",
            ],
            lineterminator="\n",
        )
        writer.writeheader()
        writer.writerow(
            {
                "patient": "Synthetic Patient",
                "ssn": "123-45-6789",
                "email": "synthetic.patient@example.test",
                "phone": "0912-345-678",
                "internal_note": "Private fixture note with MRN-A12345",
                "consent_flag": "research-ok",
                "age_band": "40-49",
            }
        )


def test_transform_pipeline_bundle_applies_policy_and_writes_metadata_audit_log(
    tmp_path: Path,
):
    source = tmp_path / "source-records.csv"
    _write_source(source)

    bundle = write_transform_pipeline_bundle(source, tmp_path / "bundle")

    assert bundle.out_dir == tmp_path / "bundle"
    for name in [
        "manifest.json",
        "policy.json",
        "transformed-records.csv",
        "transform-audit.jsonl",
        "summary.md",
    ]:
        assert (bundle.out_dir / name).exists(), name

    manifest = json.loads((bundle.out_dir / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["schema_version"] == 1
    assert manifest["mode"] == "synthetic_transform_pipeline"
    assert manifest["synthetic_only"] is True
    assert manifest["raw_phi_in_public_artifacts"] is False
    assert manifest["legal_certification"] is False
    assert manifest["external_network"] is False
    assert manifest["mcp_live_bridge"] is False
    assert manifest["actions"] == ["allow", "drop", "hash", "redact"]

    rows = list(
        csv.DictReader((bundle.out_dir / "transformed-records.csv").open(encoding="utf-8"))
    )
    assert rows == [
        {
            "patient": "[REDACTED_PATIENT_1]",
            "ssn": "[SSN_1]",
            "email": "[EMAIL_1]",
            "phone": "sha256:2133882ff72a",
            "consent_flag": "research-ok",
            "age_band": "40-49",
        }
    ]

    audit_entries = [
        json.loads(line)
        for line in (bundle.out_dir / "transform-audit.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    assert {entry["action"] for entry in audit_entries} == {
        "allow",
        "drop",
        "hash",
        "redact",
    }
    assert all(entry["raw_value_retained"] is False for entry in audit_entries)
    assert all("raw" not in entry for entry in audit_entries)
    assert {entry["field"] for entry in audit_entries} == {
        "patient",
        "ssn",
        "email",
        "phone",
        "internal_note",
        "consent_flag",
        "age_band",
    }


def test_transform_pipeline_public_artifacts_do_not_retain_raw_synthetic_values(
    tmp_path: Path,
):
    source = tmp_path / "source-records.csv"
    _write_source(source)

    bundle = write_transform_pipeline_bundle(source, tmp_path / "bundle")

    for name in [
        "manifest.json",
        "policy.json",
        "transformed-records.csv",
        "transform-audit.jsonl",
        "summary.md",
    ]:
        text = (bundle.out_dir / name).read_text(encoding="utf-8")
        for raw_value in RAW_SYNTHETIC_VALUES:
            assert raw_value not in text, f"{raw_value!r} leaked in {name}"


def test_transform_pipeline_is_deterministic(tmp_path: Path):
    source = tmp_path / "source-records.csv"
    _write_source(source)

    first = write_transform_pipeline_bundle(source, tmp_path / "first")
    second = write_transform_pipeline_bundle(source, tmp_path / "second")

    for name in [
        "manifest.json",
        "policy.json",
        "transformed-records.csv",
        "transform-audit.jsonl",
        "summary.md",
    ]:
        assert (first.out_dir / name).read_text(encoding="utf-8") == (
            second.out_dir / name
        ).read_text(encoding="utf-8"), name
