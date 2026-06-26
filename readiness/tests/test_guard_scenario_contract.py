from __future__ import annotations

import csv
import json
from pathlib import Path

from readiness import guard_scenario
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


def test_guard_scenario_writes_data_plane_guard_bundle(tmp_path: Path, capsys) -> None:
    source = tmp_path / "source-records.csv"
    _write_source(source)
    transform = write_transform_pipeline_bundle(source, tmp_path / "transform")
    out = tmp_path / "guard-scenario"

    assert guard_scenario.main(["--source", str(transform.out_dir), "--out", str(out)]) == 0
    manifest_path = Path(capsys.readouterr().out.strip())
    assert manifest_path == out / "manifest.json"

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    scenario = json.loads((out / "guard-scenario.json").read_text(encoding="utf-8"))
    policy = json.loads((out / "policy-decisions.json").read_text(encoding="utf-8"))
    audit = json.loads((out / "audit-summary.json").read_text(encoding="utf-8"))
    summary = (out / "summary.md").read_text(encoding="utf-8")

    assert manifest["schema_version"] == 1
    assert manifest["mode"] == "synthetic_data_plane_guard_scenario"
    assert manifest["source_mode"] == "synthetic_transform_pipeline"
    assert manifest["synthetic_only"] is True
    assert manifest["raw_phi_in_public_artifacts"] is False
    assert manifest["legal_certification"] is False
    assert manifest["external_network"] is False
    assert manifest["mcp_live_bridge"] is False
    assert manifest["artifacts"] == {
        "audit_summary": "audit-summary.json",
        "policy_decisions": "policy-decisions.json",
        "scenario": "guard-scenario.json",
        "summary": "summary.md",
    }

    assert scenario["mode"] == "synthetic_data_plane_guard"
    assert scenario["records_processed"] == 1
    assert scenario["policy_actions"] == ["allow", "drop", "hash", "redact"]
    assert scenario["transformed_fields"] == [
        "patient",
        "ssn",
        "email",
        "phone",
        "consent_flag",
        "age_band",
    ]
    assert scenario["guard_readiness"] == {
        "redaction_applied": True,
        "drop_applied": True,
        "hash_applied": True,
        "allow_applied": True,
        "metadata_audit_ready": True,
        "bridge_safe_by_default": True,
    }
    assert scenario["boundaries"]["legal_certification"] == "not_supported"
    assert scenario["boundaries"]["live_regulated_bridge"] == "not_supported"
    assert scenario["boundaries"]["raw_phi_export"] == "not_supported"

    assert policy["mode"] == "synthetic_policy_decisions"
    assert policy["decisions"]["internal_note"]["action"] == "drop"
    assert policy["decisions"]["phone"]["action"] == "hash"
    assert policy["decisions"]["ssn"]["action"] == "redact"
    assert all(row["raw_value_retained"] is False for row in policy["decisions"].values())

    assert audit["mode"] == "metadata_only_audit_summary"
    assert audit["entry_count"] == 7
    assert audit["raw_values_retained"] is False
    assert audit["input_hashes_included"] is False
    assert audit["action_counts"] == {
        "allow": 2,
        "drop": 1,
        "hash": 1,
        "redact": 3,
    }
    assert "Data-plane guard scenario" in summary


def test_guard_scenario_is_byte_stable_and_excludes_raw_identifiers(
    tmp_path: Path,
    capsys,
) -> None:
    source = tmp_path / "source-records.csv"
    _write_source(source)
    transform = write_transform_pipeline_bundle(source, tmp_path / "transform")
    a = tmp_path / "a"
    b = tmp_path / "b"

    assert guard_scenario.main(["--source", str(transform.out_dir), "--out", str(a)]) == 0
    capsys.readouterr()
    assert guard_scenario.main(["--source", str(transform.out_dir), "--out", str(b)]) == 0
    capsys.readouterr()

    for rel in (
        "manifest.json",
        "guard-scenario.json",
        "policy-decisions.json",
        "audit-summary.json",
        "summary.md",
    ):
        assert (a / rel).read_text(encoding="utf-8") == (b / rel).read_text(
            encoding="utf-8"
        )

    exported_text = "\n".join(
        path.read_text(encoding="utf-8") for path in a.iterdir() if path.is_file()
    )
    forbidden = (
        *RAW_SYNTHETIC_VALUES,
        "input_sha256",
        "legal advice",
        "certified",
        "compliance certification",
        "live regulated",
    )
    assert all(term.lower() not in exported_text.lower() for term in forbidden)


def test_guard_scenario_rejects_source_artifact_paths_outside_bundle(
    tmp_path: Path,
    capsys,
) -> None:
    source = tmp_path / "source-records.csv"
    _write_source(source)
    transform = write_transform_pipeline_bundle(source, tmp_path / "transform")
    manifest_path = transform.out_dir / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["artifacts"] = ["manifest.json", "../outside.json"]
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    rc = guard_scenario.main(["--source", str(transform.out_dir), "--out", str(tmp_path / "out")])

    assert rc == 1
    assert "artifact paths must stay inside the bundle" in capsys.readouterr().err
