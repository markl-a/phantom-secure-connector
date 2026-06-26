from __future__ import annotations

import json
from pathlib import Path

from readiness.demo_loop import RAW_SYNTHETIC_VALUES, write_synthetic_demo_loop


PUBLIC_ARTIFACTS = [
    "manifest.json",
    "redacted-records.csv",
    "redaction-summary.json",
    "compliance-findings.json",
    "secops-findings.json",
    "readiness-summary.json",
    "readiness.html",
    "summary.md",
]


def test_demo_loop_writes_public_synthetic_guardrail_bundle(tmp_path: Path):
    bundle = write_synthetic_demo_loop(tmp_path / "bundle", standard="hipaa")

    assert bundle.out_dir == tmp_path / "bundle"
    for name in ["source-records.csv", *PUBLIC_ARTIFACTS]:
        assert (bundle.out_dir / name).exists(), name

    manifest = json.loads((bundle.out_dir / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["schema_version"] == 1
    assert manifest["mode"] == "synthetic_guardrail_loop"
    assert manifest["standard"] == "hipaa"
    assert manifest["synthetic_only"] is True
    assert manifest["raw_phi_in_public_artifacts"] is False
    assert manifest["legal_certification"] is False
    assert manifest["external_network"] is False
    assert manifest["mcp_live_bridge"] is False
    assert manifest["artifacts"] == ["source-records.csv", *PUBLIC_ARTIFACTS]

    compliance = json.loads(
        (bundle.out_dir / "compliance-findings.json").read_text(encoding="utf-8")
    )
    readiness = json.loads(
        (bundle.out_dir / "readiness-summary.json").read_text(encoding="utf-8")
    )
    secops = json.loads((bundle.out_dir / "secops-findings.json").read_text(encoding="utf-8"))

    assert compliance["summary"]["violation_count"] >= 1
    assert readiness["summary"]["verdict"] == "findings"
    assert secops["summary"]["finding_count"] >= 1


def test_demo_loop_public_artifacts_do_not_retain_raw_synthetic_identifiers(
    tmp_path: Path,
):
    bundle = write_synthetic_demo_loop(tmp_path / "bundle")

    for name in PUBLIC_ARTIFACTS:
        text = (bundle.out_dir / name).read_text(encoding="utf-8")
        for raw_value in RAW_SYNTHETIC_VALUES:
            assert raw_value not in text, f"{raw_value!r} leaked in {name}"


def test_demo_loop_is_deterministic_for_public_artifacts(tmp_path: Path):
    first = write_synthetic_demo_loop(tmp_path / "first")
    second = write_synthetic_demo_loop(tmp_path / "second")

    for name in PUBLIC_ARTIFACTS:
        assert (first.out_dir / name).read_text(encoding="utf-8") == (
            second.out_dir / name
        ).read_text(encoding="utf-8"), name
