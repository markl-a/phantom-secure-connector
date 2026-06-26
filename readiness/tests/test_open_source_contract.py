from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def _read(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")


def test_readme_points_to_security_boundary_and_safe_smoke():
    text = _read("README.md")

    assert "Quickstart" in text
    assert "compliance_checker.checker" in text
    assert "readiness.demo_loop" in text
    assert "readiness.transform_pipeline" in text
    assert "readiness.guard_scenario" in text
    assert "mcp_bridge.client --help" in text
    assert "docs/SECURITY_BOUNDARY.md" in text
    assert "docs/SYNTHETIC_GUARDRAIL_LOOP.md" in text
    assert "docs/TRANSFORM_PIPELINE.md" in text
    assert "docs/DATA_PLANE_GUARD_SCENARIO.md" in text


def test_pyproject_packages_readiness_module_used_by_quickstart():
    text = _read("pyproject.toml")

    assert '"readiness"' in text
    assert "phantom-secure-transform" in text
    assert "phantom-secure-guard-scenario" in text


def test_security_boundary_documents_allowlist_phi_and_no_certification_claim():
    text = _read("docs/SECURITY_BOUNDARY.md")
    low = text.lower()

    assert "not legal advice" in low
    assert "not a compliance certification" in low
    assert "allowlist" in low
    assert "redacted before crossing the subprocess boundary" in text
    assert "matched` values masked by default" in text
    assert "Raw match display is local-inspection only" in text


def test_synthetic_guardrail_loop_documents_artifact_and_retention_contract():
    text = _read("docs/SYNTHETIC_GUARDRAIL_LOOP.md")

    assert "manifest.json" in text
    assert "redacted-records.csv" in text
    assert "raw_phi_in_public_artifacts" in text
    assert "legal_certification" in text
    assert "Public artifacts other than `source-records.csv`" in text


def test_transform_pipeline_documents_policy_actions_and_metadata_only_audit():
    text = _read("docs/TRANSFORM_PIPELINE.md")

    assert "redact" in text
    assert "drop" in text
    assert "hash" in text
    assert "allow" in text
    assert "transform-audit.jsonl" in text
    assert "metadata-only" in text
    assert "raw_phi_in_public_artifacts" in text
    assert "not legal advice" in text.lower()


def test_data_plane_guard_scenario_documents_safe_bridge_boundary():
    text = _read("docs/DATA_PLANE_GUARD_SCENARIO.md")
    low = text.lower()

    assert "readiness.guard_scenario" in text
    assert "phantom-secure-guard-scenario" in text
    assert "manifest.json" in text
    assert "guard-scenario.json" in text
    assert "policy-decisions.json" in text
    assert "audit-summary.json" in text
    assert "synthetic_data_plane_guard_scenario" in text
    assert "synthetic_transform_pipeline" in text
    assert "raw_phi_in_public_artifacts" in text
    assert "legal_certification" in text
    assert "mcp_live_bridge" in text
    assert "external_network" in text
    assert "metadata-only" in low
    assert "not legal advice" in low
    assert "not a" in low and "certification" in low
    assert "live mcp bridge" in low
