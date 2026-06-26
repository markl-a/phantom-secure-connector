"""Synthetic data-plane guard scenario bundle.

This P3 scenario consumes the P2 transform-pipeline bundle and writes a
metadata-only proof that redact/drop/hash/allow policy decisions were applied
before any bridge-like handoff. It does not copy raw identifiers, full rows,
per-input hashes, reversible maps, or certification claims.
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path
from typing import Any

SCHEMA_VERSION = 1

REQUIRED_SOURCE_ARTIFACTS = {
    "manifest.json",
    "policy.json",
    "transformed-records.csv",
    "transform-audit.jsonl",
    "summary.md",
}


def write_guard_scenario_bundle(
    *,
    source_bundle: str | Path,
    out_dir: str | Path,
) -> Path:
    """Write a deterministic synthetic data-plane guard scenario bundle."""
    source_root, source_manifest = _load_source_manifest(Path(source_bundle))
    _validate_source_manifest(source_root, source_manifest)

    policy = _load_json(source_root / "policy.json")
    rows = _read_csv(source_root / "transformed-records.csv")
    audit_entries = _read_jsonl(source_root / "transform-audit.jsonl")

    scenario = _build_scenario(source_manifest, policy, rows, audit_entries)
    policy_decisions = _build_policy_decisions(policy, audit_entries)
    audit_summary = _build_audit_summary(audit_entries)

    out_path = Path(out_dir)
    out_path.mkdir(parents=True, exist_ok=True)
    scenario_path = out_path / "guard-scenario.json"
    policy_path = out_path / "policy-decisions.json"
    audit_path = out_path / "audit-summary.json"
    summary_path = out_path / "summary.md"
    _dump_json(scenario_path, scenario)
    _dump_json(policy_path, policy_decisions)
    _dump_json(audit_path, audit_summary)
    summary_path.write_text(_summary_md(scenario, audit_summary), encoding="utf-8")

    manifest = {
        "schema_version": SCHEMA_VERSION,
        "mode": "synthetic_data_plane_guard_scenario",
        "source_mode": source_manifest.get("mode", ""),
        "synthetic_only": True,
        "raw_phi_in_public_artifacts": False,
        "legal_certification": False,
        "external_network": False,
        "mcp_live_bridge": False,
        "artifacts": {
            "audit_summary": _rel(out_path, audit_path),
            "policy_decisions": _rel(out_path, policy_path),
            "scenario": _rel(out_path, scenario_path),
            "summary": _rel(out_path, summary_path),
        },
    }
    manifest_path = out_path / "manifest.json"
    _dump_json(manifest_path, manifest)
    return manifest_path


def _load_source_manifest(source: Path) -> tuple[Path, dict[str, Any]]:
    manifest_path = source if source.is_file() else source / "manifest.json"
    if not manifest_path.exists():
        raise RuntimeError("guard-scenario requires a transform pipeline manifest.json")
    raw = json.loads(manifest_path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise RuntimeError("guard-scenario manifest must be a JSON object")
    return manifest_path.parent, raw


def _validate_source_manifest(root: Path, manifest: dict[str, Any]) -> None:
    if (
        manifest.get("mode") != "synthetic_transform_pipeline"
        or manifest.get("synthetic_only") is not True
        or manifest.get("raw_phi_in_public_artifacts") is not False
        or manifest.get("legal_certification") is not False
        or manifest.get("external_network") is not False
        or manifest.get("mcp_live_bridge") is not False
        or manifest.get("audit_log_retention") != "metadata_only"
    ):
        raise RuntimeError("guard-scenario only accepts safe synthetic transform bundles")

    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, list):
        raise RuntimeError("guard-scenario source manifest must list artifacts")
    for artifact in artifacts:
        if not isinstance(artifact, str):
            raise RuntimeError("guard-scenario source artifact names must be strings")
        _bundle_path(root, artifact)
    missing = REQUIRED_SOURCE_ARTIFACTS - set(artifacts)
    if missing:
        raise RuntimeError(f"guard-scenario source bundle is missing artifacts: {sorted(missing)}")


def _build_scenario(
    manifest: dict[str, Any],
    policy: dict[str, Any],
    rows: list[dict[str, str]],
    audit_entries: list[dict[str, Any]],
) -> dict[str, Any]:
    fields = list(rows[0].keys()) if rows else []
    action_counts = _action_counts(audit_entries)
    return {
        "schema_version": SCHEMA_VERSION,
        "mode": "synthetic_data_plane_guard",
        "source_mode": manifest.get("mode", ""),
        "records_processed": int(manifest.get("records_processed") or len(rows)),
        "policy_name": policy.get("name", ""),
        "policy_actions": sorted(action_counts),
        "transformed_fields": fields,
        "audit_entry_count": len(audit_entries),
        "guard_readiness": {
            "redaction_applied": action_counts.get("redact", 0) > 0,
            "drop_applied": action_counts.get("drop", 0) > 0,
            "hash_applied": action_counts.get("hash", 0) > 0,
            "allow_applied": action_counts.get("allow", 0) > 0,
            "metadata_audit_ready": bool(audit_entries)
            and all(entry.get("raw_value_retained") is False for entry in audit_entries),
            "bridge_safe_by_default": manifest.get("mcp_live_bridge") is False,
        },
        "boundaries": {
            "legal_certification": "not_supported",
            "live_regulated_bridge": "not_supported",
            "raw_phi_export": "not_supported",
            "reversible_redaction_map": "not_included",
            "external_network": "not_required",
        },
    }


def _build_policy_decisions(
    policy: dict[str, Any],
    audit_entries: list[dict[str, Any]],
) -> dict[str, Any]:
    actions = policy.get("actions") or {}
    decisions: dict[str, dict[str, Any]] = {}
    audit_by_field = {
        str(entry.get("field", "")): entry
        for entry in audit_entries
        if isinstance(entry, dict)
    }
    for field, action in sorted(actions.items()):
        entry = audit_by_field.get(str(field), {})
        decisions[str(field)] = {
            "action": str(action),
            "decision": str(entry.get("decision", "")),
            "output_field": entry.get("output_field"),
            "phi_items": int(entry.get("phi_items") or 0),
            "raw_value_retained": False,
        }
    return {
        "schema_version": SCHEMA_VERSION,
        "mode": "synthetic_policy_decisions",
        "default_action_for_unknown_fields": policy.get("default_action_for_unknown_fields", ""),
        "raw_value_retention": "never in scenario artifacts",
        "decisions": decisions,
    }


def _build_audit_summary(audit_entries: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "mode": "metadata_only_audit_summary",
        "entry_count": len(audit_entries),
        "action_counts": _action_counts(audit_entries),
        "fields_seen": sorted({str(entry.get("field", "")) for entry in audit_entries}),
        "raw_values_retained": False,
        "input_hashes_included": False,
        "full_rows_included": False,
        "reversible_map_included": False,
    }


def _action_counts(audit_entries: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for entry in audit_entries:
        action = str(entry.get("action", ""))
        counts[action] = counts.get(action, 0) + 1
    return dict(sorted(counts.items()))


def _summary_md(scenario: dict[str, Any], audit: dict[str, Any]) -> str:
    return "\n".join(
        [
            "# Data-plane guard scenario",
            "",
            "This bundle demonstrates a synthetic metadata-only guard handoff.",
            "",
            f"- Records processed: {scenario['records_processed']}",
            f"- Transformed fields: {', '.join(scenario['transformed_fields'])}",
            f"- Audit entries: {audit['entry_count']}",
            "- Boundaries: no raw PHI export, no reversible map, no external network, no live bridge.",
            "",
        ]
    )


def _load_json(path: Path) -> dict[str, Any]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise RuntimeError(f"{path.name} must be a JSON object")
    return raw


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            row = json.loads(line)
            if isinstance(row, dict):
                rows.append(row)
    return rows


def _read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        return [dict(row) for row in csv.DictReader(handle)]


def _dump_json(path: Path, value: Any) -> None:
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _bundle_path(root: Path, rel: str) -> Path:
    candidate = Path(rel)
    if candidate.is_absolute():
        raise RuntimeError("guard-scenario artifact paths must be bundle-relative")
    root_resolved = root.resolve()
    path = (root / candidate).resolve()
    try:
        path.relative_to(root_resolved)
    except ValueError as exc:
        raise RuntimeError("guard-scenario artifact paths must stay inside the bundle") from exc
    return path


def _rel(root: Path, path: Path) -> str:
    return path.relative_to(root).as_posix()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="readiness.guard_scenario")
    parser.add_argument("--source", required=True, help="transform pipeline bundle directory")
    parser.add_argument("--out", required=True, help="directory to write the scenario bundle")
    args = parser.parse_args(argv)

    try:
        manifest_path = write_guard_scenario_bundle(source_bundle=args.source, out_dir=args.out)
    except (RuntimeError, ValueError, OSError) as exc:
        print(f"guard-scenario: {exc}", file=sys.stderr)
        return 1
    sys.stdout.write(str(manifest_path) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = ["SCHEMA_VERSION", "write_guard_scenario_bundle"]
