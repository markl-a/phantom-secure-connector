"""Synthetic transform pipeline bundle with metadata-only audit logs."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from phi_redactor.redactor import RedactionMap, redact
from readiness.report import to_json


DEFAULT_POLICY: dict[str, str] = {
    "patient": "redact",
    "ssn": "redact",
    "email": "redact",
    "phone": "hash",
    "internal_note": "drop",
    "consent_flag": "allow",
    "age_band": "allow",
}

ARTIFACTS = [
    "manifest.json",
    "policy.json",
    "transformed-records.csv",
    "transform-audit.jsonl",
    "summary.md",
]

RAW_SYNTHETIC_VALUES = (
    "Synthetic Patient",
    "123-45-6789",
    "synthetic.patient@example.test",
    "0912-345-678",
    "Private fixture note with MRN-A12345",
    "MRN-A12345",
)

SENSITIVE_FIELD_TOKENS = {
    "patient": "[REDACTED_PATIENT_{n}]",
}


@dataclass(frozen=True)
class TransformPipelineBundle:
    out_dir: Path
    artifacts: list[str]


def _dump_json(path: Path, value: Any) -> None:
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _hash_value(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()[:12]


def _read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        return [dict(row) for row in csv.DictReader(handle)]


def _write_csv(path: Path, rows: list[dict[str, str]], fieldnames: list[str]) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def _redact_field(
    field: str,
    value: str,
    mapping: RedactionMap,
    field_counters: dict[str, int],
) -> str:
    template = SENSITIVE_FIELD_TOKENS.get(field)
    if template is not None:
        field_counters[field] = field_counters.get(field, 0) + 1
        return template.format(n=field_counters[field])
    clean, _ = redact(value, mode="replace", mapping=mapping)
    return clean


def _audit_entry(
    *,
    row_index: int,
    field: str,
    action: str,
    output_field: str | None,
    value: str,
    phi_items: int,
) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "record_index": row_index,
        "field": field,
        "action": action,
        "decision": "omitted" if action == "drop" else "transformed",
        "output_field": output_field,
        "input_sha256": hashlib.sha256(value.encode("utf-8")).hexdigest(),
        "input_length": len(value),
        "phi_items": phi_items,
        "raw_value_retained": False,
    }


def _summary_md(manifest: dict[str, Any], audit_count: int) -> str:
    return "\n".join(
        [
            "# Synthetic Transform Pipeline",
            "",
            "This bundle demonstrates local redact/drop/hash/allow transforms.",
            "Audit entries are metadata-only and do not retain raw sensitive values.",
            "It is a developer guardrail, not legal advice or compliance certification.",
            "",
            f"- Source: {manifest['source_name']}",
            f"- Records processed: {manifest['records_processed']}",
            f"- Audit entries: {audit_count}",
            "- External network: disabled",
            "",
        ]
    )


def write_transform_pipeline_bundle(
    source_csv: str | Path,
    out_dir: str | Path,
    policy: dict[str, str] | None = None,
) -> TransformPipelineBundle:
    """Apply a deterministic synthetic transform policy and write artifacts."""
    source_path = Path(source_csv)
    out_path = Path(out_dir)
    out_path.mkdir(parents=True, exist_ok=True)

    rows = _read_csv(source_path)
    selected_policy = dict(policy or DEFAULT_POLICY)
    invalid_actions = {
        action for action in selected_policy.values() if action not in {"allow", "drop", "hash", "redact"}
    }
    if invalid_actions:
        raise ValueError(f"unsupported transform action(s): {sorted(invalid_actions)}")

    redaction_map = RedactionMap()
    field_counters: dict[str, int] = {}
    audit_entries: list[dict[str, Any]] = []
    transformed_rows: list[dict[str, str]] = []

    for row_index, row in enumerate(rows):
        transformed: dict[str, str] = {}
        for field, value in row.items():
            action = selected_policy.get(field, "drop")
            before_count = sum(redaction_map.counters.values())
            if action == "allow":
                transformed[field] = value
                output_field = field
            elif action == "drop":
                output_field = None
            elif action == "hash":
                transformed[field] = _hash_value(value)
                output_field = field
            else:
                transformed[field] = _redact_field(field, value, redaction_map, field_counters)
                output_field = field
            after_count = sum(redaction_map.counters.values())
            audit_entries.append(
                _audit_entry(
                    row_index=row_index,
                    field=field,
                    action=action,
                    output_field=output_field,
                    value=value,
                    phi_items=max(0, after_count - before_count),
                )
            )
        transformed_rows.append(transformed)

    output_fields = [
        field
        for field in selected_policy
        if selected_policy[field] != "drop" and any(field in row for row in transformed_rows)
    ]
    _write_csv(out_path / "transformed-records.csv", transformed_rows, output_fields)

    policy_doc = {
        "schema_version": 1,
        "name": "synthetic-default-transform-policy",
        "actions": selected_policy,
        "default_action_for_unknown_fields": "drop",
        "raw_value_retention": "never in public transform artifacts",
    }
    _dump_json(out_path / "policy.json", policy_doc)

    audit_path = out_path / "transform-audit.jsonl"
    audit_path.write_text(
        "".join(json.dumps(entry, sort_keys=True) + "\n" for entry in audit_entries),
        encoding="utf-8",
    )

    manifest = {
        "schema_version": 1,
        "mode": "synthetic_transform_pipeline",
        "source_name": source_path.name,
        "records_processed": len(rows),
        "synthetic_only": True,
        "raw_phi_in_public_artifacts": False,
        "legal_certification": False,
        "external_network": False,
        "mcp_live_bridge": False,
        "audit_log_retention": "metadata_only",
        "actions": ["allow", "drop", "hash", "redact"],
        "artifacts": ARTIFACTS,
    }
    _dump_json(out_path / "manifest.json", manifest)
    (out_path / "summary.md").write_text(
        _summary_md(manifest, audit_count=len(audit_entries)),
        encoding="utf-8",
    )

    return TransformPipelineBundle(out_dir=out_path, artifacts=list(ARTIFACTS))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="readiness.transform_pipeline")
    parser.add_argument("--source", required=True, help="synthetic CSV input path")
    parser.add_argument("--out", required=True, help="directory to write the bundle")
    args = parser.parse_args(argv)

    try:
        bundle = write_transform_pipeline_bundle(args.source, args.out)
    except (FileNotFoundError, ValueError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    sys.stdout.write(to_json({"out_dir": str(bundle.out_dir), "artifacts": bundle.artifacts}) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
