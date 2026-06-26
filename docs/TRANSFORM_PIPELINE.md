# Synthetic Transform Pipeline

`phantom-secure-connector` P2 slice 2 adds a deterministic local transform
pipeline that demonstrates the privacy-gateway actions required before data is
handed to a bridge, report, or downstream tool:

```text
synthetic CSV -> policy actions -> transformed CSV + metadata-only audit log
```

Run it locally:

```powershell
python -m readiness.transform_pipeline --source <synthetic-source.csv> --out <bundle-dir>
```

Or, after installation:

```powershell
phantom-secure-transform --source <synthetic-source.csv> --out <bundle-dir>
```

## Policy Actions

The default synthetic policy covers four actions:

| Action | Meaning | Public artifact behavior |
| --- | --- | --- |
| `redact` | Replace sensitive values with deterministic tokens. | Raw values are omitted. |
| `drop` | Remove a field from the transformed dataset. | The field is absent from `transformed-records.csv`. |
| `hash` | Store a short SHA-256 digest for correlation. | Raw values are not retained. |
| `allow` | Preserve fields that are explicitly safe in the synthetic policy. | Only non-sensitive fixture fields should use this action. |

Unknown fields default to `drop`.

## Artifact Contract

The bundle writes these files:

- `manifest.json`: schema version, mode, safety flags, actions, and artifact list.
- `policy.json`: default synthetic transform policy.
- `transformed-records.csv`: output after redact/drop/hash/allow actions.
- `transform-audit.jsonl`: metadata-only per-field audit log.
- `summary.md`: short human-readable summary.

`manifest.json` must include:

```json
{
  "schema_version": 1,
  "mode": "synthetic_transform_pipeline",
  "synthetic_only": true,
  "raw_phi_in_public_artifacts": false,
  "legal_certification": false,
  "external_network": false,
  "mcp_live_bridge": false,
  "audit_log_retention": "metadata_only"
}
```

## Audit Log Boundary

`transform-audit.jsonl` records field name, action, output field, input length,
input SHA-256, PHI item count, and decision. It does not store raw values,
reversible redaction maps, full source rows, or prompt text.

The pipeline is a developer guardrail. It is not legal advice, not a
HIPAA/GDPR/PCI certification, and not proof that arbitrary real data is safe.
