# Synthetic Data-plane Guard Scenario

`phantom-secure-connector` P3 adds a deterministic scenario bundle that proves
the P2 transform pipeline can be handed to a bridge-like data-plane guard
without exporting raw identifiers, reversible maps, full rows, or live regulated
connector claims.

The scenario consumes a completed synthetic transform bundle:

```text
synthetic transform bundle -> metadata-only guard scenario bundle
```

Run it locally:

```powershell
python -m readiness.guard_scenario --source <transform-bundle-dir> --out <scenario-bundle-dir>
```

Or, after installation:

```powershell
phantom-secure-guard-scenario --source <transform-bundle-dir> --out <scenario-bundle-dir>
```

## Accepted Source Bundle

The source must be a `synthetic_transform_pipeline` bundle with these safety
flags:

```json
{
  "synthetic_only": true,
  "raw_phi_in_public_artifacts": false,
  "legal_certification": false,
  "external_network": false,
  "mcp_live_bridge": false,
  "audit_log_retention": "metadata_only"
}
```

The source manifest artifact list must stay inside the bundle directory and must
include:

- `manifest.json`
- `policy.json`
- `transformed-records.csv`
- `transform-audit.jsonl`
- `summary.md`

## Artifact Contract

The scenario bundle writes these files:

- `manifest.json`: schema version, source mode, safety flags, and artifact map.
- `guard-scenario.json`: records processed, transformed fields, policy actions,
  readiness booleans, and explicit unsupported boundaries.
- `policy-decisions.json`: metadata-only per-field policy decisions.
- `audit-summary.json`: aggregate action counts and retention flags.
- `summary.md`: short human-readable summary.

`manifest.json` must include:

```json
{
  "schema_version": 1,
  "mode": "synthetic_data_plane_guard_scenario",
  "source_mode": "synthetic_transform_pipeline",
  "synthetic_only": true,
  "raw_phi_in_public_artifacts": false,
  "legal_certification": false,
  "external_network": false,
  "mcp_live_bridge": false
}
```

## Boundary

The bundle is metadata-only. It does not include raw synthetic identifiers,
input hashes, full source rows, reversible redaction maps, prompt text, external
network activity, or a live MCP bridge.

The scenario is a developer guardrail. It is not legal advice, not a
HIPAA/GDPR/PCI certification, and not proof that arbitrary real data is safe.
