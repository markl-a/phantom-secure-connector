# Synthetic Guardrail Loop

`phantom-secure-connector` P2 ships a deterministic local bundle that proves the
minimum public guardrail path:

```text
synthetic source records -> redacted records -> compliance findings
                         -> secops findings -> readiness report
```

Run it locally:

```powershell
$bundle = Join-Path $env:TEMP ("phantom-secure-loop-" + [guid]::NewGuid().ToString("N"))
python -m readiness.demo_loop --out $bundle --standard hipaa
Get-Content (Join-Path $bundle "manifest.json")
```

Or, after installation:

```powershell
phantom-secure-demo-loop --out <bundle-dir> --standard hipaa
```

## Artifact Contract

The bundle writes these files:

- `source-records.csv`: synthetic input fixture. This is the only artifact that
  intentionally contains raw synthetic identifiers.
- `manifest.json`: schema version, mode, safety flags, and artifact list.
- `redacted-records.csv`: redacted/tokenized view of the source records.
- `redaction-summary.json`: PHI type counters only; no reversible raw mapping.
- `compliance-findings.json`: masked compliance findings.
- `secops-findings.json`: masked prompt-injection findings.
- `readiness-summary.json`: unified masked readiness result.
- `readiness.html`: self-contained readiness report.
- `summary.md`: short human-readable summary.

`manifest.json` must include:

```json
{
  "schema_version": 1,
  "mode": "synthetic_guardrail_loop",
  "synthetic_only": true,
  "raw_phi_in_public_artifacts": false,
  "legal_certification": false,
  "external_network": false,
  "mcp_live_bridge": false
}
```

## Data Retention Boundary

Public artifacts other than `source-records.csv` must not retain raw synthetic
identifiers, raw prompt-injection text, or reversible redaction maps. They may
retain masked matches, tokens, locations, counters, rule IDs, and verdicts.

The loop is a developer guardrail. It is not legal advice, not a HIPAA/GDPR/PCI
certification, and not proof that arbitrary real data is safe.
