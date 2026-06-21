# 2026-05-22 — Tier 1 initial dev

> ARCHIVED 2026-06-19 — frozen historical snapshot; current status lives in [/ROADMAP.md](../../ROADMAP.md).

## What shipped

| Module | LOC (approx) | Status | Tests |
|---|---:|---|---:|
| `phi_redactor/` | ~190 | usable today on real PHI text | 9 |
| `anomaly_detector/` | ~170 | usable today, stdlib-only | 5 |
| `compliance_checker/` | ~250 + 2 rule files | usable today on CSV/JSON | 5 |
| `secops_simulator/` | ~120 | stub wrapping phantom-secops | 2 |
| `mcp_bridge/` | ~190 | stub JSON-RPC over stdio, 3 tools | 7 |

Total: ~920 LOC source + ~250 LOC tests, stdlib-only on Python 3.10+.

## Smoke test command

```bash
cd /path/to/phantom-secure-connector
python3 -m pytest -v
```

## What real dev needs next (Tier 2)

### phi_redactor
- **LLM-augmented edge-case catches.** Regex misses free-text personal names,
  unstructured addresses, and context-dependent PHI (e.g. "the patient" + a
  rare condition that is itself identifying). Plan: call phantom-mesh's
  provider trait with a constrained prompt + cite-and-mask response schema.
- **NER fallback.** Add a Microsoft Presidio-style spaCy NER pass behind a
  feature flag for users who can't ship LLM calls.
- **Differential privacy mode.** For aggregate exports (e.g. cohort stats),
  add Laplace noise to bucket counts.

### anomaly_detector
- **Real AHI dataset validation.** Hook the Nassi et al. 2021 dataset and
  reproduce the published Pearson r baseline; add a regression test that
  fails if our generic algorithm drops below 80% of that baseline.
- **STL decomposition.** MAD is great for stationary series, weak for
  seasonal ones (sleep_score has weekly cycles). Add a Tier 2 STL path.
- **Multivariate.** Today each series is independent; AHI v2 fuses HR + SpO2.

### compliance_checker
- **HIPAA name detection.** Today regex `[A-Z][a-z]+ [A-Z][a-z]+` over-flags
  ordinary capitalised pairs ("New York", "Apple Inc"). Needs NER.
- **PCI-DSS rule file.** Card scheme + CVV patterns.
- **個資法 rule file.** Taiwan-specific personal-data definitions.
- **Audit-report HTML output.** Compliance officers want a polished report,
  not raw JSON.

### secops_simulator
- **Native OWASP LLM Top 10 harness.** Don't depend on a sibling repo clone.
  Port the scenarios into `secops_simulator/scenarios/` with stable schema.
- **phantom-mesh provider-trait adapter.** Drive the same prompt-injection
  battery against any provider phantom-mesh supports (Claude, Gemini, MLX,
  llama.cpp).

### mcp_bridge
- **Switch to official `mcp` Python SDK** once the spec stabilises.
- **Implement `phantom_fts5_search`** against the real phantom HTTP search
  endpoint (today returns a canned empty result).
- **Capability scoping.** Today the bridge trusts whatever is on stdio. Add
  per-tool capability negotiation aligned with phantom-mesh's existing cap
  system.
- **Tool surface expansion.** Plan list: `phantom_shell` (sandboxed),
  `phantom_file_read`, `phantom_file_write`, `phantom_web_fetch`,
  `phantom_event_list`, `phantom_event_query`. Target ~10 tools for first
  Claude Desktop marketplace listing.

## Out of Tier 1 scope (documented for completeness)

- HealthKit / Garmin Connect ingest pipeline.
- Multi-tenant audit-report templates for B2B consulting use.
- Chrome / VS Code extension wrapping `phi_redactor` for clipboard-redact.

## How this aligns with phantom-mesh

- Reuses the same Apache-2.0 licence.
- Stdlib-only at Tier 1 so it runs inside phantom's sandbox without
  loosening capabilities.
- Public version targets `github.com/markl-a/phantom-secure-connector`;
  a private fork with real PHI rules + secops content stays in the
  personal GitLab as documented in the master plan.
