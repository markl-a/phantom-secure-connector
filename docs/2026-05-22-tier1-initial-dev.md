# 2026-05-22 — Tier 1 initial dev

> **Correction (updated since):** this log originally listed an
> `anomaly_detector/` module as shipped. It was later moved out to
> phantom-companion and is **not** in this repo — the table and Tier 2 notes
> below have been corrected. The `mcp_bridge` server now exposes **4** tools
> (`redact_phi`, `phantom_status`, `phantom_recall_search`,
> `phantom_event_capture`) and ships an outbound MCP **client** with a
> PHI-redaction + allowlist gate, so it is no longer a pure stub.

## What shipped (current state)

| Module | Status | Tests |
|---|---|---:|
| `phi_redactor/` | usable today on PHI text (regex; no NER for names) | 9 |
| `compliance_checker/` | usable today on CSV/JSON | 6 |
| `secops_simulator/` | bridge/stub wrapping a local phantom-secops clone | 2 |
| `mcp_bridge/` | JSON-RPC over stdio; server (4 tools) + gated client | 13 |

Total: 30 tests, stdlib-only on Python 3.10+.

## Smoke test command

```bash
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
- **`phantom_recall_search`** already calls `phantom recall --json` (the real,
  supported read path that decrypts `events/`). There is no live sqlite/FTS5
  index to wire up; the earlier "implement FTS5 search" TODO was based on dead
  scaffolding and is dropped.
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
