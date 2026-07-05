# phantom-secure-connector — Feature Audit

Honest status of what is shipped and tested versus what is roadmap. Grounded in
the modules and the tests under each package's `tests/` directory (21 test files
across five packages as of this writing). Update this file when status changes.

This is a **developer guardrail**, not legal advice or a compliance
certification. The engines are stdlib-only; only the official-SDK MCP server
touches a third-party dependency (`mcp`), and it is an optional `[mcp-sdk]` extra.

Legend: **Shipped + tested** = working code with tests; **Tier-1 / partial** =
working baseline with an explicitly documented not-yet-complete boundary.

## Package status

| Package | Status | Notes |
| --- | --- | --- |
| `phi_redactor` | Shipped + tested | Regex-first PHI/PII detector + redactor. Reversible `replace` mode (token + restore mapping) and irreversible `mask` mode. Bilingual coverage (Taiwan 身分證/健保 + Western SSN/email/phone/MRN); longer patterns run first to avoid partial capture. 1 test file. Marked Tier-1: pattern coverage grows over time. |
| `compliance_checker` | Shipped + tested | Scans free text and CSV/JSON files for violations against standards defined in `rules/*.toml` (HIPAA, …). `checker.py` + `validators.py`. 3 test files. |
| `secops_simulator` | Shipped + tested | Red/blue-team injection detection + simulation (`detector.py`, `simulator.py`) — the inbound-injection gate that continuously validates behaviour. 2 test files. |
| `readiness` | Shipped + tested | Readiness scoring/assessor + HTML report + three deterministic synthetic bundles (`demo_loop`, `transform_pipeline`, `guard_scenario`), each with a documented artifact contract. 9 test files (the largest suite). |
| `mcp_bridge` (client) | Shipped + tested | Outbound MCP client (`client.py`) with the PHI-redaction + injection-scan + tool-allowlist security gate on every outbound call. Part of the 6 `mcp_bridge` test files. |
| `mcp_bridge` (stdlib server) | Shipped + tested | `mcp_bridge.server` — MCP-style `tools/list` / `tools/call` surface over plain JSON-RPC, stdlib-only (no `mcp`/`fastmcp` dependency). Exposes `redact_phi`, `list_standards`, `compliance_scan`, `compliance_scan_file`, `mask_text`, `restore_text`, …. |
| `mcp_bridge` (SDK server) | Shipped + tested (parity) | `mcp_bridge.sdk_adapter` (`phantom-secure-connector-mcp`) exposes the same tools via the official `mcp` Python SDK. Import-guarded: it is the only module that touches the SDK, installed via `pip install -e .[mcp-sdk]`. `tool_specs()` is pure so tool parity is tested with zero dependencies; `build_sdk_server()` requires the SDK. |

## MCP server: exact commands

```powershell
# stdlib JSON-RPC server (no extra needed)
python -m mcp_bridge.server

# official-SDK server (needs the optional extra)
python -m pip install -e .[mcp-sdk]
phantom-secure-connector-mcp
```

Tool table + Claude Desktop / Cursor config: [mcp_bridge/README.md](mcp_bridge/README.md).

## What "tested" means here

Tests are hermetic and offline: PHI/compliance/injection paths run against
synthetic fixtures, and the SDK-parity test does not require the `mcp` SDK to be
installed. `pip install -e .[dev] && python -m pytest -q` runs with no network.

## Honest limitations

- PHI regex coverage is Tier-1 and grows over time; it is not a guarantee of
  exhaustive de-identification for every document shape.
- Compliance scanning reflects the rules in `rules/*.toml`, not a certified audit
  against the full text of any standard.
- The SDK server is an optional extra; the stdlib server is the always-available
  path.

## Roadmap (not yet shipped)

- Expand PHI pattern coverage beyond the Tier-1 set.
- Grow the compliance rule packs beyond the current standards.
