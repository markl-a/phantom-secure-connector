# Roadmap — phantom-secure-connector

> Single source of truth for project status. README links here; do not duplicate
> status lists elsewhere. Date-stamped 2026-06-19. "Shipped" entries are grounded
> in merged commits on `master`.

## Shipped

Stdlib-only, Python 3.8+, no runtime dependencies. 112 tests passing in CI
(`phi_redactor` / `compliance_checker` / `mcp_bridge` / `secops_simulator`).

### `phi_redactor/` — PHI / PII de-identification
- Regex de-identification for Taiwan + western identifiers (TW national ID,
  NHI / 健保卡, MRN, SSN, Email, DOB).
- Reversible mapping (`mode="replace"`) with **byte-exact** `RedactionMap.restore()`,
  immune to source-token collisions; plus irreversible `mode="mask"` with an
  accurate PHI tally.
- Fail-closed type guards: malformed input fails safe, never leaks; dict-key
  redaction is collision-safe and fail-closed.

### `compliance_checker/` — CSV / JSON compliance scanner
- CLI: `python3 -m compliance_checker.checker --standard <std> <file>`.
- **Four** standards via TOML rule files: `hipaa`, `gdpr`, `pci-dss`, `tw-pii`
  (anchored regexes, no over-match).
- Violation report **masks matched PHI by default** (HIPAA "minimum necessary" /
  GDPR data minimisation); `--show-matches` opts in to raw values for local
  inspection only.
- Output formats: text (default), `--json`, and **self-contained HTML**
  audit report (`--format html` / `--html-out PATH`, `html.escape` XSS-safe).
- Clean operator-error handling: exit `0` = clean, `1` = violations, `2` =
  operator error (unknown standard, missing/unsupported file). No raw tracebacks.

### `secops_simulator/` — native OWASP-LLM01 prompt-injection / jailbreak detector
- CLI: `python3 -m secops_simulator <file-or-text>` (exit `0` = clean,
  `1` = findings, `2` = operator error; mirrors `compliance_checker`).
- Native, **hermetic** detector — no LLM, no network, no sibling-repo
  subprocess shell-out. `scan(text) -> list[Finding]`, masked by default.
- Signature families: instruction-override, persona-jailbreak (DAN / AIM /
  "you are now"), system-prompt-leak, delimiter-injection, tool-poisoning.
- `--json` and `--show-matches` flags. `simulator.run_simulation` retains an
  optional bridge to an external `phantom-secops` harness when present.

### `mcp_bridge/server.py` — inbound MCP server (phantom tools for Claude Desktop / Cursor)
- Newline-delimited JSON-RPC over stdio; cross-platform `--server` tokenising.
- **Nine** tools (up from the original 3): `phantom_status`,
  `phantom_fts5_search` (via `phantom recall --json`), `phantom_event_capture`,
  `redact_phi`, `list_standards`, `compliance_scan`, `compliance_scan_file`,
  `mask_text`, `restore_text`.
- The five engine tools wrap the **real** `compliance_checker` and
  `phi_redactor` engines. PHI is masked by default; `mask_text` returns only
  tokens (no raw PHI crosses the wire) and the reverse map stays server-side for
  `restore_text` (byte-exact round-trip). Server cannot crash on a bad call and
  never leaks PHI via error paths.

### `mcp_bridge/client.py` — outbound MCP client with security gate
- CLI (`secure-mcp` / `phantom-secure-connector` console scripts, or
  `python3 -m mcp_bridge.client`): `--server "<cmd>"` `--list` |
  `--call <tool> --args '<json>'`, with `--allow` allowlist and `--timeout`.
- Spawns an external MCP server over stdio; **outbound** calls pass an
  allowlist + PHI-redaction gate.
- **Inbound prompt-injection gate**: untrusted tool *responses* are scanned via
  `secops_simulator.scan` (block → `MCPClientError`; warn → recorded findings +
  `[gate] inbound injection flagged` log). Closes indirect prompt-injection /
  tool-poisoning from a malicious MCP server.

### Project / infra
- Apache-2.0 licence; GitHub Actions CI (pytest on Python 3.11).
- `docs/demo.cast` — asciinema recording of the PHI redactor (self-hosted, no
  third-party upload).

## In progress

- Continued hardening of the MCP inbound-injection gate and broader real-tool
  coverage on the bridge. (Nothing in this section is part of the shipped
  surface until merged to `master`.)

## Planned-next

- **`phi_redactor`** — LLM-augmented edge-case catches via the phantom-mesh
  provider trait (free-text names, unstructured addresses, context-dependent
  PHI); optional Presidio-style spaCy NER fallback behind a feature flag;
  differential-privacy mode for aggregate exports.
- **`compliance_checker`** — NER-backed HIPAA name detection (today's
  capitalised-pair regex over-flags "New York" / "Apple Inc").
- **`secops_simulator`** — broaden beyond LLM01 toward OWASP LLM02–10 and a
  live red-team battery driven through any phantom-mesh provider.
- **`mcp_bridge`** — migrate the hand-rolled JSON-RPC loop to the official `mcp`
  Python SDK once the spec stabilises; per-tool capability scoping aligned with
  phantom-mesh's cap system.
- **Ingest** — HealthKit / Garmin Connect pipeline (redact → encrypt → FTS5).
- **B2B / packaging** — multi-tenant audit-report templates; Chrome / VS Code
  clipboard-redact extension.

> Note: the time-series `anomaly_detector` that earlier specs listed as a fifth
> module has been **moved to phantom-companion** (commit `011cee7`) and is no
> longer part of this repo.
