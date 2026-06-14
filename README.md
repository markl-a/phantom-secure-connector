# phantom-secure-connector

[![CI](https://github.com/markl-a/phantom-secure-connector/actions/workflows/ci.yml/badge.svg)](https://github.com/markl-a/phantom-secure-connector/actions/workflows/ci.yml)
![status: alpha · Tier 1](https://img.shields.io/badge/status-alpha%20%C2%B7%20Tier%201-orange)
![license: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue)
[![phantom-mesh ecosystem](https://img.shields.io/badge/ecosystem-phantom--mesh-purple)](https://github.com/markl-a/phantom-mesh)

> **PHI/PII de-identification + compliance scanning + an MCP server *and*
> client (the client gates every outbound tool call through a PHI-redaction
> guardrail) — a stdlib-only security suite for the phantom-mesh ecosystem.**

The pitch in one line:

> "Sensitive data comes in de-identified; outbound tool calls are gated through
> a PHI-redaction guardrail + allowlist — for phantom-mesh."

Existing tools each solve one slice: Presidio does de-id, NeMo Guardrails does
LLM output gating, Garak does red-teaming, HIPAA scanners are separate SaaS.
This repo combines **de-id + compliance + an MCP bridge** in one dependency-free
package, handling both Western identifiers (SSN / DOB / MRN / Email) and
Taiwanese ones (national ID / NHI card / medical record number).

## What actually ships today (Tier 1)

Everything below is implemented, tested, and runnable with `python3 -m pytest`
— stdlib only, no third-party runtime dependencies.

| Module | What it does |
|---|---|
| `phi_redactor/` | Regex PHI/PII detector + redactor. Reversible (`replace`) or irreversible (`mask`) mode. Covers TW national ID, NHI, MRN, SSN, email, DOB (ISO + Chinese), TW phone, IPv4, credit-card. |
| `compliance_checker/` | Scan CSV/JSON against HIPAA / GDPR rule files; report violations as text or JSON. |
| `mcp_bridge/server.py` | stdio MCP-style **server** exposing 4 tools (`redact_phi`, `phantom_status`, `phantom_recall_search`, `phantom_event_capture`). |
| `mcp_bridge/client.py` | Outbound MCP **client** with a security gate: PHI-redacts every argument and enforces a tool allowlist *before* anything crosses the process boundary. |
| `secops_simulator/` | Thin subprocess wrapper that dispatches into a local `phantom-secops` clone if present (otherwise prints a config hint). Bridge, not a built-in red-team harness yet. |

> **Honest scope:** the PHI detector is **regex-based**. It does not redact
> personal **names** or free-text addresses — those need NER and are documented
> Tier 2 work (`phi_redactor/redactor.py` lists the gaps). The `secops_simulator`
> is a bridge/stub, not a native OWASP harness.

## Quickstart

```bash
git clone https://github.com/markl-a/phantom-secure-connector
cd phantom-secure-connector
python3 -m pytest -v        # 30 tests, stdlib-only
```

### PHI redactor

```python
from phi_redactor.redactor import redact

text = "1990-01-15 born, MRN-A123456, alice@example.com, SSN 123-45-6789"
clean, mapping = redact(text, mode="replace")
# clean   -> "[DOB_ISO_1] born, [MRN_1], [EMAIL_1], SSN [SSN_1]"
# mapping -> RedactionMap with a reversible token -> original map
```

A runnable example over synthetic data lives in
[`examples/`](examples/) — see [Sample data](#sample-data) below.

### Compliance checker

```bash
python3 -m compliance_checker.checker --standard hipaa examples/sample_phi.csv
```

### MCP server + client (the differentiator)

This repo is both ends of an MCP connection:

- **Server** — expose the phantom suite to Claude Desktop / Cursor. See
  [`mcp_bridge/README.md`](mcp_bridge/README.md) for the host config and tool
  table.
- **Client with a PHI gate** — connect *out* to an external MCP server, but
  redact PHI in the call arguments and enforce an allowlist before the payload
  leaves the process:

  ```bash
  # List an external server's tools (default server cmd: "phantom mcp"):
  python3 -m mcp_bridge.client --server "phantom mcp" --list

  # Call a tool — PHI in --args is tokenised before it crosses the boundary;
  # tools not on the allowlist are blocked locally and never hit the wire.
  python3 -m mcp_bridge.client --server "phantom mcp" \
      --call memory_store --args '{"key":"note","value":"SSN 123-45-6789"}'
  ```

  The gate prints what it did to stderr (`[gate] redacted N PHI item(s) ...`)
  so the security action is visible. The default allowlist excludes destructive
  tools (`shell`, `file_write`, `git_commit`, ...). The end-to-end gate behaviour
  is covered by tests without needing the `phantom` binary.

## Sample data

[`examples/sample_phi.csv`](examples/sample_phi.csv) is a **fully synthetic**
patient table (fabricated names / IDs — no real data).
[`examples/sample_redaction_output.txt`](examples/sample_redaction_output.txt)
is the redactor's actual output over that CSV. Regenerate it with:

```bash
python3 examples/redact_sample.py
```

## Architecture (within phantom-mesh)

phantom-secure-connector is a data-plane gate: text entering phantom-mesh memory
is run through the PHI redactor; outbound tool calls go through the MCP client
gate.

```
External data (CSV / chat / clipboard)
       |
   phi_redactor        <- TW national ID / NHI / MRN / SSN / DOB / email / phone / IPv4 / card
       |
   compliance_checker  <- HIPAA / GDPR rule files
       |
   phantom-mesh event store (encrypted at rest)
       |
   mcp_bridge/server   <- exposes redact_phi / phantom_recall_search / phantom_status / phantom_event_capture
   mcp_bridge/client   <- gates OUTBOUND tool calls (PHI redaction + allowlist)
```

### A note on the search path (read this if you saw "FTS5" anywhere)

`phantom_recall_search` reads the phantom event timeline by shelling out to
`phantom recall --json`, which decrypts the per-event `events/` store. **There is
no live sqlite/FTS5 index in this path.** An `events.sqlite` / `fts5_events`
table exists in phantom-mesh history as contentless scaffolding that was never
synced — this connector does not use it, and the tool is named for what it
actually does (`recall`), not for that dead index.

## Target users (recruiter / co-builder angle)

- **Security AI / SOC tooling** — MCP integration + a PHI-redaction guardrail on
  outbound tool calls.
- **Finance / healthcare compliance** — de-id + HIPAA/GDPR scanning over CSV/JSON.
- **MCP ecosystem builders** — a worked example of an MCP server *and* a gated
  MCP client in dependency-free Python.

**NOT doing (boundaries):** not a medical device (supportive, not diagnostic);
not a network firewall / IDS (application/data layer only); not a SOC2
certification (assists an audit, does not replace one).

## Roadmap (Tier 2+)

1. LLM-augmented PHI detection for cases regex misses (names, addresses) via a
   phantom-mesh provider trait.
2. Upgrade `secops_simulator` from a subprocess bridge to a native OWASP LLM
   Top 10 / prompt-injection harness.
3. Swap the hand-rolled JSON-RPC loop for the official `mcp` Python SDK once the
   spec stabilises.

## License

Apache-2.0. © 2026 Mark Lai ([markl-a](https://github.com/markl-a)). See
[LICENSE](LICENSE).
