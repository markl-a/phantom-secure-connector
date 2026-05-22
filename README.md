# phantom-secure-connector

> **PHI de-identification + time-series anomaly detection + compliance checks + red/blue team simulation + MCP bridge — the phantom-mesh security suite, one install.**

**Status:** alpha (Tier 1 initial dev, 2026-05-22). Smoke-tested locally; not for production PHI workloads yet.
**License:** Apache-2.0
**Spec:** `/Users/marklight/Documents/215jseeking/docs/projects/04-phantom-secure-connector.md`
**Sister project:** [phantom-mesh](https://github.com/markl-a/phantom-mesh) — distributed agent runtime; this connector secures its data plane.

---

## One-liner

> "Sensitive data comes in safely, trusted tools go out safely, behaviour is continuously red/blue-team verified — for phantom-mesh."

## Five built-in modules

| Module | Purpose | Tier 1 status |
|---|---|---|
| `phi_redactor/` | Regex-first PHI detection + reversible/irreversible redaction (TW + western identifiers) | usable today |
| `anomaly_detector/` | Generic time-series anomaly detection (port of AHI Detection v2 core) | usable today, stdlib-only |
| `compliance_checker/` | Scan CSV/JSON against HIPAA / GDPR rule files | usable today |
| `secops_simulator/` | Red/blue-team prompt-injection harness (wraps phantom-secops) | stub |
| `mcp_bridge/` | Expose phantom tools to Claude Desktop / Cursor via MCP | stub server (3 tools) |

## Why this exists (hiring & business angle)

Hiring coverage — broadest of the seven phantom-mesh projects:

- **Trend Micro** — security AI / SOC tooling
- **CTBC / Cathay / Fubon** — financial-services compliance
- **Medical-device companies** — HIPAA + de-id pipeline
- **ITRI Biomed** — health-tech research
- **Anthropic** — safety / MCP ecosystem

Niche: **the first one-stop "PHI + anomaly + compliance + red-team + MCP" phantom plugin**. The four building blocks normally sit in four separate vendors.

## Quick start

```bash
git clone https://github.com/markl-a/phantom-secure-connector
cd phantom-secure-connector
python3 -m pytest -v       # all tests, stdlib-only deps
```

### PHI redactor

```python
from phi_redactor.redactor import redact

text = "張三 1990/01/15 出生, MRN-A123456, contact alice@example.com SSN 123-45-6789"
clean, mapping = redact(text, mode="replace")
# clean → "張三 [DOB_1] 出生, [MRN_1], contact [EMAIL_1] [SSN_1]"
# mapping → reversible map back to originals
```

### Anomaly detector

```python
from anomaly_detector.detector import detect

series = [(t, value), ...]   # list[(timestamp, float)]
result = detect(series, window=7)
# result → list[(timestamp, value, is_anomaly, score)]
```

### Compliance checker

```bash
python3 -m compliance_checker.checker --standard hipaa path/to/data.csv
```

### MCP bridge

See [`mcp_bridge/README.md`](mcp_bridge/README.md) for Claude Desktop config wiring.

## NOT doing (boundary)

- Not a medical device. Supportive, not diagnostic.
- Not a network firewall / IDS. We operate at the application / data layer.
- Not a SOC2 certificate. Assists audits; does not replace them.

## Roadmap (post Tier 1)

- LLM-augmented PHI catches (edge cases regex misses) via phantom-mesh provider trait
- Real AHI dataset validation against Nassi et al. 2021 baseline
- MCP server polish to match Anthropic's evolving MCP spec
- HealthKit / Garmin Connect ingest pipeline (redact → encrypt → FTS5)

## Sources & credit

- `~/Documents/GitHub/hailmary/phantom-secops/` — red/blue team simulator (referenced, not copied)
- AHI Detection v2 research — `markl-a/ahi-cv5-report` and related repos
- Medical RAG v1.1.0 — PHI de-id architecture (sanitized for public release)
