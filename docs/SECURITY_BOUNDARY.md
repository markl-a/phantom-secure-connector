# Security Boundary And Public Demo Contract

`phantom-secure-connector` is a developer guard for PHI/PII redaction,
compliance scanning, readiness reporting, injection detection, and outbound MCP
tool calls. It is not legal advice, not a compliance certification, and not a
production regulated-data connector by itself.

## Safe Public Smoke

Use synthetic data only:

```powershell
$root = Join-Path $env:TEMP ("phantom-secure-demo-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Force -Path $root | Out-Null
$csv = Join-Path $root "patients.csv"
$html = Join-Path $root "readiness.html"

@'
name,ssn,note
Synthetic Patient,123-45-6789,checkup
'@ | Set-Content -LiteralPath $csv -Encoding UTF8

python -m compliance_checker.checker --standard hipaa --json $csv
python -m readiness $csv --standards hipaa --html-out $html
python -m mcp_bridge.client --help

Remove-Item -LiteralPath $root -Recurse -Force
```

Expected shape:

- Compliance JSON returns findings with the `matched` values masked by default.
- Readiness writes a local HTML report.
- MCP help shows the outbound bridge surface without spawning an external
  server.

## MCP Boundary

- Outbound MCP calls are denied unless the tool name is in the explicit
  allowlist.
- String arguments are recursively redacted before crossing the subprocess boundary.
- Tool discovery and tool responses are scanned for injection patterns.
- Public docs must not imply arbitrary external tools are safe by default.

## Data And Claims Policy

- Do not commit raw PHI, real patient records, credentials, audit logs containing
  raw sensitive payloads, or regulated customer data.
- Compliance findings are developer guardrails. They are not HIPAA/GDPR/PCI/TW
  legal certification.
- Raw match display is local-inspection only and must remain explicit opt-in.
