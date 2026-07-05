# phantom-secure-connector

[![CI](https://github.com/markl-a/phantom-secure-connector/actions/workflows/ci.yml/badge.svg)](https://github.com/markl-a/phantom-secure-connector/actions/workflows/ci.yml)
![license: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue)
[![phantom-mesh ecosystem](https://img.shields.io/badge/ecosystem-phantom--mesh-purple)](https://github.com/markl-a/phantom-mesh)

> PHI 去識別 + 合規掃描 + 入站注入閘 + MCP 橋接 —— phantom-mesh 的資料平面守門員。stdlib-only、雙語(台灣 + 西方識別碼)。敏感資料安全進來、可信工具安全出去、行為被紅藍隊持續驗證。

For the honest shipped-vs-roadmap status of every module, see
[FEATURE-AUDIT.md](FEATURE-AUDIT.md).

## Install

```powershell
# core (stdlib-only engines + stdlib JSON-RPC MCP server), with test tooling
python -m pip install -e .[dev]

# runtime only
python -m pip install -e .

# add the official `mcp` SDK server (optional extra)
python -m pip install -e .[mcp-sdk]
```

Requires Python >= 3.10. The engines (`phi_redactor`, `compliance_checker`,
`secops_simulator`, `readiness`) and the stdlib JSON-RPC bridge
(`mcp_bridge.server`) are stdlib-only; only the official-SDK server needs the
`mcp-sdk` extra.

## Quickstart

```powershell
python -m pip install -e .[dev]
python -m pip install -e . --dry-run --no-deps
python -m pytest -q
python -m mcp_bridge.client --help
```

## Run the MCP server

Two servers expose the same security tools (`redact_phi`, `compliance_scan`,
`compliance_scan_file`, `list_standards`, `mask_text` / `restore_text`, …). The
full tool table plus Claude Desktop / Cursor config is in
[mcp_bridge/README.md](mcp_bridge/README.md).

```powershell
# stdlib-only JSON-RPC server — no third-party deps required
python -m mcp_bridge.server

# official-SDK server — requires the mcp-sdk extra
python -m pip install -e .[mcp-sdk]
phantom-secure-connector-mcp
```

Outbound MCP tool calls made through `mcp_bridge.client` are gated by PHI
redaction, injection scanning, and an explicit tool allowlist (see
[docs/SECURITY_BOUNDARY.md](docs/SECURITY_BOUNDARY.md)).

Deterministic synthetic guardrail loop:

```powershell
$bundle = Join-Path $env:TEMP ("phantom-secure-loop-" + [guid]::NewGuid().ToString("N"))
python -m readiness.demo_loop --out $bundle --standard hipaa
Get-Content (Join-Path $bundle "manifest.json")
Remove-Item -LiteralPath $bundle -Recurse -Force
```

Deterministic synthetic transform pipeline:

```powershell
$root = Join-Path $env:TEMP ("phantom-secure-transform-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Force -Path $root | Out-Null
$csv = Join-Path $root "source-records.csv"
$bundle = Join-Path $root "bundle"

@'
patient,ssn,email,phone,internal_note,consent_flag,age_band
Synthetic Patient,123-45-6789,synthetic.patient@example.test,0912-345-678,Private fixture note with MRN-A12345,research-ok,40-49
'@ | Set-Content -LiteralPath $csv -Encoding UTF8

python -m readiness.transform_pipeline --source $csv --out $bundle
Get-Content (Join-Path $bundle "manifest.json")
Remove-Item -LiteralPath $root -Recurse -Force
```

Deterministic synthetic data-plane guard scenario:

```powershell
$root = Join-Path $env:TEMP ("phantom-secure-guard-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Force -Path $root | Out-Null
$csv = Join-Path $root "source-records.csv"
$transform = Join-Path $root "transform-bundle"
$scenario = Join-Path $root "guard-scenario"

@'
patient,ssn,email,phone,internal_note,consent_flag,age_band
Synthetic Patient,123-45-6789,synthetic.patient@example.test,0912-345-678,Private fixture note with MRN-A12345,research-ok,40-49
'@ | Set-Content -LiteralPath $csv -Encoding UTF8

python -m readiness.transform_pipeline --source $csv --out $transform
python -m readiness.guard_scenario --source $transform --out $scenario
Get-Content (Join-Path $scenario "manifest.json")
Remove-Item -LiteralPath $root -Recurse -Force
```

Synthetic compliance/readiness smoke:

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

This is a developer guardrail, not legal advice or compliance certification.
Outbound MCP calls are protected by PHI redaction, injection scanning, and an
explicit tool allowlist; see [docs/SECURITY_BOUNDARY.md](docs/SECURITY_BOUNDARY.md)
and [docs/SYNTHETIC_GUARDRAIL_LOOP.md](docs/SYNTHETIC_GUARDRAIL_LOOP.md).
The transform pipeline artifact contract is documented in
[docs/TRANSFORM_PIPELINE.md](docs/TRANSFORM_PIPELINE.md). The data-plane guard
scenario contract is documented in
[docs/DATA_PLANE_GUARD_SCENARIO.md](docs/DATA_PLANE_GUARD_SCENARIO.md).

📄 完整文件(定位 / 快速上手 / 狀態路線圖 / 開源方向 / 刻意不做):見 [docs/phantom-secure-connector.md](docs/phantom-secure-connector.md)
