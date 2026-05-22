# phantom-secure-connector

> **PHI 去識別化 + 時序異常偵測 + 合規檢查 + 紅藍隊模擬 + MCP bridge — 一站式
> phantom-mesh 安全套件**,跨產業招聘對齊(資安 / 金融 / 醫材 / AI safety),
> 一個 install 取代四家 vendor。

![status: alpha · Tier 1](https://img.shields.io/badge/status-alpha%20%C2%B7%20Tier%201-orange)
![license: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue)
[![phantom-mesh ecosystem](https://img.shields.io/badge/ecosystem-phantom--mesh-purple)](https://github.com/markl-a/phantom-mesh)

## 一句話 niche

> "Sensitive data comes in safely, trusted tools go out safely, behaviour is
> continuously red/blue-team verified — for phantom-mesh."

Presidio 只做 de-id;NeMo Guardrails 只做 LLM 輸出守門;Garak 只做 red-team;
HIPAA 合規 scanner 是另一坨 SaaS。**phantom-secure-connector 是第一個把這四
塊組合在一起 + 加 MCP bridge 的 phantom 套件** — 中文 (台灣身分證 / 健保
卡 / 病歷號) 與西方識別符 (SSN / DOB / MRN / Email) 一次處理。

## Status (2026-05-22)

- ✅ **Tier 1 shipped** (stdlib-only,本機可跑 pytest):
  - `phi_redactor/` — TW 身分證 + NHI + MRN + SSN + Email + DOB regex,
    可逆 / 不可逆 mode + reversible mapping。
  - `anomaly_detector/` — 通用時序異常偵測(AHI Detection v2 核心移植)。
  - `compliance_checker/` — CSV/JSON 對 HIPAA / GDPR 規則檔掃描。
  - `mcp_bridge/` — Claude Desktop / Cursor 可掛 3 個 phantom tool stub。
- 🟡 **Tier 2 next**: LLM-augmented PHI catches(regex 抓不到的邊界 case via
  phantom-mesh provider trait)、`secops_simulator/` 從 stub 升級(現只是
  介面,要接 phantom-secops 真實 prompt-injection harness)。
- 🟡 **Tier 3** (M2-M3, ~2026-07): AHI 真實資料 vs Nassi et al. 2021
  baseline 驗證、MCP server polish 對齊最新 spec、HealthKit / Garmin
  Connect ingest pipeline (redact → encrypt → FTS5)。

## 30-second quickstart

```bash
git clone https://github.com/markl-a/phantom-secure-connector
cd phantom-secure-connector
python3 -m pytest -v       # all tests, stdlib-only
```

### PHI redactor

```python
from phi_redactor.redactor import redact

text = "張三 1990/01/15 出生, MRN-A123456, alice@example.com SSN 123-45-6789"
clean, mapping = redact(text, mode="replace")
# clean   → "張三 [DOB_1] 出生, [MRN_1], [EMAIL_1] [SSN_1]"
# mapping → reversible map back to originals
```

### Anomaly detector

```python
from anomaly_detector.detector import detect
result = detect([(t, value), ...], window=7)
# → list[(timestamp, value, is_anomaly, score)]
```

### Compliance checker

```bash
python3 -m compliance_checker.checker --standard hipaa path/to/data.csv
```

### MCP bridge

See [`mcp_bridge/README.md`](mcp_bridge/README.md) for Claude Desktop config.

## Architecture (within phantom-mesh ecosystem)

phantom-secure-connector 是 **P4 加密為先** 的資料平面守門員 — 任何進
phantom-mesh memory 的東西先過 PHI redactor;任何離開的工具呼叫過 MCP
bridge 並 log 給 anomaly_detector 做行為偵測。

```
External data (HealthKit / CSV / chat)
       ↓
   phi_redactor  ←──  TW 身分證 / NHI / MRN / SSN / DOB / Email
       ↓
   compliance_checker  ←── HIPAA / GDPR rule files
       ↓
   phantom-mesh FTS5  (encrypted at rest)
       ↓
   mcp_bridge  ←──  Claude Desktop / Cursor
       ↓
   anomaly_detector  ←──  time-series 行為基線
       ↑
   secops_simulator  ──→  red/blue prompt-injection 持續驗證
```

Pillars served: **P4** (加密為先,主要)、**P1** (跨平台 — stdlib-only 確
保 Mac / Windows / Linux 一致行為)、**P2** (分身連線 — MCP bridge 是
phantom-mesh 與外部 IDE 的安全橋)。

## Target users (recruiter / co-builder angle)

跨產業最廣的一個 phantom-mesh satellite:

- **趨勢 Trend Micro** — security AI / SOC tooling、prompt-injection 防護
- **中信 / 國泰 / 富邦** — 金融合規 + PHI/PII de-id 管線
- **醫材公司 / 工研院生醫** — HIPAA + de-id + AHI 異常偵測背景
- **Anthropic** — MCP ecosystem + AI safety / red-team
- **Co-builders**: 想要 self-hosted Presidio + Garak + NeMo Guardrails 三合一
  的 AI infra 工程師。

NOT doing(邊界):非醫材(supportive,not diagnostic);非網路防火牆 / IDS
(資料/應用層而已);非 SOC2 證書(輔助稽核,不取代)。

## Roadmap (per master plan)

- 詳細設計: [`docs/04-phantom-secure-connector.md`](docs/)
- 七專案總圖: [phantom-mesh planning tree](https://github.com/markl-a/phantom-mesh)

3-bullet:

1. **M2** — LLM-augmented PHI(provider trait 接 phantom-mesh)、secops_simulator
   從 stub 升級到真實 prompt-injection harness。
2. **M3** — AHI 真實資料驗證、MCP polish、HealthKit/Garmin ingest。
3. **Post-M3** — SOC2 audit-ready report 自動生成、企業版加密 KMS。

## Sources & credit

- `~/Documents/GitHub/hailmary/phantom-secops/` — 紅藍隊模擬器(referenced,
  未複製)
- AHI Detection v2 research — `markl-a/ahi-cv5-report`
- Medical RAG v1.1.0 — PHI de-id 架構(public 版已 sanitize)

## License

Apache-2.0. © 2026 Mark Lai ([markl-a](https://github.com/markl-a)). See
[LICENSE](LICENSE).
