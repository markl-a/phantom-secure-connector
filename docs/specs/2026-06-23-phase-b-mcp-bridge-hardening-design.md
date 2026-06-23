# phantom-secure-connector Phase B — MCP bridge 收尾(P-A)設計

- **日期:** 2026-06-23
- **狀態:** DRAFT(待 owner review → 進 writing-plans)
- **作者:** Claude Code(brainstorming;依 owner 拍板的 ②+③+選配 SDK adapter scope + 2026-06-23 web-validated 營利分析)
- **關係:** 本文是 `docs/phantom-secure-connector.md` 路線圖 **P-A** 的設計,**不修改既有定位/紅線**。承接 Phase A(`readiness/` 報告已完成、已併入 master)。本文只定義 P-A 範圍與設計;落地後回填主文件。

---

## 0. 一句話

> 在既有 `mcp_bridge`(client + server)之上加**三層防護**:① 每工具 **capability scoping**(最小權限、拒絕執行)、② 入站**注入閘擴展**(discovery 時掃工具描述擋 tool-poisoning + 回應遞迴掃描)、③ **選配 extras-gated 官方 `mcp` SDK adapter**(核心維持零依賴)。並把每筆 capability-denial / injection finding 以 **deterministic 靜態表**對應到 **OWASP Top 10 for Agentic Applications 2026** + **台灣 PDPA / AI 基本法**,讓閘的輸出直接成為可引用的稽核交付料。

## 1. 為什麼(scope 決策依據)

- **owner 拍板**:②+③ + 選配 SDK adapter —— **不全面遷移官方 SDK**,守住 stdlib-only / 零 runtime 依賴這條主文件親口認證的差異化護城河。
- **營利分析(2026-06-23,web 驗證)**:capability scoping + injection gate 直接對應 OWASP Agentic 2026 的 *tool misuse* / *prompt injection* = 稽核賣點(MCP 稽核已是 2026 真實付費類別);官方 SDK adapter 是「能接客戶現有 MCP 棧」的互通可信度信號、營收關聯低 → 維持**最低成本、extras-gated**。**框架對應(OWASP-Agentic-2026 + PDPA/AI 基本法)= 低成本高槓桿加值**,讓閘/報告輸出變成 $8–25k 稽核的交付樣張與 NLnet 申請 demo。

## 2. 守住既有紅線(不可違反)

| 既有紅線 | Phase B 如何遵守 |
|---|---|
| stdlib-only、零 runtime 依賴 | 核心全 stdlib;官方 SDK **只在 `[mcp-sdk]` extra**,`try/except ImportError` → 核心永不因缺 SDK 而 import 失敗 |
| 報告預設遮罩 PHI | 既有 `redact_arguments` / `Violation.to_dict(show_matches=False)` / `Finding.to_dict(show_matches=False)` **原樣不動**;新輸出一律遮罩 |
| 全本機、無雲端 | 閘與對應表全本機;不外送 |
| 無 LLM | capability gate + 框架對應 = **deterministic 靜態表/查表**;注入掃描沿用既有 `secops_simulator`(regex/hermetic),**不引入 LLM** |
| 不過度宣稱合規 | 框架對應措辭一律「**對應 / 參考**(maps to / per)」非「認證 / 合規」;結構化輸出附免責欄位 |

## 3. 架構取向

**在既有閘上加層,不重寫 client/server。** 新增 3 個模組 + 既有兩檔小改 + packaging 小改:

```
mcp_bridge/
  capabilities.py   (NEW)  Capability enum + CapabilityPolicy + 每工具宣告 + check()
  frameworks.py     (NEW)  靜態對應表:capability / finding-family → OWASP-Agentic-2026 + PDPA/AI-Act 參考
  sdk_adapter.py    (NEW)  選配:try import mcp;把同一組工具(含 capability gate)經官方 SDK 再曝露一次
  server.py         (MOD)  Tool 加 capabilities 欄;tools/call 先過 capability gate;tools/list 輸出 caps + frameworks
  client.py         (MOD)  discovery 掃 tools/list 描述+名稱;回應掃描改遞迴;per-tool capability 上限(選配)
pyproject.toml      (MOD)  [project.optional-dependencies] mcp-sdk;testpaths 補 readiness/tests(修 Phase A 遺漏)
```

- **deterministic、無 LLM、核心 stdlib-only**;測試比照本 repo 慣例放 `mcp_bridge/tests/`(per-package)。

## 4. 範圍 + 行為

### ② Per-tool capability scoping(`capabilities.py` + `server.py`)

- **能力詞彙**(`Capability` enum,6 個,夠表達本套件所有工具):`NETWORK`、`FILESYSTEM`、`SUBPROCESS`、`WRITE`、`PHI_REVERSE`、`PURE`(`PURE` = 純計算、不碰外界)。
- **每工具宣告**(server 9 工具,設計值):

  | 工具 | 所需 capabilities |
  |---|---|
  | `redact_phi` / `mask_text` / `list_standards` / `compliance_scan` | `PURE` |
  | `compliance_scan_file` | `FILESYSTEM` |
  | `restore_text` | `PHI_REVERSE`(可逆還原原始 PHI = 高敏感) |
  | `phantom_status` | `NETWORK` |
  | `phantom_fts5_search` | `SUBPROCESS` |
  | `phantom_event_capture` | `SUBPROCESS` + `WRITE` |

- **`CapabilityPolicy`**:被授予的能力集合。**預設收斂**(`{PURE, FILESYSTEM}` —— 純引擎 + 唯讀檔掃描;`NETWORK`/`SUBPROCESS`/`WRITE`/`PHI_REVERSE` 預設**不授予**)。`--grant net,subprocess,write,phi-reverse` 顯式放寬。
- **`tools/call` 閘**:工具所需 caps **⊄ 授予集合 → 回 JSON-RPC error(capability denied),handler 永不執行**。錯誤訊息**靜態**(列出被拒能力,不回 caller 控制的字串 → 不洩 PHI)。錯誤 code 用自訂 `-32040`(JSON-RPC 保留外的 app 範圍),`message` 固定。
- **`tools/list` 透明化**:每工具輸出 `"capabilities": [...]` + `"frameworks": [...]`(§4 報告對應),對齊 secops 掃描器的 `x-phantom caps` 概念,全套件一致。
- **client 側**:把扁平 allowlist 升級為「allowlist + 每工具 capability 上限(選配)」;**預設維持現有 allowlist 行為不破壞**(未指定上限的工具沿用名單放行)。

### ③ Inbound 注入閘擴展(`client.py`,複用 `secops_simulator.scan`)

- **discovery-time 掃描(新)**:`list_tools()` 取回後,對每個工具的 **name + description** 跑 `scan_injection` → 封住 **tool-poisoning / line-jumping**(惡意指令藏在工具描述,現行閘**完全沒擋**)。命中行為沿用既有 `scan_mode`。**預設 `block`(fail-closed,與本 repo「security gate 必須報錯不可靜默丟資料」哲學一致)**;可切 `warn`(記 finding 不擋)。被擋 → `MCPClientError`。
- **回應掃描(改強)**:從現行 `json.dumps(result)` **整塊**掃,改成**遞迴走每個字串欄位**(沿用 client `_walk` 模式)→ 降漏掃、命中定位更準。block/warn 行為不變。
- **掃描結果**附 §4 框架對應欄位。

### ① 選配官方 `mcp` SDK adapter(`sdk_adapter.py` + packaging)

- `try: import mcp` → 缺則 `SDK_AVAILABLE = False`,呼叫建構函式時丟清楚錯誤:`官方 mcp SDK 未安裝;pip install .[mcp-sdk]`。**核心 import 路徑永不碰 SDK。**
- `build_sdk_server()`:用官方 SDK 把**同一組 `DEFAULT_TOOLS`**(含 capability gate)再曝露一次 —— 同名、同 schema、同 handler、同遮罩。
- `pyproject.toml` 加 `[project.optional-dependencies] mcp-sdk = ["mcp>=X.Y"]`(版本待 §8 釘)。
- **對照(parity)測試**:`@pytest.mark.skipif(not SDK_AVAILABLE)` —— 裝了才跑,斷言 adapter 曝露的工具名 + inputSchema 與手刻 `PhantomMCPServer` **完全一致**(行為不退步);沒裝就 skip → **核心 CI 永遠零依賴綠燈**。

### 報告對應加值(`frameworks.py`,deterministic 靜態表)

- 對應表(查表,無 LLM):
  - **capability → 框架參考**:例 `SUBPROCESS`/`WRITE` → `OWASP-AGENTIC-2026: Tool Misuse` + `PDPA 第27條(安全維護)`;`PHI_REVERSE` → `PDPA 第6條(特種個資)` + `HIPAA minimum-necessary`。
  - **injection finding family → 框架參考**:`instruction-override` 等 → `OWASP-AGENTIC-2026: Prompt Injection` / `OWASP-LLM01` + `AI 基本法(問責/安全原則)`。
- capability-denial error 與 injection finding 的**結構化輸出附 `"frameworks": [refs]`**。
- **免責欄位**:`"disclaimer": "informational mapping to OWASP/PDPA/AI-Act — NOT a certification or legal advice"`。

## 5. 三層界線 + 角色

| 層 | 不接任何東西 | 接 4 AI | 接 mesh |
|---|---|---|---|
| 能力 | client/server 閘 + capability gate + 框架對應(純本機、無 LLM) | 自己的 agent(codex/claude/openclaw/hermes)接外部 MCP 時走 client 閘 = 執行時護甲 | server 以最小權限把 phantom 套件曝露給 Claude Desktop;之後可把 `readiness.assess` 經 bridge 曝露(Phase C) |
| 角色 | **自用 + 稽核交付料(站得住)** | owner 原始目標「運行時相對安全」本體 | 更有未來 |

## 6. 與其他專案的分工(不重複)

- **secops** = MCP 設定**靜態**風險(`mcp_audit.py`,離線不連線)。**secure-connector = 執行時閘**(真的連出去 / 被連入時即時去識別 + 擋注入 + capability gate)。兩者互補,不重做。
- **phantom-mesh** = 加密/身分/傳輸;本 phase 不碰。

## 7. 風險與緩解

1. **官方 SDK 不穩定 / 依賴 churn** → extras-gated + parity 測試 + 核心永不依賴;SDK 升級只影響 opt-in 使用者。
2. **discovery `block` 太吵**(正常工具描述含 "ignore"/"system" 等字觸發誤判)→ 預設 `block` 但可切 `warn`;命中附遮罩 finding 供人工複核;§8 待確認預設值。
3. **框架對應被誤當合規認證** → 措辭「對應/參考」+ 每筆 `disclaimer` 欄位 + 免責。
4. **capability 預設過鬆/過緊** → 預設收斂(`{PURE, FILESYSTEM}`)+ `--grant` 顯式放寬;附「拒絕高敏感工具」「放寬後放行」雙向測試。
5. **守 stdlib-only** → 新模組只 import stdlib + 既有套件;SDK adapter 隔離在 try/except。

## 8. owner 定案(2026-06-23,採建議預設)

- **discovery 掃描預設 = `block`**(fail-closed;可 `--scan-mode warn` 切換)。
- **Capability 詞彙 = 6 個 enum**(`NETWORK`/`FILESYSTEM`/`SUBPROCESS`/`WRITE`/`PHI_REVERSE`/`PURE`)。
- **`default granted` = `{PURE, FILESYSTEM}`**(最小權限;`phantom_status` 的 `NETWORK` 預設擋,需 `--grant net` 放寬 —— 維持 fail-closed)。
- **`mcp` SDK pin = `mcp>=1.0`**(floor;extras-gated + parity 測試把關,升級只影響 opt-in 使用者)。

## 9. Phase C+(本 spec 外)

OWASP LLM03–10 / Agentic 其餘控制;Ingest pipeline(HealthKit/Garmin → 去識別 → 加密 → FTS5);把 `readiness.assess` 經 `mcp_bridge` 曝露成工具;B2B 報告模板 + 瀏覽器/IDE 剪貼簿擴充。
