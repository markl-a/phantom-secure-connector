# phantom-secure-connector — 統一「資料保護就緒度」稽核報告(Phase A)設計

- **日期:** 2026-06-23
- **狀態:** DRAFT(待 owner review → 進 writing-plans)
- **作者:** Claude Code(brainstorming;依本 session 的營利模型 + owner 拍板 A→B)
- **關係:** 本文是 `docs/phantom-secure-connector.md` 既有路線圖的**新增第一塊(Phase A)**,**不修改既有定位/紅線**。定位/護城河以主文件為準;本文只定義 Phase A 範圍與設計。Phase B = 主文件路線圖的 **P-A**(mcp_bridge 遷官方 SDK + capability scoping)。

---

## 0. 一句話

> 一個新的本機 CLI/模組,把**現有三個成熟引擎**(`phi_redactor` / `compliance_checker` / `secops_simulator`)跑過你指定的目標,產出**一份**對應 HIPAA/GDPR/PCI-DSS/TW-PII 的**自含式 HTML 稽核可交付物**(+ JSON)。它是 owner 自我稽核的工具,也是 **vCISO/合規服務的交付物**,並把 **secops(MCP 掃描器)+ secure-connector 合成「資料保護 + MCP 資安稽核」一個 offer**。

## 1. 為什麼做這個(決策依據)

本 session 研究(2026-06-22,有來源)結論:AI×資安 solo 的錢在**賣服務**(#2 = vCISO/合規 retainer,吃 EU AI Act 2026-08-02 + ISO 42001 + TW-PII 垂直),**免費 OSS = 可信度/交付物**,不是直接賣的產品。secure-connector 的引擎都成熟了(112 測試),缺的不是更多引擎,而是把它們**組成一份能交給客戶/自己看的稽核報告** —— 那正是合規服務的交付物。owner 選 **A→B**:先做這份統一報告(A),再做路線圖 P-A(B)。

## 2. 守住既有紅線(不可違反)

| 此 repo 既有紅線 | Phase A 如何遵守 |
|---|---|
| 報告預設遮罩 PHI(HIPAA minimum-necessary / GDPR 最小化) | 沿用 `Violation.to_dict(show_matches=False)` 與 de-id 的**只報計數不報原值**;`--show-matches` 才本機揭露 |
| 全本機、無雲端 | 只讀本機檔/目錄,純本機產出 HTML/JSON,**不外送** |
| 無 LLM(de-id/合規/注入一律 regex/hermetic) | 組合既有 regex/hermetic 引擎,**不引入 LLM** |
| stdlib-only、零 runtime 依賴 | 只用 stdlib + 既有模組,**不加依賴** |
| 不過度宣稱「HIPAA 認證」 | 報告措辭一律「**掃描輔助 / 報告**(scan-assist)」,非「certified/compliant」;含明確免責句 |

## 3. 架構取向

**組合既有引擎,不重寫、不改引擎。** 新增一個模組/套件 `readiness/`(暫名),內含一個 orchestrator + 一個統一渲染器 + CLI:

```
target (file / dir)
   ├─ compliance: compliance_checker.scan_file(csv/json, load_standard(s))  -> [Violation]   (masked)
   ├─ de-id 覆蓋: phi_redactor.redact(text, mode="mask") -> RedactionMap.counters {label:count}
   └─ 注入:       secops_simulator.scan(text)            -> [injection finding]
        (+ 選配) secops MCP 掃描器 summary.json          -> [mcp risk]
                              │
                              ▼
        readiness.assess(...) -> 統一結果物件
                              │
                              ▼
        統一 HTML 報告(沿用 compliance_checker.render_html 的樣式/XSS-safe 模式)+ JSON
        exit code: 0 clean / 1 findings / 2 operator error(與既有 CLI 契約一致)
```

- **沿用** `compliance_checker.render_html` 的 HTML 樣式與 `html.escape` XSS-safe 寫法(新的統一渲染器抄這個模式,不另造風格)。
- **deterministic、無 LLM、stdlib-only**,測試比照本 repo 慣例放在 `readiness/tests/`(本 repo 測試是 per-package,不在頂層 `tests/`)。

## 4. Phase A 範圍 + 行為

**輸入:** 單一檔案(`.csv` / `.json` / `.txt` / `.md`)或一個目錄(遞迴掃支援的副檔名)。選配 `--mcp-summary <path>` 吃 secops 掃描器的 `summary.json`。

**每個目標跑三段(各引擎能跑的才跑):**
1. **合規**(CSV/JSON):對選定標準(預設**全部四種**:hipaa/gdpr/pci-dss/tw-pii)跑 `scan_file` → 違規(預設遮罩)。`.txt`/`.md` 跳過結構化合規掃描。
2. **PHI 覆蓋**(所有文字):把目標的文字值跑 `phi_redactor.redact(mode="mask")`,讀 `RedactionMap.counters` → 偵測到的 **PHI 類型 + 計數**(TW_NHI/SSN/CREDIT/MRN/TW_ID/EMAIL/DOB/PHONE/IPV4)。
3. **注入**(所有文字):跑 `secops_simulator.scan(text)` → prompt-injection/jailbreak 命中(family + 位置,遮罩)。
4. **(選配)MCP 風險**:讀 `--mcp-summary` 的 JSON(secops 掃描器輸出)→ 併入 MCP 設定風險清單。

**輸出:** 一份**統一 HTML 報告**,分區呈現:摘要(目標、標準、各段計數、整體判定)、合規違規表(per 標準)、PHI 覆蓋表(類型×計數)、注入命中表、(選配)MCP 風險表;每筆對應其框架(HIPAA/GDPR/PCI/TW-PII / OWASP-LLM01 / OWASP-MCP)。同時可出 `--json`。底部含免責:「本報告為自動化**掃描輔助**,非法律或合規認證;PHI 預設遮罩」。

**Exit code(與既有 CLI 一致):** `0` 全 clean、`1` 有任一 finding、`2` 操作者錯誤(目標不存在/不支援/壞標準)。

**統一結果物件(orchestrator 回傳,給渲染器 + JSON):**
```
{
  "target": str,
  "standards": [str],
  "compliance": { "<standard>": [Violation.to_dict(masked)], ... },
  "phi_coverage": { "<label>": int, ... },          # 來自 RedactionMap.counters
  "injection": [ {family/rule, location, matched(masked)} ],
  "mcp": [ {severity, rule_id, owasp, message} ],   # 選配,來自 secops summary.json
  "summary": { "compliance_total": int, "phi_total": int, "injection_total": int, "mcp_total": int, "verdict": "clean|findings" }
}
```

## 5. 三層界線 + 角色

| 層 | 不接任何東西 | 接 4 AI | 接 mesh |
|---|---|---|---|
| 能力 | 跑三引擎 → 統一 HTML/JSON 稽核報告(純本機、無 LLM) | (本 repo 刻意 model-free;AI 僅 P-D 選配 NER,不在本 phase) | 之後可經 `mcp_bridge` 把 `assess` 暴露成一個工具 |
| 角色 | **自用 + 變現交付物(站得住)** | — | 更有未來 |

## 6. 與其他專案的分工(不重複)

- **secops** 出 `summary.json`(MCP 設定靜態風險)→ 本報告**消費**它併入,不重做 MCP 掃描。
- **phantom-mesh** = 加密/身分;**phantom-companion** = 時序異常(`anomaly_detector` 已在那)。本報告不碰。
- secure-connector 既有引擎**原樣沿用**,本 phase 只加「組合 + 統一渲染」一層。

## 7. 風險與緩解

1. **過度宣稱合規** → 措辭一律「掃描輔助/報告」+ 免責句;遮罩預設開。
2. **假陽性/雜訊**(尤其 de-id 的 TW_NHI 12 位數、CREDIT)→ 沿用既有引擎已收斂的 regex;報告分「類型計數」而非逐筆斷言;明確標「需人工複核」。
3. **大目錄/大檔效能** → Phase A 先單檔/淺目錄;檔案大小上限 + 計數即可,不逐筆 dump 原值。
4. **守 stdlib-only/無 LLM/無雲** → orchestrator 只 import 既有模組 + stdlib。

## 8. 待確認 / owner-gated

- 套件命名(`readiness` vs `audit_report` vs `assess`)。
- 預設標準集合(建議:全部四種一起跑,報告分區)。
- 目錄遞迴的副檔名白名單(建議:`.csv .json .txt .md`)。

## 9. Phase B(之後,非本 spec)

主文件路線圖 **P-A**:`mcp_bridge` 遷移官方 `mcp` Python SDK + 每工具 capability scoping + 入站注入閘強化(LLM02 前哨)。另:把 `assess` 經 `mcp_bridge` 暴露成工具、B2B 報告模板 = 更後面。
