# 開源生態與方向 — phantom-secure-connector

> ARCHIVED 2026-06-19 — 內容已併入 docs/phantom-secure-connector.md;此為歷史版本。

> 針對 **安全個人／健康資料連接器 + PII 安全整合** 領域的掃描。
> 撰寫於 2026-06-19。佐證規則：每一項外部論述皆附來源；在擷取當下無法重新查證的數字，
> 標記為 `[unverified]`。星數會浮動 —
> 請將其視為數量級，而非精確值。內部狀態的真實來源
> 為 [`/ROADMAP.md`](../ROADMAP.md)；本文僅補充 *外部* 脈絡與一項
> 建議方向。權威順序：ROADMAP（狀態）> 本文（方向）。

---

## 1. 本 repo 的現況（以 `master` commits 為依據）

phantom-secure-connector **以僅依賴標準函式庫（stdlib-only）的 Python 3.8+ 套件形式出貨，112 項測試
通過**，內含四個實際引擎外加一個 MCP 橋接。以已合併的 commits 為依據
（`a10a0cb` → `73d01e9`）：

| 模組 | 實際出貨內容 | 關鍵 commits |
|---|---|---|
| `phi_redactor/` | 以 regex 進行去識別化，涵蓋台灣（國民身分證、NHI/健保、MRN）與西方（SSN、DOB、Email、MRN）；可逆的 `mode="replace"` 搭配 **位元組精確（byte-exact）** 的 `RedactionMap.restore()`；fail-closed 型別防護。 | `a10a0cb`、`817c178`、`8d169f0` |
| `compliance_checker/` | CSV/JSON 掃描器，透過 TOML 規則檔支援 **4 種標準**（hipaa/gdpr/pci-dss/tw-pii）；預設遮罩比對到的 PHI；text/json/**自含式 HTML** 稽核報告；乾淨的 exit-code 契約（0/1/2）。 | `0af53cc`、`b371061`、`6ffcf5b` |
| `secops_simulator/` | **原生、封閉（hermetic）** 的 OWASP-LLM01 prompt-injection／jailbreak 偵測器 — 無 LLM、無網路、無 subprocess。5 個簽章家族（signature families）。 | `c94ffe7`、`d5bfe63` |
| `mcp_bridge/server.py` | 入站 MCP 伺服器，JSON-RPC/stdio，**9 個工具**（其中 5 個包裝實際引擎：`redact_phi`、`compliance_scan`、`mask_text`/`restore_text`、…）。傳輸上不出現原始 PHI。 | `0760dbc`、`af3d24c` |
| `mcp_bridge/client.py` | 出站 MCP 用戶端，含一個 **安全閘門**：allowlist + 出站 PHI 去識別化，且對不受信任伺服器的 **回應於入站時掃描 prompt injection**。 | `4c284c2`、`4b15803` |

**尚未建置（規劃中，依 ROADMAP 的 "Planned-next"）：**
- **Ingest pipeline（匯入管線）** — HealthKit / Garmin Connect → 去識別化 → 加密 → FTS5。*（這是
  相對於設計願景的最大缺口，也是下方生態分析的焦點。）*
- LLM/NER 強化的邊緣案例 PHI 捕捉；OWASP LLM02–10；官方 `mcp` Python SDK
  遷移；B2B 包裝 + 瀏覽器/IDE 剪貼簿去識別化擴充套件。
- 時間序列的 `anomaly_detector` 已被 **移出** 至 phantom-companion（`011cee7`）；
  不要在此處規劃它。

**誠實的利基重述。** 可防禦的定位 *不是* 「又一個去識別化函式庫」、也
*不是* 「又一個 MCP 閘道」 — 這兩個領域都已擁擠（見下文）。它是這個 **組合**：
一個 **受治理、加密、MCP 原生、面向 *個人* 敏感資料的橋接**，僅依賴標準函式庫
（零依賴、跨平台）、雙語（台灣 + 西方識別碼），並嵌入於
單一操作者的 phantom-mesh 中。下方沒有任何單一開源專案占據那個確切的交集。

---

## 2. 生態

### 2A. PII / PHI 去識別化引擎

| 專案 | URL | 星數 | 語言 | 授權 | 成熟度 | 對此利基的契合度／缺口 |
|---|---|---|---|---|---|---|
| **Microsoft Presidio** | github.com/microsoft/presidio | ~8.7k | Python | MIT | 成熟（v2.2.362，2026 年 3 月；47 個 releases） | **同類最佳的 NER 去識別化。** 缺口：沉重的相依（spaCy/transformers）打破了僅標準函式庫、零依賴的承諾；開箱即用偏向英語（台灣識別碼需要自訂 recognizers）。**Reference/optional-wrap**，絕不作為硬相依。 |
| **ARX** | github.com/arx-deidentifier/arx | ~700 `[unverified]` | Java | Apache-2.0 | 成熟、學術型 | 針對 **結構化資料集** 的 k-anonymity / l-diversity / t-closeness / differential privacy。缺口：JVM、GUI 優先、資料集層級（非串流/逐筆）。僅作為規劃中的 differential-privacy 聚合匯出模式之 **Reference**。 |
| **Tonic.ai / Tonic Textual** | tonic.ai | 不適用（商業） | — | Proprietary | 成熟的 SaaS | 合成資料 + 去識別化。非開源；對一個隱私優先、自架的工具而言是 **anti-pattern**（會上傳資料）。作為 *要避免什麼* 的 reference。 |
| **Synthea** | github.com/synthetichealth/synthea | ~3k `[unverified]` | Java | Apache-2.0 | 成熟 | 合成的 FHIR/C-CDA/CSV 病患產生器。非去識別化，但是一個 **免費、隱私安全的測試資料來源** — 採用以作為 fixtures/CI，避免碰觸真實 PHI。 |

> 2025–26 趨勢：本地部署的 LLM 現在在臨床文本上的 PHI 移除率已達 >99%；FHIR
> 去識別化 IG 草案於 2026 年 2 月發布。ROADMAP 中「LLM 強化邊緣案例」這條線
> 與該領域的走向相當一致 — 但請參見過度建置警告（§5）。

### 2B. MCP 資料連接器／安全閘道

| 專案 | URL | 星數 | 語言 | 授權 | 成熟度 | 契合度／缺口 |
|---|---|---|---|---|---|---|
| **Lasso MCP Gateway** | github.com/lasso-security/mcp-gateway | ~363 | Python | 查 repo `[unverified]` | 年輕（2025 年 4 月） | 以外掛為基礎的閘道，PII/guardrail 外掛，掃描 request/response。**最接近 `mcp_bridge.client` 閘門的競爭者。** 缺口：其最強的 guardrail 會呼叫 Lasso 的 *雲端* API（跨越了隱私邊界）；定位為企業級多 MCP 編排框架，而非個人資料。**Reference** — 確認了閘門設計是合理的；以 *完全本地 + PHI 專屬* 做出區隔。 |
| **IBM ContextForge** | github.com/IBM/mcp-context-forge | large `[unverified]` | Python | Apache-2.0 | 活躍 | 置於 MCP/A2A/REST 之前的 AI 閘道/registry/proxy，含 guardrails + 外掛。缺口：企業規模、重量級。在遷移至官方 SDK 時，作為 plugin/capability-scoping 模式的 **Reference**。 |
| **Official `mcp` Python SDK** | github.com/modelcontextprotocol/python-sdk | large | Python | MIT | 趨於穩定 | 標準的 server/client 函式庫。**Adopt** 作為手刻 JSON-RPC 迴圈的遷移目標（已是 ROADMAP 項目）— 但僅在它穩定到不會重新引入相依震盪（deps churn）時。 |
| Bifrost / Enkrypt AI | various | — | Go / Py | OSS `[unverified]` | 年輕 | 企業級 AI 閘道。對一個單人個人資料工具而言超出範圍。**Skip。** |

### 2C. 個人健康資料匯入／匯出器（規劃中的缺口）

| 專案 | URL | 星數 | 語言 | 授權 | 成熟度 | 契合度／缺口 |
|---|---|---|---|---|---|---|
| **Open Wearables**（the-momentum） | github.com/the-momentum/open-wearables | ~915 | Python `[unverified]` | MIT | 活躍（v0.3，2026） | **策略上最相關。** 自架、多供應商（Apple Health iOS、Google Health Connect、Samsung Health）、正規化 API，**自帶 MCP 伺服器** 供 Claude/ChatGPT 查詢健康資料。與規劃中的匯入 *以及* MCP 介面重疊。**Wrap/整合，不要重造** — 讓它做供應商正規化；本 repo 補上它所欠缺的 *去識別化 + 合規 + injection-gate* 層。 |
| **python-garminconnect**（cyberjunky） | github.com/cyberjunky/python-garminconnect | ~2.4k | Python | MIT | 成熟（130+ API 方法） | 乾淨的 Garmin Connect API wrapper。**Adopt** 作為 Garmin 來源連接器（但它增加一個 runtime 相依 — 用 extras flag 包起來以維持核心僅標準函式庫）。 |
| **apple-health-to-fitbit / apple-health-grafana** | github.com/simonkrenger/…, github.com/k0rventen/apple-health-grafana | small | Python | MIT `[unverified]` | 業餘 | 解析 Apple Health 匯出 XML → CSV / InfluxDB。作為 HealthKit 匯出格式的 **Reference** 解析器；不值得依賴。 |
| **Health Auto Export** | github.com/Lybron/health-auto-export | small | docs | — | 活躍 | 透過 API 推送 HealthKit 的 iOS app。作為裝置端匯出路徑的 **Reference**（免去需要自訂 iOS app）。 |

### 2D. ETL / tap 框架（針對「眾多來源」的誘惑）

| 專案 | URL | 星數 | 語言 | 授權 | 成熟度 | 契合度／缺口 |
|---|---|---|---|---|---|---|
| **Airbyte** | github.com/airbytehq/airbyte | very large | Java/Py | Elastic v2 / MIT-mix | 成熟 | 300+ 連接器。缺口：重量級（Docker、Temporal）；對單人個人管線而言是 **大幅過度建置**。**Skip** — 但偷取其 *source connector contract* 的概念。 |
| **Singer spec / Meltano** | github.com/meltano/meltano | large | Python | MIT / Apache | 成熟 | CLI 優先、比 Airbyte 輕量；Singer tap/target JSON 契約。若你日後要超越健康領域做通用化，可 **Reference** 其 tap/target *介面形狀* — 但現在 **不要** 採用其 runtime。 |

---

## 3. 建議方向（adopt / wrap / reference / build）

1. **BUILD（自建，護城河）：** 把 **去識別化 + 合規 + injection-gate 層** 當作資料流
   *穿過* 的那個東西。沒有別人同時結合 PHI 去識別化 + 合規掃描 +
   入站 injection 掃描 + MCP、完全本地、雙語。讓 `phi_redactor`、
   `compliance_checker`、`secops_simulator` 維持僅標準函式庫 — 那個零依賴、跨平台的
   特性本身就是相對於 Presidio/Airbyte 的差異化。

2. **WRAP，不要重造，供應商匯入：** 把 **Open Wearables**（以及
   專門針對 Garmin 的 **python-garminconnect**）當作 *來源* 層。本 repo 的職責
   是 **去識別化 → 合規掃描 → 加密 → FTS5** 的中段，而非重新實作
   供應商的 OAuth/正規化。這可避開 §5 中最大的過度建置陷阱。

3. **ADOPT（以 extras flags 包起來，讓核心維持零依賴）：**
   - 官方 `mcp` Python SDK → 取代手刻 JSON-RPC（已規劃）。
   - `python-garminconnect` → Garmin 來源連接器。
   - （選用）Presidio → 置於 `--ner` feature flag 後，處理自由文本/姓名邊緣案例。

4. **僅 REFERENCE：** Presidio recognizers（用於台灣自訂 recognizer 模式）、Lasso /
   ContextForge（閘道外掛 + capability-scoping 模式）、ARX（differential-privacy
   聚合模式）、Synthea（隱私安全的 CI fixtures）、Singer（tap/target 契約形狀）。

---

## 4. 分階段路徑

- **Phase A — 完成 MCP/gate 主幹（便宜、高價值、不需要真實裝置）。**
  將 `mcp_bridge` 遷移至官方 `mcp` SDK；加入逐工具的 capability scoping；拓寬
  入站 injection 閘門。純軟體，可用合成資料完整測試。
- **Phase B — 匯入契約 + Garmin 優先（真實裝置，但 Garmin API 可透過 web 存取）。**
  定義一個 source-connector 介面（Singer 形狀）。串接 `python-garminconnect` → 將
  各筆資料跑過 `phi_redactor` → `compliance_checker` → 加密 → FTS5。之所以先選 Garmin，
  是因為它不需要 iOS 裝置，只要一個 web API。
- **Phase C — HealthKit 匯入（需要 iOS / 裝置端匯出）。**
  消費 Apple Health 匯出 XML（或 Open Wearables 的正規化 feed / Health Auto
  Export 推送），而非自建原生 iOS app。依賴操作者／裝置 → 較後期。
- **Phase D — 選用的 NER + differential-privacy 匯出（沉重、選擇加入）。**
  以 Presidio 為後盾的 NER 置於 flag 後；ARX 風格的聚合匯出模式。僅在真實使用
  顯示 regex 漏抓確實有影響時才做 — 不要預先建置。

---

## 5. 誠實的過度建置與隱私警告

- **不要變成 Airbyte。** 單一操作者不需要一個帶 Docker + Temporal 的
  300 連接器 ETL 平台。抗拒「支援每一種來源」的拉力；安全地做好 2 個來源
  （Garmin、HealthKit）勝過鬆散地做 20 個。護城河是 *安全*，而非 *廣度*。
- **不要重造 Open Wearables。** 供應商正規化（OAuth、跨 Apple/Garmin/Samsung 的
  schema mapping）正是別人在維護、無差異化的沉重苦工。
  包裝它能讓團隊的力氣保留在去識別化/合規/閘門的護城河上。
- **核心維持僅標準函式庫。** 每一個相依（Presidio 的 spaCy、garminconnect 的 requests）都是
  跨平台 + 供應鏈風險。用 extras 把它們包起來；絕不讓核心 import 它們。
- **「guardrail-as-a-service」的隱私邊界。** Lasso 最強的檢查會呼叫一個雲端
  API。對一個隱私優先的工具而言那是個 *矛盾* — 整體價值就在於沒有任何東西
  離開本機。讓 injection 閘門 **完全本地**（它已經是了）。
- **LLM 強化的去識別化是雙面刃。** 把 PHI 送去 LLM 以 *尋找* PHI，本身就可能
  是洩漏。若／當加入時，它必須跑在 **本地** 模型上，或明確採用選擇加入並搭配一個
  響亮的同意閘門 — 絕不可是悄無聲息的雲端呼叫。今日的 regex+封閉設計是安全的
  預設；把 NER 視為強化，而非相依。
- **去識別化 ≠ 匿名化。** Regex 去識別化降低但不保證
  抗重新識別性（quasi-identifier 連結仍存在）。不要過度宣稱「HIPAA
  Safe Harbor compliant」；應宣稱「PHI 去識別化 + 合規 *掃描* 輔助」，一如 ROADMAP 與
  README 已謹慎地做到。維持那份誠實。

---

## 來源

- [microsoft/presidio](https://github.com/microsoft/presidio)
- [arx-deidentifier/arx](https://github.com/arx-deidentifier/arx)
- [synthetichealth/synthea](https://synthetichealth.github.io/synthea/)
- [lasso-security/mcp-gateway](https://github.com/lasso-security/mcp-gateway) · [Lasso announcement](https://www.lasso.security/resources/lasso-releases-first-open-source-security-gateway-for-mcp)
- [IBM/mcp-context-forge](https://github.com/IBM/mcp-context-forge)
- [the-momentum/open-wearables](https://github.com/the-momentum/open-wearables) · [Open Wearables 0.3 blog](https://www.themomentum.ai/blog/open-wearables-0-3-android-google-health-connect-samsung-health-railway)
- [cyberjunky/python-garminconnect](https://github.com/cyberjunky/python-garminconnect)
- [simonkrenger/apple-health-to-fitbit](https://github.com/simonkrenger/apple-health-to-fitbit) · [k0rventen/apple-health-grafana](https://github.com/k0rventen/apple-health-grafana) · [Lybron/health-auto-export](https://github.com/Lybron/health-auto-export)
- [airbytehq/airbyte](https://github.com/airbytehq/airbyte) · [meltano/meltano](https://github.com/meltano/meltano)
- [Open-source PHI de-identification technical review (IntuitionLabs, 2025)](https://intuitionlabs.ai/articles/open-source-phi-de-identification-tools)
- [Securing the Model Context Protocol (arXiv 2511.20920)](https://arxiv.org/html/2511.20920v1)
