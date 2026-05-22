# ④ phantom-secure-connector

> **PHI 去識別 + 時序異常偵測 + 合規 check + 紅藍隊模擬 + MCP bridge,一個 phantom-mesh 安全套件全包**
> 招聘覆蓋最廣的項目(銀行 / 醫材 / 趨勢 / 工研院 / Anthropic 都看)

## 一句話定位

「phantom-mesh 的安全資料 + 工具暴露套件 — 敏感資料安全進來、可信工具安全出去、行為紅藍隊持續驗證。」

## 對齊 BIG-GOAL

- **P2 多模態理解**:secure ingestion(健康/醫療/金融 multimodal 資料)
- **P4 加密為先**:HKDF + age v1 加密、PHI 去識別、SOC2/HIPAA/GDPR 合規

## 五個內建模組

```
phantom-secure-connector/
├── phi-redactor/         # PHI 自動偵測 + 去識別(NER + regex + LLM)
├── anomaly-detector/     # 時序異常偵測(AHI v2 通用化)
├── compliance-checker/   # SOC2/HIPAA/GDPR/個資法 規則 check
├── secops-simulator/     # 紅藍隊 prompt injection + jailbreak 模擬(原 phantom-secops)
└── mcp-bridge/           # phantom → MCP server,Claude Desktop / Cursor 上架
```

## 競品分析

| 競品 | 強項 | phantom-secure-connector 差異 |
|---|---|---|
| **Microsoft Presidio** | PHI NER + de-id | phantom-secure 加 LLM-augmented(catches 邊角 case)+ 整合 phantom |
| **NeMo Guardrails**(NVIDIA)| LLM safety guardrails | 本專案為 connector + audit,不是 guardrail at inference |
| **Garak**(LLM red team)| LLM 安全測試 | 在 phantom 內持續跑,不只 one-shot test |
| **AnonymPy** | de-id Python lib | 為 phantom plugin,跟 mesh 整合 |
| **Anthropic 自有 safety tools** | 內部用 | open-source 對外版 |

**niche**:**第一個整合「PHI + 異常 + 合規 + 紅藍隊 + MCP」一站式 phantom 套件**,前 4 個本來各自孤立。

## 招聘 / 副業 / 應用評分

| 維度 | 評分 | 對應 |
|---|---|---|
| **招聘** | ⭐⭐⭐⭐⭐ | **趨勢科技**(資安 AI) + 中信 / 國泰 / 富邦(金融合規) + 醫材公司 + 工研院生醫所 + 鼎新(企業合規) + Anthropic(safety) |
| **副業** | ⭐⭐⭐⭐ | 資安 AI 顧問接案 + extension 上架 + 醫療 AI 合規認證顧問 |
| **個人應用** | ⭐⭐⭐⭐⭐ | 健康場景真實使用 + 家庭健康資料安全處理 |

## 應用情境

- **健康資料** ← anomaly-detector(時序模型)+ phi-redactor(Apple HealthKit data 安全處理)
- **家人健康** ← phi-redactor(用藥/就醫紀錄 redact 後跨家人分享)
- **跨應用整合**(次要)← mcp-bridge 讓 Claude Desktop 直接用 phantom tools

## 核心功能

### 1. phi-redactor

```python
# 自動去識別,可 reversibly(內存 mapping)或 irreversibly
phantom secure redact "張三 1990/01/15 出生,病歷號 A123456,血壓 145/95"
# → "[PERSON_1] [DOB_1] 出生,病歷號 [MRN_1],血壓 145/95"
# (血壓不去識別,是 PHI 邊界,LLM-augmented 判斷)
```

### 2. anomaly-detector

```python
# AHI Detection v2 通用化:任何時序資料找異常
phantom secure anomaly --series sleep_score --window 7d
# 用 5-fold CV + Pearson r 評估方法(對標 Nassi et al. 2021)
# 不只 sleep apnea,通用到心率 / 步數 / 血糖 / 血壓 / 用 LLM token / commits
```

### 3. compliance-checker

```python
phantom secure check --standard hipaa /path/to/data.csv
# 掃 sensitive fields → 報告
# 規則檔可擴充:SOC2 / HIPAA / GDPR / 個資法 / PCI-DSS
```

### 4. secops-simulator(原 phantom-secops)

```python
phantom secure redteam --target phantom-mesh
# 跑 OWASP LLM Top 10 全套 prompt injection
# + jailbreak benchmark(GCG, AIM)
# + 紅藍隊 multi-agent simulation
# 輸出 audit report(可給合規部門看)
```

### 5. mcp-bridge

```bash
# Claude Desktop / Cursor / Codex 設定加一行:
{"phantom": {"command": "phantom", "args": ["mcp", "serve"]}}
# → phantom 30 個 tools 全部暴露給 Claude Desktop
# → Claude Desktop 對話可以直接呼叫 phantom 的 FTS5 / shell / file / web
```

## MVP scope

### Must have(M2 W5-7)
- [ ] phi-redactor 基本款(NER + regex,先不接 LLM)
- [ ] anomaly-detector 通用化(從 AHI Detection v2 抽出 time-series 核心)
- [ ] compliance-checker HIPAA + GDPR 規則檔
- [ ] mcp-bridge:phantom MCP server 介面 + 上架 Claude Desktop
- [ ] secops-simulator basic OWASP LLM Top 10 自動跑

### Nice to have(M3+)
- [ ] PHI LLM-augmented(catches 邊角 case)
- [ ] HealthKit / Garmin Connect ingest pipeline(去識別 + 加密入 FTS5)
- [ ] 多家用戶共用合規 audit report 模板
- [ ] secops simulation 對其他 LLM(不只 phantom)
- [ ] mcp-bridge 對 Cursor / Codex 也上架

### NOT doing
- 醫療臨床診斷(BIG-GOAL 明確 rule out)
- 取代 IT 防火牆 / IDS(本專案為 application-level,不是 network)
- 一鍵 SOC2 認證(只能輔助,不替代)

## 改裝來源

**現有**:
- phantom-secops repo(已有,red/blue team simulation)
- phantom-mesh `dist/ahi-calibration-report`(AHI 校正報告)
- Medical RAG v1.1.0 內含的 PHI 去識別架構(sanitized 公開)

**整合**:
- phantom-mesh provider trait(LLM-augmented PHI 用 Claude/Gemini)
- phantom-mesh encrypted storage(原生支援 secure data)
- phantom-mesh MCP server(已在 roadmap)

## 風險

- **PHI 邊界判定**:NER + regex 抓不到所有,LLM-augmented 又增本錢 → 兩階段方案,使用者選層級
- **醫療法規**:醫療 AI 為地雷區,phantom-secure-connector 必須明寫「**Not a medical device**」+ 「supportive, not diagnostic」
- **secops 攻擊面**:host 一個會 simulate prompt injection 的工具,自己被攻擊的 surface 增加
- **MCP spec 變動**:Anthropic 還在迭代 MCP spec,要密切追

## 變現路徑

| 路徑 | 細節 |
|---|---|
| 資安 AI 顧問 | 中小公司 secops audit 接案 |
| 醫療 AI 合規顧問 | 醫材公司導入接案 |
| Chrome / VS Code extension | PHI redactor as extension,自動 redact paste |
| Claude Desktop marketplace | mcp-bridge 上架,sponsor / freemium |
| 線上課程 | 「LLM 應用合規與安全」 |

## 為什麼放 M2 W5-7(招聘主力期)

- **招聘覆蓋最廣**(7 家以上),投履歷主力武器
- 改裝資產最齊(AHI + phantom-secops + Medical RAG PHI)
- MCP 為 2026 趨勢,搶第一波
- 是 phantom 的「**安全護城河**」,先做 phantom 才能宣稱 production-ready

---

*Sanitized public spec. Author: Mark Lai ([@markl-a](https://github.com/markl-a)).*
