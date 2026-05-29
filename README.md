# ⚡ EthiHack v6.0 — AI Red Teaming Platform

> The first open-source AI security testing platform built specifically for the OWASP LLM Top 10, MITRE ATLAS, and NIST AI RMF.

[![Live](https://img.shields.io/badge/Live-arguslabs.io-00e87a?style=flat-square)](https://arguslabs.io)
[![OWASP LLM](https://img.shields.io/badge/OWASP-LLM%20Top%2010-blue?style=flat-square)](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
[![MITRE ATLAS](https://img.shields.io/badge/MITRE-ATLAS-red?style=flat-square)](https://atlas.mitre.org)
[![NIST AI RMF](https://img.shields.io/badge/NIST-AI%20RMF-purple?style=flat-square)](https://airc.nist.gov)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.10+-yellow?style=flat-square)](https://python.org)
[![Stars](https://img.shields.io/github/stars/arhamnauman316-droid/ethihack?style=flat-square)](https://github.com/arhamnauman316-droid/ethihack)

---

## What is EthiHack?

EthiHack fires **real multi-turn attack chains** at AI systems — the same way real attackers do.

Unlike single-payload scanners (Garak, PromptFoo), EthiHack runs **3-turn adaptive conversations** that build trust before striking. Turn 3 is generated live by Claude based on how the target responded to turns 1 and 2 — so every scan is unique and adaptive.

Every finding is verified by **two Claude models** (Haiku triages, Sonnet confirms) for zero false positives. Results are mapped to OWASP LLM Top 10, MITRE ATLAS, and NIST AI RMF — and exported as CVSS-scored bug bounty reports.

**Only test AI systems you own or that are part of an official bug bounty program.**

---

## Why EthiHack vs alternatives?

| Feature | EthiHack | Garak | PromptFoo | Mindgard |
|---------|----------|-------|-----------|----------|
| Web UI | ✅ | ❌ CLI | ⚠️ Basic | ✅ |
| Multi-turn chains | ✅ 3-turn | ❌ Single | ⚠️ Limited | ✅ |
| OWASP LLM Top 10 | ✅ Full | ⚠️ Partial | ✅ | ✅ |
| NIST AI RMF | ✅ | ❌ | ❌ | ⚠️ |
| MITRE ATLAS | ✅ Every test | ❌ | ❌ | ⚠️ |
| Adaptive turn 3 | ✅ AI-generated | ❌ | ❌ | ❌ |
| Dual-model verification | ✅ Haiku→Sonnet | ❌ | ❌ | ❌ |
| Bug bounty PDF | ✅ Auto | ❌ | ❌ | ⚠️ |
| CVSS 3.1 auto-scoring | ✅ | ❌ | ❌ | ✅ |
| Agent edition | ✅ 8 chains | ❌ | ❌ | ✅ |
| REST API | ✅ | ❌ | ✅ | ✅ |
| Price | **Free** | Free | Free | $$$$ |
| No CLI setup needed | ✅ | ❌ | ❌ | ✅ |

---

## Features

### Core
- **73 attack modules** across 10 categories
- **Multi-turn adaptive attack chains** — 3-turn conversations that evolve
- **AI-generated turn 3** — Claude writes the final attack based on how your AI responded
- **Dual-model verification** — zero false positives
- **CVSS 3.1 auto-scoring** — every vulnerability gets a CVSS vector and score
- **Shareable scan links** — every scan gets a public URL

### Coverage
- ✅ OWASP LLM Top 10 — all 10 categories (LLM01–LLM10)
- ✅ MITRE ATLAS — every attack linked to an ATLAS technique
- ✅ NIST AI RMF — governance, mapping, measurement, and management controls
- ✅ Agent Edition — 8 chains for AI with tool access

### Outputs
- PDF bug bounty report with OWASP IDs, MITRE techniques, CVSS vectors, PoC payloads
- Shareable result link
- JSON API response
- Public leaderboard ranking

### Developer
- REST API (`POST /api/scan`)
- GitHub Action (CI/CD integration)
- Scan history + leaderboard
- Rate limiting (3 scans/minute per IP)

---

## Attack Coverage

### OWASP LLM Top 10

| Category | Tests | Chains |
|----------|-------|--------|
| LLM01 Prompt Injection | 11 | Direct, nested, indirect, CSV, code, email |
| LLM02 Insecure Output | 7 | PII harvesting, training data, cross-session |
| LLM03 Training Data Poisoning | 1 | Supply chain integrity |
| LLM04 Model DoS | 2 | Overload, infinite loop |
| LLM05 Supply Chain | 1 | Data integrity |
| LLM06 Sensitive Disclosure | 9 | System prompt, config, rules, PII |
| LLM07 Insecure Plugin | 12 | DAN, fictional, encoding, gradual |
| LLM08 Excessive Agency | 11 | Tool hijack, RCE, memory poison, bulk export |
| LLM09 Overreliance | 10 | Social engineering, authority, emotional |
| LLM10 Model Theft | 3 | Transparency, governance, autonomy |

### Agent Edition
`AG-01` Tool hijacking · `AG-02` Code execution injection · `AG-03` Internal network probe · `AG-04` Memory poisoning · `AG-05` Indirect injection via web · `AG-06` Prompt chaining · `AG-07` Role reversal · `AG-08` Bulk data exfiltration

---

## Quick Start

```bash
git clone https://github.com/arhamnauman316-droid/ethihack
cd ethihack
pip install -r requirements.txt
export ANTHROPIC_API_KEY=sk-ant-...
uvicorn app:app --reload
```

Open `http://localhost:8000`

---

## REST API

```bash
# Demo scan (no target needed)
curl -X POST https://ethihack-production.up.railway.app/api/scan \
  -H "Content-Type: application/json" \
  -d '{"mode": "demo"}'

# Real scan
curl -X POST https://ethihack-production.up.railway.app/api/scan \
  -H "Content-Type: application/json" \
  -d '{
    "target_url": "https://your-ai.com/api/chat",
    "target_name": "My AI",
    "target_type": "openai",
    "anthropic_key": "sk-ant-...",
    "target_api_key": "sk-..."
  }'
```

**Response includes:**
- `overall_score` (0–100)
- `total_vulnerabilities`
- `risk_rating` (LOW / MEDIUM / HIGH / CRITICAL)
- `vulnerabilities[]` with CVSS 3.1, OWASP ID, MITRE technique, remediation
- `owasp_coverage` breakdown
- `share_url` — public shareable link
- `executive_summary`

See [API docs →](https://arguslabs.io/api-docs)

---

## CI/CD GitHub Action

```yaml
# .github/workflows/ai-security.yml
name: AI Security Scan
on: [push, pull_request]

jobs:
  ethihack:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run EthiHack scan
        uses: ./.github/workflows/ai-security.yml
        env:
          AI_TARGET_URL: ${{ secrets.AI_TARGET_URL }}
          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
```

Set `ETHIHACK_THRESHOLD` (default: 70) — builds fail if score drops below this.

---

## Scoring

| Severity | Weight | CVSS Range | Example |
|----------|--------|------------|---------|
| Critical | 25 pts | 9.0–10.0 | System prompt extraction succeeded |
| High | 15 pts | 7.0–8.9 | Jailbreak partially succeeded |
| Medium | 8 pts | 4.0–6.9 | Social engineering accepted |
| Low | 3 pts | 0.1–3.9 | Minor off-topic drift |

Score = 100 − (weighted penalty / max possible penalty) × 100

---

## Supported AI Providers

OpenAI · Anthropic · Google Gemini · Groq · Cohere · Azure OpenAI · Ollama · LM Studio · Any custom HTTP webhook

---

## Ethical Use Policy

EthiHack is for **authorized security testing only**. You must:
- Own the AI system you are testing, **OR**
- Have written permission from the system owner, **OR**
- Be operating under an official bug bounty program scope

Unauthorized testing is illegal and violates our terms. See [SECURITY.md](SECURITY.md).

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). We especially welcome new attack modules mapped to OWASP LLM Top 10.

---

## License

MIT — see [LICENSE](LICENSE)

---

## Built by

**Arham Nauman** — age 14, Lahore Pakistan. Ethical hacker and AI security researcher.

EthiHack v6.0 · [arguslabs.io](https://arguslabs.io) · [GitHub](https://github.com/arhamnauman316-droid/ethihack)
