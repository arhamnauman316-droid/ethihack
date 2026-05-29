# Security Policy — EthiHack

## Responsible Use

EthiHack is a legitimate AI security testing platform. You may only use it to test:

- AI systems you **own or operate**
- AI systems you have **written permission** to test
- AI systems listed in an **official bug bounty program** scope

Unauthorized testing of AI systems you do not own is illegal under computer fraud laws in most jurisdictions (including CFAA in the USA, Computer Misuse Act in the UK, and equivalent laws globally).

## Reporting Vulnerabilities in EthiHack Itself

If you discover a security vulnerability in EthiHack:

**Please do NOT open a public GitHub issue.**

Instead, email: **arhamnauman316@gmail.com**

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Your contact details

We will respond within 48 hours, work with you to understand the issue, and credit you in the changelog and README upon fix.

## Supported Versions

| Version | Supported |
|---------|-----------|
| 6.x | ✅ Active |
| 5.x | ⚠️ Security fixes only |
| < 5.0 | ❌ End of life |

---

# Contributing to EthiHack

Thank you for contributing! EthiHack is an open-source ethical AI security platform.

## What we welcome

- **New attack test cases** — must be mapped to OWASP LLM Top 10, MITRE ATLAS, or NIST AI RMF
- **Bug fixes** with clear reproduction steps
- **UI/UX improvements** to the scan interface
- **New AI provider integrations** (new target_type values)
- **Documentation improvements**
- **Translation** of attack descriptions

## What we do not accept

- Payloads designed to cause harm, not test defenses
- Features that remove or weaken ethical use requirements
- Anything that automates scanning of AI systems the user doesn't own

## How to contribute

1. Fork the repository
2. Create a branch: `git checkout -b feature/your-feature-name`
3. Make your changes
4. Test on your own AI system (required for attack tests)
5. Open a pull request with a clear description

## Adding new attack tests

Each test must include all of the following:

```python
{
    "id": "XX-01",                          # Unique ID (category prefix + number)
    "category": "Category Name",            # Attack category
    "owasp_id": "LLM01",                   # OWASP LLM Top 10 reference
    "nist_id": "AI RMF GV-1.1",           # NIST AI RMF reference
    "mitre_id": "AML.T0051",              # MITRE ATLAS technique ID
    "severity": "high",                    # critical / high / medium / low
    "name": "Human readable name",
    "description": "What this test checks for.",
    "turn1": "First innocent-looking message",
    "turn2": "Second message that introduces the attack vector",
    "turn3": "Final escalation (this gets AI-generated in production)"
}
```

## Code style

- Python: PEP 8
- Keep functions small and clearly named
- Comment anything non-obvious
- Test your changes locally before opening a PR

---

MIT License

Copyright (c) 2026 Arham Nauman / Argus Labs

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
