# BugScanner Pro 🔍✦

An AI-powered web application vulnerability scanner that **automatically finds bugs** and generates a **professional pentest report** — complete with CVSS v3.1 scoring, AI-written analysis, and a print-ready PDF.

---

## Setup (Windows)

```bat
:: 1. Open Command Prompt or PowerShell and navigate to this folder
cd C:\path\to\bugscanner

:: 2. Create virtual environment
python -m venv venv
venv\Scripts\activate

:: 3. Install dependencies
pip install -r requirements.txt

:: 4. Run the app
python app.py
```

Then open **http://127.0.0.1:5000** in your browser.

---

## Features

### Auto-Scanner (9 modules)
| Module | What it finds |
|---|---|
| Security Headers | Missing HSTS, CSP, X-Frame-Options, unsafe-inline |
| SSL/TLS | Expired/expiring certs, TLS 1.0/1.1, weak ciphers |
| Cookie Security | Missing HttpOnly, Secure, SameSite |
| CORS | Wildcard, reflected origin, null-origin + credentials |
| XSS Probe | Reflected XSS across URL parameters |
| SQLi Probe | Error-based SQL injection detection |
| File Enumeration | .git, .env, phpMyAdmin, SQL dumps, admin panels |
| Authentication | Login forms, CSRF, HTTP Basic Auth, autocomplete |
| Info Disclosure | HTML comments, emails, robots.txt, stack traces |

### CVSS v3.1 Scoring
Every finding gets an automatic CVSS v3.1 base score + vector string based on the vulnerability type.

### AI-Powered Report (Optional)
If you provide an Anthropic API key:
- Claude writes a professional executive summary in formal pentest report language
- Each Critical/High finding gets an AI risk analysis explaining the real-world attack scenario
- Optional — the tool works without an API key using template-based reports

### Professional Report
- Cover page with client, tester, date, and risk rating
- Table of contents
- Executive summary
- Scope & methodology
- Findings summary (severity matrix + full table)
- Detailed findings (CVSS, description, evidence, fix, reference)
- Remediation roadmap (prioritised with effort estimates)
- Print to PDF via browser

---

## Get an API Key (for AI reports)

1. Go to https://console.anthropic.com
2. Create an account → API Keys → Create key
3. Paste it in the scanner UI (it's never stored or sent anywhere except Anthropic)

---

## Legal

> **Only scan systems you own or have explicit written permission to assess.**
> Unauthorised security testing is illegal.

Good demo targets:
- http://testphp.vulnweb.com
- https://juice-shop.herokuapp.com
- Your own DVWA or VulnHub VM

---

## CV Talking Points

- Built an AI-powered security assessment tool using Python, Flask, and the Anthropic Claude API
- Implemented 9 independent vulnerability scan modules following OWASP Testing Guide methodology
- Integrated CVSS v3.1 scoring system with automatic vector string generation
- Designed and implemented a professional print-ready pentest report template
- Used LLM API integration to generate context-aware executive summaries and risk analyses
