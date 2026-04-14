"""
AI Report Generator
Uses Claude to write professional, context-aware pentest report sections.
Falls back to template-based generation if no API key is provided.
"""

import json
from datetime import datetime


def _call_claude(prompt: str, api_key: str) -> str:
    """Call Claude API and return text response."""
    try:
        import anthropic
        client = anthropic.Anthropic(api_key=api_key)
        msg = client.messages.create(
            model="claude-opus-4-6",
            max_tokens=1500,
            messages=[{"role": "user", "content": prompt}]
        )
        return msg.content[0].text
    except Exception as e:
        return None


def _template_executive_summary(data: dict) -> str:
    c = data["summary"]["counts"]
    risk = data["summary"]["risk"]
    domain = data["domain"]
    total = data["total"]

    critical_findings = [f for f in data["findings"] if f["severity"] == "critical"]
    high_findings     = [f for f in data["findings"] if f["severity"] == "high"]

    top_issues = []
    for f in (critical_findings + high_findings)[:3]:
        top_issues.append(f["title"])

    top_str = ""
    if top_issues:
        top_str = f" The most significant issues identified include: {'; '.join(top_issues)}."

    return (
        f"A security assessment was conducted against {domain}. "
        f"The assessment identified {total} security findings, comprising "
        f"{c['critical']} Critical, {c['high']} High, {c['medium']} Medium, "
        f"{c['low']} Low, and {c['info']} Informational severity issues. "
        f"The overall risk rating for this application is assessed as <strong>{risk}</strong>.{top_str} "
        f"Immediate remediation is recommended for all Critical and High severity findings "
        f"before the application is exposed to production traffic."
    )


def _template_methodology() -> str:
    return (
        "The assessment followed the OWASP Testing Guide (OTGv4) and covered the OWASP Top 10 "
        "vulnerability categories. Testing was performed using a black-box approach with no "
        "prior access to source code or architecture documentation. Modules executed include: "
        "HTTP security header analysis, SSL/TLS configuration review, cookie security audit, "
        "CORS policy testing, reflected XSS parameter probing, error-based SQL injection detection, "
        "sensitive file and directory enumeration, authentication mechanism review, "
        "and information disclosure assessment."
    )


def _ai_executive_summary(data: dict, api_key: str) -> str:
    findings_summary = []
    for f in data["findings"]:
        if f["severity"] in ("critical", "high"):
            findings_summary.append({
                "title": f["title"],
                "severity": f["severity"],
                "cvss": f.get("cvss_score", 0),
                "module": f["module"],
            })

    prompt = f"""You are a senior penetration tester writing a professional security assessment report.

Write an executive summary (3-4 paragraphs) for a web application security assessment with these details:
- Target: {data['domain']}
- Overall Risk: {data['summary']['risk']}
- Total findings: {data['total']}
- Breakdown: {data['summary']['counts']}
- Top critical/high findings: {json.dumps(findings_summary[:6], indent=2)}

Requirements:
- Professional, formal tone suitable for C-suite executives
- Explain the business risk impact, not just technical details
- Highlight the most critical issues without technical jargon
- End with a clear recommendation on urgency
- Do NOT use markdown headers or bullet points — plain paragraphs only
- 200-300 words maximum"""

    result = _call_claude(prompt, api_key)
    return result if result else _template_executive_summary(data)


def _ai_finding_analysis(finding: dict, api_key: str) -> str:
    """Generate a deeper technical analysis for a critical/high finding."""
    prompt = f"""You are a senior penetration tester. Write a concise technical analysis (2-3 sentences) 
for this vulnerability finding, explaining the real-world attack scenario and business impact:

Title: {finding['title']}
Module: {finding['module']}
Severity: {finding['severity']}
CVSS Score: {finding.get('cvss_score', 'N/A')}
Evidence: {finding.get('evidence', 'N/A')}

Write only the analysis sentences, no headers or bullet points. Focus on what an attacker can actually do."""

    result = _call_claude(prompt, api_key)
    return result if result else ""


def generate_ai_report(scan_data: dict, api_key: str = None) -> dict:
    """Generate full report content, using AI if API key is provided."""
    now = datetime.now()
    meta = scan_data.get("meta", {})

    # Executive summary
    if api_key:
        exec_summary = _ai_executive_summary(scan_data, api_key)
    else:
        exec_summary = _template_executive_summary(scan_data)

    # Enhance critical/high findings with AI analysis
    enhanced_findings = []
    for f in scan_data["findings"]:
        ef = dict(f)
        if api_key and f["severity"] in ("critical", "high") and f.get("cvss_score", 0) >= 7.0:
            ef["ai_analysis"] = _ai_finding_analysis(f, api_key)
        else:
            ef["ai_analysis"] = ""
        enhanced_findings.append(ef)

    return {
        "generated_at": now.strftime("%d %B %Y, %H:%M"),
        "report_date":  now.strftime("%d %B %Y"),
        "tester":       meta.get("tester", "Security Researcher"),
        "client":       meta.get("client", "Client Organisation"),
        "target":       scan_data["domain"],
        "target_url":   scan_data["url"],
        "risk":         scan_data["summary"]["risk"],
        "score":        scan_data["summary"]["score"],
        "counts":       scan_data["summary"]["counts"],
        "total":        scan_data["total"],
        "server":       scan_data.get("server", ""),
        "elapsed":      scan_data.get("elapsed", 0),
        "exec_summary": exec_summary,
        "methodology":  _template_methodology(),
        "findings":     enhanced_findings,
        "ai_powered":   bool(api_key),
    }
