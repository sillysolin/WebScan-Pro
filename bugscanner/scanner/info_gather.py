"""
Module: Information Gathering
Checks for information disclosure in HTML comments, robots.txt,
sitemap.xml, and technology fingerprinting.
"""

import re
import requests


def gather_info(url: str, headers: dict, body: str, req_headers: dict, timeout: int) -> list:
    """Gather information about the target from various sources."""
    findings = []
    base = url.rstrip("/")

    # ── HTML comments ────────────────────────────────────────────────────────
    comments = re.findall(r"<!--(.*?)-->", body, re.DOTALL)
    interesting_keywords = [
        "todo", "fixme", "hack", "bug", "password", "secret", "key",
        "token", "api", "debug", "admin", "credential", "internal",
    ]
    for comment in comments:
        c = comment.strip()
        if len(c) < 3:
            continue
        c_lower = c.lower()
        if any(kw in c_lower for kw in interesting_keywords):
            findings.append({
                "module": "Information Disclosure",
                "title": "Sensitive Keyword in HTML Comment",
                "severity": "medium",
                "description": "An HTML comment contains a potentially sensitive keyword that may reveal internal information or credentials.",
                "recommendation": "Remove all developer comments from production HTML. Use build tools to strip comments.",
                "reference": "https://owasp.org/www-project-web-security-testing-guide/",
                "evidence": f"Comment: <!--{c[:200]}-->",
            })
            break  # report once

    # ── Email addresses in body ──────────────────────────────────────────────
    emails = re.findall(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+", body)
    if emails:
        unique = list(set(emails))[:5]
        findings.append({
            "module": "Information Disclosure",
            "title": "Email Addresses Exposed",
            "severity": "info",
            "description": f"Found {len(set(emails))} email address(es) in page source. These can be used for phishing or social engineering.",
            "recommendation": "Obfuscate email addresses on public pages or use contact forms.",
            "reference": "",
            "evidence": "Emails: " + ", ".join(unique),
        })

    # ── robots.txt ───────────────────────────────────────────────────────────
    try:
        r = requests.get(f"{base}/robots.txt", headers=req_headers, timeout=timeout,
                         verify=False, allow_redirects=True)
        if r.status_code == 200 and "user-agent" in r.text.lower():
            disallowed = re.findall(r"Disallow:\s*(.+)", r.text)
            sensitive = [p.strip() for p in disallowed if any(
                kw in p.lower() for kw in ["admin", "api", "backup", "private", "internal", "config", "secret"]
            )]
            if sensitive:
                findings.append({
                    "module": "Information Disclosure",
                    "title": "Sensitive Paths in robots.txt",
                    "severity": "low",
                    "description": "robots.txt reveals Disallow entries for sensitive-looking paths, providing a roadmap for attackers.",
                    "recommendation": "Do not rely on robots.txt for security. Protect sensitive paths with authentication.",
                    "reference": "https://owasp.org/www-project-web-security-testing-guide/",
                    "evidence": "Disallowed: " + ", ".join(sensitive[:10]),
                })
            else:
                findings.append({
                    "module": "Information Disclosure",
                    "title": "robots.txt Accessible",
                    "severity": "info",
                    "description": "robots.txt is present and accessible.",
                    "recommendation": "Review entries for sensitive path disclosure.",
                    "reference": "",
                    "evidence": f"Found {len(disallowed)} Disallow entries",
                })
    except Exception:
        pass

    # ── sitemap.xml ──────────────────────────────────────────────────────────
    try:
        r = requests.get(f"{base}/sitemap.xml", headers=req_headers, timeout=timeout,
                         verify=False, allow_redirects=True)
        if r.status_code == 200 and "<url" in r.text.lower():
            urls_found = re.findall(r"<loc>(.*?)</loc>", r.text)
            internal_paths = [u for u in urls_found if any(
                kw in u.lower() for kw in ["admin", "internal", "private", "api", "config"]
            )]
            if internal_paths:
                findings.append({
                    "module": "Information Disclosure",
                    "title": "Sensitive URLs in sitemap.xml",
                    "severity": "low",
                    "description": "sitemap.xml lists URLs that may include sensitive areas of the application.",
                    "recommendation": "Review sitemap.xml entries. Exclude sensitive paths.",
                    "reference": "",
                    "evidence": "Paths: " + ", ".join(internal_paths[:5]),
                })
    except Exception:
        pass

    # ── Technology fingerprinting ────────────────────────────────────────────
    tech_patterns = [
        ("WordPress", r"wp-content|wp-includes|wordpress", "info"),
        ("jQuery version", r"jquery[/-](\d+\.\d+\.\d+)", "info"),
        ("React", r"react\.production\.min\.js|__REACT_DEVTOOLS", "info"),
        ("Angular", r"ng-version|angular\.min\.js", "info"),
        ("Bootstrap version", r"bootstrap[/-](\d+\.\d+\.\d+)", "info"),
        ("PHP error", r"<b>Warning</b>.*?PHP|<b>Fatal error</b>", "medium"),
        ("Stack trace", r"at .+\(.+:\d+:\d+\)|Traceback \(most recent call", "high"),
        ("ASP.NET error", r"__VIEWSTATE|aspnet_client", "info"),
    ]
    for name, pattern, severity in tech_patterns:
        match = re.search(pattern, body, re.IGNORECASE)
        if match:
            if severity in ("medium", "high"):
                findings.append({
                    "module": "Information Disclosure",
                    "title": f"Error / Stack Trace Detected: {name}",
                    "severity": severity,
                    "description": f"The server returned a {name} which reveals internal implementation details to attackers.",
                    "recommendation": "Disable detailed error output in production. Use custom error pages.",
                    "reference": "https://owasp.org/www-community/Improper_Error_Handling",
                    "evidence": match.group(0)[:150],
                })
            else:
                findings.append({
                    "module": "Fingerprinting",
                    "title": f"Technology Detected: {name}",
                    "severity": "info",
                    "description": f"{name} detected in page source.",
                    "recommendation": "Keep all libraries and frameworks up to date.",
                    "reference": "",
                    "evidence": match.group(0)[:100],
                })

    return findings
