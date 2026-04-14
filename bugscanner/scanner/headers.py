"""
Module: Security Headers Analysis
Checks for presence and correct configuration of HTTP security headers.
"""


REQUIRED_HEADERS = [
    {
        "header": "Strict-Transport-Security",
        "short": "HSTS",
        "severity": "high",
        "description": "HSTS header missing. The browser may be tricked into using HTTP instead of HTTPS, enabling downgrade attacks.",
        "recommendation": "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
        "reference": "https://owasp.org/www-project-secure-headers/#strict-transport-security",
    },
    {
        "header": "Content-Security-Policy",
        "short": "CSP",
        "severity": "high",
        "description": "No Content-Security-Policy header. The site is vulnerable to XSS and data injection attacks without content restrictions.",
        "recommendation": "Define a strict CSP policy restricting script, style, and resource sources.",
        "reference": "https://owasp.org/www-project-secure-headers/#content-security-policy",
    },
    {
        "header": "X-Frame-Options",
        "short": "X-Frame-Options",
        "severity": "medium",
        "description": "Missing X-Frame-Options header. The page can be embedded in an iframe, enabling clickjacking attacks.",
        "recommendation": "Add: X-Frame-Options: DENY  or use CSP frame-ancestors directive.",
        "reference": "https://owasp.org/www-project-secure-headers/#x-frame-options",
    },
    {
        "header": "X-Content-Type-Options",
        "short": "X-Content-Type-Options",
        "severity": "medium",
        "description": "Missing X-Content-Type-Options. Browsers may MIME-sniff responses, potentially executing malicious files.",
        "recommendation": "Add: X-Content-Type-Options: nosniff",
        "reference": "https://owasp.org/www-project-secure-headers/#x-content-type-options",
    },
    {
        "header": "Referrer-Policy",
        "short": "Referrer-Policy",
        "severity": "low",
        "description": "No Referrer-Policy header. Sensitive URL parameters may be leaked to third-party sites via the Referer header.",
        "recommendation": "Add: Referrer-Policy: strict-origin-when-cross-origin",
        "reference": "https://owasp.org/www-project-secure-headers/#referrer-policy",
    },
    {
        "header": "Permissions-Policy",
        "short": "Permissions-Policy",
        "severity": "low",
        "description": "Missing Permissions-Policy header. Browser features (camera, microphone, geolocation) are not restricted.",
        "recommendation": "Add: Permissions-Policy: geolocation=(), camera=(), microphone=()",
        "reference": "https://owasp.org/www-project-secure-headers/#permissions-policy",
    },
]

LEAK_HEADERS = [
    {
        "header": "X-Powered-By",
        "severity": "low",
        "description_tpl": "X-Powered-By header exposes technology: {value}. This aids fingerprinting and targeted attacks.",
        "recommendation": "Remove or obscure this header in your server/framework configuration.",
    },
    {
        "header": "Server",
        "severity": "info",
        "description_tpl": "Server header discloses software version: {value}. Avoid exposing version numbers.",
        "recommendation": "Remove the Server header or suppress version information.",
    },
    {
        "header": "X-AspNet-Version",
        "severity": "low",
        "description_tpl": "X-AspNet-Version header discloses ASP.NET version: {value}.",
        "recommendation": "Disable via <httpRuntime enableVersionHeader='false'> in web.config.",
    },
    {
        "header": "X-AspNetMvc-Version",
        "severity": "low",
        "description_tpl": "X-AspNetMvc-Version header exposed: {value}.",
        "recommendation": "Disable in Global.asax: MvcHandler.DisableMvcResponseHeader = true",
    },
]


def check_security_headers(headers: dict) -> list:
    """Analyse response headers for missing security controls and info leakage."""
    findings = []
    headers_lower = {k.lower(): v for k, v in headers.items()}

    # Check for missing required headers
    for cfg in REQUIRED_HEADERS:
        if cfg["header"].lower() not in headers_lower:
            findings.append({
                "module": "Security Headers",
                "title": f"Missing {cfg['short']} Header",
                "severity": cfg["severity"],
                "description": cfg["description"],
                "recommendation": cfg["recommendation"],
                "reference": cfg["reference"],
                "evidence": f"Header '{cfg['header']}' not present in response",
            })

    # Check CSP for unsafe directives even if present
    csp = headers_lower.get("content-security-policy", "")
    if csp:
        if "'unsafe-inline'" in csp:
            findings.append({
                "module": "Security Headers",
                "title": "CSP allows 'unsafe-inline'",
                "severity": "medium",
                "description": "The Content-Security-Policy permits inline scripts ('unsafe-inline'), significantly weakening XSS protection.",
                "recommendation": "Remove 'unsafe-inline' and use nonces or hashes instead.",
                "reference": "https://csp.withgoogle.com/docs/strict-csp.html",
                "evidence": f"CSP: {csp[:200]}",
            })
        if "'unsafe-eval'" in csp:
            findings.append({
                "module": "Security Headers",
                "title": "CSP allows 'unsafe-eval'",
                "severity": "medium",
                "description": "The CSP includes 'unsafe-eval', allowing eval() and similar functions that can be exploited.",
                "recommendation": "Remove 'unsafe-eval' from your CSP policy.",
                "reference": "https://csp.withgoogle.com/docs/strict-csp.html",
                "evidence": f"CSP: {csp[:200]}",
            })

    # Check HSTS for weak values
    hsts = headers_lower.get("strict-transport-security", "")
    if hsts:
        import re
        m = re.search(r"max-age=(\d+)", hsts)
        if m and int(m.group(1)) < 31536000:
            findings.append({
                "module": "Security Headers",
                "title": "HSTS max-age too short",
                "severity": "low",
                "description": f"HSTS max-age is {m.group(1)} seconds (<1 year). Short durations reduce protection effectiveness.",
                "recommendation": "Set max-age to at least 31536000 (1 year) with includeSubDomains.",
                "reference": "https://hstspreload.org/",
                "evidence": f"Strict-Transport-Security: {hsts}",
            })

    # Check for information-leaking headers
    for cfg in LEAK_HEADERS:
        val = headers_lower.get(cfg["header"].lower(), "")
        if val:
            findings.append({
                "module": "Information Disclosure",
                "title": f"{cfg['header']} Header Exposed",
                "severity": cfg["severity"],
                "description": cfg["description_tpl"].format(value=val),
                "recommendation": cfg["recommendation"],
                "reference": "https://owasp.org/www-project-web-security-testing-guide/",
                "evidence": f"{cfg['header']}: {val}",
            })

    return findings
