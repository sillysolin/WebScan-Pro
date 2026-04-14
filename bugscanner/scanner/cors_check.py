"""
Module: CORS Misconfiguration Check
Tests for overly permissive Cross-Origin Resource Sharing headers.
"""

import requests


def check_cors(url: str, resp_headers: dict, req_headers: dict, timeout: int) -> list:
    """Check for CORS misconfiguration by sending an Origin header."""
    findings = []

    test_headers = dict(req_headers)
    test_headers["Origin"] = "https://evil-attacker.com"

    try:
        r = requests.get(url, headers=test_headers, timeout=timeout,
                         verify=False, allow_redirects=True)
        acao = r.headers.get("Access-Control-Allow-Origin", "")
        acac = r.headers.get("Access-Control-Allow-Credentials", "").lower()
    except Exception:
        return findings

    if acao == "*":
        findings.append({
            "module": "CORS",
            "title": "CORS Wildcard Origin (Access-Control-Allow-Origin: *)",
            "severity": "medium",
            "description": (
                "The server allows any origin to make cross-origin requests. "
                "While credentials can't be sent with wildcard ACAO, "
                "unauthenticated API data may be read by any website."
            ),
            "recommendation": (
                "Restrict the allowed origin to specific trusted domains. "
                "Avoid using '*' for any API that returns sensitive data."
            ),
            "reference": "https://portswigger.net/web-security/cors",
            "evidence": f"Access-Control-Allow-Origin: {acao}",
        })

    elif acao == "https://evil-attacker.com":
        if acac == "true":
            findings.append({
                "module": "CORS",
                "title": "CORS Misconfiguration — Arbitrary Origin Reflected with Credentials",
                "severity": "critical",
                "description": (
                    "The server reflects any provided Origin header and allows credentials. "
                    "An attacker can craft a malicious page that makes authenticated requests "
                    "to this API and reads the response — full account takeover may be possible."
                ),
                "recommendation": (
                    "Validate Origin against a strict whitelist. Never combine "
                    "Access-Control-Allow-Credentials: true with a reflected/wildcard origin."
                ),
                "reference": "https://portswigger.net/web-security/cors",
                "evidence": f"ACAO: {acao}  |  ACAC: {acac}",
            })
        else:
            findings.append({
                "module": "CORS",
                "title": "CORS — Arbitrary Origin Reflected",
                "severity": "high",
                "description": (
                    "The server reflects any attacker-supplied Origin header. "
                    "Without credentials this is limited, but it can enable "
                    "reading unauthenticated API responses from a malicious page."
                ),
                "recommendation": "Validate and whitelist allowed Origins server-side.",
                "reference": "https://portswigger.net/web-security/cors",
                "evidence": f"ACAO: {acao}",
            })

    # Null origin bypass
    test_headers_null = dict(req_headers)
    test_headers_null["Origin"] = "null"
    try:
        r2 = requests.get(url, headers=test_headers_null, timeout=timeout,
                          verify=False, allow_redirects=True)
        acao2 = r2.headers.get("Access-Control-Allow-Origin", "")
        acac2 = r2.headers.get("Access-Control-Allow-Credentials", "").lower()
        if acao2 == "null" and acac2 == "true":
            findings.append({
                "module": "CORS",
                "title": "CORS Null Origin Bypass with Credentials",
                "severity": "high",
                "description": (
                    "The server trusts 'null' as a CORS origin and allows credentials. "
                    "Sandboxed iframes can exploit this to make authenticated cross-origin requests."
                ),
                "recommendation": "Do not trust the 'null' origin. Whitelist only explicit HTTPS origins.",
                "reference": "https://portswigger.net/web-security/cors",
                "evidence": f"Origin: null → ACAO: {acao2}, ACAC: {acac2}",
            })
    except Exception:
        pass

    return findings
