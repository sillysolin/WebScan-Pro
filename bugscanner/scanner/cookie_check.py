"""
Module: Cookie Security Analysis
Checks session and other cookies for missing security flags.
"""


def check_cookies(headers: dict) -> list:
    """Inspect Set-Cookie headers for missing security attributes."""
    findings = []
    headers_lower = {k.lower(): v for k, v in headers.items()}

    raw_cookies = []
    # requests may merge multiple Set-Cookie as comma-separated
    sc = headers_lower.get("set-cookie", "")
    if sc:
        raw_cookies = [sc] if isinstance(sc, str) else sc

    if not raw_cookies:
        return findings

    for cookie_str in raw_cookies:
        cookie_lower = cookie_str.lower()
        parts = [p.strip() for p in cookie_str.split(";")]
        name = parts[0].split("=")[0].strip() if parts else "unknown"
        attrs = [p.lower() for p in parts[1:]]

        # HttpOnly
        if "httponly" not in attrs:
            findings.append({
                "module": "Cookie Security",
                "title": f"Cookie Missing HttpOnly Flag: {name}",
                "severity": "medium",
                "description": f"Cookie '{name}' does not have the HttpOnly flag set. JavaScript can read this cookie, enabling theft via XSS.",
                "recommendation": f"Set the HttpOnly attribute: Set-Cookie: {name}=...; HttpOnly",
                "reference": "https://owasp.org/www-community/HttpOnly",
                "evidence": cookie_str[:150],
            })

        # Secure flag
        if "secure" not in attrs:
            findings.append({
                "module": "Cookie Security",
                "title": f"Cookie Missing Secure Flag: {name}",
                "severity": "medium",
                "description": f"Cookie '{name}' lacks the Secure flag. It may be transmitted over unencrypted HTTP connections.",
                "recommendation": f"Add Secure attribute: Set-Cookie: {name}=...; Secure",
                "reference": "https://owasp.org/www-community/controls/SecureCookieAttribute",
                "evidence": cookie_str[:150],
            })

        # SameSite
        has_samesite = any("samesite" in a for a in attrs)
        if not has_samesite:
            findings.append({
                "module": "Cookie Security",
                "title": f"Cookie Missing SameSite Attribute: {name}",
                "severity": "low",
                "description": f"Cookie '{name}' has no SameSite attribute, leaving it vulnerable to CSRF attacks in some browser configurations.",
                "recommendation": "Add SameSite=Strict or SameSite=Lax to the cookie.",
                "reference": "https://owasp.org/www-community/SameSite",
                "evidence": cookie_str[:150],
            })
        else:
            # Check for SameSite=None without Secure
            samesite_none = any("samesite=none" in a for a in attrs)
            if samesite_none and "secure" not in attrs:
                findings.append({
                    "module": "Cookie Security",
                    "title": f"SameSite=None Without Secure: {name}",
                    "severity": "medium",
                    "description": f"Cookie '{name}' is set with SameSite=None but without Secure flag — this is rejected by modern browsers and insecure.",
                    "recommendation": "Add the Secure flag when using SameSite=None.",
                    "reference": "https://web.dev/samesite-cookies-explained/",
                    "evidence": cookie_str[:150],
                })

        # Session cookie (no Expires/Max-Age) — informational
        is_session = not any("expires" in a or "max-age" in a for a in attrs)
        if is_session:
            findings.append({
                "module": "Cookie Security",
                "title": f"Session Cookie (no expiry): {name}",
                "severity": "info",
                "description": f"Cookie '{name}' has no Expires/Max-Age. It will persist until the browser session ends.",
                "recommendation": "This is normal for session cookies. Ensure session is properly invalidated on logout.",
                "reference": "",
                "evidence": cookie_str[:100],
            })

    return findings
