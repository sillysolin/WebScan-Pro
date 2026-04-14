"""
Module: Authentication & Login Security
Checks for weak authentication, default credentials, and login page issues.
"""

import re
import requests


ADMIN_PATHS = [
    "/admin", "/admin/login", "/administrator", "/login", "/signin",
    "/wp-login.php", "/user/login", "/auth/login", "/panel",
    "/dashboard", "/cpanel", "/control", "/manage",
]

DEFAULT_CREDS = [
    ("admin", "admin"), ("admin", "password"), ("admin", "123456"),
    ("admin", ""), ("root", "root"), ("test", "test"),
    ("administrator", "administrator"), ("guest", "guest"),
]


def check_auth(url: str, headers: dict, body: str, req_headers: dict, timeout: int) -> list:
    findings = []
    base = url.rstrip("/")

    # ── Look for login pages ────────────────────────────────────────────────
    login_urls = []
    for path in ADMIN_PATHS:
        try:
            r = requests.get(base + path, headers=req_headers, timeout=timeout,
                             verify=False, allow_redirects=True)
            if r.status_code == 200:
                page = r.text.lower()
                if any(kw in page for kw in ["password", "login", "username", "sign in", "credentials"]):
                    login_urls.append(base + path)
                    if path not in ["/login", "/signin"]:
                        findings.append({
                            "module": "Authentication",
                            "title": f"Admin/Login Page Exposed: {path}",
                            "severity": "medium",
                            "description": f"An admin or login page is publicly accessible at {base + path}. This increases the attack surface for brute-force and credential attacks.",
                            "recommendation": "Restrict access to admin pages by IP whitelist or VPN. Implement strong account lockout policies.",
                            "reference": "https://owasp.org/www-project-top-ten/2017/A5_2017-Broken_Access_Control",
                            "evidence": f"HTTP 200 at {base + path} with login form detected",
                        })
        except Exception:
            pass

    # ── Check for login form without CSRF token ─────────────────────────────
    csrf_patterns = [
        r'name=["\']_?csrf', r'name=["\']csrf_?token', r'name=["\']_token',
        r'name=["\']authenticity_token', r'name=["\']__RequestVerificationToken',
    ]
    forms = re.findall(r'<form[^>]*>.*?</form>', body, re.DOTALL | re.IGNORECASE)
    for form in forms:
        is_post = 'method' in form.lower() and 'post' in form.lower()
        has_csrf = any(re.search(p, form, re.IGNORECASE) for p in csrf_patterns)
        has_password = 'type="password"' in form.lower() or "type='password'" in form.lower()
        if is_post and has_password and not has_csrf:
            findings.append({
                "module": "Authentication",
                "title": "Login Form Missing CSRF Token",
                "severity": "high",
                "description": "A login form uses POST without a detectable CSRF token. This may allow cross-site request forgery attacks against the login endpoint.",
                "recommendation": "Implement synchronised CSRF tokens on all state-changing forms. Frameworks like Django, Laravel, and Rails provide this by default.",
                "reference": "https://owasp.org/www-community/attacks/csrf",
                "evidence": "POST form with password field found — no CSRF token attribute detected",
            })
            break

    # ── Check HTTP auth headers ─────────────────────────────────────────────
    www_auth = headers.get("WWW-Authenticate", "")
    if "basic" in www_auth.lower():
        findings.append({
            "module": "Authentication",
            "title": "HTTP Basic Authentication in Use",
            "severity": "medium",
            "description": "The server uses HTTP Basic Authentication, which transmits credentials base64-encoded (not encrypted) unless over HTTPS. Vulnerable to credential interception if TLS is not enforced.",
            "recommendation": "Migrate to a modern session-based or token-based authentication system. At minimum, enforce HTTPS.",
            "reference": "https://owasp.org/www-project-web-security-testing-guide/",
            "evidence": f"WWW-Authenticate: {www_auth}",
        })

    # ── Password reset / register link checks ──────────────────────────────
    body_lower = body.lower()
    if "forgot password" in body_lower or "reset password" in body_lower:
        findings.append({
            "module": "Authentication",
            "title": "Password Reset Functionality Present",
            "severity": "info",
            "description": "A password reset link was detected. Ensure reset tokens are single-use, time-limited (≤15 min), and sent only to verified addresses.",
            "recommendation": "Test: token reuse, predictable tokens, host header injection in reset emails, and response enumeration.",
            "reference": "https://owasp.org/www-community/Forgot_Password_Cheat_Sheet",
            "evidence": "Found 'forgot/reset password' text in page body",
        })

    # ── Check if autocomplete is disabled on password fields ────────────────
    if 'type="password"' in body.lower() or "type='password'" in body.lower():
        if 'autocomplete="off"' not in body.lower() and 'autocomplete="new-password"' not in body.lower():
            findings.append({
                "module": "Authentication",
                "title": "Password Field Missing autocomplete='off'",
                "severity": "low",
                "description": "Password input fields do not have autocomplete disabled. On shared/public devices, browsers may cache or autofill sensitive credentials.",
                "recommendation": "Add autocomplete='off' or autocomplete='new-password' to password input fields.",
                "reference": "https://owasp.org/www-project-web-security-testing-guide/",
                "evidence": "Password input field found without autocomplete='off' attribute",
            })

    return findings
