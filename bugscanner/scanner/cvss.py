"""
CVSS v3.1 Base Score approximation.
Maps finding types to realistic CVSS vectors and scores.
"""

# Predefined CVSS v3.1 vectors per finding title keyword
CVSS_MAP = {
    # Critical
    "sql injection":            (9.8,  "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    "remote code":              (9.8,  "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    "rce":                      (9.8,  "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    "git repository":           (9.1,  "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"),
    ".env file":                (9.1,  "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"),
    "sql dump":                 (9.1,  "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"),
    "certificate expired":      (9.0,  "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"),
    "arbitrary origin reflected with credentials": (9.0, "AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N"),
    "admin panel found":        (8.1,  "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"),
    "phpmyadmin":               (9.8,  "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),

    # High
    "stored xss":               (8.8,  "AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:N"),
    "reflected xss":            (7.4,  "AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N"),
    "hsts":                     (7.4,  "AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N"),
    "content-security-policy":  (6.1,  "AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"),
    "cors":                     (7.5,  "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    "null origin":              (7.4,  "AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N"),
    "weak tls":                 (7.4,  "AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N"),
    "weak cipher":              (6.5,  "AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    "missing x-frame":          (6.1,  "AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"),
    "stack trace":              (5.3,  "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),
    "debug":                    (7.5,  "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    "tomcat manager":           (8.8,  "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"),

    # Medium
    "cookie missing httponly":  (5.4,  "AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N"),
    "cookie missing secure":    (5.9,  "AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    "cookie missing samesite":  (4.3,  "AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N"),
    "x-content-type":           (4.3,  "AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N"),
    "sensitive paths in robots":(3.7,  "AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N"),
    "email addresses":          (4.3,  "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),
    "html comment":             (4.3,  "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),
    "backup":                   (5.9,  "AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    "error.log":                (5.3,  "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),
    "swagger":                  (5.3,  "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),
    "referrer-policy":          (3.7,  "AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N"),
    "permissions-policy":       (3.1,  "AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N"),
    "server header":            (3.7,  "AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N"),
    "x-powered-by":             (3.7,  "AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N"),

    # Low / Info
    "certificate expiring soon":(2.6,  "AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:L/A:N"),
    "technology detected":      (0.0,  "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"),
    "session cookie":           (0.0,  "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"),
    "robots.txt":               (0.0,  "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"),
    "ssl certificate valid":    (0.0,  "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"),
    "tls protocol":             (0.0,  "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"),
}

# Severity → fallback CVSS score
SEVERITY_DEFAULTS = {
    "critical": (8.5, "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"),
    "high":     (7.2, "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    "medium":   (5.3, "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N"),
    "low":      (3.1, "AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N"),
    "info":     (0.0, "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"),
}


def _cvss_rating(score: float) -> str:
    if score == 0.0: return "None"
    if score < 4.0:  return "Low"
    if score < 7.0:  return "Medium"
    if score < 9.0:  return "High"
    return "Critical"


def attach_cvss(finding: dict) -> dict:
    title_lower = finding.get("title", "").lower()

    score, vector = None, None
    for keyword, (s, v) in CVSS_MAP.items():
        if keyword in title_lower:
            score, vector = s, v
            break

    if score is None:
        score, vector = SEVERITY_DEFAULTS.get(
            finding.get("severity", "info"),
            (0.0, "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N")
        )

    finding["cvss_score"]  = score
    finding["cvss_vector"] = vector
    finding["cvss_rating"] = _cvss_rating(score)
    return finding
