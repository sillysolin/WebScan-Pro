"""
Module: SQL Injection Probe (Error-Based Detection)
Injects basic SQL metacharacters and looks for DB error messages in responses.
This is a light, error-based probe — NOT a full exploitation attempt.
"""

import re
import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse


# Error signatures for common databases
DB_ERROR_PATTERNS = [
    (r"you have an error in your sql syntax", "MySQL"),
    (r"warning: mysql_", "MySQL"),
    (r"unclosed quotation mark after the character string", "MSSQL"),
    (r"quoted string not properly terminated", "Oracle/PostgreSQL"),
    (r"pg_query\(\).*error", "PostgreSQL"),
    (r"sqlite3.operationalerror", "SQLite"),
    (r"ora-\d{5}:", "Oracle"),
    (r"microsoft ole db provider for sql server", "MSSQL"),
    (r"syntax error.*near", "Generic SQL"),
    (r"invalid query", "Generic SQL"),
]

# Payloads designed to trigger DB errors (not exploit)
ERROR_PAYLOADS = ["'", '"', "1'", "1\"", "1 OR '1'='1", "1; --"]


def _inject(url: str, param: str, payload: str) -> str:
    """Return URL with parameter set to payload."""
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    params[param] = [payload]
    return urlunparse(parsed._replace(query=urlencode(params, doseq=True)))


def probe_sqli(url: str, req_headers: dict, timeout: int) -> list:
    """Probe URL parameters for SQL injection error messages."""
    findings = []
    parsed = urlparse(url)
    params = parse_qs(parsed.query)

    if not params:
        return findings

    for param in list(params.keys())[:5]:
        for payload in ERROR_PAYLOADS:
            test_url = _inject(url, param, payload)
            try:
                r = requests.get(test_url, headers=req_headers, timeout=timeout,
                                 verify=False, allow_redirects=True)
                body = r.text.lower()
                for pattern, db_name in DB_ERROR_PATTERNS:
                    if re.search(pattern, body, re.IGNORECASE):
                        findings.append({
                            "module": "SQL Injection",
                            "title": f"SQL Injection — DB Error Triggered: '{param}'",
                            "severity": "critical",
                            "description": (
                                f"Parameter '{param}' triggered a {db_name} database error when injected with "
                                f"SQL metacharacters. This strongly indicates SQL injection vulnerability."
                            ),
                            "recommendation": (
                                "Use parameterised queries (prepared statements) for all database interactions. "
                                "Never concatenate user input into SQL strings. "
                                "Implement a WAF as a secondary control."
                            ),
                            "reference": "https://owasp.org/www-community/attacks/SQL_Injection",
                            "evidence": f"Payload: {payload!r} → {db_name} error in response",
                        })
                        return findings  # stop after first confirmed finding
            except Exception:
                pass

    return findings
