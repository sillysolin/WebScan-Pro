"""
Scanner orchestrator — runs all modules and attaches CVSS v3 scores.
"""

import requests
import time
import warnings
from urllib.parse import urlparse

from .headers    import check_security_headers
from .ssl_check  import check_ssl
from .info_gather import gather_info
from .cookie_check import check_cookies
from .xss_probe  import probe_xss
from .sqli_probe import probe_sqli
from .cors_check import check_cors
from .file_enum  import enumerate_sensitive_files
from .auth_check import check_auth
from .cvss       import attach_cvss

warnings.filterwarnings("ignore")   # suppress InsecureRequestWarning

TIMEOUT = 8
REQ_HEADERS = {
    "User-Agent": "BugScannerPro/2.0 (Authorised Security Assessment)",
    "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
}


def fetch(url: str) -> dict:
    try:
        r = requests.get(url, headers=REQ_HEADERS, timeout=TIMEOUT,
                         allow_redirects=True, verify=False)
        return {
            "ok": True, "status": r.status_code,
            "headers": dict(r.headers), "body": r.text[:60000],
            "url": r.url, "elapsed": round(r.elapsed.total_seconds(), 3),
        }
    except requests.exceptions.SSLError as e:
        return {"ok": False, "error": f"SSL Error: {str(e)[:120]}"}
    except requests.exceptions.ConnectionError:
        return {"ok": False, "error": "Connection refused or DNS resolution failed"}
    except requests.exceptions.Timeout:
        return {"ok": False, "error": "Request timed out after 8 seconds"}
    except Exception as e:
        return {"ok": False, "error": str(e)[:120]}


def compute_summary(findings: list) -> dict:
    weights = {"critical": 40, "high": 20, "medium": 10, "low": 3, "info": 0}
    counts  = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    score   = 0
    for f in findings:
        s = f.get("severity", "info")
        counts[s] = counts.get(s, 0) + 1
        score += weights.get(s, 0)
    score = min(score, 100)
    risk = ("Critical" if score >= 60 else "High" if score >= 35
            else "Medium" if score >= 15 else "Low" if score > 0 else "Clean")
    return {"score": score, "risk": risk, "counts": counts}


def run_full_scan(url: str) -> dict:
    start   = time.time()
    parsed  = urlparse(url)
    domain  = parsed.netloc

    resp = fetch(url)
    if not resp["ok"]:
        return {"error": resp["error"], "url": url}

    findings = []
    findings += check_security_headers(resp["headers"])
    findings += check_cookies(resp["headers"])
    findings += check_cors(url, resp["headers"], REQ_HEADERS, TIMEOUT)
    findings += gather_info(url, resp["headers"], resp["body"], REQ_HEADERS, TIMEOUT)
    findings += probe_xss(url, resp["body"], REQ_HEADERS, TIMEOUT)
    findings += probe_sqli(url, REQ_HEADERS, TIMEOUT)
    findings += enumerate_sensitive_files(url, REQ_HEADERS, TIMEOUT)
    findings += check_auth(url, resp["headers"], resp["body"], REQ_HEADERS, TIMEOUT)

    if parsed.scheme == "https":
        findings += check_ssl(domain, parsed.port or 443)

    # Attach CVSS v3 scores to every finding
    findings = [attach_cvss(f) for f in findings]

    # Sort: critical → info, then by CVSS score desc
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings.sort(key=lambda f: (order.get(f["severity"], 5), -f.get("cvss_score", 0)))

    summary = compute_summary(findings)
    elapsed = round(time.time() - start, 2)

    return {
        "url": url, "domain": domain,
        "status_code": resp["status"],
        "elapsed": elapsed,
        "server": resp["headers"].get("Server", "Not disclosed"),
        "x_powered_by": resp["headers"].get("X-Powered-By", ""),
        "findings": findings,
        "summary": summary,
        "total": len(findings),
    }
