"""
Module: XSS Reflection Probe
Tests URL parameters and forms for basic reflected XSS.
NOTE: This is a passive/light probe using benign payloads only.
      It checks for reflection — it does NOT execute JS.
"""

import re
import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse


# Benign probe strings that indicate potential XSS reflection
XSS_PROBES = [
    '<script>wsProbe1</script>',
    '"><wsProbe2>',
    "';wsProbe3--",
]


def _inject_param(url: str, param: str, payload: str) -> str:
    """Return a URL with the given parameter replaced by payload."""
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    params[param] = [payload]
    new_query = urlencode(params, doseq=True)
    return urlunparse(parsed._replace(query=new_query))


def probe_xss(url: str, body: str, req_headers: dict, timeout: int) -> list:
    """Probe URL parameters for reflected XSS."""
    findings = []
    parsed = urlparse(url)
    params = parse_qs(parsed.query)

    if not params:
        # Try to find query parameters from links in body
        links = re.findall(r'href=["\']([^"\']*\?[^"\']+)["\']', body)
        for link in links[:3]:
            if link.startswith("http"):
                sub_parsed = urlparse(link)
            else:
                sub_parsed = urlparse(url.rstrip("/") + "/" + link.lstrip("/"))
            sub_params = parse_qs(sub_parsed.query)
            if sub_params:
                params = sub_params
                parsed = sub_parsed
                url = urlunparse(sub_parsed)
                break

    if not params:
        return findings

    for param in list(params.keys())[:5]:  # test first 5 params
        for probe in XSS_PROBES:
            test_url = _inject_param(url, param, probe)
            try:
                r = requests.get(test_url, headers=req_headers, timeout=timeout,
                                 verify=False, allow_redirects=True)
                if probe.lower() in r.text.lower():
                    findings.append({
                        "module": "XSS",
                        "title": f"Reflected XSS Candidate: parameter '{param}'",
                        "severity": "high",
                        "description": (
                            f"The parameter '{param}' reflects user input without apparent encoding. "
                            "This is a strong indicator of reflected XSS."
                        ),
                        "recommendation": (
                            "Encode all user-controlled output. Use context-appropriate escaping "
                            "(HTML encode for HTML context, JS encode for script context). "
                            "Implement a strict Content-Security-Policy."
                        ),
                        "reference": "https://owasp.org/www-community/attacks/xss/",
                        "evidence": f"Probe '{probe[:40]}' reflected in response at param '{param}'",
                    })
                    break  # one finding per param is enough
            except Exception:
                pass

    return findings
