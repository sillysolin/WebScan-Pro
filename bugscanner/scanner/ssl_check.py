"""
Module: SSL/TLS Certificate & Configuration Analysis
Checks certificate validity, expiry, and protocol weaknesses.
"""

import ssl
import socket
import datetime


def check_ssl(hostname: str, port: int = 443) -> list:
    """Inspect SSL certificate and TLS configuration."""
    findings = []

    # Strip port from hostname if present (e.g., "example.com:443")
    clean_host = hostname.split(":")[0]

    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((clean_host, port), timeout=8) as sock:
            with ctx.wrap_socket(sock, server_hostname=clean_host) as ssock:
                cert = ssock.getpeercert()
                protocol = ssock.version()
                cipher = ssock.cipher()
    except ssl.SSLCertVerificationError as e:
        findings.append({
            "module": "SSL/TLS",
            "title": "SSL Certificate Verification Failed",
            "severity": "critical",
            "description": f"The server's SSL certificate could not be verified: {str(e)[:200]}. Users are vulnerable to MITM attacks.",
            "recommendation": "Obtain a valid certificate from a trusted CA (e.g., Let's Encrypt).",
            "reference": "https://owasp.org/www-project-transport-layer-protection-cheat-sheet/",
            "evidence": str(e)[:200],
        })
        return findings
    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        findings.append({
            "module": "SSL/TLS",
            "title": "Could Not Connect for SSL Check",
            "severity": "info",
            "description": f"Unable to open TLS connection to {clean_host}:{port} — {str(e)[:100]}",
            "recommendation": "Ensure the server is accessible and TLS is configured.",
            "reference": "",
            "evidence": str(e)[:100],
        })
        return findings
    except Exception as e:
        return []

    # ── Certificate expiry ───────────────────────────────────────────────────
    not_after = cert.get("notAfter")
    if not_after:
        expiry = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
        days_left = (expiry - datetime.datetime.utcnow()).days
        if days_left < 0:
            findings.append({
                "module": "SSL/TLS",
                "title": "SSL Certificate Expired",
                "severity": "critical",
                "description": f"The SSL certificate expired {abs(days_left)} days ago. All connections display a browser warning.",
                "recommendation": "Renew the certificate immediately.",
                "reference": "https://letsencrypt.org/",
                "evidence": f"Not After: {not_after}",
            })
        elif days_left < 14:
            findings.append({
                "module": "SSL/TLS",
                "title": "SSL Certificate Expiring Very Soon",
                "severity": "high",
                "description": f"Certificate expires in {days_left} days. Service disruption imminent.",
                "recommendation": "Renew the certificate immediately.",
                "reference": "https://letsencrypt.org/",
                "evidence": f"Not After: {not_after} ({days_left} days)",
            })
        elif days_left < 30:
            findings.append({
                "module": "SSL/TLS",
                "title": "SSL Certificate Expiring Soon",
                "severity": "medium",
                "description": f"Certificate expires in {days_left} days.",
                "recommendation": "Schedule certificate renewal before it expires.",
                "reference": "",
                "evidence": f"Not After: {not_after} ({days_left} days)",
            })
        else:
            findings.append({
                "module": "SSL/TLS",
                "title": "SSL Certificate Valid",
                "severity": "info",
                "description": f"Certificate is valid for {days_left} more days.",
                "recommendation": "No action required.",
                "reference": "",
                "evidence": f"Not After: {not_after}",
            })

    # ── Protocol version ─────────────────────────────────────────────────────
    weak_protocols = {"TLSv1": "high", "TLSv1.1": "high", "SSLv2": "critical", "SSLv3": "critical"}
    if protocol in weak_protocols:
        findings.append({
            "module": "SSL/TLS",
            "title": f"Weak TLS Protocol in Use: {protocol}",
            "severity": weak_protocols[protocol],
            "description": f"The server negotiated {protocol}, which is deprecated and vulnerable (POODLE, BEAST, etc.).",
            "recommendation": "Disable TLS 1.0 and 1.1. Only TLS 1.2 and TLS 1.3 should be enabled.",
            "reference": "https://ssl-config.mozilla.org/",
            "evidence": f"Negotiated protocol: {protocol}",
        })
    else:
        findings.append({
            "module": "SSL/TLS",
            "title": f"TLS Protocol: {protocol}",
            "severity": "info",
            "description": f"Server negotiated {protocol}.",
            "recommendation": "No action required.",
            "reference": "",
            "evidence": f"Protocol: {protocol}",
        })

    # ── Cipher strength ──────────────────────────────────────────────────────
    if cipher:
        cipher_name, _, bits = cipher
        weak_ciphers = ["RC4", "DES", "3DES", "NULL", "EXPORT", "anon"]
        if any(w in cipher_name.upper() for w in weak_ciphers):
            findings.append({
                "module": "SSL/TLS",
                "title": f"Weak Cipher Suite: {cipher_name}",
                "severity": "high",
                "description": f"The negotiated cipher {cipher_name} is considered weak or broken.",
                "recommendation": "Restrict allowed ciphers to modern AEAD cipher suites (AES-GCM, ChaCha20).",
                "reference": "https://ssl-config.mozilla.org/",
                "evidence": f"Cipher: {cipher_name}, Bits: {bits}",
            })

    return findings
