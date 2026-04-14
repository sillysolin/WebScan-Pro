"""
Module: Sensitive File & Directory Enumeration
Probes for commonly exposed sensitive files and admin paths.
"""

import requests

SENSITIVE_PATHS = [
    # Source control
    ("/.git/HEAD",         "critical", "Git repository exposed",     "Git metadata accessible — source code and credentials may be extractable."),
    ("/.git/config",       "critical", "Git config exposed",         "Git config file accessible — remote URLs and credentials may be leaked."),
    ("/.svn/entries",      "high",     "SVN repository exposed",     "SVN working directory metadata accessible."),
    ("/.hg/",              "high",     "Mercurial repo exposed",     "Mercurial repository metadata accessible."),

    # Config / env files
    ("/.env",              "critical", ".env file exposed",          "Environment file may contain database credentials, API keys, and secrets."),
    ("/.env.local",        "critical", ".env.local file exposed",    "Local environment file with potential secret keys."),
    ("/.env.production",   "critical", ".env.production exposed",    "Production environment file with potential secret keys."),
    ("/config.php",        "high",     "config.php exposed",         "PHP config file may contain DB credentials."),
    ("/config.yml",        "high",     "config.yml exposed",         "YAML config file with potential secrets."),
    ("/wp-config.php",     "critical", "wp-config.php accessible",   "WordPress config with DB credentials — though PHP execution may prevent reading."),
    ("/database.yml",      "high",     "database.yml exposed",       "Rails database config with credentials."),

    # Admin panels
    ("/admin",             "medium",   "Admin panel found",          "Admin panel accessible — check for authentication bypass."),
    ("/admin/login",       "medium",   "Admin login page found",     "Admin login endpoint accessible."),
    ("/wp-admin/",         "medium",   "WordPress admin found",      "WordPress admin panel accessible."),
    ("/phpmyadmin/",       "high",     "phpMyAdmin exposed",         "phpMyAdmin database management accessible — high-value target."),
    ("/adminer.php",       "high",     "Adminer exposed",            "Adminer DB tool accessible."),
    ("/manager/html",      "high",     "Tomcat Manager exposed",     "Apache Tomcat manager panel — check for default credentials."),

    # Backup / logs
    ("/backup.zip",        "high",     "backup.zip found",           "Site backup archive accessible."),
    ("/backup.sql",        "critical", "SQL dump found",             "Database dump accessible — contains all data."),
    ("/dump.sql",          "critical", "SQL dump found",             "Database dump accessible."),
    ("/error.log",         "medium",   "error.log accessible",       "Application error log exposed — may reveal stack traces and paths."),
    ("/access.log",        "medium",   "access.log accessible",      "Web server access log exposed."),
    ("/.DS_Store",         "low",      ".DS_Store file found",       "Mac OS metadata file reveals directory structure."),

    # API / debug
    ("/api/v1/users",      "medium",   "API users endpoint found",   "User enumeration endpoint accessible."),
    ("/swagger-ui.html",   "medium",   "Swagger UI exposed",         "API documentation accessible — full endpoint map available to attackers."),
    ("/api-docs",          "medium",   "API docs exposed",           "API documentation endpoint accessible."),
    ("/__debug__/",        "high",     "Debug panel accessible",     "Application debug panel exposed in production."),
    ("/server-status",     "medium",   "Apache server-status found", "Apache server status page leaks server info and recent requests."),
    ("/server-info",       "medium",   "Apache server-info found",   "Apache server info page exposes loaded modules."),
]


def enumerate_sensitive_files(url: str, req_headers: dict, timeout: int) -> list:
    """Probe for sensitive files and directories."""
    findings = []
    base = url.rstrip("/")

    for path, severity, title, description in SENSITIVE_PATHS:
        try:
            test_url = base + path
            r = requests.get(test_url, headers=req_headers, timeout=timeout,
                             verify=False, allow_redirects=False)
            # Consider 200 and some 403 (exists but protected) interesting
            if r.status_code == 200:
                findings.append({
                    "module": "File Enumeration",
                    "title": title,
                    "severity": severity,
                    "description": description,
                    "recommendation": (
                        "Restrict access to this file/path via web server configuration. "
                        "Remove sensitive files from the web root entirely."
                    ),
                    "reference": "https://owasp.org/www-project-web-security-testing-guide/",
                    "evidence": f"HTTP 200 at {test_url}",
                })
            elif r.status_code == 403 and ".git" in path:
                # .git 403 still means directory exists
                findings.append({
                    "module": "File Enumeration",
                    "title": title + " (403 — directory exists)",
                    "severity": severity,
                    "description": description + " The directory exists but returns 403 — partial access may still be possible.",
                    "recommendation": "Remove the .git directory from the web root entirely.",
                    "reference": "https://owasp.org/www-project-web-security-testing-guide/",
                    "evidence": f"HTTP 403 at {test_url} (directory present)",
                })
        except Exception:
            pass

    return findings
