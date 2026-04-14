🛡️ WebScan Pro: Modular Vulnerability Scanner

WebScan Pro is a professional-grade, Flask-based web security tool designed to automate the detection of common vulnerabilities and misconfigurations. It maps findings directly to the OWASP Top 10 framework, providing developers and security researchers with actionable insights.
🚀 Key Features

The tool is built with a modular architecture, featuring 8 independent scan modules:

    Injection Probing: Specialized engines for detecting Reflected XSS and Error-based SQL Injection.

    SSL/TLS Audit: Checks for certificate expiry, weak ciphers, and outdated TLS versions.

    Security Headers: Analyzes HSTS, Content Security Policy (CSP), and X-Frame-Options.

    Information Gathering: Scans for exposed .env files, .git directories, and sensitive HTML comments.

    Cookie Security: Verifies HttpOnly, Secure, and SameSite flags.

    CORS Configuration: Detects wildcard origins and reflection bypasses.

🛠️ Tech Stack

    Language: Python 3.x

    Framework: Flask (REST API Backend)

    Frontend: HTML5, CSS3, Jinja2

    Libraries: Requests, SSL, Urllib3

💻 How to Run Locally

    Clone the repository:
    Bash

    git clone https://github.com/[Your-Username]/WebScan-Pro.git
    cd WebScan-Pro

    Set up a virtual environment:
    Bash

    python3 -m venv venv
    source venv/bin/activate  # On Windows use: venv\Scripts\activate

    Install dependencies:
    Bash

    pip install -r requirements.txt

    Launch the application:
    Bash

    python app.py

    Navigate to http://127.0.0.1:5000 in your browser.

⚠️ Legal Disclaimer

This tool is for educational and authorized testing purposes only. Never scan a website or IP address without explicit written permission from the owner. Use legal environments like OWASP Juice Shop or DVWA for practice.
📄 License

Distributed under the MIT License. See LICENSE for more information.
