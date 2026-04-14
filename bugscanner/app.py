"""
BugScanner Pro — AI-Powered Web Vulnerability Scanner
Scans targets, scores findings with CVSS v3, and generates
a professional pentest report using Claude AI.
"""

import os
from flask import Flask, render_template, request, jsonify
from scanner import run_full_scan
from report.generator import generate_ai_report

app = Flask(__name__)
app.secret_key = os.urandom(24)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/scan", methods=["POST"])
def scan():
    data = request.get_json()
    target = data.get("url", "").strip()
    tester = data.get("tester", "Security Researcher").strip()
    client = data.get("client", "Client Organisation").strip()

    if not target:
        return jsonify({"error": "No URL provided"}), 400
    if not target.startswith(("http://", "https://")):
        target = "https://" + target

    results = run_full_scan(target)
    if "error" in results:
        return jsonify(results), 400

    results["meta"] = {"tester": tester, "client": client}
    return jsonify(results)


@app.route("/generate-report", methods=["POST"])
def generate_report():
    data = request.get_json()
    scan_results = data.get("scan_results")
    api_key = data.get("api_key", "").strip()

    if not scan_results:
        return jsonify({"error": "No scan results provided"}), 400

    report = generate_ai_report(scan_results, api_key or None)
    return jsonify(report)


@app.route("/report")
def report_page():
    return render_template("report.html")


if __name__ == "__main__":
    print("\n" + "="*50)
    print("  BugScanner Pro")
    print("  http://127.0.0.1:5000")
    print("="*50 + "\n")
    app.run(debug=True, port=5000)
