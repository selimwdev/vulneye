#!/usr/bin/env python3
from flask import Flask, request, jsonify
import requests
from urllib.parse import urljoin
import re
import warnings
import random
import string

warnings.filterwarnings("ignore")
app = Flask(__name__)

# -------------------------------
# 1️⃣ Apache / Tomcat outdated / RCE
# -------------------------------
apache_versions_to_check = ["2.4.63", "2.4.62"]
tomcat_versions_to_check = ["9.0.73", "9.0.72"]

def scan_apache_tomcat(target):
    result = {"apache_outdated": None, "apache_rce": None,
              "tomcat_outdated": None, "tomcat_rce": None}
    try:
        r = requests.get(target, timeout=7, verify=False)
        server = r.headers.get("Server", "")
        if "Apache" in server:
            result["apache_outdated"] = server if server in apache_versions_to_check else None
        if "Tomcat" in server:
            result["tomcat_outdated"] = server if server in tomcat_versions_to_check else None
    except:
        pass
    return result

def scan_fingerprint(target):
    """
    Detect fingerprint disclosure from HTTP headers.
    Returns server type, X-Powered-By, and any header that leaks version info.
    """
    fingerprint = {}
    try:
        r = requests.get(target, timeout=7, verify=False)
        for header in ["Server", "X-Powered-By", "X-AspNet-Version", "X-Runtime"]:
            if header in r.headers:
                fingerprint[header] = r.headers[header]
        # Also check if 'Server' header exposes version
        server = r.headers.get("Server", "")
        if server:
            if any(s in server.lower() for s in ["apache", "nginx", "tomcat", "iis"]):
                fingerprint["server_detected"] = server
    except:
        pass
    return fingerprint


# -------------------------------
# 2️⃣ Login endpoints (frameworks)
# -------------------------------
login_endpoints = [
    "/login", "/grafana/login", "/graph/login", "/accounts/login/", "/wp-login.php",
    "/admin", "/manager/html", "/phpmyadmin", "/console"
]

def scan_login_pages(target):
    found = []
    for path in login_endpoints:
        url = urljoin(target, path)
        try:
            r = requests.get(url, timeout=5, verify=False)
            if r.status_code == 200:
                found.append(url)
        except:
            continue
    return found

# -------------------------------
# 3️⃣ phpMyAdmin and admin endpoints
# -------------------------------
admin_endpoints = [
    "/phpmyadmin", "/admin", "/manager/html", "/wp-admin", "/console",
    "/grafana", "/prometheus", "/splunk", "/jenkins", "/rundeck", "/sonarqube"
]

outdated_versions = {
    "grafana": ["10.2.2", "10.2.3", "10.1.5"],
    "phpmyadmin": ["5.2.0", "5.1.1", "5.0.2"],
    "goanywhere": ["6.8.0", "6.7.0"],
    "jenkins": ["2.401", "2.400", "2.399"],
    "splunk": ["10.3.0", "10.2.5"],
    "prometheus": ["2.50.0", "2.49.0"],
    "rundeck": ["4.15.0", "4.14.0"],
    "sonarqube": ["10.2", "10.1"],
    "elasticsearch": ["8.11.0", "8.10.2"],
    "kibana": ["8.11.0", "8.10.2"]
}

def detect_service_version(url, service_name):
    version = None
    outdated = False
    try:
        r = requests.get(url, timeout=7, verify=False)
        server_header = r.headers.get("Server", "") or r.headers.get("X-Powered-By", "")
        if server_header:
            match = re.search(r"(\d+\.\d+(\.\d+)?)", server_header)
            if match:
                version = match.group(1)
        if not version:
            match = re.search(rf"{service_name}[: ]?(\d+\.\d+(\.\d+)?)", r.text, re.IGNORECASE)
            if match:
                version = match.group(1)
        if version and service_name.lower() in outdated_versions:
            if version in outdated_versions[service_name.lower()]:
                outdated = True
    except:
        pass
    return {"version": version, "outdated": outdated}

def scan_admin_endpoints(target):
    found = []
    versions = {}
    for path in admin_endpoints:
        url = urljoin(target, path)
        try:
            r = requests.get(url, timeout=5, verify=False)
            if r.status_code == 200:
                found.append(url)
                service_name = path.strip("/").lower()
                if service_name in outdated_versions:
                    versions[service_name] = detect_service_version(url, service_name)
        except:
            continue
    phpmyadmin_version = versions.get("phpmyadmin")
    return found, phpmyadmin_version, versions

# -------------------------------
# 4️⃣ Sensitive files
# -------------------------------
sensitive_files = [
    ".env", ".git/config", "config.php", "wp-config.php", "settings.py",
    "application.properties", "application.yml", "backup.zip", "db.sql",
    "*.bak", "*.old", "deploy.sh", "setup.sh", "install.php", "update.php",
    "id_rsa", "id_rsa.pub", "keys.pem", ".htpasswd", "error.log", "access.log"
]

def scan_sensitive_files(target):
    found = []
    for path in sensitive_files:
        url = urljoin(target, path)
        try:
            r = requests.get(url, timeout=5, verify=False)
            if r.status_code == 200:
                found.append(url)
        except:
            continue
    return found

# -------------------------------
# 5️⃣ Directory listing
# -------------------------------
def scan_directory_listing(target):
    listings = []
    try:
        r = requests.get(target, timeout=5, verify=False)
        if "Index of /" in r.text:
            listings.append(target)
    except:
        pass
    return listings

# -------------------------------
# 6️⃣ Services endpoints
# -------------------------------
services_endpoints = [
    "/webclient", "/webtransfer", "/moveit", "/secureft", "/guacamole",
    "/thinfinity", "/nagiosxi", "/zabbix", "/grafana", "/prometheus",
    "/icingaweb2", "/netbox", "/netcrunch", "/pfg", "/Orion", "/boomi",
    "/talend", "/tibco", "/mulesoft", "/sap", "/app/kibana", "/splunk",
    "/graph", "/elasticsearch", "/kibana", "/jenkins", "/rundeck", "/sonarqube"
]

def scan_services(target):
    found = []
    versions = {}
    for path in services_endpoints:
        url = urljoin(target, path)
        try:
            r = requests.get(url, timeout=5, verify=False)
            if r.status_code == 200:
                found.append(url)
                service_name = path.strip("/").lower()
                if service_name in outdated_versions:
                    versions[service_name] = detect_service_version(url, service_name)
        except:
            continue
    return found, versions

# -------------------------------
# 7️⃣ Internal / sensitive endpoints
# -------------------------------
internal_endpoints = [
    "/api/keys", "/admin/api", "/internal/", "/debug", "/status", "/health",
    "/config", "/_config", "/setup", "/system", "/internal/settings"
]

def scan_internal(target):
    found = []
    for path in internal_endpoints:
        url = urljoin(target, path)
        try:
            r = requests.get(url, timeout=5, verify=False)
            if r.status_code == 200:
                found.append(url)
        except:
            continue
    return found

# -------------------------------
# 8️⃣ Debug mode detection (frameworks) - KEEP EVERYTHING
# -------------------------------
debug_patterns = {
    "django": [
        "<title>Technical Error", "django.middleware.debug",
        "Using the URLconf defined in", "You're seeing this error because you have DEBUG = True",
        "Exception Type:", "Exception Value:", "Request Method:", "Traceback", "settings.py",
        "Debug mode is active", "WSGIRequest"
    ],
    "laravel": [
        "<title>Whoops!", "laravel_session", "/_ignition", "/_debugbar",
        "exception_message", "laravel.log", "Whoops! Something went wrong."
    ],
    "flask": [
        "The debugger is active!", "werkzeug debugger", "flask.app",
        "Traceback (most recent call last)", "Request Method:", "URL:"
    ],
    "symfony": [
        "Symfony Exception", "Debug Toolbar", "Exception thrown", "Stack trace",
        "Controller:", "Request:", "Response:"
    ],
    "rails": [
        "Rails Error", "stack level too deep", "Application Trace", "Framework Trace",
        "Full Trace", "Rails.root", "Parameters:"
    ]
}

debug_endpoints = [
    "/_profiler", "/_debugbar", "/debug", "/_status", "/_ignition", "/_ignition/execute-solution",
    "/_profiler/db", "/_profiler/info", "/_profiler/logs", "/_profiler/config",
    "/_dev", "/_devbar", "/_devtools", "/__debug__/", "/__debug__/toolbar", "/__debug__/dump",
    "/api/debug", "/api/test", "/debugbar", "/phpinfo.php", "/info", "/_errors",
    "/_trace", "/_log", "/logs", "/system/info", "/system/debug", "/admin/debug",
    "/debug/console", "/debug/dashboard", "/debug/status", "/dev.php", "/test.php",
    "/debug.php", "/info.php", "/debug.log", "/_profiler/status", "/_profiler/request",
    "/_profiler/performance", "/_profiler/exceptions", "/_profiler/session", "/_profiler/templates",
    "/__profiler__/", "/__profiler__/status", "/__profiler__/logs", "/__profiler__/config",
    "/_rails/info", "/_rails/debug", "/_rails/logs", "/_rails/performance", "/api/rails/debug",
    "/debug-api", "/status/debug", "/internal/debug", "/_monitor/debug", "/_monitor/logs",
    "/_graph/debug", "/_graph/status", "/_graph/logs"
]

def scan_debug_mode(target):
    found_debug = []
    for path in debug_endpoints:
        url = urljoin(target, path)
        try:
            r = requests.get(url, timeout=5, verify=False)
            if r.status_code == 200:
                found_debug.append(f"Debug endpoint accessible: {url}")
        except:
            continue
    try:
        r = requests.get(target, timeout=7, verify=False)
        content_lower = r.text.lower()
        for fw, patterns in debug_patterns.items():
            for pat in patterns:
                if pat.lower() in content_lower:
                    found_debug.append(f"{fw} debug mode detected via page content")
    except:
        pass
    return found_debug

# -------------------------------
# Flask route
# -------------------------------
@app.route("/scan", methods=["POST"])
def scan():
    data = request.get_json()
    target = data.get("target")
    if not target:
        return jsonify({"error": "No target provided"}), 400

    results = {}
    results.update(scan_apache_tomcat(target))
    results["login_pages"] = scan_login_pages(target)
    results["admin_endpoints"], results["phpmyadmin_version"], results["admin_versions"] = scan_admin_endpoints(target)
    results["sensitive_files"] = scan_sensitive_files(target)
    results["directory_listing"] = scan_directory_listing(target)
    results["services_endpoints"], results["services_versions"] = scan_services(target)
    results["internal_endpoints"] = scan_internal(target)
    results["debug_mode"] = scan_debug_mode(target)
    results["fingerprint_disclosure"] = scan_fingerprint(target)

    return jsonify(results)

# -------------------------------
# Run Flask
# -------------------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5017)
