#!/usr/bin/env python3
# file: flask_telnet_check.py
from flask import Flask, request, jsonify
import socket
import subprocess
import shutil
import time

app = Flask(__name__)

DEFAULT_TIMEOUT = 5.0

def check_port_open(host, port=23, timeout=DEFAULT_TIMEOUT):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        rc = s.connect_ex((host, port))
        s.close()
        return rc == 0
    except Exception as e:
        try:
            s.close()
        except:
            pass
        return False

def grab_banner(host, port=23, timeout=DEFAULT_TIMEOUT, recv_bytes=1024):
    """محاولة استقبال بانر أولي — لا ترسل بيانات افتراضياً"""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((host, port))
        # انتظر قليلاً ثم اقرأ
        time.sleep(0.3)
        data = b""
        try:
            data = s.recv(recv_bytes)
        except socket.timeout:
            pass
        except Exception:
            pass
        s.close()
        return data.decode(errors="replace")
    except Exception as e:
        try:
            s.close()
        except:
            pass
        return ""

def run_nmap_telnet_checks(host, timeout=30):
    """ينفّذ nmap مع سكربتات telnet إن وجد. لا يحاول brute-force."""
    if not shutil.which("nmap"):
        return {"error": "nmap_not_found"}
    out = {}
    scripts = {
        "telnet-encryption": f"-p23 --script telnet-encryption {host}",
        "telnet-ntlm-info": f"-p23 --script telnet-ntlm-info {host}"
    }
    for name, args in scripts.items():
        try:
            # نحب نحتفظ بالـ stdout فقط لتضمينه كـ evidence
            proc = subprocess.run(["nmap"] + args.split(), capture_output=True, text=True, timeout=timeout)
            out[name] = {"rc": proc.returncode, "stdout": proc.stdout}
        except subprocess.TimeoutExpired:
            out[name] = {"error": "timeout"}
        except Exception as e:
            out[name] = {"error": str(e)}
    return out

def assess_vulnerability_from_nmap(nmap_results, banner_text):
    """
    Determine vulnerable/info_disclosure/severity based on nmap script outputs and banner.
    Returns dict with keys: vulnerable (bool), info_disclosure (bool), vulnerability_reasons (list), severity (str)
    """
    vuln = False
    info_disc = False
    reasons = []
    severity = "None"

    if not nmap_results:
        # no nmap data -> base decision on banner only (very weak)
        if banner_text:
            # if banner contains obvious service/version info, mark info_disclosure
            bn = banner_text.lower()
            if any(k in bn for k in ("telnet", "login", "username", "password")):
                info_disc = True
                reasons.append("Banner sent by server reveals service information.")
                severity = "Low"
        return {"vulnerable": vuln, "info_disclosure": info_disc, "vulnerability_reasons": reasons, "severity": severity}

    # Check telnet-encryption script output
    enc = nmap_results.get("telnet-encryption")
    if enc and "stdout" in enc and enc.get("rc", 0) == 0:
        out = (enc.get("stdout") or "").lower()
        if "does not support encryption" in out or "no encryption" in out or "not supported" in out:
            vuln = True
            info_disc = True
            reasons.append("Telnet server does not support encryption (cleartext protocol). Credentials may be intercepted.")
            severity = "High"

    # Check telnet-ntlm-info output for disclosure of NTLM/host info
    ntlm = nmap_results.get("telnet-ntlm-info")
    if ntlm and "stdout" in ntlm and ntlm.get("rc", 0) == 0:
        out = (ntlm.get("stdout") or "").lower()
        # detect typical disclosure indicators
        if any(k in out for k in ("ntlmssp", "netbios name", "dns name", "domain name", "workstation")):
            info_disc = True
            reasons.append("telnet-ntlm-info returned NTLM/host information (NetBIOS/DNS/OS build details).")
            # if not already high from encryption, set low severity for info disclosure
            if not vuln and severity != "High":
                severity = "Low"

    # If banner clearly shows credentials prompt but encryption unknown, mark at least Low
    if banner_text and not vuln:
        bn = banner_text.lower()
        if any(k in bn for k in ("login:", "username:", "password:", "welcome")):
            # presence of login prompt indicates interactive login - mark info disclosure
            info_disc = True
            reasons.append("Service provides interactive login prompt (may accept credentials over cleartext).")
            if severity == "None":
                severity = "Low"

    # Default severity when vuln true but not set
    if vuln and severity == "None":
        severity = "High"

    return {"vulnerable": vuln, "info_disclosure": info_disc, "vulnerability_reasons": reasons, "severity": severity}

@app.route("/scan", methods=["POST"])
def scan_telnet():
    """
    JSON body:
    {
      "target": "1.2.3.4",
      "banner": true,               # default true
      "nmap_checks": false          # default false (requires nmap installed)
    }
    """
    data = request.json or {}
    target = data.get("target")
    if not target:
        return jsonify({"error": "target required"}), 400

    want_banner = data.get("banner", True)
    want_nmap = data.get("nmap_checks", False)

    result = {
        "target": target,
        "port": 23,
        "reachable": False,
        "banner": None,
        "nmap": None,
        "error": None,
        # new fields
        "vulnerable": False,
        "info_disclosure": False,
        "vulnerability_reasons": [],
        "severity": "None"
    }

    try:
        is_open = check_port_open(target, 23)
        result["reachable"] = is_open

        banner_text = ""
        if is_open and want_banner:
            banner_text = grab_banner(target, 23)
            result["banner"] = banner_text

        nmap_results = None
        if want_nmap:
            nmap_results = run_nmap_telnet_checks(target)
            result["nmap"] = nmap_results

        # Assess vulnerability based on gathered data
        assessment = assess_vulnerability_from_nmap(nmap_results, banner_text)
        result["vulnerable"] = assessment["vulnerable"]
        result["info_disclosure"] = assessment["info_disclosure"]
        result["vulnerability_reasons"] = assessment["vulnerability_reasons"]
        result["severity"] = assessment["severity"]

    except Exception as e:
        result["error"] = str(e)

    return jsonify(result)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5015, debug=True)
