#!/usr/bin/env python3
from flask import Flask, request, jsonify
import socket
import subprocess
import re
import time

app = Flask(__name__)

# -------------------------------
# Banner grabber with version detection
# -------------------------------
def ftp_banner(ip, port=21):
    try:
        sock = socket.create_connection((ip, port), timeout=5)
        banner = sock.recv(1024).decode(errors="ignore").strip()
        sock.close()
        version_match = re.search(r"(\w+FTP).*?([\d\.]+)?", banner, re.IGNORECASE)
        version = version_match.group(0) if version_match else None
        vulnerable_versions = ["ProFTPD", "vsftpd", "Pure-FTPd"]
        user_enum_possible = any(v.lower() in banner.lower() for v in vulnerable_versions)
        return {
            "banner": banner,
            "version": version,
            "user_enum_possible": user_enum_possible
        }
    except Exception:
        return {"banner": None, "version": None, "user_enum_possible": False}

# -------------------------------
# Anonymous login check
# -------------------------------
def ftp_anonymous(ip, port=21):
    try:
        import ftplib
        ftp = ftplib.FTP()
        ftp.connect(ip, port, timeout=5)
        ftp.login(user='anonymous', passwd='anonymous')
        ftp.quit()
        return True
    except Exception:
        return False

# -------------------------------
# User enumeration detection via Nmap
# -------------------------------
def ftp_user_enum_nmap(ip):
    scripts = [
        "ftp-anon",
        "ftp-feat",
        "ftp-vsftpd-backdoor",
        "ftp-proftpd-backdoor",
        "ftp-bounce"
    ]
    results = {
        "ftp-anon": False,
        "ftp-feat": False,
        "vsftpd-backdoor": False,
        "proftpd-backdoor": False,
        "ftp-bounce": False,
        "ftp-user-enum": False,  # ← جديد
        "combined_output": ""
    }

    try:
        for script in scripts:
            start = time.time()
            proc = subprocess.run(
                ["nmap", "-p21", "--script", script, "-sV", "--max-retries", "2", "--host-timeout", "30s", ip],
                capture_output=True, text=True, timeout=120
            )
            elapsed = time.time() - start
            output = proc.stdout.lower()
            results["combined_output"] += f"\n----{script}----\n" + output

            # تعيين True/False لكل سكربت بناءً على المحتوى
            if script == "ftp-anon":
                results["ftp-anon"] = "anonymous login allowed" in output
            elif script == "ftp-feat":
                results["ftp-feat"] = any(k in output for k in ["features", "supported"])
            elif script == "ftp-vsftpd-backdoor":
                results["vsftpd-backdoor"] = "vsftpd" in output and "backdoor" in output
            elif script == "ftp-proftpd-backdoor":
                results["proftpd-backdoor"] = "proftpd" in output and "backdoor" in output
            elif script == "ftp-bounce":
                results["ftp-bounce"] = "bounce" in output

            # تحديد ftp-user-enum إذا أي سكربت فيه hints عن login/users
            if any(k in output for k in ["login", "user", "ftp-anon", "password required"]):
                results["ftp-user-enum"] = True

            # Timing heuristic: سريع جدًا → False
            if elapsed < 1:
                results[script] = False

        return results
    except subprocess.TimeoutExpired:
        return {"error": "Nmap script timed out after 120 seconds"}
    except Exception as e:
        return {"error": str(e)}

# -------------------------------
# Flask endpoint
# -------------------------------
@app.route("/scan", methods=["POST"])
def scan_ftp():
    data = request.json
    target = data.get("target")
    results = {}

    banner_info = ftp_banner(target)
    results.update(banner_info)

    results["anonymous_login"] = ftp_anonymous(target)
    results["nmap_checks"] = ftp_user_enum_nmap(target)

    return jsonify(results)

# -------------------------------
# Main
# -------------------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5004, debug=True)
