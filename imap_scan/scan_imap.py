#!/usr/bin/env python3
from flask import Flask, request, jsonify
import imaplib
import ssl
import socket
import re
import subprocess
import time

app = Flask(__name__)

# -------------------------------
# IMAP Banner grabber (SSL or plain)
# -------------------------------
def imap_banner(ip, port=143, use_ssl=False):
    try:
        if use_ssl:
            context = ssl.create_default_context()
            with socket.create_connection((ip, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=ip) as ssock:
                    banner = ssock.recv(1024).decode(errors="ignore").strip()
        else:
            with socket.create_connection((ip, port), timeout=10) as sock:
                banner = sock.recv(1024).decode(errors="ignore").strip()
        version_match = re.search(r'(?i)(dovecot|courier|uw-imap|exchange)[^\s]*', banner)
        version = version_match.group(0) if version_match else None
        return {"status": True, "banner": banner, "version": version}
    except Exception as e:
        return {"status": False, "banner": None, "version": None, "error": str(e)}

# -------------------------------
# Test login and check user enumeration
# -------------------------------
def imap_user_enum(ip, port=143, use_ssl=False, test_users=None):
    if test_users is None:
        test_users = ["admin", "testuser", "nonexistentuser"]

    results = {"user_enumeration": False, "details": [], "plaintext_login_vulnerable": False}

    for user in test_users:
        try:
            if use_ssl:
                context = ssl.create_default_context()
                imap = imaplib.IMAP4_SSL(ip, port, ssl_context=context)
            else:
                imap = imaplib.IMAP4(ip, port)
            imap.login(user, "wrongpassword")
        except imaplib.IMAP4.error as e:
            msg = str(e)
            # إذا اليوزر موجود
            if any(k in msg.lower() for k in ["auth failed", "authentication failed", "invalid credentials"]):
                results["details"].append({"user": user, "exists": True, "message": msg})
            elif any(k in msg.lower() for k in ["no", "bad"]):
                results["details"].append({"user": user, "exists": False, "message": msg})
            else:
                results["details"].append({"user": user, "exists": None, "message": msg})
            # إذا السيرفر قبل login بدون SSL
            if not use_ssl and "auth failed" in msg.lower():
                results["plaintext_login_vulnerable"] = True
        except Exception as e:
            results["details"].append({"user": user, "exists": None, "message": str(e)})

    exists_msgs = [d for d in results["details"] if d["exists"] is True]
    non_exists_msgs = [d for d in results["details"] if d["exists"] is False]
    if exists_msgs and non_exists_msgs:
        results["user_enumeration"] = True

    return results

# -------------------------------
# Nmap IMAP brute-force check
# -------------------------------
def imap_nmap_enum(ip):
    results = {"imap-brute": False, "combined_output": ""}
    try:
        start = time.time()
        proc = subprocess.run(
            ["nmap", "-p143,993", "--script", "imap-brute", ip],
            capture_output=True, text=True, timeout=180
        )
        output = proc.stdout.lower()
        results["combined_output"] = output
        if any(k in output for k in ["login", "password", "valid", "accepted"]):
            results["imap-brute"] = True
    except subprocess.TimeoutExpired:
        results["combined_output"] += "\nTimeout occurred"
    except Exception as e:
        results["combined_output"] += f"\nError: {str(e)}"
    return results

# -------------------------------
# Flask endpoint
# -------------------------------
@app.route("/scan", methods=["POST"])
def scan_imap():
    data = request.json
    target = data.get("target")

    results = {}

    # Banner & login checks
    results["banner_ssl"] = imap_banner(target, port=993, use_ssl=True)
    results["user_enum_ssl"] = imap_user_enum(target, port=993, use_ssl=True)
    results["banner_plain"] = imap_banner(target, port=143, use_ssl=False)
    results["user_enum_plain"] = imap_user_enum(target, port=143, use_ssl=False)

    # Nmap brute-force
    results["nmap_checks"] = imap_nmap_enum(target)

    # Vulnerability flags
    results["vulnerable"] = (
        results["user_enum_ssl"]["user_enumeration"] or
        results["user_enum_plain"]["user_enumeration"] or
        results["user_enum_plain"]["plaintext_login_vulnerable"] or
        results["nmap_checks"]["imap-brute"]
    )

    return jsonify(results)

# -------------------------------
# Main
# -------------------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5005, debug=True)
