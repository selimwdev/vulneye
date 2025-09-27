#!/usr/bin/env python3
from flask import Flask, request, jsonify
import smtplib
import ssl
import dns.resolver

app = Flask(__name__)

def try_smtp_methods(ip, port):
    errors = []
    # 1. Plain
    try:
        server = smtplib.SMTP(ip, port, timeout=5)
        server.ehlo()
        return "plain", server
    except Exception as e:
        errors.append(f"Plain: {e}")
    # 2. STARTTLS
    try:
        server = smtplib.SMTP(ip, port, timeout=5)
        server.ehlo()
        server.starttls(context=ssl.create_default_context())
        server.ehlo()
        return "starttls", server
    except Exception as e:
        errors.append(f"STARTTLS: {e}")
    # 3. SSL
    try:
        context = ssl.create_default_context()
        server = smtplib.SMTP_SSL(ip, port, timeout=5, context=context)
        return "ssl", server
    except Exception as e:
        errors.append(f"SSL: {e}")
    return "error", ", ".join(errors)

def get_banner(ip, port):
    method, server = try_smtp_methods(ip, port)
    if method == "error":
        return None  # تجاهل البورت المغلق
    try:
        code, resp = server.docmd("NOOP")
        server.quit()
        return {"status": True, "info": resp.decode(errors="ignore").strip()}
    except Exception as e:
        return {"status": False, "info": str(e)}

def check_relay(ip, port):
    method, server = try_smtp_methods(ip, port)
    if method == "error":
        return None
    try:
        code1, resp1 = server.mail("test@example.com")
        code2, resp2 = server.rcpt("test@anotherexample.com")
        server.quit()
        status = code2 == 250
        return {"status": status, "info": "Open relay" if status else "Not an open relay"}
    except Exception as e:
        return {"status": False, "info": str(e)}

def enum_users(ip, port, users):
    method, server = try_smtp_methods(ip, port)
    if method == "error":
        return None
    found = []
    try:
        for u in users:
            code, _ = server.docmd("VRFY", u)
            if code == 250:
                found.append(u)
        server.quit()
        return {"status": bool(found), "found": found, "info": "Users verified"}
    except Exception as e:
        return {"status": False, "found": [], "info": str(e)}

def mx_lookup(domain):
    try:
        answers = dns.resolver.resolve(domain, "MX")
        return [str(r.exchange) for r in answers]
    except Exception as e:
        return f"Error: {e}"

@app.route("/scan", methods=["POST"])
def scan_smtp():
    data = request.json
    target = data.get("target")
    domain = data.get("domain")
    users = data.get("users", ["admin","test","root","user"])

    ports = [25, 465, 587]
    results = {}

    for p in ports:
        banner = get_banner(target, p)
        relay = check_relay(target, p)
        enum = enum_users(target, p, users)

        # إذا كلهم None، تجاهل البورت
        if any([banner, relay, enum]):
            results[p] = {}
            if banner: results[p]["banner"] = banner
            if relay: results[p]["open_relay"] = relay
            if enum: results[p]["user_enum"] = enum

    if domain:
        results["mx_records"] = mx_lookup(domain)

    return jsonify(results)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5012, debug=True)
