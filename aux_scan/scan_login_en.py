# secure_login_scanner_noapikey.py
"""
Flask scanner (no API key) that checks many ports/services and reports 'login over unencrypted channel'.
- WARNING: run only on hosts/networks you are authorized to test.
- Does NOT perform MITM or packet interception.
- Uses TLS handshake attempts + protocol probes + HTTP heuristics.
- Python libs: flask, requests
"""

from flask import Flask, request, jsonify
import socket, ssl, time, re
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests

app = Flask(__name__)

# ---------------- CONFIG ----------------
SOCKET_TIMEOUT = 4.0
THREADS = 40

# default ~50 ports (adjustable)
PORTS_50 = [
    21, 22, 23, 25, 37, 53, 67, 68, 69, 80, 81, 88, 110, 111, 119, 123, 135,
    139, 143, 161, 162, 389, 443, 445, 465, 514, 587, 636, 993, 995, 1433,
    1521, 1723, 1883, 2049, 2082, 2083, 2087, 2095, 2181, 2375, 2380, 3306,
    3389, 3690, 4000, 4443, 5432, 5900, 6379, 7001
]

# services to probe deeper
PRIORITY_SERVICES = {
    80: "http", 443: "https",
    21: "ftp", 22: "ssh",
    25: "smtp", 587: "smtp-submission", 465: "smtps",
    110: "pop3", 143: "imap",
    3306: "mysql", 5432: "postgresql",
    389: "ldap", 636: "ldaps",
    3389: "rdp", 5900: "vnc"
}

# ---------------- low-level helpers ----------------

def tcp_connect(ip, port, timeout=SOCKET_TIMEOUT):
    try:
        s = socket.create_connection((ip, port), timeout=timeout)
        s.settimeout(timeout)
        return s
    except Exception:
        return None

def try_read_banner(ip, port, timeout=SOCKET_TIMEOUT, max_bytes=2048):
    s = tcp_connect(ip, port, timeout)
    if not s:
        return None, "connect_failed"
    try:
        data = s.recv(max_bytes)
        s.close()
        return data.decode(errors='ignore') if data else "", None
    except Exception as e:
        try: s.close()
        except: pass
        return None, f"recv_error:{e}"

def attempt_tls_handshake_plain(ip, port, timeout=SOCKET_TIMEOUT):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    s = tcp_connect(ip, port, timeout)
    if not s:
        return False, "connect_failed"
    try:
        ss = ctx.wrap_socket(s, server_hostname=ip)
        cert = ss.getpeercert()
        ss.close()
        return True, {"cert": cert}
    except Exception as e:
        try: s.close()
        except: pass
        return False, f"handshake_failed:{e}"

# ---------------- protocol probes ----------------

def http_probe(ip, port):
    proto = "https" if port in (443, 8443) else "http"
    url = f"{proto}://{ip}:{port}/"
    try:
        r = requests.get(url, timeout=SOCKET_TIMEOUT, verify=False)
    except Exception as e:
        return {"reachable": False, "error": str(e)}

    snippet = r.text[:4000] if r.text else ""
    server = r.headers.get("Server")
    login = False
    if re.search(r'<input[^>]+type=["\']?password', snippet, re.I):
        login = True
    elif re.search(r'<form[^>]+>.*?(login|signin|username|password).*?</form>', snippet, re.I | re.S):
        login = True
    elif re.search(r'\b(login|sign in|username|password)\b', snippet, re.I):
        login = True
    return {"reachable": True, "server": server, "login": login, "snippet": snippet[:1000]}

def smtp_probe(ip, port):
    s = tcp_connect(ip, port)
    if not s:
        return {"reachable": False, "error": "connect_failed"}
    try:
        banner = s.recv(1024).decode(errors='ignore')
        s.send(b"EHLO scanner.local\r\n")
        ehlo = s.recv(2048).decode(errors='ignore')
        s.close()
    except Exception as e:
        try: s.close()
        except: pass
        return {"reachable": False, "error": str(e)}
    return {
        "reachable": True,
        "banner": banner.strip(),
        "ehlo": ehlo,
        "starttls": "STARTTLS" in ehlo.upper(),
        "auth": "AUTH" in ehlo.upper()
    }

def imap_probe(ip, port):
    s = tcp_connect(ip, port)
    if not s:
        return {"reachable": False, "error": "connect_failed"}
    try:
        banner = s.recv(1024).decode(errors='ignore')
        s.send(b"A001 CAPABILITY\r\n")
        cap = s.recv(2048).decode(errors='ignore')
        s.close()
    except Exception as e:
        try: s.close()
        except: pass
        return {"reachable": False, "error": str(e)}
    return {
        "reachable": True,
        "banner": banner.strip(),
        "cap": cap,
        "starttls": "STARTTLS" in cap.upper(),
        "auth": "AUTH" in cap.upper() or "LOGIN" in cap.upper()
    }

def pop3_probe(ip, port):
    s = tcp_connect(ip, port)
    if not s:
        return {"reachable": False, "error": "connect_failed"}
    try:
        banner = s.recv(1024).decode(errors='ignore')
        s.send(b"CAPA\r\n")
        resp = s.recv(2048).decode(errors='ignore')
        s.close()
    except Exception as e:
        try: s.close()
        except: pass
        return {"reachable": False, "error": str(e)}
    return {
        "reachable": True,
        "banner": banner.strip(),
        "capa": resp,
        "stls": "STLS" in resp.upper()
    }

def ftp_probe(ip, port):
    s = tcp_connect(ip, port)
    if not s:
        return {"reachable": False, "error": "connect_failed"}
    try:
        banner = s.recv(1024).decode(errors='ignore')
        s.send(b"FEAT\r\n")
        feat = s.recv(2048).decode(errors='ignore')
        s.close()
    except Exception as e:
        try: s.close()
        except: pass
        return {"reachable": False, "error": str(e)}
    return {
        "reachable": True,
        "banner": banner.strip(),
        "feat": feat,
        "auth_tls": "AUTH TLS" in feat.upper() or "TLS" in feat.upper()
    }

def ldap_probe(ip, port):
    s = tcp_connect(ip, port)
    if not s:
        return {"reachable": False, "error": "connect_failed"}
    try:
        data = s.recv(512).decode(errors='ignore')
        s.close()
    except Exception:
        data = ""
    return {"reachable": True, "banner": data.strip()}

def mysql_probe(ip, port):
    s = tcp_connect(ip, port)
    if not s:
        return {"reachable": False, "error": "connect_failed"}
    try:
        data = s.recv(512)
        s.close()
        text = data.decode(errors='ignore')
    except Exception as e:
        return {"reachable": False, "error": str(e)}
    m = re.search(r"(\d+\.\d+\.\d+)", text)
    tls_ok, tls_info = attempt_tls_handshake_plain(ip, port)
    return {
        "reachable": True,
        "banner": text.strip(),
        "version": m.group(1) if m else None,
        "tls_immediate": tls_ok
    }

def postgres_probe(ip, port):
    s = tcp_connect(ip, port)
    if not s:
        return {"reachable": False, "error": "connect_failed"}
    try:
        data = s.recv(512)
        s.close()
        text = data.decode(errors='ignore')
    except Exception as e:
        return {"reachable": False, "error": str(e)}
    m = re.search(r"(\d+\.\d+)", text)
    tls_ok, tls_info = attempt_tls_handshake_plain(ip, port)
    return {
        "reachable": True,
        "banner": text.strip(),
        "version": m.group(1) if m else None,
        "tls_immediate": tls_ok
    }

# ---------------- analysis ----------------

def analyze_port(ip, port):
    out = {
        "port": port, "reachable": False, "banner": None,
        "service_guess": PRIORITY_SERVICES.get(port),
        "encrypted": None, "login_present": False,
        "insecure_login": False, "notes": []
    }

    banner, err = try_read_banner(ip, port)
    if banner is None and err:
        out["notes"].append(err)
        return out
    out["reachable"] = True
    out["banner"] = banner

    tls_ok, tls_info = attempt_tls_handshake_plain(ip, port)
    if tls_ok:
        out["encrypted"] = True
        out["notes"].append("tls_immediate_success")

    try:
        if port in (80, 81, 8080):
            info = http_probe(ip, port)
            out["service_guess"] = "http"
            out["login_present"] = info.get("login", False)
            out["encrypted"] = False
            if out["login_present"]:
                out["insecure_login"] = True

        elif port in (443, 8443):
            info = http_probe(ip, port)
            out["service_guess"] = "https"
            out["login_present"] = info.get("login", False)
            if out["login_present"] and not out["encrypted"]:
                out["insecure_login"] = True

        elif port in (25, 587, 465):
            info = smtp_probe(ip, port)
            if info.get("reachable"):
                out["notes"].append(f"starttls:{info.get('starttls')}, auth:{info.get('auth')}")
                out["encrypted"] = info.get("starttls")
                if info.get("auth") and not info.get("starttls"):
                    out["login_present"] = True
                    out["insecure_login"] = True

        elif port == 143:
            info = imap_probe(ip, port)
            if info.get("reachable"):
                out["notes"].append(f"starttls:{info.get('starttls')}, auth:{info.get('auth')}")
                out["encrypted"] = info.get("starttls")
                if info.get("auth") and not info.get("starttls"):
                    out["insecure_login"] = True

        elif port == 110:
            info = pop3_probe(ip, port)
            if info.get("reachable"):
                out["encrypted"] = info.get("stls")
                if not info.get("stls"):
                    out["insecure_login"] = True

        elif port == 21:
            info = ftp_probe(ip, port)
            if info.get("reachable"):
                out["encrypted"] = info.get("auth_tls")
                if not info.get("auth_tls"):
                    out["insecure_login"] = True

        elif port == 22:
            out["encrypted"] = True
            out["notes"].append("ssh_encrypted_by_design")

        elif port == 3306:
            info = mysql_probe(ip, port)
            if info.get("version"):
                out["notes"].append(f"mysql_version:{info.get('version')}")
            if not info.get("tls_immediate"):
                out["insecure_login"] = True

        elif port == 5432:
            info = postgres_probe(ip, port)
            if info.get("version"):
                out["notes"].append(f"postgres_version:{info.get('version')}")
            if not info.get("tls_immediate"):
                out["insecure_login"] = True

    except Exception as e:
        out["notes"].append(f"probe_exception:{e}")

    return out

# ---------------- Flask endpoints ----------------

@app.route("/scan", methods=["POST"])
def scan_multi():
    body = request.get_json(force=True, silent=True)
    if not body:
        return jsonify({"error": "invalid_json"}), 400
    target = body.get("target")
    ports = body.get("ports") or PORTS_50
    if not target:
        return jsonify({"error": "target_required"}), 400

    start = time.time()
    results, insecure = [], []

    with ThreadPoolExecutor(max_workers=THREADS) as ex:
        futures = {ex.submit(analyze_port, target, int(p)): p for p in ports}
        for fut in as_completed(futures):
            info = fut.result()
            results.append(info)
            if info.get("insecure_login"):
                insecure.append({
                    "port": info["port"],
                    "service": info.get("service_guess"),
                    "notes": info.get("notes", []),
                    "banner": info.get("banner")
                })

    summary = {
        "target": target,
        "scanned_ports": ports,
        "insecure_logins_found": len(insecure),
        "insecure_cases": insecure,
        "duration_seconds": round(time.time() - start, 3)
    }
    return jsonify({"results": results, "summary": summary})

@app.route("/health")
def health():
    return jsonify({"status": "ok"})

if __name__ == "__main__":
    print("WARNING: This server has NO API key. Run only on authorized targets and protect access via firewall.")
    app.run(host="0.0.0.0", port=5002)
