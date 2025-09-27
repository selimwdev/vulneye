# ssl_tls_scan.py
"""
Flask SSL/TLS checker

Requirements:
Flask==2.2.5
xmltodict==0.13.0
cryptography==41.0.0

System tools:
- nmap
- openssl

Usage:
python -m venv .venv
# Windows:
.venv\Scripts\Activate.ps1
# Linux/macOS:
source .venv/bin/activate
pip install -r requirements.txt
python ssl_tls_scan.py

Endpoint:
POST /scan/ssl JSON body: {"target":"example.com","ports":[443,8443]}
GET  /health
"""

from flask import Flask, request, jsonify
import subprocess, shlex, socket, ssl, datetime, os, xmltodict

app = Flask(__name__)

NMAP_CMD = os.getenv("NMAP_CMD", "nmap")
DEFAULT_PORTS = [443]

WEAK_CIPHERS = [
    "RC4", "DES", "3DES", "MD5", "NULL", "EXP"
]
OLD_TLS = ["SSLv2","SSLv3","TLSv1","TLSv1.0","TLSv1.1"]

def run_cmd(cmd, timeout=20):
    if isinstance(cmd, str):
        cmd = shlex.split(cmd)
    try:
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=timeout)
        return p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired:
        return -2, "", "timeout"
    except Exception as e:
        return -1, "", str(e)

def check_cert(host, port, timeout=5):
    res = {"valid": False, "expired": None, "issuer": None, "subject": None, "error": None}
    try:
        context = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                res["issuer"] = dict(x[0] for x in cert.get("issuer", []))
                res["subject"] = dict(x[0] for x in cert.get("subject", []))
                not_after = cert.get("notAfter")
                if not_after:
                    expire_dt = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                    res["expired"] = expire_dt < datetime.datetime.utcnow()
                res["valid"] = True
    except Exception as e:
        res["error"] = str(e)
    return res

def nmap_ssl_enum(host, ports):
    results = {}
    for port in ports:
        rc, out, err = run_cmd([NMAP_CMD, "-p", str(port), "--script", "ssl-enum-ciphers", "-oX", "-", host], timeout=60)
        results[port] = {"nmap_success": rc==0, "details": None}
        if rc==0 and out:
            try:
                parsed = xmltodict.parse(out)
                results[port]["details"] = parsed
            except Exception as e:
                results[port]["details"] = f"parse_error:{str(e)}"
        elif rc!=0:
            results[port]["details"] = err
    return results

@app.route("/scan", methods=["POST"])
def scan_ssl():
    body = request.get_json(force=True, silent=True)
    if not body:
        return jsonify({"error":"invalid_json"}), 400
    target = body.get("target")
    ports = body.get("ports", DEFAULT_PORTS)
    if isinstance(ports, int):
        ports = [ports]
    if not target:
        return jsonify({"error":"target_required"}), 400

    results = {}
    for port in ports:
        port_info = {"cert": None, "weak_ciphers": [], "old_tls": []}
        cert_info = check_cert(target, port)
        port_info["cert"] = cert_info

        # use nmap ssl-enum-ciphers to get protocols/ciphers
        nmap_result = nmap_ssl_enum(target, [port])
        details = nmap_result.get(port, {}).get("details")
        if isinstance(details, dict):
            # parse XML for weak ciphers & old TLS
            try:
                host = details.get("nmaprun", {}).get("host", {})
                ports_block = host.get("ports", {}).get("port", [])
                if isinstance(ports_block, dict):
                    ports_block = [ports_block]
                for p in ports_block:
                    scripts = p.get("script", [])
                    if isinstance(scripts, dict):
                        scripts = [scripts]
                    for s in scripts:
                        if s.get("@id") == "ssl-enum-ciphers":
                            table = s.get("table", [])
                            if isinstance(table, dict):
                                table = [table]
                            for t in table:
                                proto = t.get("@key")
                                if proto in OLD_TLS:
                                    port_info["old_tls"].append(proto)
                                elems = t.get("table", [])
                                if isinstance(elems, dict):
                                    elems = [elems]
                                for e in elems:
                                    cipher = e.get("@key","")
                                    if any(wc.lower() in cipher.lower() for wc in WEAK_CIPHERS):
                                        port_info["weak_ciphers"].append(cipher)
            except Exception as e:
                port_info["notes"] = f"parse_error:{str(e)}"
        results[port] = port_info

    return jsonify({"target": target, "results": results})

@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status":"ok"})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5016)
