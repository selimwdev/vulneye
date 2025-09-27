# dns_scan_auto_v3.py
from flask import Flask, request, jsonify
import subprocess
import socket

app = Flask(__name__)

def check_alive(ip):
    param = "-n" if subprocess.os.name == "nt" else "-c"
    try:
        subprocess.check_output(["ping", param, "1", ip], stderr=subprocess.DEVNULL)
        return True
    except subprocess.CalledProcessError:
        return False

def grab_banner(ip):
    try:
        output = subprocess.check_output(["dig", "version.bind", "CHAOS", "TXT", f"@{ip}"], stderr=subprocess.DEVNULL, text=True)
        for line in output.splitlines():
            if "version.bind" in line:
                return line.split('"')[1] if '"' in line else line
        return None
    except Exception:
        return None

def discover_dns_server(ip):
    """Try CHAOS TXT first, fallback to reverse lookup"""
    banner_ip = ip
    try:
        banner = grab_banner(ip)
        if banner:
            return ip
    except:
        pass
    # fallback reverse DNS
    try:
        domain = socket.gethostbyaddr(ip)[0]
        return ip  # still using user IP if reverse exists
    except:
        return ip

def check_dynamic_update(ip):
    """Attempt dynamic update without knowing domain exactly"""
    try:
        # Using a test subdomain
        cmd = f"echo -e 'server {ip}\nupdate add test-dns-check. 3600 A 127.0.0.1\nsend\nquit' | nsupdate -v"
        subprocess.check_output(cmd, shell=True, stderr=subprocess.DEVNULL)
        return True
    except subprocess.CalledProcessError:
        return False

def check_zone_transfer(ip):
    """Attempt zone transfer with dummy domain (best effort)"""
    try:
        cmd = ["dig", "AXFR", f"@{ip}"]
        output = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, text=True)
        if "Transfer failed" in output or "connection refused" in output.lower():
            return False
        return True
    except Exception:
        return False

@app.route("/scan", methods=["POST"])
def scan_dns():
    data = request.get_json(force=True, silent=True)
    if not data or "target" not in data:
        return jsonify({"error": "target_ip_required"}), 400

    target_ip = data["target"]
    dns_ip = discover_dns_server(target_ip)

    result = {
        "target_ip": target_ip,
        "dns_ip": dns_ip,
        "alive": check_alive(dns_ip),
        "banner": grab_banner(dns_ip),
        "dynamic_update_allowed": check_dynamic_update(dns_ip),
        "zone_transfer": check_zone_transfer(dns_ip)
    }

    return jsonify(result), 200

@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5003)
