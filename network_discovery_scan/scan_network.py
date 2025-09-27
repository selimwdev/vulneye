# network_discovery_fast_fixed.py
from flask import Flask, request, jsonify
import ipaddress
import platform
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed

app = Flask(__name__)
MAX_THREADS = 100  # adjustable for speed

def ping_host(ip):
    """Returns True if host responds to ping, else False (ping twice to reduce false negatives)"""
    param = "-n" if platform.system().lower() == "windows" else "-c"
    timeout_param = "-w" if platform.system().lower() == "windows" else "-W"
    command = ["ping", param, "1", timeout_param, "1", str(ip)]
    for _ in range(2):  # try twice
        try:
            subprocess.check_output(command, stderr=subprocess.DEVNULL)
            return True
        except subprocess.CalledProcessError:
            continue
    return False

def scan_range(start_ip, end_ip):
    alive_hosts = []
    start_int = int(ipaddress.IPv4Address(start_ip))
    end_int = int(ipaddress.IPv4Address(end_ip))

    # skip network and broadcast addresses
    if start_int & 0xFF == 0:
        start_int += 1
    if end_int & 0xFF == 255:
        end_int -= 1

    ips = [str(ipaddress.IPv4Address(ip)) for ip in range(start_int, end_int + 1)]

    with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        future_to_ip = {executor.submit(ping_host, ip): ip for ip in ips}
        for future in as_completed(future_to_ip):
            ip = future_to_ip[future]
            if future.result():
                alive_hosts.append(ip)

    return sorted(alive_hosts, key=lambda x: tuple(map(int, x.split('.'))))

def get_local_ips():
    """Get all IPs on local /24 subnet"""
    hostname = socket.gethostname()
    local_ip = socket.gethostbyname(hostname)
    net = ipaddress.IPv4Network(local_ip + '/24', strict=False)
    return scan_range(str(net.network_address + 1), str(net.broadcast_address - 1))

@app.route("/scan", methods=["POST"])
def scan_network():
    data = request.get_json(force=True, silent=True)
    if not data:
        return jsonify({"error": "invalid_json"}), 400

    target = data.get("target")
    if not target:
        return jsonify({"error": "target_required"}), 400

    try:
        if target.lower() == "local":
            alive = get_local_ips()
        elif "-" in target:
            start_ip, end_ip = target.split("-")
            alive = scan_range(start_ip.strip(), end_ip.strip())
        else:
            alive = scan_range(target.strip(), target.strip())
    except Exception as e:
        return jsonify({"error": str(e)}), 400

    return jsonify({"alive_hosts": alive, "count": len(alive)}), 200

@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5006)
