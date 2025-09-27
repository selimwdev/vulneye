# icmp_scan_api.py
from flask import Flask, request, jsonify
from concurrent.futures import ThreadPoolExecutor, as_completed
import ipaddress
from scapy.all import ICMP, IP, sr1, conf
import socket

app = Flask(__name__)
MAX_THREADS = 50  # adjustable for speed

conf.verb = 0  # Disable Scapy verbose output

def scan_icmp(ip):
    """Send ICMP echo request and ICMP timestamp request to detect alive and timestamp disclosure"""
    result = {
        "alive": False,
        "timestamp_disclosure": False,
        "icmp_redirect": False,
        "echo_reply": False,
        "unreachable": False
    }

    try:
        # 1. Echo request
        echo_pkt = IP(dst=ip)/ICMP(type=8)
        echo_resp = sr1(echo_pkt, timeout=1)
        if echo_resp:
            result["alive"] = True
            if echo_resp.haslayer(ICMP):
                icmp_type = echo_resp.getlayer(ICMP).type
                icmp_code = echo_resp.getlayer(ICMP).code
                if icmp_type == 0:
                    result["echo_reply"] = True
                if icmp_type == 3:
                    result["unreachable"] = True
                if icmp_type == 5:
                    result["icmp_redirect"] = True

        # 2. Timestamp request
        ts_pkt = IP(dst=ip)/ICMP(type=13)
        ts_resp = sr1(ts_pkt, timeout=1)
        if ts_resp:
            if ts_resp.haslayer(ICMP):
                if ts_resp.getlayer(ICMP).type == 14:
                    result["timestamp_disclosure"] = True

    except Exception:
        pass

    return ip, result

def scan_range(start_ip, end_ip):
    alive_hosts = {}
    ips = [str(ipaddress.IPv4Address(ip)) for ip in range(int(ipaddress.IPv4Address(start_ip)), int(ipaddress.IPv4Address(end_ip))+1)]
    with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        future_to_ip = {executor.submit(scan_icmp, ip): ip for ip in ips}
        for future in as_completed(future_to_ip):
            ip, data = future.result()
            alive_hosts[ip] = data
    return alive_hosts

@app.route("/scan", methods=["POST"])
def scan_icmp_route():
    data = request.get_json(force=True, silent=True)
    if not data:
        return jsonify({"error": "invalid_json"}), 400

    target = data.get("target")
    if not target:
        return jsonify({"error": "target_required"}), 400

    try:
        if "-" in target:
            start_ip, end_ip = target.split("-")
            result = scan_range(start_ip.strip(), end_ip.strip())
        else:
            result = scan_range(target.strip(), target.strip())
    except Exception as e:
        return jsonify({"error": str(e)}), 400

    return jsonify(result), 200

@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5007)
