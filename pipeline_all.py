# file: pipeline_flask.py
from flask import Flask, request, jsonify
import requests
import threading
from time import time

app = Flask(__name__)

SCANNERS = [
    {"name": "ARP Scanner", "port": 5001, "any_port": True},
    {"name": "Aux Scanner", "port": 5002, "any_port": True},
    {"name": "DNS Scanner", "port": 5003, "any_port": True},
    {"name": "FTP Scanner", "port": 5004, "any_port": True},
    {"name": "IMAP Scanner", "port": 5005, "any_port": True},
    {"name": "Network Discovery", "port": 5006, "any_port": True},
    {"name": "Ping Scanner", "port": 5007, "any_port": True},
    {"name": "Port Scanner", "port": 5008, "any_port": True},
    {"name": "RDP Scanner", "port": 5009, "any_port": True},
    {"name": "Service Scanner", "port": 5010, "any_port": True},
    {"name": "SMB Scanner", "port": 5011, "any_port": True},
    {"name": "SMTP Scanner", "port": 5012, "any_port": True},
    {"name": "SSH Scanner", "port": 5013, "any_port": True},
    {"name": "TCP Scanner", "port": 5014, "any_port": True},
    {"name": "Telnet Scanner", "port": 5015, "any_port": True},
    {"name": "TLS/SSL Scanner", "port": 5016, "any_port": True},
    {"name": "Web Scanner", "port": 5017, "any_port": True},
]

def call_scanner(scanner, target_ip, port=None, results_dict=None):
    """يرسل POST request لكل سكانر ويرجع النتيجة"""
    url = f"http://127.0.0.1:{scanner['port']}/scan"

    # Default payload
    if scanner["name"] == "RDP Scanner":
        payload = {"targets": [target_ip]}   # 👈 تعديل هنا
    else:
        payload = {"target": target_ip}

    if port:
        if scanner["name"] == "Web Scanner":
            # Web scanner محتاج URL كامل
            if port == 443:
                payload["target"] = f"https://{target_ip}:{port}"
            else:
                payload["target"] = f"http://{target_ip}:{port}"
        else:
            payload["port"] = port

    try:
        resp = requests.post(url, json=payload, timeout=60)
        resp.raise_for_status()
        data = resp.json()
    except Exception as e:
        data = {"error": str(e)}

    if results_dict is not None:
        results_dict[scanner["name"]] = data

def run_pipeline(target_ip, open_ports):
    results = {}
    threads = []

    for scanner in SCANNERS:
        if scanner.get("any_port", False):
            t = threading.Thread(target=call_scanner, args=(scanner, target_ip, None, results))
            t.start()
            threads.append(t)
        else:
            target_ports = scanner.get("target_ports", [])
            for p in open_ports:
                if p in target_ports:
                    t = threading.Thread(target=call_scanner, args=(scanner, target_ip, p, results))
                    t.start()
                    threads.append(t)

    for t in threads:
        t.join()

    return results

@app.route("/pipeline", methods=["POST"])
def pipeline_api():
    data = request.get_json()
    target_ip = data.get("target")
    if not target_ip:
        return jsonify({"error": "target IP is required"}), 400

    # أولاً نعمل Port Scan
    port_scan_url = "http://127.0.0.1:5008/scan"
    try:
        resp = requests.post(port_scan_url, json={"target": target_ip}, timeout=60)
        resp.raise_for_status()
        port_data = resp.json()
        open_ports = [p["port"] for p in port_data.get("open_ports", [])]
    except Exception as e:
        open_ports = []
    
    start_time = time()
    results = run_pipeline(target_ip, open_ports)
    duration = time() - start_time

    final_output = {
        "target": target_ip,
        "duration_seconds": round(duration, 3),
        "open_ports": open_ports,
        "results": results
    }

    return jsonify(final_output)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5112, debug=True)
