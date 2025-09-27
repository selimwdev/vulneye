# file: app.py
from flask import Flask, render_template_string
import subprocess
import threading
import sys
import ctypes
import os

app = Flask(__name__)

# ----------------------------
# التحقق من صلاحيات Administrator
# ----------------------------
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

if not is_admin():
    # إعادة تشغيل السكربت بصلاحيات admin (UAC يظهر مرة واحدة فقط)
    ctypes.windll.shell32.ShellExecuteW(
        None, "runas", sys.executable, " ".join(sys.argv), None, 1
    )
    sys.exit(0)

# ----------------------------
# تعريف السكانرز مع البورتات من 5001 إلى 5017
# ----------------------------
SCANNERS = [
    {"name": "ARP Scanner", "path": "arp_scan/scan_arp.py", "port": 5001},
    {"name": "Aux Scanner", "path": "aux_scan/scan_login_en.py", "port": 5002},
    {"name": "DNS Scanner", "path": "dns_scan/scan_dns.py", "port": 5003},
    {"name": "FTP Scanner", "path": "ftp_scan/scan_ftp.py", "port": 5004},
    {"name": "IMAP Scanner", "path": "imap_scan/scan_imap.py", "port": 5005},
    {"name": "Network Discovery", "path": "network_discovery_scan/scan_network.py", "port": 5006},
    {"name": "Ping Scanner", "path": "ping_scan/scan_ping.py", "port": 5007},
    {"name": "Port Scanner", "path": "port_scan/scan_port.py", "port": 5008},
    {"name": "RDP Scanner", "path": "rdp_scan/scan_rdp.py", "port": 5009},
    {"name": "Service Scanner", "path": "service_scan/scan_service.py", "port": 5010},
    {"name": "SMB Scanner", "path": "smb_scan/scan_smb.py", "port": 5011},
    {"name": "SMTP Scanner", "path": "smtp_scan/scan_smtp.py", "port": 5012},
    {"name": "SSH Scanner", "path": "ssh_scan/scan_ssh.py", "port": 5013},
    {"name": "TCP Scanner", "path": "tcp_scan/scan_tcp.py", "port": 5014},
    {"name": "Telnet Scanner", "path": "telnet_scan/scan_telnet.py", "port": 5015},
    {"name": "TLS/SSL Scanner", "path": "tls_ssl_scan/tls_ssl_scan.py", "port": 5016},
    {"name": "Web Scanner", "path": "web_scan/scan-basic.py", "port": 5017},
]

scanner_status = {s['name']: {"running": False, "servers": []} for s in SCANNERS}

# ----------------------------
# تشغيل السكانر كـ subprocess بدون أي prompts
# ----------------------------
def run_scanner(scanner):
    try:
        scanner_status[scanner["name"]]["running"] = True
        process = subprocess.Popen(
            ["python", scanner["path"], str(scanner["port"])],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            stdin=subprocess.DEVNULL,  # منع أي input
            text=True
        )
        stdout, stderr = process.communicate()
        servers = [line.strip() for line in stdout.splitlines() if line.strip()]
        scanner_status[scanner["name"]]["servers"] = servers
    except Exception as e:
        scanner_status[scanner["name"]]["servers"] = [f"Error: {e}"]
    finally:
        scanner_status[scanner["name"]]["running"] = False

def run_all_scanners():
    for s in SCANNERS:
        t = threading.Thread(target=run_scanner, args=(s,))
        t.start()

# ----------------------------
# صفحة الصحة Health Page
# ----------------------------
@app.route("/health")
def health():
    template = """
    <h1>Scanner Health Page</h1>
    <table border="1" cellpadding="5">
        <tr><th>Scanner</th><th>Status</th><th>Servers Found</th></tr>
        {% for name, info in status.items() %}
        <tr>
            <td>{{ name }}</td>
            <td>{{ 'Running' if info.get('running') else 'Idle' }}</td>
            <td>
                {% for s in info.get('servers', []) %}
                    <div>{{ s }}</div>
                {% else %}
                    <div>-</div>
                {% endfor %}
            </td>
        </tr>
        {% endfor %}
    </table>
    """
    return render_template_string(template, status=scanner_status)

# ----------------------------
# تشغيل كل السكانرز عند بداية البرنامج
# ----------------------------
run_all_scanners()

if __name__ == "__main__":
    app.run(port=5099)
