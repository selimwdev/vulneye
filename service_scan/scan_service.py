# banner_grab_api.py
from flask import Flask, request, jsonify
import socket, time, re
from packaging import version as pkg_version
import requests

app = Flask(__name__)

PASTEBIN_URL = "https://pastebin.com/raw/ZijTbQAz"
COMMON_PORTS = [22, 21, 80, 443, 25, 110, 143, 3306, 5432]

# Regex patterns مربوطة بالـ service نفسها
SERVICE_PATTERNS = {
    "openssh": r"SSH-\d+\.\d+-OpenSSH[_-]?([\d\.p]+)?",
    "dropbear": r"SSH-\d+\.\d+-Dropbear[_-]?([\d\.p]+)?",
    "vsftpd": r"220.*vsftpd\s*([\d\.]+)",
    "proftpd": r"220.*ProFTPD\s*([\d\.]+)",
    "mysql": r"mysql[^0-9]*?(\d+\.\d+\.\d+)",
    "postgresql": r"postgres(?:ql)?[^0-9]*?(\d+\.\d+)",
    "nginx": r"nginx/([\d\.]+)",
    "apache": r"Apache/([\d\.]+)",
    "lighttpd": r"lighttpd/([\d\.]+)",
    "iis": r"Microsoft-IIS/([\d\.]+)"
}

ALL_SERVICES = list(SERVICE_PATTERNS.keys()) + [
    "comware", "caddy", "postfix", "exim", "sendmail",
    "dovecot", "courier", "cyrus", "bind9", "unbound", "powerdns",
    "mariadb", "mongodb", "redis", "memcached",
    "tomcat", "jetty", "glassfish", "wildfly", "haproxy", "squid",
    "openvpn", "wireguard", "xrdp", "vnc", "docker", "kubernetes",
    "etcd", "consul", "vault", "jenkins", "gitlab"
]

def load_latest_versions():
    try:
        r = requests.get(PASTEBIN_URL, timeout=5)
        if r.status_code == 200:
            data = r.json()
            latest_versions = {}
            for item in data:
                service_name = item.get("service", "unknown").lower()
                versions = item.get("versions", {})
                latest_versions[service_name] = versions
            return latest_versions
    except Exception as e:
        print(f"Error loading latest versions: {e}")
    return {}

LATEST_VERSIONS = load_latest_versions()

def fallback_banner(ip, port, timeout=5):
    if port in [80, 443]:
        try:
            url = f"http://{ip}:{port}" if port == 80 else f"https://{ip}:{port}"
            r = requests.get(url, timeout=timeout, verify=False)
            server = r.headers.get("Server")
            if server:
                return server
            return r.text[:200] if r.text else None
        except Exception:
            return None
    if port == 3306:
        try:
            with socket.create_connection((ip, port), timeout=timeout) as s:
                data = s.recv(100).decode(errors="ignore")
                if "mysql" in data.lower():
                    m = re.search(r"(\d+\.\d+\.\d+)", data)
                    return f"mysql {m.group(1)}" if m else "mysql"
        except Exception:
            return None
    if port == 5432:
        try:
            with socket.create_connection((ip, port), timeout=timeout) as s:
                s.send(b"\x00\x00\x00\x08\x04\xd2\x16\x2f")
                data = s.recv(100).decode(errors="ignore")
                if "postgres" in data.lower():
                    m = re.search(r"(\d+\.\d+)", data)
                    return f"postgresql {m.group(1)}" if m else "postgresql"
        except Exception:
            return None
    return None

def grab_banner(ip, port, timeout=5):
    banner = None
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.settimeout(timeout)
            try:
                banner = s.recv(1024).decode(errors='ignore').strip()
            except socket.timeout:
                banner = None
    except Exception:
        banner = None
    if not banner:
        banner = fallback_banner(ip, port, timeout)
    return {"banner": banner}

def clean_banner(banner):
    if not banner:
        return ""
    return re.sub(r'[^ -~]+', '', banner)

def parse_banner(banner, port=None):
    banner = clean_banner(banner)
    if not banner:
        return None, None

    # MySQL special handling
    if port == 3306 or "mysql" in banner.lower():
        m = re.search(r"(\d+\.\d+\.\d+)", banner)
        if m:
            return "mysql", m.group(1)
        return "mysql", None

    # PostgreSQL special handling
    if port == 5432 or "postgres" in banner.lower():
        m = re.search(r"(\d+\.\d+)", banner)
        if m:
            return "postgresql", m.group(1)
        return "postgresql", None

    # 1. Regex بتاع السيرفسات الأساسية
    for service, pattern in SERVICE_PATTERNS.items():
        m = re.search(pattern, banner, re.IGNORECASE)
        if m:
            return service, m.group(1) if m.group(1) else None

    # 2. أي سيرفس بالاسم + رقم
    for service in ALL_SERVICES:
        m = re.search(rf"({service})[^\d]*?(\d+\.\d+(?:\.\d+)?)", banner, re.IGNORECASE)
        if m:
            return service.lower(), m.group(2)

    # 3. سيرفس بالاسم فقط
    for service in ALL_SERVICES:
        if re.search(service, banner, re.IGNORECASE):
            return service.lower(), None

    # 4. fallback: رقم version فقط
    m = re.search(r"(\d+\.\d+(?:\.\d+)?)", banner)
    if m:
        return "unknown", m.group(1)

    return "unknown", None

def normalize_version(ver_str):
    if not ver_str:
        return None
    cleaned = re.sub(r'[^0-9\.]', '.', ver_str)
    cleaned = re.sub(r'\.+', '.', cleaned).strip('.')
    if not cleaned:
        return None
    parts = cleaned.split('.')
    while len(parts) < 3:
        parts.append("0")
    return ".".join(parts[:3])

def compare_versions(ver1, ver2):
    try:
        return pkg_version.parse(normalize_version(ver1)) >= pkg_version.parse(normalize_version(ver2))
    except:
        return False

def check_version(service_name, current_version):
    if not current_version:
        return {"current_version": None, "latest_version": None, "up_to_date": None, "risk": "unknown"}
    service_versions = LATEST_VERSIONS.get(service_name.lower(), {})
    latest_versions = []
    for vers_list in service_versions.values():
        if isinstance(vers_list, list):
            latest_versions.extend(vers_list)
    latest = max(latest_versions, key=lambda v: pkg_version.parse(normalize_version(v))) if latest_versions else None
    risk = "unknown"
    if current_version:
        curr_ver_parsed = pkg_version.parse(normalize_version(current_version))
        for level in ["extreme_danger", "high_risk", "medium_risk"]:
            for v in service_versions.get(level, []):
                try:
                    v_parsed = pkg_version.parse(normalize_version(v))
                    if curr_ver_parsed <= v_parsed:
                        risk = level
                        break
                except:
                    continue
            if risk != "unknown":
                break
    up_to_date = compare_versions(current_version, latest) if latest else None
    return {
        "current_version": current_version,
        "latest_version": latest,
        "up_to_date": up_to_date,
        "risk": risk
    }

@app.route("/scan", methods=["POST"])
def scan_banner():
    body = request.get_json(force=True, silent=True)
    if not body:
        return jsonify({"error": "invalid_json"}), 400
    target = body.get("target")
    ports = body.get("port")
    if not target:
        return jsonify({"error": "target_required"}), 400
    global LATEST_VERSIONS
    LATEST_VERSIONS = load_latest_versions()
    start = time.time()
    results = []
    if not ports:
        ports_to_try = COMMON_PORTS
    else:
        if isinstance(ports, int):
            ports_to_try = [ports]
        elif isinstance(ports, list):
            ports_to_try = ports
        else:
            return jsonify({"error": "invalid_port_format"}), 400
    for port in ports_to_try:
        result = grab_banner(target, port)
        banner = result.get("banner")
        service_name, version = parse_banner(banner, port)
        version_info = check_version(service_name, version)
        result.update({
            "target": target,
            "port": port,
            "duration_seconds": round(time.time() - start, 3),
            "service_name": service_name,
            "version_info": version_info
        })
        results.append(result)
    return jsonify(results), 200

@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5010)
