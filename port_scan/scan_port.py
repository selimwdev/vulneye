from flask import Flask, request, jsonify
import socket
import concurrent.futures
import time
import ipaddress

app = Flask(__name__)

# default config
DEFAULT_TIMEOUT = 1.0       # seconds per port connect
DEFAULT_CONCURRENCY = 200   # thread pool size
MAX_PORTS = 1500            # limit number of ports scanned to avoid abuse

def parse_ports(ports_spec):
    """
    accepts: "80,443,1-1024" or [80,443] or "80" or None -> default common ports
    returns sorted unique list of ints
    """
    if not ports_spec:
        # default list if none provided
        return [21,22,23,25,53,80,110,143,111,443,445,587,3306,3389,8080,993,995,1433,1521,5900,8443,465,1434,5432,1723,2049]
    if isinstance(ports_spec, list):
        parts = ports_spec
    else:
        parts = str(ports_spec).split(",")
    ports_set = set()
    for p in parts:
        p = str(p).strip()
        if not p:
            continue
        if "-" in p:
            try:
                a, b = p.split("-", 1)
                a = int(a); b = int(b)
                if a > b: a, b = b, a
                for i in range(max(1, a), min(65535, b) + 1):
                    ports_set.add(i)
            except ValueError:
                continue
        else:
            try:
                ports_set.add(int(p))
            except ValueError:
                continue
    ports = sorted([p for p in ports_set if 1 <= p <= 65535])
    if len(ports) > MAX_PORTS:
        raise ValueError(f"too many ports requested (max {MAX_PORTS})")
    return ports

def scan_port_once(target_ip, port, timeout):
    """
    try tcp connect to target_ip:port
    returns dict {port:int, open:bool, service:str|null, error:str|null}
    """
    try:
        with socket.create_connection((target_ip, port), timeout=timeout) as s:
            # success -> port open
            try:
                service = socket.getservbyport(port)
            except Exception:
                service = None
            return {"port": port, "open": True, "service": service}
    except socket.timeout:
        return {"port": port, "open": False, "error": "timeout"}
    except ConnectionRefusedError:
        return {"port": port, "open": False, "error": "refused"}
    except OSError as e:
        # e.g., network unreachable, no route to host, etc.
        return {"port": port, "open": False, "error": str(e)}
    except Exception as e:
        return {"port": port, "open": False, "error": str(e)}

@app.route("/scan", methods=["POST"])
def scan_port_api():
    """
    POST JSON body:
    {
      "target":"1.2.3.4" or "example.com",
      "ports": "22,80,443" OR "1-1024" OR ["22","80"],
      "timeout": 1.0,           # optional seconds
      "concurrency": 100        # optional
    }
    Response: JSON with open ports list
    """
    body = request.get_json(force=True, silent=True)
    if not body:
        return jsonify({"error": "invalid_json"}), 400

    target = body.get("target")
    if not target:
        return jsonify({"error": "target_required"}), 400

    # resolve and validate target (allow hostname or IP)
    try:
        # try interpret as IP first
        try:
            ipaddress.ip_address(target)
            target_ip = target
        except Exception:
            # resolve hostname -> IPv4 (prefer IPv4)
            target_ip = socket.gethostbyname(target)
    except Exception as e:
        return jsonify({"error": "cannot_resolve_target", "detail": str(e)}), 400

    # parse ports
    try:
        ports = parse_ports(body.get("ports"))
    except ValueError as e:
        return jsonify({"error": "bad_ports", "detail": str(e)}), 400

    timeout = float(body.get("timeout", DEFAULT_TIMEOUT))
    concurrency = int(body.get("concurrency", DEFAULT_CONCURRENCY))
    if concurrency < 1: concurrency = 1
    if concurrency > 500: concurrency = 500

    # protect: if many ports but concurrency small, it's ok; overall limit already applied
    start = time.time()
    open_ports = []
    scanned = 0

    # use ThreadPoolExecutor for IO-bound TCP connects
    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as exe:
        futures = {exe.submit(scan_port_once, target_ip, p, timeout): p for p in ports}
        for fut in concurrent.futures.as_completed(futures):
            scanned += 1
            try:
                res = fut.result()
            except Exception as e:
                res = {"port": futures[fut], "open": False, "error": str(e)}
            if res.get("open"):
                open_ports.append({"port": res["port"], "service": res.get("service")})
    duration = time.time() - start

    resp = {
        "target": target,
        "resolved_ip": target_ip,
        "scanned_ports": len(ports),
        "open_count": len(open_ports),
        "open_ports": sorted(open_ports, key=lambda x: x["port"]),
        "duration_seconds": round(duration, 3)
    }
    return jsonify(resp), 200

@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5008)
