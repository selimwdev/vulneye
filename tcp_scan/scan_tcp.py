#!/usr/bin/env python3
from flask import Flask, request, jsonify
import subprocess
import re
import socket
import time
import shutil

app = Flask(__name__)

# -------------------------------
# Parse rpcinfo / nmap rpcinfo-like output
# -------------------------------
def parse_rpcinfo_output(output):
    """
    Parse rpcinfo-style output for lines like:
      100000  2,3,4        111/tcp   rpcbind
    or nmap-style lines like:
    |   100000  2,3,4        111/tcp   rpcbind
    or nmap continuation lines like:
    |_  100000  3,4          111/udp6  rpcbind

    Returns list of dicts:
      {"program": int, "versions": [...], "protocol": "tcp"/"udp", "port": int, "raw_protocol": "tcp6"}
    """
    res = []
    if not output:
        return res

    # Accept optional leading '|' or '|_' then whitespace
    pattern = re.compile(r"^\|_?\s*(\d+)\s+([\d,]+)\s+(\d+)\/(tcp6?|udp6?)\b", re.IGNORECASE)

    seen = set()  # deduplicate by (program, port, proto)
    for line in output.splitlines():
        line = line.strip()
        m = pattern.search(line)
        if not m:
            continue
        prog = int(m.group(1))
        versions = [v.strip() for v in m.group(2).split(",") if v.strip()]
        port = int(m.group(3))
        proto_raw = m.group(4).lower()  # e.g. tcp, tcp6, udp6
        proto = re.sub(r'6$', '', proto_raw)  # normalize tcp6->tcp, udp6->udp

        key = (prog, port, proto)
        if key in seen:
            continue
        seen.add(key)

        res.append({
            "program": prog,
            "versions": versions,
            "protocol": proto,
            "port": port,
            "raw_protocol": proto_raw
        })

    return res


def run_nmap_port111(ip, timeout=180):
    """Run nmap against port 111 and return stdout, rc, elapsed, err
    Uses -sSUC to allow rpcinfo-like parsing from nmap's script output (nmap 7.50+).
    """
    try:
        start = time.time()
        proc = subprocess.run(
            ["nmap", "-sSUC", "-p111", ip],
            capture_output=True, text=True, timeout=timeout
        )
        elapsed = time.time() - start
        return proc.stdout, proc.returncode, elapsed, None
    except subprocess.TimeoutExpired:
        return "", -1, None, "nmap_timeout"
    except FileNotFoundError:
        return "", -1, None, "nmap_not_found"
    except Exception as e:
        return "", -1, None, str(e)


def run_rpcinfo(ip):
    """Try to run rpcinfo -p <ip> locally if available."""
    if not shutil.which("rpcinfo"):
        return None, "rpcinfo_not_found"
    try:
        proc = subprocess.run(["rpcinfo", "-p", ip], capture_output=True, text=True, timeout=20)
        return proc.stdout, None
    except subprocess.TimeoutExpired:
        return None, "rpcinfo_timeout"
    except Exception as e:
        return None, str(e)


def check_portmapper(ip):
    port = 111
    result = {
        "port": port,
        "service": "rpcbind",
        "protocols": [],
        "open": False,
        "programs_exposed": [],
        "vulnerable": False,
        "info_disclosure": False,
        "risk": "",
        "error": None,
        "raw": {"nmap": None, "rpcinfo": None}
    }

    # 1) Try rpcinfo (best) if available
    rpc_out, rpc_err = run_rpcinfo(ip)
    if rpc_out:
        result["raw"]["rpcinfo"] = rpc_out
        parsed = parse_rpcinfo_output(rpc_out)
        if parsed:
            result["open"] = True
            for p in parsed:
                if p["protocol"].upper() not in result["protocols"]:
                    result["protocols"].append(p["protocol"].upper())
                entry = {"program": p["program"], "versions": p["versions"], "protocol": p["protocol"], "port": p["port"]}
                result["programs_exposed"].append(entry)
    else:
        # store rpcinfo error or note
        result["raw"]["rpcinfo"] = {"error": rpc_err}

    # 2) fallback to nmap scan (gives both tcp/udp presence and rpcinfo-like lines)
    nmap_out, rc, elapsed, nmap_err = run_nmap_port111(ip)
    result["raw"]["nmap"] = {"out": nmap_out, "rc": rc, "elapsed": elapsed, "err": nmap_err}
    if nmap_err:
        # if nmap timed out or failed, record and continue with whatever we have
        # but only set top-level error if nothing else succeeded
        result["error"] = nmap_err

    nmap_lower = (nmap_out or "").lower()
    if "111/tcp open" in nmap_lower or "111/udp open" in nmap_lower:
        result["open"] = True
    if "111/tcp open" in nmap_lower and "TCP" not in result["protocols"]:
        result["protocols"].append("TCP")
    if "111/udp open" in nmap_lower and "UDP" not in result["protocols"]:
        result["protocols"].append("UDP")

    # parse rpcinfo-like lines from nmap output if not already parsed or to augment
    parsed_nmap = parse_rpcinfo_output(nmap_out or "")
    for p in parsed_nmap:
        # avoid duplicates
        if not any((pe["program"] == p["program"] and pe["protocol"] == p["protocol"] and pe["port"] == p["port"]) for pe in result["programs_exposed"]):
            result["programs_exposed"].append({"program": p["program"], "versions": p["versions"], "protocol": p["protocol"], "port": p["port"]})

    # Decide vulnerability / info_disclosure
    # Policy: if port open and programs_exposed non-empty => info disclosure true
    if result["open"] and result["programs_exposed"]:
        result["info_disclosure"] = True
        result["vulnerable"] = True
        result["risk"] = "Information disclosure via open portmapper, can be used to enumerate NFS/NIS/RPC services"
    else:
        # If open but no programs parsed, still mark open and leave vulnerable=false.
        result["info_disclosure"] = False
        result["vulnerable"] = False
        result["risk"] = ""

    return result

# -------------------------------
# Flask endpoint
# -------------------------------
@app.route("/scan", methods=["POST"])
def scan_portmapper():
    data = request.json or {}
    target = data.get("target")
    if not target:
        return jsonify({"error": "target required"}), 400
    try:
        res = check_portmapper(target)
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    return jsonify(res)

# -------------------------------
# Main
# -------------------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5014, debug=True)
