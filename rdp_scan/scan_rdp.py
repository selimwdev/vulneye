#!/usr/bin/env python3
"""
Flask RDP BlueKeep (CVE-2019-0708) non-destructive scanner - Final (modified)
- Produces clear JSON fields:
  - nla_enabled: true/false/null
  - tls_enabled: true/false/null
  - encrypted: same as tls_enabled (keeps naming clarity)
  - safety_status: "SAFE" / "POTENTIALLY_VULNERABLE" / "VULNERABLE" / "UNKNOWN"
  - bluekeep: true/false/null (from rdpscan if available)
  - username_enumeration_possible: true/false/null
- Uses nmap --script rdp-enum-encryption (if nmap installed) and rdpscan (if available).
- Non-exploitative checks only.

Modifications:
- Will detect rdpscan or rdpscan.exe if placed in the same folder as this script (or inside rdpscan/)
- When invoking rdpscan, will pass host:port so Windows builds that accept a single arg still work for non-default ports.
"""

import os
import re
import subprocess
import threading
import queue
import shutil
import json
import time
import socket
from flask import Flask, request, jsonify

APP_ROOT = os.path.abspath(os.path.dirname(__file__))
RDPSCAN_DIR = os.path.join(APP_ROOT, 'rdpscan')
# By default look for rdpscan or rdpscan.exe inside rdpscan/ or next to this script
RDPSCAN_BIN = os.path.join(RDPSCAN_DIR, 'rdpscan')
DEFAULT_RDP_PORT = 3389

app = Flask(__name__)

# ------------------ Utilities ------------------

def ensure_rdpscan(timeout=300):
    """Try to return path to rdpscan binary; check common locations including APP_ROOT.
    Attempt to clone & build if missing (Linux), but prefer local rdpscan.exe placed alongside this script.
    """
    # accept Windows exe too
    candidates = [
        os.path.join(APP_ROOT, 'rdpscan'),
        os.path.join(APP_ROOT, 'rdpscan.exe'),
        RDPSCAN_BIN,
        RDPSCAN_BIN + '.exe',
    ]
    for c in candidates:
        if os.path.exists(c) and os.access(c, os.X_OK):
            return c
    # try to clone & build (only if 'git' and 'make' exist)
    if shutil.which('git') and shutil.which('make'):
        if not os.path.exists(RDPSCAN_DIR):
            try:
                subprocess.check_call(['git', 'clone', 'https://github.com/robertdavidgraham/rdpscan.git', RDPSCAN_DIR], timeout=120)
            except Exception as e:
                # cloning failed; return None so scanner continues with nmap only
                return None
        try:
            subprocess.check_call(['make', '-C', RDPSCAN_DIR], timeout=timeout)
        except Exception:
            return None
        for c in candidates:
            if os.path.exists(c) and os.access(c, os.X_OK):
                return c
    # not available
    return None


def parse_target(target):
    if ':' in target and not target.startswith('['):
        parts = target.rsplit(':', 1)
        host = parts[0]
        try:
            port = int(parts[1])
        except ValueError:
            port = DEFAULT_RDP_PORT
        return host, port
    return target, DEFAULT_RDP_PORT


def check_port_open(host, port, timeout=3):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((host, port))
        try:
            s.settimeout(0.5)
            data = s.recv(4096)
        except Exception:
            data = b''
        s.close()
        return True, data.decode('latin-1', errors='ignore') if data else None
    except Exception:
        try:
            s.close()
        except Exception:
            pass
        return False, None


def run_rdpscan(binpath, host, port, timeout=30):
    """Run rdpscan if available. Windows builds often take single host arg; pass host:port when port != 3389.
    """
    if not binpath:
        return None, 'rdpscan binary missing'
    bin_exec = binpath
    # prefer explicit .exe if exists on Windows
    if os.name == 'nt' and not bin_exec.lower().endswith('.exe'):
        if os.path.exists(bin_exec + '.exe'):
            bin_exec = bin_exec + '.exe'
    if not os.path.exists(bin_exec):
        return None, 'rdpscan binary missing'
    # build argument: if port != default, pass host:port so Windows single-arg builds accept it
    host_arg = f"{host}:{port}" if port and port != DEFAULT_RDP_PORT else host
    cmd = [bin_exec, host_arg]
    try:
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout, text=True)
        return proc.returncode, proc.stdout
    except subprocess.TimeoutExpired:
        return None, 'rdpscan timed out'
    except Exception as e:
        return None, f'rdpscan execution error: {e}'


def run_nmap_rdp_enum(host, port, timeout=40):
    if shutil.which('nmap') is None:
        return None
    cmd = ['nmap', '-Pn', '-p', str(port), '--script', 'rdp-enum-encryption', host]
    try:
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout, text=True)
        return proc.stdout
    except Exception:
        return None

# ------------------ Parsers ------------------

def extract_line_with_terms(text, terms):
    if not text:
        return None
    for line in text.splitlines():
        low = line.lower()
        for t in terms:
            if t in low:
                return line.strip()
    return None


def parse_rdpscan_output(output):
    out = output or ''
    lower = out.lower()
    result = {
        'vulnerable': None,
        'evidence': None,
        'nla_required': None,
        'raw_rdpscan': out,
        'other_vulns': []
    }
    # SAFE / VULNERABLE detection
    if re.search(r'\bvulnerable\b', out, flags=re.IGNORECASE) or re.search(r'cve-?2019-0708', out, flags=re.IGNORECASE) or re.search(r'bluekeep', out, flags=re.IGNORECASE):
        result['vulnerable'] = True
        result['evidence'] = extract_line_with_terms(out, ['vulnerable', 'cve', 'bluekeep', 'remote code'])
    elif re.search(r'\bsafe\b', out, flags=re.IGNORECASE) or re.search(r'patched', out, flags=re.IGNORECASE) or re.search(r'not vulnerable', out, flags=re.IGNORECASE):
        result['vulnerable'] = False
        result['evidence'] = extract_line_with_terms(out, ['safe', 'patched', 'nla', 'credssp'])
    # NLA detection phrases
    if re.search(r'credssp\s*/?\s*nla\s*required', out, flags=re.IGNORECASE) or re.search(r'nla\s*required', out, flags=re.IGNORECASE):
        result['nla_required'] = True
    elif re.search(r'credssp\s*not\s*required', out, flags=re.IGNORECASE) or re.search(r'nla\s*not\s*required', out, flags=re.IGNORECASE):
        result['nla_required'] = False
    elif 'credssp' in lower and 'success' in lower:
        result['nla_required'] = None
    # find CVEs
    for m in re.finditer(r'(CVE-?\d{4}-\d{4,7})', out, flags=re.IGNORECASE):
        result['other_vulns'].append(m.group(1).upper())
    for keyword in ['bluekeep', 'eternalblue', 'ms17-010', 'cve-2019-0708']:
        if keyword in lower and keyword.upper() not in [x.upper() for x in result['other_vulns']]:
            result['other_vulns'].append(keyword)
    return result


def parse_nmap_rdp_output(output):
    if not output:
        return {}
    parsed = {'rdp_banner': None, 'encryption': None, 'nla_required': None, 'raw_nmap': output}
    for line in output.splitlines():
        ll = line.lower().strip()
        # capture encryption header lines
        if 'encryption' in ll and parsed['encryption'] is None:
            parsed['encryption'] = line.strip()
        # banner-like
        if parsed['rdp_banner'] is None and any(token in ll for token in ['ms rdp', 'rdp server', 'build', 'version', 'product', 'security layer']):
            parsed['rdp_banner'] = line.strip()
        # CredSSP / NLA handling: treat SUCCESS or REQUIRED as enabled
        if 'credssp' in ll or 'network level authentication' in ll or 'nla' in ll:
            if 'success' in ll or 'required' in ll:
                parsed['nla_required'] = True
            elif 'not' in ll or 'no' in ll:
                parsed['nla_required'] = False
            else:
                # leave None if ambiguous
                if parsed['nla_required'] is None:
                    parsed['nla_required'] = None
        # RDSTLS / TLS handling: treat SUCCESS as TLS enabled
        if 'rdstls' in ll or 'tls' in ll:
            if 'success' in ll:
                parsed['encryption'] = line.strip()
            elif parsed['encryption'] is None:
                parsed['encryption'] = line.strip()
    return parsed

# ------------------ Worker ------------------

def worker(q, results, binpath):
    while True:
        try:
            target = q.get_nowait()
        except queue.Empty:
            return
        host, port = parse_target(target)
        entry = {'target': target, 'timestamp': time.time(), 'port': port}

        port_open, tcp_banner = check_port_open(host, port)
        entry['port_open'] = bool(port_open)
        entry['tcp_banner'] = tcp_banner

        # rdpscan
        rdpscan_rc = None
        rdpscan_out = None
        parsed_rdpscan = {'vulnerable': None, 'evidence': None, 'nla_required': None, 'raw_rdpscan': None, 'other_vulns': []}
        if port_open and binpath:
            rdpscan_rc, rdpscan_out = run_rdpscan(binpath, host, port)
            if rdpscan_out:
                parsed_rdpscan = parse_rdpscan_output(rdpscan_out)

        # nmap
        nmap_out = run_nmap_rdp_enum(host, port)
        parsed_nmap = parse_nmap_rdp_output(nmap_out) if nmap_out else {}

        # could_be_enumerated
        could_be_enumerated = False
        if tcp_banner:
            could_be_enumerated = True
        if parsed_nmap.get('rdp_banner'):
            could_be_enumerated = True
        if parsed_rdpscan.get('raw_rdpscan'):
            if any(k in (parsed_rdpscan.get('raw_rdpscan') or '').lower() for k in ['version', 'build', 'product', 'rdp', 'encryption']):
                could_be_enumerated = True

        # encryption text from nmap
        encryption_text = parsed_nmap.get('encryption') or ''
        # derive tls_enabled
        tls_enabled = None
        if encryption_text:
            if 'success' in encryption_text.lower() or 'rdstls' in encryption_text.lower() or 'tls' in encryption_text.lower():
                tls_enabled = True
            else:
                tls_enabled = False
        else:
            tls_enabled = None

        # derive nla_required/nla_enabled: priority rdpscan -> nmap
        nla_req = parsed_rdpscan.get('nla_required') if parsed_rdpscan.get('nla_required') is not None else parsed_nmap.get('nla_required')
        nla_enabled = None
        if nla_req is True:
            nla_enabled = True
        elif nla_req is False:
            nla_enabled = False
        else:
            nla_enabled = None

        # username enumeration heuristic
        username_enum_possible = None
        if nla_enabled is False and entry['port_open']:
            username_enum_possible = True
        elif nla_enabled is True:
            username_enum_possible = False

        # bluekeep from rdpscan if present
        bluekeep = parsed_rdpscan.get('vulnerable')  # could be True/False/None

        # determine safety_status
        safety_status = 'UNKNOWN'
        # Priority:
        # 1) If rdpscan says vulnerable -> VULNERABLE
        # 2) If rdpscan says safe -> SAFE
        # 3) Else if NLA enabled or TLS enabled -> SAFE
        # 4) Else if NLA disabled and TLS disabled -> POTENTIALLY_VULNERABLE
        if bluekeep is True:
            safety_status = 'VULNERABLE (BlueKeep)'
        elif bluekeep is False:
            # if explicitly safe by rdpscan
            safety_status = 'SAFE'
        else:
            if nla_enabled is True or tls_enabled is True:
                safety_status = 'SAFE'
            elif nla_enabled is False and tls_enabled is False:
                safety_status = 'POTENTIALLY_VULNERABLE'
            else:
                safety_status = 'UNKNOWN'

        result = {
            'target': target,
            'port': port,
            'port_open': entry['port_open'],
            'could_be_enumerated': bool(could_be_enumerated),
            'rdp_banner': parsed_nmap.get('rdp_banner') or parsed_rdpscan.get('raw_rdpscan') or tcp_banner,
            'encryption': encryption_text or None,
            'tls_enabled': tls_enabled,
            'encrypted': tls_enabled,                    # alias for clarity
            'nla_required': nla_req,
            'nla_enabled': nla_enabled,
            'nla_vulnerable': None if nla_enabled is None else (not nla_enabled),
            'username_enumeration_possible': username_enum_possible,
            'bluekeep': bluekeep,
            'other_vulns': parsed_rdpscan.get('other_vulns') or [],
            'evidence': parsed_rdpscan.get('evidence'),
            'raw_rdpscan': parsed_rdpscan.get('raw_rdpscan'),
            'raw_nmap': parsed_nmap.get('raw_nmap') if parsed_nmap else nmap_out,
            'safety_status': safety_status,
        }

        results[target] = result
        q.task_done()

# ------------------ Flask endpoints ------------------

@app.route('/scan', methods=['POST'])
def scan_route():
    data = request.get_json(force=True)
    targets = data.get('targets') or data.get('hosts')
    if not targets or not isinstance(targets, list):
        return jsonify({'error': 'provide JSON with "targets": ["1.2.3.4", ...]'}), 400

    parallel = int(data.get('parallel', 4))
    # try to find rdpscan, but continue even if missing
    try:
        binpath = ensure_rdpscan()
    except Exception:
        binpath = None

    q = queue.Queue()
    for t in targets:
        q.put(t)
    results = {}
    threads = []
    for _ in range(min(parallel, max(1, len(targets)))):
        th = threading.Thread(target=worker, args=(q, results, binpath), daemon=True)
        th.start()
        threads.append(th)

    q.join()
    out = [results.get(t, {'target': t, 'error': 'no result'}) for t in targets]
    return jsonify({'scanned': len(out), 'results': out})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5009)
