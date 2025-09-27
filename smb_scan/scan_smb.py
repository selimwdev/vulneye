# scan_smb_fixed.py
"""
Flask SMB scanner / enumerator (safe, non-exploitative checks)

This version adds explicit MS17-010 (EternalBlue) checks via nmap scripts (if nmap is available),
and returns a clearer JSON summary: eternalblue status, null-session result, enumeration_possible, etc.

Security: this script only runs non-exploitative checks (nmap NSE scripts, smbclient, impacket null-session attempts).
Do not run against systems you don't have authorization to test.
"""
from flask import Flask, request, jsonify
import socket, time, subprocess, shlex, os, ipaddress, platform, sys, shutil
from contextlib import suppress

app = Flask(__name__)

# Configuration (can be overridden via env)
NMAP_CMD = os.getenv("NMAP_CMD", "nmap")
SMBCLIENT_CMD = os.getenv("SMBCLIENT_CMD", "smbclient")
RPCCLIENT_CMD = os.getenv("RPCCLIENT_CMD", "rpcclient")
SMBMAP_CMD = os.getenv("SMBMAP_CMD", "smbmap")
DEFAULT_PORTS = [139, 445]
CONNECT_TIMEOUT = 3
NMAP_TIMEOUT = 30

# Flags
ALLOW_PRIVATE = os.getenv("ALLOW_PRIVATE", "true").lower() in ("1", "true", "yes")
NO_AUTO_INSTALL = os.getenv("NO_AUTO_INSTALL", "0").lower() in ("1", "true", "yes")
AUTO_INSTALL = os.getenv("AUTO_INSTALL", "0").lower() in ("1", "true", "yes")

WINDOWS_MODE = platform.system().lower().startswith("win")

# Try to import impacket SMBConnection if present (used as Windows fallback)
if WINDOWS_MODE:
    with suppress(ImportError):
        from impacket.smbconnection import SMBConnection

def run_cmd(cmd, timeout=20, check=False):
    """Run command (list or str). Return (rc, stdout, stderr)."""
    if isinstance(cmd, str):
        cmd_list = shlex.split(cmd)
    else:
        cmd_list = cmd
    try:
        p = subprocess.run(cmd_list, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=timeout)
        if check and p.returncode != 0:
            raise subprocess.CalledProcessError(p.returncode, cmd_list, output=p.stdout, stderr=p.stderr)
        return p.returncode, p.stdout or "", p.stderr or ""
    except subprocess.TimeoutExpired:
        return -2, "", "timeout"
    except FileNotFoundError as e:
        return -1, "", f"not_found:{e}"
    except subprocess.CalledProcessError as e:
        return e.returncode, e.output or "", e.stderr or ""
    except Exception as e:
        return -1, "", str(e)

def check_cmd_exists(cmd):
    return shutil.which(cmd) is not None

def tcp_connect(ip, port, timeout=CONNECT_TIMEOUT):
    try:
        with socket.create_connection((ip, int(port)), timeout=timeout) as s:
            s.settimeout(0.5)
            try:
                data = s.recv(1024)
                banner = data.decode(errors='ignore').strip() if data else None
            except Exception:
                banner = None
            return True, banner
    except Exception:
        return False, None

# ------------------ SMB LOGIC ------------------

def parse_smbclient_shares(output):
    """Parse smbclient -L output into share names."""
    shares = []
    lines = [l.rstrip() for l in (output or "").splitlines() if l.strip()]
    if not lines:
        return []
    header_idx = None
    dash_idx = None
    for i, l in enumerate(lines[:120]):
        if 'Sharename' in l or 'Share name' in l or 'Sharename'.lower() in l.lower():
            header_idx = i
        if set(l.strip()) <= set('- ') and len(l.strip()) >= 3:
            dash_idx = i
            break
    start = None
    if dash_idx is not None:
        start = dash_idx + 1
    elif header_idx is not None:
        start = header_idx + 1
    else:
        for i, l in enumerate(lines[:80]):
            if len(l.split()) >= 2 and any(w.lower() in l.lower() for w in ('disk', 'ipc', 'printer')):
                start = i
                break
    if start is not None:
        for l in lines[start: start + 500]:
            if not l.strip():
                break
            parts = l.split()
            if not parts:
                continue
            name = parts[0].strip()
            if name and not set(name) <= set('-') and name.lower() not in ('sharename', 'share', 'server', 'comment'):
                shares.append(name)
    else:
        for l in lines:
            for token in l.split():
                if token.endswith('$') or token.isupper():
                    if token not in shares and len(token) <= 64:
                        shares.append(token)
    unique = []
    for s in shares:
        if s not in unique:
            unique.append(s)
    return unique

def check_null_session_smbclient(ip, port=445):
    """Use smbclient (if available)."""
    cmd = [SMBCLIENT_CMD, '-L', f'//{ip}', '-p', str(port), '-N']
    rc, out, err = run_cmd(cmd, timeout=20)
    if rc == -1 and ('not_found' in (err or '').lower()):
        return {'available': False, 'error': 'smbclient_not_found', 'raw': err}
    combined = (out or '') + "\n" + (err or '')
    shares = parse_smbclient_shares(out or "")
    null_session = bool(shares)
    return {'available': True, 'null_session': null_session, 'shares': shares, 'raw': combined}

def check_null_session_windows(ip, port=445):
    """Fallback using impacket on Windows if smbclient is missing."""
    if "SMBConnection" not in globals():
        return {'available': False, 'error': 'impacket_not_installed'}
    try:
        smb = SMBConnection(ip, ip, sess_port=port, timeout=3)
        smb.login("", "")  # null session
        shares = []
        try:
            for s in smb.listShares():
                # safe extraction
                name = None
                if isinstance(s, dict):
                    name = s.get('shi1_netname')
                else:
                    try:
                        name = s[0]
                    except Exception:
                        name = None
                if name:
                    if isinstance(name, bytes):
                        name = name.decode(errors='ignore')
                    name = name.rstrip('\x00')
                    shares.append(name)
        except Exception:
            pass
        return {'available': True, 'null_session': bool(shares), 'shares': shares}
    except Exception as e:
        return {'available': True, 'null_session': False, 'error': str(e)}

def run_nmap_smb_scripts(ip, ports):
    """Run a set of smb-related nmap scripts (os/protocols/vuln*)."""
    findings = {'raw': None, 'vulns': [], 'smb_version': None, 'os': None}
    ports_str = ",".join(str(p) for p in ports)
    scripts = 'smb-os-discovery,smb-protocols,smb-vuln*'
    cmd = [NMAP_CMD, '-Pn', '-p', ports_str, '--script', scripts, ip, '-oN', '-']
    rc, out, err = run_cmd(cmd, timeout=NMAP_TIMEOUT)
    if rc == -1 and ('not_found' in (err or '').lower()):
        return {'raw': '', 'vulns': [], 'smb_version': None, 'os': None, 'error': 'nmap_not_found'}
    combined = (out or '') + "\n" + (err or '')
    findings['raw'] = combined
    for line in combined.splitlines():
        l = line.strip(); low = l.lower()
        if 'os:' in low and findings['os'] is None:
            findings['os'] = l
        if 'samba' in low or 'smb' in low:
            if findings['smb_version'] is None:
                findings['smb_version'] = l
        if 'vuln' in low or 'cve' in low or 'vulnerable' in low:
            findings['vulns'].append(l)
    findings['vulns'] = list(dict.fromkeys(findings['vulns']))
    return findings

def run_nmap_check_ms17(ip, port=445):
    """
    Run nmap script smb-vuln-ms17-010 against ip:port.
    Return dict {status: 'vulnerable'|'not_vulnerable'|'not_tested'|'error', raw, detail}
    """
    # If nmap not present, return not_tested
    if not check_cmd_exists(NMAP_CMD):
        return {'status': 'not_tested', 'error': 'nmap_not_found', 'raw': None}
    cmd = [NMAP_CMD, '-Pn', '-p', str(port), '--script', 'smb-vuln-ms17-010', ip, '-oN', '-']
    rc, out, err = run_cmd(cmd, timeout=60)
    combined = (out or '') + "\n" + (err or '')
    if rc == -2:
        return {'status': 'error', 'error': 'timeout', 'raw': combined}
    if rc == -1 and ('not_found' in (err or '').lower()):
        return {'status': 'not_tested', 'error': 'nmap_not_found', 'raw': combined}
    # parse result: look for 'VULNERABLE' or 'NOT VULNERABLE' or cve mention
    low = combined.lower()
    if 'vulnerable' in low and 'ms17-010' in low or 'cve-2017-0144' in low:
        return {'status': 'vulnerable', 'raw': combined}
    if 'not vulnerable' in low or 'false' in low or 'no vulnerability' in low:
        return {'status': 'not_vulnerable', 'raw': combined}
    # ambiguous/unknown
    return {'status': 'not_vulnerable' if 'false' in low else 'error', 'raw': combined}

def run_nmap_windows(ip, ports):
    """Windows fallback: just test with socket, no nmap."""
    results = []
    for p in ports:
        open_, _ = tcp_connect(ip, p)
        results.append({'port': p, 'open': open_})
    return {'raw': 'windows_basic_scan', 'ports': results, 'vulns': []}

def try_rpcclient_enum(ip):
    cmd = [RPCCLIENT_CMD, '-U', "", ip, '-c', 'enumdomusers']
    rc, out, err = run_cmd(cmd, timeout=30)
    if rc == -1 and ('not_found' in (err or '').lower()):
        return {'available': False, 'error': 'rpcclient_not_found', 'raw': err}
    combined = (out or '') + "\n" + (err or '')
    if 'error' in combined.lower() and 'nt_status' in combined.lower():
        return {'available': True, 'enum_possible': False, 'raw': combined}
    if any(line.strip() and line.strip()[0].isalnum() for line in (out or '').splitlines()):
        return {'available': True, 'enum_possible': True, 'raw': combined}
    return {'available': True, 'enum_possible': False, 'raw': combined}

def try_rpcclient_windows(ip):
    return {'available': False, 'error': 'rpc_not_available_on_windows'}

# ------------------ ROUTES ------------------

@app.route('/scan', methods=['POST'])
def scan_smb():
    body = request.get_json(force=True, silent=True)
    if not body:
        return jsonify({'error': 'invalid_json'}), 400
    target = body.get('target')
    ports = body.get('ports', DEFAULT_PORTS)
    if not target:
        return jsonify({'error': 'target_required'}), 400

    # resolve target to IP
    try:
        ipaddress.ip_address(target); ip = target
    except Exception:
        try:
            ip = socket.gethostbyname(target)
        except Exception as e:
            return jsonify({'error': 'resolve_failed', 'detail': str(e)}), 400

    try:
        ipobj = ipaddress.ip_address(ip)
        if ipobj.is_private and not ALLOW_PRIVATE:
            return jsonify({'error': 'target_is_private', 'detail': 'private IP scanning disabled'}), 400
    except Exception:
        pass

    start = time.time()
    result = {'target': target, 'ip': ip, 'ports': ports,
              'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
              'checked': {}, 'summary': {'any_eternalblue_vulnerable': False, 'any_null_session': False, 'any_enumeration_possible': False}}

    for p in ports:
        port_block = {'open': False, 'banner': None, 'null_session_attempt': None,
                      'shares': [], 'nmap': None, 'rpcclient': None, 'notes': [], 'eternalblue': None, 'enumeration_possible': False}
        open_, banner = tcp_connect(ip, p)
        port_block['open'] = open_
        port_block['banner'] = banner
        if not open_:
            port_block['notes'].append('port_closed_or_filtered')
            result['checked'][str(p)] = port_block
            continue

        # Null session (try smbclient or impacket fallback on Windows)
        try:
            if WINDOWS_MODE and not check_cmd_exists(SMBCLIENT_CMD):
                smb_res = check_null_session_windows(ip, port=p)
            else:
                smb_res = check_null_session_smbclient(ip, port=p)
            port_block['null_session_attempt'] = smb_res
            if smb_res.get('shares'):
                port_block['shares'] = smb_res['shares']
                port_block['enumeration_possible'] = True
                result['summary']['any_null_session'] = result['summary']['any_null_session'] or bool(smb_res.get('null_session'))
                result['summary']['any_enumeration_possible'] = result['summary']['any_enumeration_possible'] or bool(smb_res.get('shares'))
        except Exception as e:
            port_block['notes'].append(f'smbclient_error:{e}')

        # RPC enumeration (best-effort)
        try:
            if WINDOWS_MODE and not check_cmd_exists(RPCCLIENT_CMD):
                rpc_res = try_rpcclient_windows(ip)
            else:
                rpc_res = try_rpcclient_enum(ip)
            port_block['rpcclient'] = rpc_res
            if rpc_res.get('available') and rpc_res.get('enum_possible'):
                port_block['enumeration_possible'] = True
                result['summary']['any_enumeration_possible'] = True
        except Exception as e:
            port_block['notes'].append(f'rpcclient_error:{e}')

        # nmap scripts (general)
        try:
            if WINDOWS_MODE and not check_cmd_exists(NMAP_CMD):
                nmap_findings = run_nmap_windows(ip, [p])
            else:
                nmap_findings = run_nmap_smb_scripts(ip, [p])
            port_block['nmap'] = nmap_findings
            if nmap_findings and nmap_findings.get('vulns'):
                port_block['notes'].append('nmap_reported_vulns')
        except Exception as e:
            port_block['notes'].append(f'nmap_error:{e}')

        # explicit check for EternalBlue (MS17-010)
        try:
            ms17_res = run_nmap_check_ms17(ip, port=p)
            port_block['eternalblue'] = ms17_res
            if isinstance(ms17_res, dict) and ms17_res.get('status') == 'vulnerable':
                result['summary']['any_eternalblue_vulnerable'] = True
        except Exception as e:
            port_block['eternalblue'] = {'status': 'error', 'error': str(e)}

        # final enumeration_possible inference
        # enumeration_possible true if shares listed or rpc enum_possible true
        if not port_block['enumeration_possible']:
            if port_block.get('shares'):
                port_block['enumeration_possible'] = True
                result['summary']['any_enumeration_possible'] = True

        result['checked'][str(p)] = port_block

    result['duration_seconds'] = round(time.time() - start, 3)
    return jsonify(result), 200

@app.route('/health', methods=['GET'])
def health():
    return jsonify({'status': 'ok', 'windows_mode': WINDOWS_MODE})

if __name__ == '__main__':
    port = 5011
    bind_ip = os.getenv('BIND_IP', '0.0.0.0')
    app.run(host=bind_ip, port=port)
