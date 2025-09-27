# ssh_check_api_full.py
"""
Flask SSH checker with terrapin heuristic

Requirements (put in requirements.txt):
Flask==2.2.5
xmltodict==0.13.0
asyncssh==2.13.0

System tools (should be in PATH):
- nmap
- ssh-keyscan
- ssh-audit (optional, recommended)

Usage:
  python -m venv .venv
  # Windows:
  .\.venv\Scripts\Activate.ps1
  # Linux/macOS:
  source .venv/bin/activate
  pip install -r requirements.txt
  python ssh_check_api_full.py

Endpoint:
  POST /scan/ssh  JSON body: {"target":"proxy5.follow.it","port":22}
  GET  /health
"""
from flask import Flask, request, jsonify
import subprocess, shlex, json, time, socket, os, asyncio
import ipaddress
import xmltodict
import asyncssh

app = Flask(__name__)

SSH_AUDIT_CMD = os.getenv("SSH_AUDIT_CMD", "ssh-audit")
SSH_KEYSCAN_CMD = os.getenv("SSH_KEYSCAN_CMD", "ssh-keyscan")
NMAP_CMD = os.getenv("NMAP_CMD", "nmap")
DEFAULT_PORT = 22
NMAP_TIMEOUT = 25

# Heuristic weak lists
WEAK_KEX = {"diffie-hellman-group1-sha1", "diffie-hellman-group14-sha1"}
WEAK_ENC = {"3des-cbc", "des", "arcfour", "arcfour128", "arcfour256", "rc4"}
WEAK_MAC = {"hmac-md5", "hmac-sha1"}

def run_cmd(cmd, timeout=20):
    if isinstance(cmd, str):
        cmd = shlex.split(cmd)
    try:
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=timeout)
        return p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired:
        return -2, "", "timeout"
    except Exception as e:
        return -1, "", str(e)

def safe_resolve(host):
    try:
        ipaddress.ip_address(host)
        return host
    except Exception:
        return socket.gethostbyname(host)

async def async_handshake_algos(host, port, timeout=10):
    """
    Use asyncssh to perform a non-auth handshake and extract server algorithms.
    Returns dict with kex, ciphers (in/out), macs, server_version, reachable flag, error.
    """
    res = {"reachable": False, "error": None, "server_version": None,
           "kex": [], "ciphers": [], "macs": [], "compression": []}
    try:
        # connect without auth; asyncssh will perform KEX and negotiate algorithms.
        # We set known_hosts=None to avoid host-check; we do NOT authenticate.
        conn = await asyncio.wait_for(asyncssh.connect(host, port=port, known_hosts=None, username=None, agent_forwarding=False, client_keys=None), timeout=timeout)
        try:
            trans = conn._get_transport()  # protected API but works to fetch negotiated algos
            # negotiated algorithms
            server_version = trans.get_server_version() if hasattr(trans, "get_server_version") else None
            kex = trans.get_extra_info("kex_algorithm") if hasattr(trans, "get_extra_info") else None
            # fallback: inspect transport attributes if available
            negotiated = {}
            # Try to get lists from transport where possible
            try:
                k = trans.kex_algorithm if hasattr(trans, "kex_algorithm") else None
            except Exception:
                k = None
            # asyncssh internals vary; attempt multiple ways
            try:
                # encryption algorithms in use
                enc_in = trans.get_extra_info("encryption_in") if hasattr(trans, "get_extra_info") else None
                macs_in = trans.get_extra_info("mac_in") if hasattr(trans, "get_extra_info") else None
                comp_in = trans.get_extra_info("compression_in") if hasattr(trans, "get_extra_info") else None
            except Exception:
                enc_in = macs_in = comp_in = None

            # Normalize results: if values present, put into lists
            if server_version:
                res["server_version"] = server_version
            if k:
                if isinstance(k, (list,tuple)):
                    res["kex"] = list(k)
                else:
                    res["kex"] = [k]
            if kex and not res["kex"]:
                if isinstance(kex, (list,tuple)):
                    res["kex"] = list(kex)
                else:
                    res["kex"] = [kex]
            if enc_in:
                if isinstance(enc_in, (list,tuple)):
                    res["ciphers"] = list(enc_in)
                else:
                    res["ciphers"] = [enc_in]
            elif isinstance(trans, object):
                # try attribute names some versions expose
                try:
                    ci = getattr(trans, "encryption_in", None)
                    if ci:
                        res["ciphers"] = ci if isinstance(ci, (list,tuple)) else [ci]
                except Exception:
                    pass
            if macs_in:
                res["macs"] = list(macs_in) if isinstance(macs_in, (list,tuple)) else [macs_in]
            if comp_in:
                res["compression"] = list(comp_in) if isinstance(comp_in, (list,tuple)) else [comp_in]
            # mark reachable
            res["reachable"] = True
        finally:
            conn.close()
            await conn.wait_closed()
    except asyncio.TimeoutError:
        res["error"] = "timeout"
    except (asyncssh.Error, OSError) as e:
        res["error"] = str(e)
    except Exception as e:
        res["error"] = str(e)
    return res

@app.route("/scan", methods=["POST"])
def scan_ssh():
    body = request.get_json(force=True, silent=True)
    if not body:
        return jsonify({"error":"invalid_json"}), 400
    target = body.get("target")
    port = int(body.get("port", DEFAULT_PORT))
    if not target:
        return jsonify({"error":"target_required"}), 400

    try:
        resolved_ip = safe_resolve(target)
    except Exception as e:
        return jsonify({"error":"resolve_failed","detail":str(e)}), 400

    # block private ranges by default
    allow_private = os.getenv("ALLOW_PRIVATE","false").lower() in ("1","true","yes")
    try:
        ipobj = ipaddress.ip_address(resolved_ip)
        if ipobj.is_private and not allow_private:
            return jsonify({"error":"target_is_private","detail":"private IP scanning disabled"}), 400
    except Exception:
        pass

    started = time.time()
    result = {
        "target": target,
        "ip": resolved_ip,
        "port": port,
        "duration_seconds": None,
        "host_keys": [],
        "kex_algorithms": [],
        "enc_algorithms": [],
        "mac_algorithms": [],
        "compression": [],
        "auth_methods": [],
        "weak_encryption": False,
        "weak_details": [],
        "user_enum_possible": False,
        "user_enum_reason": None,
        "terrapin_possible": False,
        "terrapin_reason": None,
        "notes": []
    }

    # 1) host keys (ssh-keyscan)
    rc, kout, kerr = run_cmd(f"{SSH_KEYSCAN_CMD} -p {port} -T 3 {resolved_ip}", timeout=8)
    if rc == 0 and kout:
        keys = []
        for line in kout.splitlines():
            if not line.strip(): continue
            parts = line.split()
            if len(parts) >= 2:
                keys.append({"type": parts[0], "key": parts[1]})
        result["host_keys"] = keys
    else:
        result["notes"].append("host_keys_unavailable")

    # 2) try ssh-audit -j (preferred)
    rc, outa, erra = run_cmd([SSH_AUDIT_CMD, "-j", f"{resolved_ip}:{port}"], timeout=20)
    sa_used = False
    if rc == 0 and outa:
        try:
            jd = json.loads(outa)
            sa_used = True
            # extract lists if present
            for sec, map_to in (("kex","kex_algorithms"), ("enc","enc_algorithms"), ("mac","mac_algorithms"), ("compression","compression")):
                secobj = jd.get(sec, {})
                if isinstance(secobj, dict):
                    result[map_to] = list(secobj.keys())
            # check weak entries in ssh-audit info
            weak = []
            for sec in ("kex","enc","mac"):
                sdict = jd.get(sec, {})
                if isinstance(sdict, dict):
                    for algo, info in sdict.items():
                        if isinstance(info, dict):
                            status = (info.get("status") or "") if info.get("status") else ""
                            notes = info.get("notes") or []
                            combined = " ".join([str(status)] + (notes if isinstance(notes, list) else [str(notes)]))
                            if any(tok in str(combined).lower() for tok in ("unsafe","deprecated","weak")):
                                weak.append({"section": sec, "algorithm": algo})
            if weak:
                result["weak_encryption"] = True
                result["weak_details"].extend(weak)
            # ssh-audit might also include auth info; try to pick up password allowed
            auths = jd.get("auth", {})
            if isinstance(auths, dict):
                methods = []
                for m in ("password","publickey","keyboard-interactive","gssapi-with-mic"):
                    # some entries might be present as keys or notes
                    if m in auths:
                        methods.append(m)
                if methods:
                    result["auth_methods"] = methods
        except Exception:
            result["notes"].append("ssh-audit-parse-failed")
    else:
        result["notes"].append("ssh-audit-unavailable")

    # 3) nmap fallback to gather algos and auth methods
    nmap_scripts = "ssh2-enum-algos,ssh-auth-methods,ssh-hostkey"
    rc, nout, nerr = run_cmd([NMAP_CMD, "-p", str(port), "-Pn", "--script", nmap_scripts, "-oX", "-", resolved_ip], timeout=NMAP_TIMEOUT)
    if rc == 0 and nout:
        try:
            parsed = xmltodict.parse(nout)
            nmaprun = parsed.get("nmaprun", {})
            host = nmaprun.get("host")
            if isinstance(host, list):
                host = host[0]
            scripts = []
            # hostscript
            hs = host.get("hostscript", {}).get("script")
            if hs:
                if isinstance(hs, list):
                    for s in hs:
                        scripts.append(s)
                else:
                    scripts.append(hs)
            # port-level scripts
            ports_block = host.get("ports", {}).get("port")
            if ports_block:
                if isinstance(ports_block, list):
                    for p in ports_block:
                        ps = p.get("script")
                        if ps:
                            if isinstance(ps, list):
                                scripts.extend(ps)
                            else:
                                scripts.append(ps)
                else:
                    ps = ports_block.get("script")
                    if ps:
                        if isinstance(ps, list):
                            scripts.extend(ps)
                        else:
                            scripts.append(ps)
            # parse script outputs
            for s in scripts:
                sid = s.get("@id","")
                sout = s.get("@output","") or ""
                if sid == "ssh2-enum-algos":
                    # try parse table entries if present
                    table = s.get("table")
                    if table and isinstance(table, list):
                        for t in table:
                            key = t.get("@key","")
                            elems = t.get("elem",[])
                            if not isinstance(elems, list):
                                elems = [elems]
                            items = []
                            for e in elems:
                                if isinstance(e, dict):
                                    items.append(e.get("#text"))
                                else:
                                    items.append(str(e))
                            if key == "kex_algorithms":
                                result["kex_algorithms"] = items
                            elif key in ("encryption_algorithms","encryption"):
                                result["enc_algorithms"] = items
                            elif key == "mac_algorithms":
                                result["mac_algorithms"] = items
                            elif key == "compression_algorithms":
                                result["compression"] = items
                    else:
                        # fallback: text parsing
                        lines = sout.splitlines()
                        cur = None
                        for L in lines:
                            Ls = L.strip()
                            if Ls.endswith(":") and "algorithms" in Ls:
                                cur = Ls.lower()
                                continue
                            if cur and Ls:
                                token = Ls.split()[0].strip()
                                if "kex" in cur:
                                    if token not in result["kex_algorithms"]:
                                        result["kex_algorithms"].append(token)
                                elif "encrypt" in cur:
                                    if token not in result["enc_algorithms"]:
                                        result["enc_algorithms"].append(token)
                                elif "mac" in cur:
                                    if token not in result["mac_algorithms"]:
                                        result["mac_algorithms"].append(token)
                elif sid == "ssh-auth-methods":
                    txt = sout.lower()
                    # try to extract methods
                    for tok in ("publickey","password","keyboard-interactive","gssapi-with-mic"):
                        if tok in txt and tok not in result["auth_methods"]:
                            result["auth_methods"].append(tok)
        except Exception:
            result["notes"].append("nmap-parse-failed")
    else:
        result["notes"].append("nmap-unavailable-or-failed")

    # 4) asyncssh handshake to get negotiated/advertised algos and server version (safe, no auth)
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        handshake = loop.run_until_complete(async_handshake_algos(resolved_ip, port, timeout=10))
        # ---- START ADDED: message-based user-enum detection using asyncssh auth attempts ----
        # We'll attempt two failed auths with different usernames and compare the exception messages.
        # If messages differ, it's likely message-based user enumeration is possible.
        message_enum_detected = False
        message_enum_msgs = []
        try:
            async def try_invalid_login(host, port, username):
                try:
                    # connecting with credentials — we expect it to fail, capture exception message
                    await asyncssh.connect(host, port=port, username=username, password="incorrect_password", known_hosts=None, client_keys=None)
                    return "unexpected_success"
                except Exception as exc:
                    return str(exc)
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            coro1 = try_invalid_login(resolved_ip, port, "nonexistent_user_12345")
            coro2 = try_invalid_login(resolved_ip, port, "probably_not_a_user_98765")
            # run both sequentially (avoid hammering); small timeout
            try:
                msg1 = loop.run_until_complete(asyncio.wait_for(coro1, timeout=10))
            except Exception as e:
                msg1 = f"error:{e}"
            try:
                msg2 = loop.run_until_complete(asyncio.wait_for(coro2, timeout=10))
            except Exception as e:
                msg2 = f"error:{e}"
            loop.close()
            message_enum_msgs = [msg1, msg2]
            # compare normalized messages (strip host/ip noise)
            norm1 = msg1.strip().lower()
            norm2 = msg2.strip().lower()
            if norm1 != norm2:
                message_enum_detected = True
                # add reason explanation
                result["user_enum_possible"] = True
                result["user_enum_reason"] = f"Message-based differences detected: msg1='{msg1[:200]}', msg2='{msg2[:200]}'"
                result["notes"].append(f"user_enum_messages: [{msg1[:300]}] [{msg2[:300]}]")
        except Exception as e:
            # if something in message-based detection failed, note but continue
            result["notes"].append(f"message_enum_detection_error:{str(e)}")
        # ---- END ADDED message-based detection ----

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        # close the loop we used for handshake earlier (we'll reuse variable safely)
        try:
            loop.close()
        except Exception:
            pass

        if handshake.get("reachable"):
            # merge heuristics: include server-provided negotiated lists if empty
            if handshake.get("kex") and not result["kex_algorithms"]:
                result["kex_algorithms"] = handshake["kex"]
            if handshake.get("ciphers") and not result["enc_algorithms"]:
                result["enc_algorithms"] = handshake["ciphers"]
            if handshake.get("macs") and not result["mac_algorithms"]:
                result["mac_algorithms"] = handshake["macs"]
            if handshake.get("compression") and not result["compression"]:
                result["compression"] = handshake["compression"]
            if handshake.get("server_version"):
                result.setdefault("server_version", handshake.get("server_version"))
            # terrapin heuristic:
            # Terrapin-like issues are typically connected to specific server versions/implementations and
            # certain algorithm combinations. We flag possible if server advertises chacha20-poly1305 AND
            # supports diffie-hellman-group14-sha1 (example heuristic) or server_version contains vulnerable banner.
            algs = set([a.lower() for a in (result.get("enc_algorithms") or [])])
            kexs = set([k.lower() for k in (result.get("kex_algorithms") or [])])
            sv = (handshake.get("server_version") or "").lower()
            terrapin_flag = False
            terrapin_reasons = []
            # heuristic rules (non-exhaustive)
            if "chacha20-poly1305@openssh.com" in algs and any(k for k in kexs if "group14" in k or "sha1" in k):
                terrapin_flag = True
                terrapin_reasons.append("server advertises chacha20-poly1305 together with group14/sha1 KEX (heuristic match)")
            # server version matching common vulnerable strings (example)
            if sv and ("erlang" in sv and any(v in sv for v in ("otp","ssh"))):
                terrapin_flag = terrapin_flag or True
                terrapin_reasons.append(f"server banner contains Erlang/OTP indicative string: '{sv}'")
            result["terrapin_possible"] = terrapin_flag
            if terrapin_flag:
                # put readable reason
                result["terrapin_reason"] = "; ".join(terrapin_reasons)
        else:
            result["notes"].append(f"handshake_failed:{handshake.get('error')}")
    except Exception as e:
        result["notes"].append(f"handshake_exception:{str(e)}")

    # Heuristic weak algos if not already flagged
    weak_found = []
    for a in result.get("kex_algorithms", []):
        if a.lower() in WEAK_KEX or ("sha1" in a.lower() and "group" in a.lower()):
            weak_found.append({"type":"kex","algo":a})
    for a in result.get("enc_algorithms", []):
        if a.lower() in WEAK_ENC or "cbc" in a.lower():
            weak_found.append({"type":"enc","algo":a})
    for a in result.get("mac_algorithms", []):
        if a.lower() in WEAK_MAC:
            weak_found.append({"type":"mac","algo":a})
    if weak_found and not result["weak_encryption"]:
        result["weak_encryption"] = True
        result["weak_details"].extend(weak_found)

    # user enumeration heuristic (also consider auth_methods gathered earlier via ssh-audit/nmap)
    if any("password" in m.lower() for m in result.get("auth_methods", [])):
        # if we already set reason via message-based check, keep it; otherwise add explanation
        if not result["user_enum_reason"]:
            result["user_enum_possible"] = True
            result["user_enum_reason"] = "Password authentication enabled -> server may reveal different responses for valid vs invalid users (message-based enumeration risk)"
        else:
            # append additional context if message-based already found
            result["user_enum_reason"] = f"{result['user_enum_reason']} | Password authentication enabled"

    result["duration_seconds"] = round(time.time() - started, 3)

    # cleanup empty arrays for readability
    for k in list(result.keys()):
        if isinstance(result[k], list) and len(result[k]) == 0:
            result.pop(k)

    return jsonify(result), 200

@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status":"ok"})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5013)
