#!/usr/bin/env python3
"""
bootstrap_and_run.py

Purpose:
- Detect OS
- Check/install common dependencies for the SMB scanner:
  system tools: nmap, smbclient, rpcclient (impacket tools), smbmap, git, dig, tcpdump, nbtscan
  python packages: impacket, flask, xmltodict, packaging
- If installation requires admin rights or user action, print explicit instructions.
- If scan_smb.py exists in same directory, attempt to run it after bootstrapping.

Usage:
  python bootstrap_and_run.py
"""

import sys
import os
import shutil
import subprocess
import platform
import argparse
from pathlib import Path

# tools we want available (best-effort)
SYSTEM_TOOLS = ["nmap", "smbclient", "rpcclient", "smbmap", "nbtscan", "dig", "tcpdump", "git"]
PIP_PKGS = ["impacket", "flask", "xmltodict", "packaging", "scapy"]

# map package managers to install commands (best-effort)
LINUX_PKGS = {
    # package name mapping for apt (Debian/Ubuntu)
    "apt": {
        "nmap": "nmap",
        "smbclient": "smbclient",
        "rpcclient": "samba-common-bin",   # rpcclient provided by samba tools (samba-client in some distros)
        "smbmap": "smbmap",
        "nbtscan": "nbtscan",
        "dig": "dnsutils",
        "tcpdump": "tcpdump",
        "git": "git",
    },
    # Fedora / RHEL (dnf)
    "dnf": {
        "nmap": "nmap",
        "smbclient": "samba-client",
        "rpcclient": "samba-client",
        "smbmap": "smbmap",
        "nbtscan": "nbtscan",
        "dig": "bind-utils",
        "tcpdump": "tcpdump",
        "git": "git",
    },
    # Alpine
    "apk": {
        "nmap": "nmap",
        "smbclient": "samba-client",
        "rpcclient": "samba-client",
        "smbmap": "smbmap",
        "nbtscan": "nbtscan",
        "dig": "bind-tools",
        "tcpdump": "tcpdump",
        "git": "git",
    }
}

MAC_PKGS = {
    "brew": {
        "nmap": "nmap",
        "smbclient": "samba",   # brew samba has client tools
        "rpcclient": "samba",
        "smbmap": "smbmap",
        "nbtscan": "nbtscan",
        "dig": "bind",
        "tcpdump": "tcpdump",
        "git": "git",
    }
}

WINDOWS_PKGS_CHOICE = {
    "choco": {
        "nmap": "nmap",
        "git": "git",
        # many linux-native tools not available natively; recommend WSL for full features
    },
    "winget": {
        "nmap": "Nmap.Nmap",
        "git": "Git.Git",
    }
}


def is_tool(name):
    return shutil.which(name) is not None


def run_cmd(cmd, capture=False):
    try:
        if capture:
            res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)
            return res.returncode, res.stdout.strip(), res.stderr.strip()
        else:
            res = subprocess.run(cmd, check=False)
            return res.returncode, None, None
    except Exception as e:
        return -1, "", str(e)


def need_sudo():
    # check if running as root on unix-like
    if os.name != "nt":
        return os.geteuid() != 0
    return False


def print_header(msg):
    print("\n" + "="*60)
    print(msg)
    print("="*60 + "\n")


def install_via_apt(packages):
    if need_sudo():
        print("apt install requires root. Re-run the script with sudo or install the following manually:")
        print("sudo apt update && sudo apt install -y " + " ".join(packages))
        return False
    cmd = ["apt", "update"]
    print("Running: apt update ...")
    run_cmd(cmd)
    cmd2 = ["apt", "install", "-y"] + packages
    print("Running:", " ".join(cmd2))
    rc, out, err = run_cmd(cmd2, capture=True)
    return rc == 0


def install_via_dnf(packages):
    if need_sudo():
        print("dnf install requires root. Re-run the script with sudo or install the following manually:")
        print("sudo dnf install -y " + " ".join(packages))
        return False
    cmd = ["dnf", "install", "-y"] + packages
    print("Running:", " ".join(cmd))
    rc, out, err = run_cmd(cmd, capture=True)
    return rc == 0


def install_via_apk(packages):
    if need_sudo():
        print("apk add requires root. Re-run the script with sudo or install the following manually:")
        print("sudo apk add " + " ".join(packages))
        return False
    cmd = ["apk", "add"] + packages
    print("Running:", " ".join(cmd))
    rc, out, err = run_cmd(cmd, capture=True)
    return rc == 0


def install_via_brew(packages):
    cmd = ["brew", "install"] + packages
    print("Running:", " ".join(cmd))
    rc, out, err = run_cmd(cmd, capture=True)
    return rc == 0


def install_via_choco(packages):
    cmd = ["choco", "install", "-y"] + packages
    print("Running:", " ".join(cmd))
    rc, out, err = run_cmd(cmd, capture=True)
    return rc == 0


def install_via_winget(packages):
    # winget expects specific ids; caller will prepare correct ids
    for pkg in packages:
        cmd = ["winget", "install", "--accept-package-agreements", "--accept-source-agreements", pkg]
        print("Running:", " ".join(cmd))
        rc, out, err = run_cmd(cmd, capture=True)
        if rc != 0:
            return False
    return True


def ensure_system_tools():
    print_header("Checking system tools")
    missing = [t for t in SYSTEM_TOOLS if not is_tool(t)]
    if not missing:
        print("All system tools present:", SYSTEM_TOOLS)
        return True

    print("Missing tools detected:", missing)
    system = platform.system().lower()
    print("Detected OS:", system)

    if system == "linux":
        # detect distro package manager
        if shutil.which("apt"):
            mapping = LINUX_PKGS["apt"]
            pkgs = [mapping.get(m, m) for m in missing if m in mapping]
            if pkgs:
                ok = install_via_apt(pkgs)
                if ok:
                    print("Installed packages via apt:", pkgs)
                else:
                    print("apt install failed or requires manual intervention for:", pkgs)
        elif shutil.which("dnf"):
            mapping = LINUX_PKGS["dnf"]
            pkgs = [mapping.get(m, m) for m in missing if m in mapping]
            if pkgs:
                ok = install_via_dnf(pkgs)
                if ok:
                    print("Installed packages via dnf:", pkgs)
                else:
                    print("dnf install failed or requires manual intervention for:", pkgs)
        elif shutil.which("apk"):
            mapping = LINUX_PKGS["apk"]
            pkgs = [mapping.get(m, m) for m in missing if m in mapping]
            if pkgs:
                ok = install_via_apk(pkgs)
                if ok:
                    print("Installed packages via apk:", pkgs)
                else:
                    print("apk add failed or requires manual intervention for:", pkgs)
        else:
            print("Unknown Linux package manager. Please install manually:", missing)
    elif system == "darwin":
        if shutil.which("brew"):
            mapping = MAC_PKGS["brew"]
            pkgs = [mapping.get(m, m) for m in missing if m in mapping]
            if pkgs:
                ok = install_via_brew(pkgs)
                if ok:
                    print("Installed packages via brew:", pkgs)
                else:
                    print("brew install failed or requires manual intervention for:", pkgs)
        else:
            print("Homebrew not found. Install Homebrew from https://brew.sh and then run:")
            print("brew install " + " ".join([MAC_PKGS["brew"].get(m, m) for m in missing if m in MAC_PKGS["brew"]]))
    elif system == "windows":
        # try choco then winget
        if shutil.which("choco"):
            mapping = WINDOWS_PKGS_CHOICE["choco"]
            pkgs = [mapping.get(m) for m in missing if m in mapping]
            pkgs = [p for p in pkgs if p]
            if pkgs:
                ok = install_via_choco(pkgs)
                if ok:
                    print("Installed packages via choco:", pkgs)
                else:
                    print("choco install failed. Please run as Administrator and try to install:", pkgs)
            else:
                print("Some missing tools are not available via choco. Consider using WSL (recommended) for full SMB tooling.")
        elif shutil.which("winget"):
            mapping = WINDOWS_PKGS_CHOICE["winget"]
            pkgs = [mapping.get(m) for m in missing if m in mapping]
            pkgs = [p for p in pkgs if p]
            if pkgs:
                ok = install_via_winget(pkgs)
                if ok:
                    print("Installed packages via winget:", pkgs)
                else:
                    print("winget install failed. Please run elevated or install manually.")
            else:
                print("Missing tools not available via winget. Recommend enabling WSL and running the Linux installer there.")
        else:
            print("Chocolatey/winget not found. On Windows it's recommended to enable WSL (Ubuntu) and run the Linux installer there.")
    else:
        print("Unhandled OS for automatic system package installation. Missing tools:", missing)

    # Re-check which are still missing and report
    still_missing = [t for t in missing if not is_tool(t)]
    if still_missing:
        print("\nAfter attempts, still missing:", still_missing)
        print("You will need to install them manually or run the appropriate system package manager as admin.")
        return False
    print("All required system tools are now present.")
    return True


def ensure_pip_packages():
    print_header("Checking Python packages (pip)")
    # try import to see if installed
    not_installed = []
    for pkg in PIP_PKGS:
        try:
            __import__(pkg if pkg != "packaging" else "packaging.version")
        except Exception:
            not_installed.append(pkg)
    if not not_installed:
        print("All Python packages present:", PIP_PKGS)
        return True

    print("Missing pip packages:", not_installed)
    # Attempt to install using the same interpreter's pip
    pip_exe = shutil.which("pip") or shutil.which("pip3") or (sys.executable + " -m pip")
    # prefer using sys.executable -m pip
    install_cmd = [sys.executable, "-m", "pip", "install"] + not_installed
    print("Running:", " ".join(install_cmd))
    rc, out, err = run_cmd(install_cmd, capture=True)
    if rc == 0:
        print("pip install succeeded.")
        return True
    else:
        print("pip install failed. Please run (as user or with sudo) the following:")
        print(" ".join(install_cmd))
        print("Error:", err)
        return False


def run_smb_scanner_if_exists():
    # if file scan_smb.py exists in same dir, run it
    here = Path(__file__).resolve().parent
    scanner = here / "scan_smb.py"
    if scanner.exists():
        print_header("Launching scan_smb.py")
        # run in background in a new process with same Python interpreter
        cmd = [sys.executable, str(scanner)]
        print("Running:", " ".join(cmd))
        # On Windows, create new process; on unix we can exec or spawn.
        try:
            subprocess.Popen(cmd)
            print("smb_scan_api started (subprocess).")
            return True
        except Exception as e:
            print("Failed to start scan_smb.py:", e)
            return False
    else:
        print("scan_smb.py not found in current directory. Skipping automatic launch.")
        return False


def main():
    parser = argparse.ArgumentParser(description="Bootstrap dependencies for SMB scanner and optionally run it.")
    parser.add_argument("--no-run", action="store_true", help="Don't auto-run scan_smb.py after bootstrapping")
    args = parser.parse_args()

    print_header("Bootstrap script for SMB scanner - starting checks")

    ok_tools = ensure_system_tools()
    ok_pip = ensure_pip_packages()

    print_header("Summary")
    print("System tools OK:", ok_tools)
    print("Python packages OK:", ok_pip)
    if not ok_tools:
        print("\nSome system tools are missing. If you are on Windows, consider enabling WSL and running the Linux installer inside Ubuntu.")
        print("If you need, re-run this script with elevated privileges or install missing tools manually.")
    if not ok_pip:
        print("\nPython packages failed to install automatically. Try:\n  " + sys.executable + " -m pip install " + " ".join(PIP_PKGS))

    if not args.no_run:
        run_smb_scanner_if_exists()

    print("\nBootstrap finished.")

if __name__ == "__main__":
    main()
