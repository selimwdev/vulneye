<#
 setup.ps1
 PowerShell installer wrapper that writes a bash script into WSL and runs it.
 Run as Administrator.
#>

Set-StrictMode -Version Latest
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::UTF8

function Write-Log { param($m) Write-Host "[*] $m" -ForegroundColor Cyan }
function Write-Err { param($m) Write-Host "[ERROR] $m" -ForegroundColor Red }
function Write-Ok  { param($m) Write-Host "[OK] $m" -ForegroundColor Green }

# require admin for WSL install
$IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $IsAdmin) {
    Write-Err "This script should be run as Administrator for full functionality (installing WSL or system packages)."
    Write-Host "You can still run parts of it without admin, but WSL install will fail."
}

# check wsl availability
$wslInstalled = $false
try {
    & wsl -l -v > $null 2>&1
    if ($LASTEXITCODE -eq 0) { $wslInstalled = $true }
} catch { $wslInstalled = $false }

if (-not $wslInstalled) {
    Write-Log "WSL not detected. Attempting to install WSL (may require reboot)."
    try {
        & wsl --install -d Ubuntu
        if ($LASTEXITCODE -eq 0) {
            Write-Ok "wsl --install started. After reboot, open Ubuntu once to finish distro setup then re-run this script."
            exit 0
        } else {
            Write-Err "wsl --install returned exit code $LASTEXITCODE. You may need to enable features manually."
        }
    } catch {
        Write-Err "Failed to run 'wsl --install'. Error: $_"
    }
} else {
    Write-Ok "WSL detected."
}

# write bash installer to a temp file and run it inside WSL
$bashPath = "/tmp/wsl_smb_setup.sh"
# here-string for bash content (single-quoted to avoid variable expansion by PowerShell)
$bashContent = @'
#!/usr/bin/env bash
set -euo pipefail
IFS=$'\''\n\t'\''

echo "=== WSL SMB/tools installer (inside WSL) ==="
echo "User: $(whoami), Date: $(date)"
echo

if command -v apt-get >/dev/null 2>&1; then
  echo "[*] Using apt to install packages..."
  sudo apt-get update -y
  sudo apt-get install -y --no-install-recommends \
    nmap smbclient samba smbmap rpcbind python3 python3-pip python3-venv \
    build-essential python3-dev libssl-dev libffi-dev libsasl2-dev pkg-config git
else
  echo "[!] apt-get not found inside WSL. Please use a Debian/Ubuntu WSL distro or install packages manually."
  exit 0
fi

# ensure local bin in PATH for this session
export PATH="$HOME/.local/bin:$PATH"

echo "[*] Upgrading pip and installing Python packages (impacket, Flask, smbprotocol, smbmap)..."
python3 -m pip install --user --upgrade pip setuptools wheel --no-cache-dir
python3 -m pip install --user --no-cache-dir impacket Flask smbprotocol smbmap || {
  echo "[!] pip install had issues; trying no-build-isolation"
  python3 -m pip install --user --no-cache-dir --no-build-isolation impacket Flask smbprotocol smbmap || {
    echo "[ERROR] pip install ultimately failed. Try: python3 -m pip install --user --no-cache-dir impacket"
  }
}

echo
echo "=== Quick checks ==="
echo "nmap: $(command -v nmap || echo missing)"
echo "smbclient: $(command -v smbclient || echo missing)"
echo "smbmap: $(command -v smbmap || echo missing)"
echo "python3: $(command -v python3 || echo missing)"
python3 - <<'PY' || echo "impacket import failed"
try:
  import impacket
  print("impacket ok")
except Exception as e:
  print("impacket import error:", e)
PY

echo
echo "If ~/.local/bin not in PATH, add: export PATH=\"\$HOME/.local/bin:\$PATH\" to your shell startup file."
echo "Done WSL setup."
'@

# Save bash script into a temporary file on Windows then copy into WSL /tmp via wsl.exe
$tmpFile = Join-Path $env:TEMP "wsl_smb_setup.sh"
Set-Content -Path $tmpFile -Value $bashContent -Encoding UTF8
Write-Log "Wrote WSL bash installer to $tmpFile"

if ($wslInstalled) {
    Write-Log "Copying installer into WSL at $bashPath and executing..."
    # Use wsl.exe to create the file on the WSL side then run it
    try {
        # Use 'wsl -- cat > /tmp/wsl_smb_setup.sh' to write content
        $content = Get-Content -Raw -Path $tmpFile
        & wsl -- bash -c "cat > $bashPath <<'BASH'
$content
BASH
chmod +x $bashPath
sudo $bashPath
" 2>&1 | Write-Host
        Write-Ok "WSL installer finished (or attempted)."
    } catch {
        Write-Err "Failed to execute installer inside WSL: $_"
    }
} else {
    Write-Err "WSL not installed; skipped WSL install steps."
}

# Windows native fallback: try to install nmap and pip packages
Write-Log "Attempting Windows-native fallback installs (nmap via winget/choco, pip install user packages)."

$gotNmap = $false
if (Get-Command winget -ErrorAction SilentlyContinue) {
    Write-Log "Trying winget install nmap..."
    try {
        winget install --silent --accept-package-agreements --accept-source-agreements nmap
        $gotNmap = $true
    } catch { Write-Err "winget nmap install failed: $_" }
}
if (-not $gotNmap -and (Get-Command choco -ErrorAction SilentlyContinue)) {
    Write-Log "Trying choco install nmap..."
    try {
        choco install nmap -y
        $gotNmap = $true
    } catch { Write-Err "choco nmap install failed: $_" }
}
if ($gotNmap) { Write-Ok "nmap installation attempted." } else { Write-Err "Could not install nmap via winget/choco." }

# Install Python packages on Windows (user site) if python present
$pythonCmd = $null
if (Get-Command python -ErrorAction SilentlyContinue) { $pythonCmd = "python" }
elseif (Get-Command python3 -ErrorAction SilentlyContinue) { $pythonCmd = "python3" }

if ($pythonCmd) {
    Write-Log "Attempting pip install of Python packages (impacket, Flask, smbprotocol, smbmap) to user site."
    $origTemp = $env:TEMP
    try {
        $shortTmp = "C:\Temp\piptemp"
        if (-not (Test-Path $shortTmp)) { New-Item -Path $shortTmp -ItemType Directory | Out-Null }
        $env:TEMP = $shortTmp
        & $pythonCmd -m pip install --user --no-cache-dir impacket Flask smbprotocol smbmap
        if ($LASTEXITCODE -eq 0) { Write-Ok "pip user install succeeded." } else { Write-Err "pip exited with code $LASTEXITCODE." }
    } catch {
        Write-Err "pip install failed on Windows: $_"
    } finally {
        $env:TEMP = $origTemp
    }
} else {
    Write-Err "Python not found on Windows PATH. Please install Python 3.8+."
}

# final summary
Write-Host
Write-Ok "Setup script completed. Summary:"
Write-Host " - WSL installed: $wslInstalled"
Write-Host " - Check inside WSL (if used): nmap, smbclient, smbmap, python3, impacket import"
Write-Host " - On Windows, check: nmap --version ; python -c \"import impacket; print('ok')\""

