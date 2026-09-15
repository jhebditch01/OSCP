#!/usr/bin/env bash
#
# deploy.sh — sets up a Python venv for the OSCP Copilot app, installs every
# pip-installable offensive tool referenced across the methodology data, and
# makes sure the standard Kali wordlists (rockyou.txt, dirbuster, seclists)
# are actually present and usable.
#
# Usage:
#   ./deploy.sh                 # full setup
#   ./deploy.sh --no-apt        # skip apt/wordlist steps (not on Kali, or no sudo)
#   ./deploy.sh --no-clone      # skip git-clone-based tools (tier 2)
#   ./deploy.sh --no-apt --no-clone   # venv + pip-only tools, nothing else
#
# Safe to re-run — every step checks for existing state before acting.

set -uo pipefail

VENV_DIR=".venv"
TOOLS_DIR="tools"
SKIP_APT=0
SKIP_CLONE=0

for arg in "$@"; do
    case "$arg" in
        --no-apt) SKIP_APT=1 ;;
        --no-clone) SKIP_CLONE=1 ;;
        *) echo "Unknown option: $arg" >&2; exit 1 ;;
    esac
done

# ---- logging helpers -------------------------------------------------------
C_GREEN='\033[0;32m'; C_YELLOW='\033[0;33m'; C_RED='\033[0;31m'; C_BLUE='\033[0;34m'; C_RESET='\033[0m'
log_step() { echo -e "\n${C_BLUE}==>${C_RESET} $1"; }
log_ok()   { echo -e "  ${C_GREEN}[OK]${C_RESET} $1"; }
log_warn() { echo -e "  ${C_YELLOW}[WARN]${C_RESET} $1"; }
log_fail() { echo -e "  ${C_RED}[FAIL]${C_RESET} $1"; }

FAILED_PIP=()
FAILED_CLONE=()
MISSING_APT=()

# ---- 1. venv ----------------------------------------------------------------
log_step "Setting up Python virtual environment ($VENV_DIR)"

if ! command -v python3 >/dev/null 2>&1; then
    log_fail "python3 not found on PATH. Install it first (apt install python3)."
    exit 1
fi

if ! python3 -m venv --help >/dev/null 2>&1; then
    log_warn "python3-venv module not available, attempting to install it"
    if [ "$SKIP_APT" -eq 0 ] && command -v apt-get >/dev/null 2>&1; then
        sudo apt-get update -qq && sudo apt-get install -y python3-venv python3-pip
    else
        log_fail "Cannot create a venv without python3-venv. Install it manually or drop --no-apt."
        exit 1
    fi
fi

if [ ! -d "$VENV_DIR" ]; then
    python3 -m venv "$VENV_DIR"
    log_ok "Created venv at ./$VENV_DIR"
else
    log_ok "Venv already exists at ./$VENV_DIR"
fi

# shellcheck disable=SC1091
source "$VENV_DIR/bin/activate"
python3 -m pip install --upgrade pip setuptools wheel -q
log_ok "pip/setuptools/wheel upgraded inside venv"

# ---- 2. the app itself (from pyproject.toml: rich, textual) ----------------
log_step "Installing the OSCP Copilot app and its dependencies"
if [ -f "pyproject.toml" ]; then
    if pip install -e . -q; then
        log_ok "Installed app + dependencies (rich, textual) from pyproject.toml"
    else
        log_fail "pip install -e . failed — check pyproject.toml"
        FAILED_PIP+=("oscp-checklist (pyproject.toml)")
    fi
else
    log_warn "No pyproject.toml found — installing rich/textual directly"
    pip install "rich>=13.0.0" "textual>=0.50.0" -q || FAILED_PIP+=("rich" "textual")
fi

# ---- 3. Tier 1 — offensive tools with a real PyPI package ------------------
log_step "Installing pip-installable offensive tools referenced in the methodology data"

# name -> pypi package (differs from the command name for a couple of these)
declare -A PIP_TOOLS=(
    [impacket]="impacket"
    [bloodhound-python]="bloodhound"
    [dnsrecon]="dnsrecon"
    [ldapdomaindump]="ldapdomaindump"
    [ldeep]="ldeep"
    [certipy]="certipy-ad"
    [donpapi]="donpapi"
    [dploot]="dploot"
    [lsassy]="lsassy"
    [manspider]="manspider"
    [name-that-hash]="name-that-hash"
    [netexec]="netexec"
    [crackmapexec]="crackmapexec"
    [smbmap]="smbmap"
    [hashid]="hashid"
    [git-dumper]="git-dumper"
    [pyftpdlib]="pyftpdlib"
    [uploadserver]="uploadserver"
)

for cmd_name in "${!PIP_TOOLS[@]}"; do
    pkg="${PIP_TOOLS[$cmd_name]}"
    if pip install "$pkg" -q; then
        log_ok "$cmd_name  (pip package: $pkg)"
    else
        log_fail "$cmd_name  (pip package: $pkg) — install failed"
        FAILED_PIP+=("$pkg")
    fi
done

# ---- 4. Tier 2 — GitHub-only tools (no PyPI package) ------------------------
if [ "$SKIP_CLONE" -eq 1 ]; then
    log_step "Skipping git-clone tools (--no-clone)"
else
    log_step "Cloning & installing GitHub-only tools (no PyPI package exists for these)"
    mkdir -p "$TOOLS_DIR"

    # name -> repo URL
    declare -A CLONE_TOOLS=(
        [windapsearch]="https://github.com/ropnop/windapsearch.git"
        [gMSADumper]="https://github.com/micahvandeusen/gMSADumper.git"
        [sccmhunter]="https://github.com/garrettfoster13/sccmhunter.git"
    )

    for name in "${!CLONE_TOOLS[@]}"; do
        repo="${CLONE_TOOLS[$name]}"
        dest="$TOOLS_DIR/$name"
        if [ -d "$dest" ]; then
            log_ok "$name already cloned at $dest"
        elif git clone -q "$repo" "$dest" 2>/dev/null; then
            log_ok "$name cloned to $dest"
        else
            log_fail "$name — git clone failed (network or repo moved)"
            FAILED_CLONE+=("$name")
            continue
        fi
        if [ -f "$dest/requirements.txt" ]; then
            pip install -r "$dest/requirements.txt" -q || log_warn "$name: some requirements failed to install"
        fi
    done
fi

# ---- 5. Wordlists (rockyou, dirbuster, seclists) ----------------------------
if [ "$SKIP_APT" -eq 1 ]; then
    log_step "Skipping wordlist/apt setup (--no-apt)"
else
    log_step "Verifying wordlists (rockyou.txt, dirbuster, seclists)"

    if ! command -v apt-get >/dev/null 2>&1; then
        log_warn "apt-get not found — not a Debian/Kali system, skipping wordlist package checks"
    else
        for pkg in wordlists dirbuster seclists; do
            if dpkg -s "$pkg" >/dev/null 2>&1; then
                log_ok "apt package '$pkg' already installed"
            else
                log_warn "apt package '$pkg' missing — installing (this can take a while for seclists)"
                if sudo apt-get install -y "$pkg" -qq; then
                    log_ok "installed '$pkg'"
                else
                    log_fail "could not install '$pkg'"
                    MISSING_APT+=("$pkg")
                fi
            fi
        done
    fi

    ROCKYOU="/usr/share/wordlists/rockyou.txt"
    ROCKYOU_GZ="/usr/share/wordlists/rockyou.txt.gz"
    if [ -f "$ROCKYOU" ]; then
        log_ok "rockyou.txt already extracted at $ROCKYOU"
    elif [ -f "$ROCKYOU_GZ" ]; then
        if sudo gunzip -k "$ROCKYOU_GZ"; then
            log_ok "extracted rockyou.txt from $ROCKYOU_GZ"
        else
            log_fail "failed to extract $ROCKYOU_GZ"
        fi
    else
        log_warn "rockyou.txt not found anywhere under /usr/share/wordlists — the 'wordlists' apt package may not have installed correctly"
    fi

    if [ -d "/usr/share/wordlists/dirbuster" ]; then
        log_ok "dirbuster wordlists present at /usr/share/wordlists/dirbuster"
    else
        log_warn "no /usr/share/wordlists/dirbuster directory found"
    fi

    if [ -d "/usr/share/wordlists/seclists" ]; then
        log_ok "seclists present at /usr/share/wordlists/seclists"
    else
        log_warn "no /usr/share/wordlists/seclists directory found"
    fi
fi

# ---- 6. Summary --------------------------------------------------------------
log_step "Deployment summary"
echo -e "  Activate the venv with: ${C_YELLOW}source $VENV_DIR/bin/activate${C_RESET}"
echo -e "  Run the app with:       ${C_YELLOW}oscp-check${C_RESET}  (or: python3 -m src.main)"

if [ ${#FAILED_PIP[@]} -gt 0 ]; then
    log_warn "pip packages that failed to install: ${FAILED_PIP[*]}"
fi
if [ ${#FAILED_CLONE[@]} -gt 0 ]; then
    log_warn "GitHub tools that failed to clone: ${FAILED_CLONE[*]}"
fi
if [ ${#MISSING_APT[@]} -gt 0 ]; then
    log_warn "apt packages that failed to install: ${MISSING_APT[*]}"
fi

cat <<'EOF'

  Not covered by this script (no reliable automated source):
    - Compiled Windows post-ex binaries: mimikatz, Rubeus, SharpHound,
      GodPotato, PrintSpoofer, SeRestoreAbuse, SharpGPOAbuse, winPEAS,
      noPac.exe — grab current builds from their respective GitHub
      Releases pages and drop them wherever your Python HTTP server
      root points (see the File Transfer section in the app).
    - Go/Rust binaries: ligolo-ng, chisel, kerbrute, rusthound-ce —
      download prebuilt releases or `go install` / `cargo install`.
    - Ruby gems: evil-winrm, gpp-decrypt (gem install evil-winrm).
    - Standard Kali apt tools assumed already present: nmap, hydra,
      gobuster, feroxbuster, ffuf, sqlmap, exiftool, enum4linux,
      onesixtyone, snmp-check, sslscan, testssl.sh, tshark.
EOF
