#!/bin/bash
#=====================================================================
# vps-max-security — Bootstrap Installer
# Usage: curl -fsSL https://raw.githubusercontent.com/qilichevasilbek/vps-max-security/master/install.sh | sudo bash
#=====================================================================

set -euo pipefail

readonly INSTALL_DIR="/opt/vps-max-security"
readonly REPO_URL="https://github.com/qilichevasilbek/vps-max-security.git"
readonly BIN_LINK="/usr/local/bin/vps-max-security"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info()  { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

echo ""
echo "══════════════════════════════════════════════════"
echo "  VPS MAX SECURITY — Installer"
echo "══════════════════════════════════════════════════"
echo ""

# ── Pre-flight checks ────────────────────────────────────

# Must be root
if [[ $EUID -ne 0 ]]; then
    log_error "This installer must be run as root (use sudo)."
    exit 1
fi

# Must be Ubuntu
if [[ -f /etc/os-release ]]; then
    # shellcheck disable=SC1091
    source /etc/os-release
    if [[ "${ID}" != "ubuntu" ]]; then
        log_error "This tool is designed for Ubuntu. Detected: ${ID}"
        exit 1
    fi
    if [[ "${VERSION_ID}" != "24.04" ]]; then
        log_warn "Designed for Ubuntu 24.04. Detected: ${VERSION_ID}."
    fi
    log_info "Detected: ${PRETTY_NAME}"
else
    log_error "Cannot detect OS. /etc/os-release not found."
    exit 1
fi

# ── Install git if needed ────────────────────────────────

if ! command -v git &>/dev/null; then
    log_info "Installing git..."
    apt update -y && apt install git -y
fi

# ── Clone or update ──────────────────────────────────────

if [[ -d "${INSTALL_DIR}" ]]; then
    log_info "Existing installation found. Updating..."
    git -C "${INSTALL_DIR}" pull --ff-only
else
    log_info "Cloning vps-max-security..."
    git clone "${REPO_URL}" "${INSTALL_DIR}"
fi

# ── Create symlink ───────────────────────────────────────

if [[ -L "${BIN_LINK}" ]]; then
    rm -f "${BIN_LINK}"
fi
ln -s "${INSTALL_DIR}/vps-max-security" "${BIN_LINK}"
chmod +x "${INSTALL_DIR}/vps-max-security"

# ── Verify ───────────────────────────────────────────────

log_info "Installation complete!"
echo ""
echo "  Installed to:  ${INSTALL_DIR}"
echo "  CLI command:   vps-max-security"
echo "  Version:       $(cat "${INSTALL_DIR}/VERSION")"
echo ""
echo "  Get started:"
echo "    sudo vps-max-security              # Interactive wizard"
echo "    sudo vps-max-security --dry-run    # Preview changes"
echo "    sudo vps-max-security --help       # Show all options"
echo ""
