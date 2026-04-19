#!/bin/bash
#=====================================================================
# vps-max-security — Bootstrap Installer
#
# Run on a brand-new VPS (Contabo, Hetzner, Hostinger, DigitalOcean):
#   curl -fsSL https://raw.githubusercontent.com/qilichevasilbek/vps-max-security/master/install.sh | sudo bash
#
# What this does:
#   1. Verifies Ubuntu 24.04
#   2. Installs git (if missing)
#   3. Clones the repo to /opt/vps-max-security
#   4. Creates /usr/local/bin/vps-max-security symlink
#
# Then you run: sudo vps-max-security
# The tool will:
#   - Create your admin user (if needed)
#   - Copy SSH keys from root (if available)
#   - Ask 3 questions (profile, SSH port, admin user)
#   - Apply 20 hardening modules
#=====================================================================

set -euo pipefail

readonly INSTALL_DIR="/opt/vps-max-security"
readonly REPO_URL="https://github.com/qilichevasilbek/vps-max-security.git"
readonly BIN_LINK="/usr/local/bin/vps-max-security"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

log_info()  { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

echo ""
echo -e "${BOLD}══════════════════════════════════════════════════${NC}"
echo -e "${BOLD}  VPS MAX SECURITY — Installer${NC}"
echo -e "${BOLD}══════════════════════════════════════════════════${NC}"
echo ""

# ── Pre-flight checks ────────────────────────────────────

if [[ $EUID -ne 0 ]]; then
    log_error "Run as root: curl ... | sudo bash"
    exit 1
fi

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
    log_error "Cannot detect OS."
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
    git -C "${INSTALL_DIR}" pull --ff-only || {
        log_warn "Pull failed. Re-cloning..."
        rm -rf "${INSTALL_DIR}"
        git clone "${REPO_URL}" "${INSTALL_DIR}"
    }
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

# ── Done ─────────────────────────────────────────────────

log_info "Installation complete!"
echo ""
echo "  Installed to:  ${INSTALL_DIR}"
echo "  Version:       $(cat "${INSTALL_DIR}/VERSION")"
echo ""
echo -e "${BOLD}  Next: run the hardening tool:${NC}"
echo ""
echo -e "    ${GREEN}sudo vps-max-security${NC}"
echo ""
echo -e "${DIM}  The tool will:${NC}"
echo -e "${DIM}    • Create an admin user (if you only have root)${NC}"
echo -e "${DIM}    • Set up SSH keys (copies from root or lets you paste)${NC}"
echo -e "${DIM}    • Ask 3 questions (profile, SSH port, admin user)${NC}"
echo -e "${DIM}    • Apply 20 hardening modules${NC}"
echo -e "${DIM}    • Install DOCKER-USER firewall if Docker is present${NC}"
echo ""
