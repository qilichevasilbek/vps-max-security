#!/bin/bash
# core.sh — Logging, colors, guards, backup/restore, file helpers
# shellcheck disable=SC2034

VMS_VERSION="$(cat "${VMS_DIR}/VERSION" 2>/dev/null || echo "unknown")"
readonly VMS_VERSION
readonly VMS_CONFIG_DIR="/etc/vps-max-security"
readonly VMS_BACKUP_DIR="${VMS_CONFIG_DIR}/backups"
readonly VMS_STATE_FILE="${VMS_CONFIG_DIR}/state"
readonly VMS_LOG_FILE="${VMS_CONFIG_DIR}/hardening.log"
readonly VMS_CONFIG_FILE="${VMS_CONFIG_DIR}/config.conf"

# Colors
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly CYAN='\033[0;36m'
readonly BOLD='\033[1m'
readonly DIM='\033[2m'
readonly NC='\033[0m'

# Dry-run mode (set by CLI)
DRY_RUN="${DRY_RUN:-false}"

# ── Logging ──────────────────────────────────────────────

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
    _log_to_file "INFO" "$1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
    _log_to_file "WARN" "$1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
    _log_to_file "ERROR" "$1"
}

log_step() {
    echo -e "${CYAN}  ▸${NC} $1"
    _log_to_file "STEP" "$1"
}

log_success() {
    echo -e "${GREEN}  ✓${NC} $1"
    _log_to_file "OK" "$1"
}

log_skip() {
    echo -e "${DIM}  ○ $1 (already applied)${NC}"
    _log_to_file "SKIP" "$1"
}

log_dry() {
    echo -e "${BLUE}[DRY-RUN]${NC} $1"
}

_log_to_file() {
    local level="$1" msg="$2"
    if [[ -d "${VMS_CONFIG_DIR}" ]]; then
        echo "$(date '+%Y-%m-%d %H:%M:%S') [${level}] ${msg}" >> "${VMS_LOG_FILE}" 2>/dev/null || true
    fi
}

# ── Guards ───────────────────────────────────────────────

require_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This tool must be run as root (use sudo)."
        exit 1
    fi
}

require_ubuntu() {
    if [[ ! -f /etc/os-release ]]; then
        log_error "Cannot detect OS. /etc/os-release not found."
        exit 1
    fi
    # shellcheck disable=SC1091
    source /etc/os-release
    if [[ "${ID}" != "ubuntu" ]]; then
        log_error "This tool is designed for Ubuntu. Detected: ${ID}"
        exit 1
    fi
    if [[ "${VERSION_ID}" != "24.04" ]]; then
        log_warn "Designed for Ubuntu 24.04. Detected: ${VERSION_ID}. Proceeding anyway."
    fi
}

require_user_exists() {
    local user="$1"
    if ! id "${user}" &>/dev/null; then
        log_error "User '${user}' does not exist. Create it first:"
        echo "  adduser ${user} && usermod -aG sudo ${user}"
        exit 1
    fi
}

require_ssh_keys() {
    local user="$1"
    local keyfile="/home/${user}/.ssh/authorized_keys"
    if [[ ! -f "${keyfile}" ]] || [[ ! -s "${keyfile}" ]]; then
        log_error "No SSH keys found for '${user}'. Set up key auth first:"
        echo "  ssh-copy-id -i ~/.ssh/id_ed25519.pub ${user}@YOUR_VPS_IP"
        exit 1
    fi
}

# ── Init ─────────────────────────────────────────────────

init_dirs() {
    mkdir -p "${VMS_CONFIG_DIR}" "${VMS_BACKUP_DIR}"
    touch "${VMS_LOG_FILE}" "${VMS_STATE_FILE}"
}

# ── Backup / Restore ─────────────────────────────────────

backup_file() {
    local file="$1"
    if [[ ! -f "${file}" ]]; then
        return 0
    fi
    local ts
    ts="$(date +%Y%m%d-%H%M%S)"
    local dest="${VMS_BACKUP_DIR}/${file//\//_}_${ts}"
    if [[ "${DRY_RUN}" == "true" ]]; then
        log_dry "Would backup ${file} → ${dest}"
        return 0
    fi
    cp -a "${file}" "${dest}"
    log_step "Backed up ${file}"
}

restore_latest() {
    local file="$1"
    local pattern="${VMS_BACKUP_DIR}/${file//\//_}_*"
    # shellcheck disable=SC2086
    local latest
    latest="$(ls -t ${pattern} 2>/dev/null | head -1)"
    if [[ -z "${latest}" ]]; then
        log_error "No backup found for ${file}"
        return 1
    fi
    cp -a "${latest}" "${file}"
    log_info "Restored ${file} from ${latest}"
}

rollback_all() {
    log_info "Rolling back all changes from latest backups..."
    local count=0
    local restored_files=""
    for backup in "${VMS_BACKUP_DIR}"/*; do
        [[ -f "${backup}" ]] || continue
        local basename
        basename="$(basename "${backup}")"
        # Strip timestamp suffix: _YYYYMMDD-HHMMSS
        local original
        original="${basename%_[0-9]*-[0-9]*}"
        original="${original//_/\/}"
        # Only restore the latest backup per original file
        if [[ "${restored_files}" == *"|${original}|"* ]]; then
            continue
        fi
        restored_files="${restored_files}|${original}|"
        restore_latest "${original}" && ((count++))
    done
    log_info "Restored ${count} file(s). Restarting services..."
    systemctl restart ssh 2>/dev/null || true
    systemctl restart fail2ban 2>/dev/null || true
    ufw reload 2>/dev/null || true
    sysctl --system &>/dev/null || true
    log_success "Rollback complete."
}

# ── File Helpers ─────────────────────────────────────────

# Write file only if content changed (SHA256 comparison)
safe_write() {
    local dest="$1" content="$2"
    if [[ "${DRY_RUN}" == "true" ]]; then
        log_dry "Would write ${dest}"
        return 0
    fi
    local new_hash old_hash=""
    new_hash="$(echo "${content}" | sha256sum | awk '{print $1}')"
    if [[ -f "${dest}" ]]; then
        old_hash="$(sha256sum "${dest}" | awk '{print $1}')"
    fi
    if [[ "${new_hash}" == "${old_hash}" ]]; then
        return 1  # No change needed
    fi
    backup_file "${dest}"
    echo "${content}" > "${dest}"
    return 0
}

# Install a config template with variable substitution
install_config() {
    local template="$1" dest="$2"
    if [[ ! -f "${template}" ]]; then
        log_error "Template not found: ${template}"
        return 1
    fi
    local content
    content="$(envsubst < "${template}")"
    safe_write "${dest}" "${content}"
}

# ── State Tracking ───────────────────────────────────────

state_set() {
    local module="$1" status="$2"
    local ts
    ts="$(date '+%Y-%m-%d %H:%M:%S')"
    # Remove old entry for this module
    if [[ -f "${VMS_STATE_FILE}" ]]; then
        local tmp
        tmp="$(grep -v "^${module}|" "${VMS_STATE_FILE}" 2>/dev/null || true)"
        echo "${tmp}" > "${VMS_STATE_FILE}"
    fi
    echo "${module}|${status}|${ts}" >> "${VMS_STATE_FILE}"
}

state_get() {
    local module="$1"
    grep "^${module}|" "${VMS_STATE_FILE}" 2>/dev/null | tail -1
}

state_list() {
    if [[ ! -s "${VMS_STATE_FILE}" ]]; then
        echo "No modules have been applied yet."
        return
    fi
    printf "${BOLD}%-25s %-12s %s${NC}\n" "MODULE" "STATUS" "TIMESTAMP"
    echo "─────────────────────────────────────────────────────────"
    while IFS='|' read -r module status ts; do
        [[ -z "${module}" ]] && continue
        local color="${NC}"
        case "${status}" in
            applied)  color="${GREEN}" ;;
            skipped)  color="${DIM}" ;;
            failed)   color="${RED}" ;;
        esac
        printf "${color}%-25s %-12s %s${NC}\n" "${module}" "${status}" "${ts}"
    done < "${VMS_STATE_FILE}"
}
