#!/bin/bash
# config.sh — Config load/save/validate/defaults + auto-detection

# ── Auto-detection helpers ──────────────────────────────────

detect_docker() {
    command -v docker &>/dev/null && echo "true" || echo "false"
}

detect_ssh_port() {
    grep -oP '^\s*Port\s+\K\d+' /etc/ssh/sshd_config 2>/dev/null | head -1 || echo "22"
}

detect_admin_user() {
    local user="${SUDO_USER:-}"
    [[ -z "${user}" ]] && user="$(logname 2>/dev/null || true)"
    [[ -z "${user}" || "${user}" == "root" ]] && user="deployer"
    echo "${user}"
}

detect_ipv6() {
    if ip -6 addr show scope global 2>/dev/null | grep -q inet6; then
        echo "true"
    else
        echo "false"
    fi
}

detect_container_count() {
    if command -v docker &>/dev/null; then
        docker ps -q 2>/dev/null | wc -l | tr -d ' '
    else
        echo "0"
    fi
}

# ── Profile → port expansion ────────────────────────────────

profile_apply() {
    case "${PROFILE}" in
        web)
            PUBLIC_TCP_PORTS="80,443"
            PUBLIC_UDP_PORTS=""
            ;;
        realtime)
            PUBLIC_TCP_PORTS="80,443"
            PUBLIC_UDP_PORTS="3478,50000:50100"
            ;;
        custom)
            # PUBLIC_TCP_PORTS and PUBLIC_UDP_PORTS set by wizard or config
            ;;
        *)
            log_warn "Unknown profile '${PROFILE}', falling back to 'web'"
            PROFILE="web"
            PUBLIC_TCP_PORTS="80,443"
            PUBLIC_UDP_PORTS=""
            ;;
    esac
}

# ── Load ────────────────────────────────────────────────────

# Load defaults, then overlay saved config, then migrate legacy vars
config_load() {
    # Source defaults first
    # shellcheck disable=SC1091
    source "${VMS_DIR}/configs/defaults.conf"

    # Overlay saved config if it exists
    if [[ -f "${VMS_CONFIG_FILE}" ]]; then
        # shellcheck disable=SC1090
        source "${VMS_CONFIG_FILE}"
        log_step "Loaded config from ${VMS_CONFIG_FILE}"
    fi

    # ── Backward compat: migrate 1.x FIREWALL_PORTS ──
    if [[ -z "${PROFILE:-}" && -n "${FIREWALL_PORTS:-}" ]]; then
        PROFILE="custom"
        PUBLIC_TCP_PORTS="${FIREWALL_PORTS}"
        PUBLIC_UDP_PORTS="${PUBLIC_UDP_PORTS:-}"
    fi
    # Migrate old LIVEKIT_ENABLED to realtime profile
    if [[ "${LIVEKIT_ENABLED:-}" == "true" && "${PROFILE:-}" != "realtime" ]]; then
        PROFILE="realtime"
        local lk_start="${LIVEKIT_UDP_RANGE_START:-50000}"
        local lk_end="${LIVEKIT_UDP_RANGE_END:-50100}"
        PUBLIC_UDP_PORTS="3478,${lk_start}:${lk_end}"
    fi

    # Auto-detect things the wizard won't ask about
    DOCKER_DETECTED="$(detect_docker)"
    export DOCKER_DETECTED
}

# ── Save ────────────────────────────────────────────────────

config_save() {
    if [[ "${DRY_RUN}" == "true" ]]; then
        log_dry "Would save config to ${VMS_CONFIG_FILE}"
        return 0
    fi

    mkdir -p "$(dirname "${VMS_CONFIG_FILE}")"
    cat > "${VMS_CONFIG_FILE}" << EOF
# vps-max-security configuration
# Generated: $(date '+%Y-%m-%d %H:%M:%S')
# Edit this file and re-run 'sudo vps-max-security' to apply changes.

# Profile: web | realtime | custom
PROFILE="${PROFILE}"

# Ports opened through the firewall (and DOCKER-USER chain)
PUBLIC_TCP_PORTS="${PUBLIC_TCP_PORTS}"
PUBLIC_UDP_PORTS="${PUBLIC_UDP_PORTS}"

# SSH
SSH_PORT="${SSH_PORT}"
ADMIN_USER="${ADMIN_USER}"

# Advanced (change here, not in wizard)
ENABLE_IPV6="${ENABLE_IPV6}"
DNS_PROVIDER="${DNS_PROVIDER}"
MAX_SSH_RETRIES="${MAX_SSH_RETRIES}"
BAN_DURATION_HOURS="${BAN_DURATION_HOURS}"
SHM_NOEXEC="${SHM_NOEXEC}"
RUN_ALL_MODULES="${RUN_ALL_MODULES}"
EOF
    chmod 600 "${VMS_CONFIG_FILE}"
    log_step "Config saved to ${VMS_CONFIG_FILE}"
}

# ── Validate ────────────────────────────────────────────────

config_validate() {
    local errors=0

    # Profile
    case "${PROFILE}" in
        web|realtime|custom) ;;
        *)
            log_error "Invalid profile: ${PROFILE} (must be web, realtime, or custom)"
            ((errors++)) || true
            ;;
    esac

    # SSH port
    if [[ ! "${SSH_PORT}" =~ ^[0-9]+$ ]]; then
        log_error "Invalid SSH port: ${SSH_PORT} (must be numeric)"
        ((errors++)) || true
    elif (( SSH_PORT < 1 || SSH_PORT > 65535 )); then
        log_error "Invalid SSH port: ${SSH_PORT} (must be 1-65535)"
        ((errors++)) || true
    fi
    if (( SSH_PORT == 22 )); then
        log_warn "Using default port 22 is not recommended."
    fi

    # Admin user
    if [[ -z "${ADMIN_USER}" ]]; then
        log_error "Admin user cannot be empty."
        ((errors++)) || true
    elif [[ ! "${ADMIN_USER}" =~ ^[a-z_][a-z0-9_-]{0,31}$ ]]; then
        log_error "Invalid admin user: ${ADMIN_USER} (must be a valid Linux username)"
        ((errors++)) || true
    fi

    # TCP ports: comma-separated numbers or ranges (e.g., "80,443,8080:8090")
    if [[ -n "${PUBLIC_TCP_PORTS}" && ! "${PUBLIC_TCP_PORTS}" =~ ^[0-9,:[:space:]]+$ ]]; then
        log_error "Invalid TCP ports: ${PUBLIC_TCP_PORTS}"
        ((errors++)) || true
    fi

    # UDP ports: same format, can be empty
    if [[ -n "${PUBLIC_UDP_PORTS}" && ! "${PUBLIC_UDP_PORTS}" =~ ^[0-9,:[:space:]]+$ ]]; then
        log_error "Invalid UDP ports: ${PUBLIC_UDP_PORTS}"
        ((errors++)) || true
    fi

    # Max retries
    if [[ ! "${MAX_SSH_RETRIES}" =~ ^[0-9]+$ ]] || (( MAX_SSH_RETRIES < 1 )); then
        log_error "Invalid max SSH retries: ${MAX_SSH_RETRIES}"
        ((errors++)) || true
    fi

    # Ban duration
    if [[ ! "${BAN_DURATION_HOURS}" =~ ^[0-9]+$ ]] || (( BAN_DURATION_HOURS < 1 )); then
        log_error "Invalid ban duration: ${BAN_DURATION_HOURS}"
        ((errors++)) || true
    fi

    # DNS provider
    case "${DNS_PROVIDER}" in
        cloudflare|quad9|google) ;;
        *)
            log_error "Invalid DNS provider: ${DNS_PROVIDER} (use cloudflare, quad9, or google)"
            ((errors++)) || true
            ;;
    esac

    (( errors > 0 )) && return 1
    return 0
}

# ── DNS helpers ─────────────────────────────────────────────

config_dns_primary() {
    case "${DNS_PROVIDER}" in
        cloudflare) echo "1.1.1.1 1.0.0.1" ;;
        quad9)      echo "9.9.9.9 149.112.112.112" ;;
        google)     echo "8.8.8.8 8.8.4.4" ;;
        *)          echo "1.1.1.1 1.0.0.1" ;;
    esac
}

config_dns_fallback() {
    case "${DNS_PROVIDER}" in
        cloudflare) echo "9.9.9.9" ;;
        quad9)      echo "1.1.1.1" ;;
        google)     echo "1.1.1.1" ;;
        *)          echo "1.1.1.1 1.0.0.1" ;;
    esac
}

# ── Compute derived values + export for envsubst ────────────

config_compute() {
    # Expand profile into port lists (if not custom)
    profile_apply

    # Ban duration in seconds
    BAN_DURATION_SECS=$(( BAN_DURATION_HOURS * 3600 ))

    # DNS values
    DNS_PRIMARY="$(config_dns_primary)"
    DNS_FALLBACK="$(config_dns_fallback)"

    # Backward compat alias (some modules may still reference this)
    FIREWALL_PORTS="${PUBLIC_TCP_PORTS}"

    # Export ALL config vars so envsubst (called by install_config) can see them.
    export PROFILE PUBLIC_TCP_PORTS PUBLIC_UDP_PORTS \
           SSH_PORT ADMIN_USER ENABLE_IPV6 FIREWALL_PORTS \
           MAX_SSH_RETRIES BAN_DURATION_HOURS DNS_PROVIDER \
           RUN_ALL_MODULES BAN_DURATION_SECS DNS_PRIMARY DNS_FALLBACK \
           SHM_NOEXEC DOCKER_DETECTED
}
