#!/bin/bash
# config.sh — Config load/save/validate/defaults

# Load defaults, then overlay saved config
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
}

# Save current config values to disk
config_save() {
    if [[ "${DRY_RUN}" == "true" ]]; then
        log_dry "Would save config to ${VMS_CONFIG_FILE}"
        return 0
    fi

    mkdir -p "$(dirname "${VMS_CONFIG_FILE}")"
    cat > "${VMS_CONFIG_FILE}" << EOF
# vps-max-security configuration
# Generated: $(date '+%Y-%m-%d %H:%M:%S')

SSH_PORT="${SSH_PORT}"
ADMIN_USER="${ADMIN_USER}"
ENABLE_IPV6="${ENABLE_IPV6}"
FIREWALL_PORTS="${FIREWALL_PORTS}"
MAX_SSH_RETRIES="${MAX_SSH_RETRIES}"
BAN_DURATION_HOURS="${BAN_DURATION_HOURS}"
DNS_PROVIDER="${DNS_PROVIDER}"
RUN_ALL_MODULES="${RUN_ALL_MODULES}"
EOF
    chmod 600 "${VMS_CONFIG_FILE}"
    log_step "Config saved to ${VMS_CONFIG_FILE}"
}

# Validate config values
config_validate() {
    local errors=0

    # SSH port
    if [[ ! "${SSH_PORT}" =~ ^[0-9]+$ ]] || (( SSH_PORT < 1 || SSH_PORT > 65535 )); then
        log_error "Invalid SSH port: ${SSH_PORT}"
        ((errors++))
    fi
    if (( SSH_PORT == 22 )); then
        log_warn "Using default port 22 is not recommended."
    fi

    # Admin user
    if [[ -z "${ADMIN_USER}" ]]; then
        log_error "Admin user cannot be empty."
        ((errors++))
    fi

    # Max retries
    if [[ ! "${MAX_SSH_RETRIES}" =~ ^[0-9]+$ ]] || (( MAX_SSH_RETRIES < 1 )); then
        log_error "Invalid max SSH retries: ${MAX_SSH_RETRIES}"
        ((errors++))
    fi

    # Ban duration
    if [[ ! "${BAN_DURATION_HOURS}" =~ ^[0-9]+$ ]] || (( BAN_DURATION_HOURS < 1 )); then
        log_error "Invalid ban duration: ${BAN_DURATION_HOURS}"
        ((errors++))
    fi

    # DNS provider
    case "${DNS_PROVIDER}" in
        cloudflare|quad9|google) ;;
        *)
            log_error "Invalid DNS provider: ${DNS_PROVIDER} (use cloudflare, quad9, or google)"
            ((errors++))
            ;;
    esac

    return "${errors}"
}

# Get DNS IPs based on provider choice
config_dns_primary() {
    case "${DNS_PROVIDER}" in
        cloudflare) echo "1.1.1.1 1.0.0.1" ;;
        quad9)      echo "9.9.9.9 149.112.112.112" ;;
        google)     echo "8.8.8.8 8.8.4.4" ;;
    esac
}

config_dns_fallback() {
    case "${DNS_PROVIDER}" in
        cloudflare) echo "9.9.9.9" ;;
        quad9)      echo "1.1.1.1" ;;
        google)     echo "1.1.1.1" ;;
    esac
}

# Compute derived values
config_compute() {
    # Ban duration in seconds
    BAN_DURATION_SECS=$(( BAN_DURATION_HOURS * 3600 ))
    export BAN_DURATION_SECS

    # DNS values
    DNS_PRIMARY="$(config_dns_primary)"
    DNS_FALLBACK="$(config_dns_fallback)"
    export DNS_PRIMARY DNS_FALLBACK

    # Firewall ports as array
    IFS=',' read -ra FW_PORTS <<< "${FIREWALL_PORTS}"
    export FW_PORTS
}
