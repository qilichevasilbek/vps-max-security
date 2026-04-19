#!/bin/bash
# Module 04: UFW firewall + DOCKER-USER chain
#
# Closes the UFW ↔ Docker bypass (Docker DNAT rules run before filter INPUT,
# so UFW's "default deny incoming" does NOT protect published container ports).
# Installs a default-DROP DOCKER-USER chain via /etc/ufw/after.rules markers.
#
# Generic: uses PUBLIC_TCP_PORTS and PUBLIC_UDP_PORTS set by profile/wizard.
# No application-specific knowledge (LiveKit, Jitsi, etc.) — just port lists.

_VMS_DU_BEGIN='# BEGIN VPS-MAX-SECURITY DOCKER-USER'
_VMS_DU_END='# END VPS-MAX-SECURITY DOCKER-USER'
_VMS_UFW_AFTER='/etc/ufw/after.rules'

check_firewall() {
    ufw status 2>/dev/null | grep -q "Status: active" && \
    ufw status 2>/dev/null | grep -q "${SSH_PORT}/tcp" && \
    grep -qF "${_VMS_DU_BEGIN}" "${_VMS_UFW_AFTER}" 2>/dev/null
}

apply_firewall() {
    backup_file "/etc/ufw/user.rules"
    backup_file "/etc/ufw/user6.rules"

    log_step "Installing UFW..."
    apt install ufw -y

    log_step "Setting default policies..."
    ufw default deny incoming
    ufw default allow outgoing

    # Open public TCP ports
    local tcp_ports="${PUBLIC_TCP_PORTS:-80,443}"
    if [[ -n "${tcp_ports}" ]]; then
        log_step "Allowing public TCP ports: ${tcp_ports}..."
        IFS=',' read -ra tcp_list <<< "${tcp_ports}"
        for port in "${tcp_list[@]}"; do
            port="$(echo "${port}" | tr -d ' ')"
            [[ -z "${port}" ]] && continue
            ufw allow "${port}"/tcp comment "public-tcp-${port}"
        done
    fi

    # Open public UDP ports (if any — empty for "web" profile)
    local udp_ports="${PUBLIC_UDP_PORTS:-}"
    if [[ -n "${udp_ports}" ]]; then
        log_step "Allowing public UDP ports: ${udp_ports}..."
        IFS=',' read -ra udp_list <<< "${udp_ports}"
        for port in "${udp_list[@]}"; do
            port="$(echo "${port}" | tr -d ' ')"
            [[ -z "${port}" ]] && continue
            ufw allow "${port}"/udp comment "public-udp-${port}"
        done
    fi

    log_step "Rate-limiting SSH..."
    ufw limit "${SSH_PORT}"/tcp

    log_step "Enabling firewall..."
    echo "y" | ufw enable

    # Docker needs the FORWARD chain to accept forwarded bridge traffic,
    # but we enforce per-packet policy in DOCKER-USER below.
    if [[ -f /etc/default/ufw ]]; then
        backup_file "/etc/default/ufw"
        sed -i 's/DEFAULT_FORWARD_POLICY="DROP"/DEFAULT_FORWARD_POLICY="ACCEPT"/' /etc/default/ufw
    fi

    # Only install DOCKER-USER chain if Docker is present
    if [[ "${DOCKER_DETECTED:-false}" == "true" ]]; then
        log_step "Installing default-DROP DOCKER-USER chain..."
        install_docker_user_chain
    else
        log_info "Docker not detected — skipping DOCKER-USER chain"
    fi

    log_step "Reloading UFW..."
    ufw reload || true

    log_success "UFW firewall configured"
    if [[ "${DOCKER_DETECTED:-false}" == "true" ]]; then
        log_info "DOCKER-USER chain active: only TCP [${tcp_ports}] and UDP [${udp_ports:-none}] reach containers."
    fi
}

# Install DOCKER-USER chain rules into /etc/ufw/after.rules.
# Generic: uses PUBLIC_TCP_PORTS + PUBLIC_UDP_PORTS, no app-specific logic.
install_docker_user_chain() {
    backup_file "${_VMS_UFW_AFTER}"

    local tcp_ports udp_ports
    tcp_ports="$(echo "${PUBLIC_TCP_PORTS:-80,443}" | tr -d ' ')"
    udp_ports="$(echo "${PUBLIC_UDP_PORTS:-}" | tr -d ' ')"

    # Build UDP rules only if there are UDP ports to open
    local udp_rules=""
    if [[ -n "${udp_ports}" ]]; then
        udp_rules="-A DOCKER-USER -p udp -m multiport --dports ${udp_ports} -j RETURN"
    else
        udp_rules="# (no public UDP ports configured)"
    fi

    local block
    block=$(cat <<RULES
${_VMS_DU_BEGIN}
# DOCKER-USER chain — installed by vps-max-security.
# Filters forwarded packets destined for Docker containers.
# Profile: ${PROFILE:-custom} | TCP: ${tcp_ports} | UDP: ${udp_ports:-none}
:DOCKER-USER - [0:0]
-A DOCKER-USER -m conntrack --ctstate RELATED,ESTABLISHED -j RETURN
-A DOCKER-USER -m conntrack --ctstate INVALID -j DROP
-A DOCKER-USER -i lo -j RETURN
-A DOCKER-USER -s 172.16.0.0/12 -j RETURN
-A DOCKER-USER -s 10.0.0.0/8 -j RETURN
-A DOCKER-USER -s 192.168.0.0/16 -j RETURN
-A DOCKER-USER -p tcp -m multiport --dports ${tcp_ports} -j RETURN
${udp_rules}
-A DOCKER-USER -p tcp --syn -m multiport --dports ${tcp_ports} -m hashlimit --hashlimit-name vms-syn --hashlimit-mode srcip --hashlimit-above 50/sec --hashlimit-burst 100 -j DROP
-A DOCKER-USER -p tcp --syn -m connlimit --connlimit-above 100 --connlimit-mask 32 -j DROP
-A DOCKER-USER -j DROP
${_VMS_DU_END}
RULES
)

    if [[ "${DRY_RUN}" == "true" ]]; then
        log_dry "Would install DOCKER-USER block in ${_VMS_UFW_AFTER}"
        return 0
    fi

    # Bootstrap after.rules if missing
    if [[ ! -f "${_VMS_UFW_AFTER}" ]] || ! grep -q '^\*filter' "${_VMS_UFW_AFTER}"; then
        cat > "${_VMS_UFW_AFTER}" <<'STUB'
*filter
:ufw-after-input - [0:0]
:ufw-after-output - [0:0]
:ufw-after-forward - [0:0]
COMMIT
STUB
    fi

    # Remove any existing block (idempotency)
    if grep -qF "${_VMS_DU_BEGIN}" "${_VMS_UFW_AFTER}"; then
        sed -i "/${_VMS_DU_BEGIN}/,/${_VMS_DU_END}/d" "${_VMS_UFW_AFTER}"
    fi

    # Insert BEFORE first ^COMMIT$ so rules are inside the *filter section.
    local tmp inserted=false line
    tmp="$(mktemp)"
    while IFS= read -r line || [[ -n "${line}" ]]; do
        if [[ "${line}" == "COMMIT" ]] && [[ "${inserted}" == "false" ]]; then
            printf '%s\n' "${block}"
            inserted=true
        fi
        printf '%s\n' "${line}"
    done < "${_VMS_UFW_AFTER}" > "${tmp}"

    if ! grep -qF "${_VMS_DU_BEGIN}" "${tmp}"; then
        log_error "Failed to insert DOCKER-USER block — no COMMIT line found"
        rm -f "${tmp}"
        return 1
    fi

    mv "${tmp}" "${_VMS_UFW_AFTER}"
    chmod 640 "${_VMS_UFW_AFTER}"
}

audit_firewall() {
    ufw status 2>/dev/null | grep -q "Status: active" || return 1
    ufw status 2>/dev/null | grep -q "${SSH_PORT}/tcp" || return 1
    ufw status 2>/dev/null | grep -q "LIMIT" || return 1
    # DOCKER-USER chain only required if Docker is present
    if [[ "${DOCKER_DETECTED:-false}" == "true" ]]; then
        grep -qF "${_VMS_DU_BEGIN}" "${_VMS_UFW_AFTER}" 2>/dev/null || return 1
        iptables -L DOCKER-USER -n 2>/dev/null | tail -2 | grep -q "DROP" || return 1
    fi
    return 0
}
