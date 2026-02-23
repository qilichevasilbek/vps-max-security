#!/bin/bash
# Module 04: UFW firewall configuration

check_firewall() {
    ufw status 2>/dev/null | grep -q "Status: active" && \
    ufw status 2>/dev/null | grep -q "${SSH_PORT}/tcp"
}

apply_firewall() {
    log_step "Installing UFW..."
    apt install ufw -y

    log_step "Setting default policies..."
    ufw default deny incoming
    ufw default allow outgoing

    log_step "Allowing SSH on port ${SSH_PORT}..."
    ufw allow "${SSH_PORT}"/tcp comment 'SSH'

    log_step "Allowing additional ports: ${FIREWALL_PORTS}..."
    IFS=',' read -ra ports <<< "${FIREWALL_PORTS}"
    for port in "${ports[@]}"; do
        port="$(echo "${port}" | tr -d ' ')"
        ufw allow "${port}"/tcp comment "allowed-${port}"
    done

    log_step "Rate-limiting SSH..."
    ufw limit "${SSH_PORT}"/tcp

    log_step "Enabling firewall..."
    echo "y" | ufw enable

    log_success "UFW firewall configured and active"
}

audit_firewall() {
    ufw status 2>/dev/null | grep -q "Status: active" && \
    ufw status 2>/dev/null | grep -q "${SSH_PORT}/tcp" && \
    ufw status 2>/dev/null | grep -q "LIMIT"
}
