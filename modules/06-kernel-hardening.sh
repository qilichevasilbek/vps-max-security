#!/bin/bash
# Module 06: Kernel hardening via sysctl

check_kernel_hardening() {
    [[ -f /etc/sysctl.d/99-hardening.conf ]] && \
    grep -q "kernel.dmesg_restrict = 1" /etc/sysctl.d/99-hardening.conf 2>/dev/null && \
    [[ "$(sysctl -n kernel.dmesg_restrict 2>/dev/null)" == "1" ]]
}

apply_kernel_hardening() {
    log_step "Writing hardened sysctl config..."
    backup_file "/etc/sysctl.d/99-hardening.conf"

    cp "${VMS_DIR}/configs/sysctl-hardening.conf" /etc/sysctl.d/99-hardening.conf

    # Disable IPv6 if not needed
    if [[ "${ENABLE_IPV6}" == "false" ]]; then
        log_step "Disabling IPv6..."
        cat >> /etc/sysctl.d/99-hardening.conf << 'EOF'

#=============================================
# IPv6 (disabled)
#=============================================
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1
EOF
    fi

    log_step "Applying sysctl settings..."
    sysctl --system &>/dev/null

    log_success "Kernel hardened via sysctl"
}

audit_kernel_hardening() {
    [[ "$(sysctl -n kernel.dmesg_restrict 2>/dev/null)" == "1" ]] && \
    [[ "$(sysctl -n kernel.kptr_restrict 2>/dev/null)" == "2" ]] && \
    [[ "$(sysctl -n net.ipv4.tcp_syncookies 2>/dev/null)" == "1" ]] && \
    [[ "$(sysctl -n kernel.randomize_va_space 2>/dev/null)" == "2" ]] && \
    [[ "$(sysctl -n net.ipv4.conf.all.rp_filter 2>/dev/null)" == "1" ]]
}
