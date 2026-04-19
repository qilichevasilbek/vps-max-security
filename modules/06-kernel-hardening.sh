#!/bin/bash
# Module 06: Kernel hardening via sysctl (+ br_netfilter autoload + core dump lockdown)

check_kernel_hardening() {
    [[ -f /etc/sysctl.d/99-hardening.conf ]] && \
    grep -q "kernel.dmesg_restrict = 1" /etc/sysctl.d/99-hardening.conf 2>/dev/null && \
    [[ -f /etc/modules-load.d/br_netfilter.conf ]] && \
    [[ -f /etc/security/limits.d/10-nocore.conf ]] && \
    [[ "$(sysctl -n kernel.dmesg_restrict 2>/dev/null)" == "1" ]] && \
    [[ "$(sysctl -n fs.protected_symlinks 2>/dev/null)" == "1" ]]
}

apply_kernel_hardening() {
    log_step "Ensuring br_netfilter loads at boot (required for Docker bridge sysctls)..."
    backup_file "/etc/modules-load.d/br_netfilter.conf"
    cp "${VMS_DIR}/configs/modules-load-br_netfilter.conf" /etc/modules-load.d/br_netfilter.conf
    if ! lsmod | grep -q '^br_netfilter'; then
        modprobe br_netfilter 2>/dev/null || \
            log_warn "Could not modprobe br_netfilter now — will load on next boot"
    fi

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
# Do NOT disable on loopback -- Docker embedded DNS needs it
# net.ipv6.conf.lo.disable_ipv6 = 1
EOF
    fi

    log_step "Applying sysctl settings..."
    sysctl --system &>/dev/null

    log_step "Disabling core dumps (prevents secret leakage from crashes)..."
    backup_file "/etc/security/limits.d/10-nocore.conf"
    cp "${VMS_DIR}/configs/limits-nocore.conf" /etc/security/limits.d/10-nocore.conf
    # Neutralize systemd-coredump if present
    if systemctl list-unit-files 2>/dev/null | grep -q '^systemd-coredump\.socket'; then
        systemctl mask systemd-coredump.socket 2>/dev/null || true
    fi
    # Belt-and-braces: route core_pattern to /bin/false so nothing is written
    if [[ ! -f /etc/sysctl.d/50-coredump.conf ]]; then
        echo 'kernel.core_pattern=|/bin/false' > /etc/sysctl.d/50-coredump.conf
        sysctl -q -p /etc/sysctl.d/50-coredump.conf 2>/dev/null || true
    fi

    log_success "Kernel hardened via sysctl (+ br_netfilter autoload, core dumps disabled)"
}

audit_kernel_hardening() {
    [[ "$(sysctl -n kernel.dmesg_restrict 2>/dev/null)" == "1" ]] && \
    [[ "$(sysctl -n kernel.kptr_restrict 2>/dev/null)" == "2" ]] && \
    [[ "$(sysctl -n net.ipv4.tcp_syncookies 2>/dev/null)" == "1" ]] && \
    [[ "$(sysctl -n kernel.randomize_va_space 2>/dev/null)" == "2" ]] && \
    [[ "$(sysctl -n net.ipv4.conf.all.rp_filter 2>/dev/null)" == "2" ]] && \
    [[ "$(sysctl -n kernel.yama.ptrace_scope 2>/dev/null)" -ge "1" ]] && \
    [[ "$(sysctl -n fs.protected_symlinks 2>/dev/null)" == "1" ]] && \
    [[ "$(sysctl -n fs.protected_hardlinks 2>/dev/null)" == "1" ]] && \
    lsmod 2>/dev/null | grep -q '^br_netfilter'
}
