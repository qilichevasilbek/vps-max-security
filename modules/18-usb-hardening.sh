#!/bin/bash
# Module 18: Block unused hardware interfaces + kernel module blacklist
# Source: CIS Benchmark — disable unnecessary kernel modules on a VPS

check_usb_hardening() {
    [[ -f /etc/modprobe.d/usb-block.conf ]] && \
    [[ -f /etc/modprobe.d/uvc-block.conf ]] && \
    [[ -f /etc/modprobe.d/vms-hardening.conf ]] && \
    grep -q "install usb-storage /bin/true" /etc/modprobe.d/usb-block.conf 2>/dev/null
}

apply_usb_hardening() {
    log_step "Blocking USB storage..."
    backup_file "/etc/modprobe.d/usb-block.conf"
    cat > /etc/modprobe.d/usb-block.conf << 'EOF'
# Block USB storage (not needed on VPS)
install usb-storage /bin/true
blacklist usb-storage

# Block Thunderbolt (not needed on VPS)
blacklist thunderbolt
EOF

    log_step "Blocking UVC video driver (CVE-2024-53104)..."
    backup_file "/etc/modprobe.d/uvc-block.conf"
    cat > /etc/modprobe.d/uvc-block.conf << 'EOF'
# Block UVC video driver — CVE-2024-53104 mitigation
install uvcvideo /bin/true
blacklist uvcvideo
EOF

    log_step "Installing rare-module blacklist (DCCP, SCTP, RDS, TIPC, etc.)..."
    backup_file "/etc/modprobe.d/vms-hardening.conf"
    cp "${VMS_DIR}/configs/blacklist-hardening.conf" /etc/modprobe.d/vms-hardening.conf

    # squashfs is an exploit-prone rare filesystem, but snapd depends on it.
    # Only blacklist if snapd is NOT present. Log the decision explicitly.
    if command -v snap >/dev/null 2>&1; then
        log_info "snapd detected — leaving squashfs enabled (required by snap)"
    else
        log_step "Blacklisting squashfs (snapd not present)..."
        printf '\n# squashfs — blacklisted because snapd is not installed\ninstall squashfs /bin/false\n' \
            >> /etc/modprobe.d/vms-hardening.conf
    fi

    log_step "Updating initramfs..."
    update-initramfs -u 2>/dev/null || true

    log_success "USB/Thunderbolt/UVC blocked + rare modules blacklisted"
}

audit_usb_hardening() {
    [[ -f /etc/modprobe.d/usb-block.conf ]] && \
    [[ -f /etc/modprobe.d/uvc-block.conf ]] && \
    [[ -f /etc/modprobe.d/vms-hardening.conf ]] && \
    grep -q "install usb-storage /bin/true" /etc/modprobe.d/usb-block.conf 2>/dev/null && \
    grep -q "install dccp" /etc/modprobe.d/vms-hardening.conf 2>/dev/null
}
