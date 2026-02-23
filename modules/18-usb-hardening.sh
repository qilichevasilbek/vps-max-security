#!/bin/bash
# Module 18: Block USB/Thunderbolt on VPS (not needed, attack vector)
# Source: CIS Benchmark — disable unnecessary hardware interfaces

check_usb_hardening() {
    [[ -f /etc/modprobe.d/usb-block.conf ]] && \
    grep -q "install usb-storage /bin/true" /etc/modprobe.d/usb-block.conf 2>/dev/null
}

apply_usb_hardening() {
    log_step "Blocking USB storage..."
    cat > /etc/modprobe.d/usb-block.conf << 'EOF'
# Block USB storage (not needed on VPS)
install usb-storage /bin/true
blacklist usb-storage

# Block Thunderbolt (not needed on VPS)
blacklist thunderbolt
EOF

    log_step "Blocking UVC video driver (CVE-2024-53104)..."
    cat > /etc/modprobe.d/uvc-block.conf << 'EOF'
# Block UVC video driver — CVE-2024-53104 mitigation
install uvcvideo /bin/true
blacklist uvcvideo
EOF

    log_success "USB/Thunderbolt/UVC blocked"
}

audit_usb_hardening() {
    [[ -f /etc/modprobe.d/usb-block.conf ]] && \
    grep -q "install usb-storage /bin/true" /etc/modprobe.d/usb-block.conf 2>/dev/null && \
    [[ -f /etc/modprobe.d/uvc-block.conf ]]
}
