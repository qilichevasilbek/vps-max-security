#!/bin/bash
# Module 10: Secure shared memory

check_shared_memory() {
    grep -q "/dev/shm.*noexec" /etc/fstab 2>/dev/null
}

apply_shared_memory() {
    log_step "Securing /dev/shm..."
    backup_file "/etc/fstab"

    if ! grep -q "/dev/shm" /etc/fstab; then
        echo 'tmpfs /dev/shm tmpfs defaults,noexec,nodev,nosuid 0 0' >> /etc/fstab
    fi

    mount -o remount /dev/shm 2>/dev/null || true

    log_success "Shared memory secured (noexec,nodev,nosuid)"
}

audit_shared_memory() {
    mount | grep "/dev/shm" | grep -q "noexec" 2>/dev/null
}
