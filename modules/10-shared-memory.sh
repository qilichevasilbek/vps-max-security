#!/bin/bash
# Module 10: Secure /dev/shm
#
# Default: nosuid,nodev (always safe).
# Optional: +noexec — stricter but BREAKS Chromium / Puppeteer / Playwright
# and LiveKit egress with a chromium recorder. Opt-in via SHM_NOEXEC=true
# in the wizard.
#
# Per-container workaround if you need noexec on the host but exec inside
# a specific container: --tmpfs /dev/shm:rw,exec,size=1g

_vms_shm_mount_opts() {
    if [[ "${SHM_NOEXEC:-false}" == "true" ]]; then
        echo "defaults,noexec,nodev,nosuid"
    else
        echo "defaults,nodev,nosuid"
    fi
}

check_shared_memory() {
    local expected
    expected="$(_vms_shm_mount_opts)"
    # Check the expected opts string appears on the /dev/shm line in fstab
    grep -E '^\s*tmpfs\s+/dev/shm\s' /etc/fstab 2>/dev/null | grep -q "${expected}"
}

apply_shared_memory() {
    log_step "Securing /dev/shm..."
    backup_file "/etc/fstab"

    local opts
    opts="$(_vms_shm_mount_opts)"

    if grep -q "/dev/shm" /etc/fstab; then
        sed -i "\|/dev/shm|c\\tmpfs /dev/shm tmpfs ${opts} 0 0" /etc/fstab
    else
        printf 'tmpfs /dev/shm tmpfs %s 0 0\n' "${opts}" >> /etc/fstab
    fi

    mount -o remount /dev/shm 2>/dev/null || true

    if [[ "${SHM_NOEXEC:-false}" == "true" ]]; then
        log_warn "/dev/shm mounted noexec — headless browser containers will need --tmpfs /dev/shm:rw,exec"
        log_success "Shared memory locked down (noexec,nodev,nosuid)"
    else
        log_success "Shared memory secured (nodev,nosuid) — noexec skipped for Chromium/LiveKit compat"
    fi
}

audit_shared_memory() {
    mount | grep "/dev/shm" | grep -q "nosuid" 2>/dev/null && \
    mount | grep "/dev/shm" | grep -q "nodev"  2>/dev/null
    # noexec is intentionally not required here — it is opt-in.
}
