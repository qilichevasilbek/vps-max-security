#!/bin/bash
# Module 01: Full system update

check_system_update() {
    # System updates are always worth checking — never skip
    return 1
}

apply_system_update() {
    log_step "Updating package lists..."
    apt update -y

    log_step "Upgrading packages..."
    apt upgrade -y

    log_step "Running dist-upgrade..."
    apt dist-upgrade -y

    log_step "Removing unused packages..."
    apt autoremove -y
    apt autoclean -y

    log_success "System fully updated"
}

audit_system_update() {
    # Check if there are security updates pending
    local updates
    updates="$(apt list --upgradable 2>/dev/null | grep -c -i security || true)"
    [[ "${updates}" -eq 0 ]]
}
