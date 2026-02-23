#!/bin/bash
# Module 09: Rootkit scanners (rkhunter + chkrootkit)

check_rootkit_scanners() {
    dpkg -l rkhunter &>/dev/null && \
    dpkg -l chkrootkit &>/dev/null
}

apply_rootkit_scanners() {
    log_step "Installing rkhunter and chkrootkit..."
    apt install rkhunter chkrootkit -y

    log_step "Updating rkhunter signatures..."
    rkhunter --update 2>/dev/null || true

    log_success "Rootkit scanners installed"
}

audit_rootkit_scanners() {
    dpkg -l rkhunter &>/dev/null && \
    dpkg -l chkrootkit &>/dev/null
}
