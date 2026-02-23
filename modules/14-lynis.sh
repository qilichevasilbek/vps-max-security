#!/bin/bash
# Module 14: Install Lynis security auditor

check_lynis() {
    dpkg -l lynis &>/dev/null
}

apply_lynis() {
    log_step "Installing Lynis security auditor..."
    apt install lynis -y

    log_success "Lynis installed (run: sudo lynis audit system)"
}

audit_lynis() {
    dpkg -l lynis &>/dev/null
}
