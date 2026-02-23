#!/bin/bash
# Module 02: Automatic security updates

check_auto_updates() {
    [[ -f /etc/apt/apt.conf.d/20auto-upgrades ]] && \
    grep -q 'APT::Periodic::Unattended-Upgrade "1"' /etc/apt/apt.conf.d/20auto-upgrades 2>/dev/null
}

apply_auto_updates() {
    log_step "Installing unattended-upgrades..."
    apt install unattended-upgrades apt-listchanges -y

    log_step "Configuring automatic updates..."
    backup_file "/etc/apt/apt.conf.d/20auto-upgrades"
    cat > /etc/apt/apt.conf.d/20auto-upgrades << 'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOF

    log_success "Automatic security updates enabled"
}

audit_auto_updates() {
    dpkg -l unattended-upgrades &>/dev/null && \
    [[ -f /etc/apt/apt.conf.d/20auto-upgrades ]] && \
    grep -q 'Unattended-Upgrade "1"' /etc/apt/apt.conf.d/20auto-upgrades 2>/dev/null
}
