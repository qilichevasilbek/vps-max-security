#!/bin/bash
# Module 16: PAM hardening and password policies

check_login_security() {
    [[ -f /etc/security/pwquality.conf ]] && \
    grep -q "minlen" /etc/security/pwquality.conf 2>/dev/null && \
    dpkg -l libpam-pwquality &>/dev/null
}

apply_login_security() {
    log_step "Installing PAM quality modules..."
    apt install libpam-pwquality -y

    log_step "Configuring password quality requirements..."
    backup_file "/etc/security/pwquality.conf"
    cat > /etc/security/pwquality.conf << 'EOF'
# Password quality requirements (applies to password changes only)
# Does NOT affect SSH key auth — only matters if someone sets a password
minlen = 10
minclass = 3
maxrepeat = 3
dcredit = -1
ucredit = -1
lcredit = -1
reject_username
# NOTE: enforce_for_root removed — can lock you out of sudo
EOF

    log_step "Setting password aging policies..."
    backup_file "/etc/login.defs"
    sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   365/' /etc/login.defs
    sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   1/' /etc/login.defs
    sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE   14/' /etc/login.defs

    # NOTE: pam_faillock not added — with key-only SSH auth it adds no security
    # value but risks locking out the admin via sudo. Fail2Ban already handles
    # brute-force protection at the SSH level.

    log_success "Login security hardened (password policies)"
}

audit_login_security() {
    [[ -f /etc/security/pwquality.conf ]] && \
    grep -q "minlen" /etc/security/pwquality.conf 2>/dev/null && \
    dpkg -l libpam-pwquality &>/dev/null
}
