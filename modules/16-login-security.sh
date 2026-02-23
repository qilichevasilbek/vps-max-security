#!/bin/bash
# Module 16: PAM hardening and password policies

check_login_security() {
    [[ -f /etc/security/pwquality.conf ]] && \
    grep -q "minlen" /etc/security/pwquality.conf 2>/dev/null && \
    grep -q "PASS_MAX_DAYS" /etc/login.defs 2>/dev/null && \
    [[ "$(grep '^PASS_MAX_DAYS' /etc/login.defs 2>/dev/null | awk '{print $2}')" -le 90 ]]
}

apply_login_security() {
    log_step "Installing PAM quality modules..."
    apt install libpam-pwquality -y

    log_step "Configuring password quality requirements..."
    backup_file "/etc/security/pwquality.conf"
    cat > /etc/security/pwquality.conf << 'EOF'
# Password quality requirements
minlen = 12
minclass = 3
maxrepeat = 3
dcredit = -1
ucredit = -1
lcredit = -1
ocredit = -1
reject_username
enforce_for_root
EOF

    log_step "Setting password aging policies..."
    backup_file "/etc/login.defs"
    sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   90/' /etc/login.defs
    sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   7/' /etc/login.defs
    sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE   14/' /etc/login.defs

    log_step "Configuring account lockout..."
    backup_file "/etc/pam.d/common-auth"
    if ! grep -q "pam_faillock" /etc/pam.d/common-auth 2>/dev/null; then
        # Add faillock before pam_unix
        sed -i '/pam_unix.so/i auth    required    pam_faillock.so preauth silent deny=5 unlock_time=900' /etc/pam.d/common-auth
    fi

    log_success "Login security hardened (PAM + password policies)"
}

audit_login_security() {
    [[ -f /etc/security/pwquality.conf ]] && \
    grep -q "minlen" /etc/security/pwquality.conf 2>/dev/null && \
    dpkg -l libpam-pwquality &>/dev/null && \
    [[ "$(grep '^PASS_MAX_DAYS' /etc/login.defs 2>/dev/null | awk '{print $2}')" -le 90 ]]
}
