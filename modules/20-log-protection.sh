#!/bin/bash
# Module 20: Log protection (immutable logs + rotation)

check_log_protection() {
    # Check if auth.log has immutable attribute
    local attrs
    attrs="$(lsattr /var/log/auth.log 2>/dev/null | awk '{print $1}')"
    [[ "${attrs}" == *"a"* ]]
}

apply_log_protection() {
    log_step "Making critical logs append-only (immutable)..."

    # Remove immutable first to allow changes, then re-add
    chattr -a /var/log/auth.log 2>/dev/null || true
    chattr -a /var/log/syslog 2>/dev/null || true

    chattr +a /var/log/auth.log 2>/dev/null || true
    chattr +a /var/log/syslog 2>/dev/null || true

    log_step "Configuring log rotation for security logs..."
    if [[ ! -f /etc/logrotate.d/vps-security ]]; then
        cat > /etc/logrotate.d/vps-security << 'EOF'
/var/log/auth.log /var/log/syslog {
    weekly
    rotate 52
    compress
    delaycompress
    missingok
    notifempty
    create 0640 root adm
    prerotate
        /usr/bin/chattr -a /var/log/auth.log 2>/dev/null || true
        /usr/bin/chattr -a /var/log/syslog 2>/dev/null || true
    endscript
    postrotate
        /usr/bin/chattr +a /var/log/auth.log 2>/dev/null || true
        /usr/bin/chattr +a /var/log/syslog 2>/dev/null || true
        /usr/lib/rsyslog/rsyslog-rotate 2>/dev/null || true
    endscript
}
EOF
    fi

    log_success "Log protection enabled (append-only + rotation)"
}

audit_log_protection() {
    local attrs
    attrs="$(lsattr /var/log/auth.log 2>/dev/null | awk '{print $1}')"
    [[ "${attrs}" == *"a"* ]] && \
    [[ -f /etc/logrotate.d/vps-security ]]
}
