#!/bin/bash
# Module 12: Audit daemon (auditd)

check_audit_daemon() {
    systemctl is-active auditd &>/dev/null && \
    [[ -f /etc/audit/rules.d/hardening.rules ]]
}

apply_audit_daemon() {
    log_step "Installing auditd..."
    apt install auditd -y
    apt install audispd-plugins -y 2>/dev/null || apt install audisp-plugins -y 2>/dev/null || true

    log_step "Writing audit rules..."
    backup_file "/etc/audit/rules.d/hardening.rules"
    cp "${VMS_DIR}/configs/auditd-rules.conf" /etc/audit/rules.d/hardening.rules

    log_step "Enabling and starting auditd..."
    systemctl enable auditd
    service auditd restart || systemctl start auditd

    # Merge /etc/audit/rules.d/*.rules into /etc/audit/audit.rules and push into
    # the running kernel auditd. Without this, only whatever audit.rules already
    # contains gets loaded — so on Ubuntu 24.04 you may end up with only a
    # partial subset of our hardening.rules in the live auditctl table.
    log_step "Loading audit rules into the kernel (augenrules --load)..."
    if command -v augenrules >/dev/null 2>&1; then
        augenrules --load 2>&1 | sed 's/^/    /' || \
            log_warn "augenrules --load returned non-zero — some rules may not be active until next reboot"
    else
        auditctl -R /etc/audit/audit.rules 2>&1 | sed 's/^/    /' || true
    fi

    log_success "Audit daemon configured and active"
}

audit_audit_daemon() {
    systemctl is-active auditd &>/dev/null && \
    [[ -f /etc/audit/rules.d/hardening.rules ]] && \
    auditctl -l 2>/dev/null | grep -q "sshd_config" && \
    auditctl -l 2>/dev/null | grep -q -- "-k docker" && \
    auditctl -l 2>/dev/null | grep -q -- "-k rootcmd"
}
