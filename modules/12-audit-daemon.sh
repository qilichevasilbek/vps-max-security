#!/bin/bash
# Module 12: Audit daemon (auditd)

check_audit_daemon() {
    systemctl is-active auditd &>/dev/null && \
    [[ -f /etc/audit/rules.d/hardening.rules ]]
}

apply_audit_daemon() {
    log_step "Installing auditd..."
    apt install auditd audispd-plugins -y

    log_step "Writing audit rules..."
    backup_file "/etc/audit/rules.d/hardening.rules"
    cp "${VMS_DIR}/configs/auditd-rules.conf" /etc/audit/rules.d/hardening.rules

    log_step "Enabling and starting auditd..."
    systemctl enable auditd
    systemctl restart auditd

    log_success "Audit daemon configured and active"
}

audit_audit_daemon() {
    systemctl is-active auditd &>/dev/null && \
    [[ -f /etc/audit/rules.d/hardening.rules ]] && \
    auditctl -l 2>/dev/null | grep -q "sshd_config"
}
