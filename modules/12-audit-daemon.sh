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

    log_success "Audit daemon configured and active"
}

audit_audit_daemon() {
    systemctl is-active auditd &>/dev/null && \
    [[ -f /etc/audit/rules.d/hardening.rules ]] && \
    auditctl -l 2>/dev/null | grep -q "sshd_config" && \
    auditctl -l 2>/dev/null | grep -q -- "-k docker" && \
    auditctl -l 2>/dev/null | grep -q -- "-k rootcmd"
}
