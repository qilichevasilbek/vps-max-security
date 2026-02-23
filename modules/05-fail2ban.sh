#!/bin/bash
# Module 05: Fail2Ban intrusion prevention

check_fail2ban() {
    systemctl is-active fail2ban &>/dev/null && \
    [[ -f /etc/fail2ban/jail.local ]] && \
    grep -q "port = ${SSH_PORT}" /etc/fail2ban/jail.local 2>/dev/null
}

apply_fail2ban() {
    log_step "Installing Fail2Ban..."
    apt install fail2ban -y

    log_step "Writing jail config..."
    backup_file "/etc/fail2ban/jail.local"

    cat > /etc/fail2ban/jail.local << JAILEOF
[DEFAULT]
bantime = ${BAN_DURATION_SECS}
findtime = 600
maxretry = ${MAX_SSH_RETRIES}
banaction = ufw
backend = systemd

[sshd]
enabled = true
port = ${SSH_PORT}
filter = sshd
logpath = /var/log/auth.log
maxretry = ${MAX_SSH_RETRIES}
bantime = ${BAN_DURATION_SECS}

[recidive]
enabled = true
filter = recidive
logpath = /var/log/fail2ban.log
bantime = 604800
findtime = 86400
maxretry = 3
JAILEOF

    log_step "Enabling and starting Fail2Ban..."
    systemctl enable fail2ban
    systemctl restart fail2ban

    log_success "Fail2Ban configured and active"
}

audit_fail2ban() {
    systemctl is-active fail2ban &>/dev/null && \
    [[ -f /etc/fail2ban/jail.local ]] && \
    grep -q "enabled = true" /etc/fail2ban/jail.local 2>/dev/null
}
