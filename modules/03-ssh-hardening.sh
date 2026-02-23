#!/bin/bash
# Module 03: SSH hardening (config + crypto + banner)

check_ssh_hardening() {
    # Check if our hardened config is in place
    [[ -f /etc/ssh/sshd_config ]] && \
    grep -q "^Port ${SSH_PORT}$" /etc/ssh/sshd_config 2>/dev/null && \
    grep -q "^PermitRootLogin no$" /etc/ssh/sshd_config 2>/dev/null && \
    grep -q "^PasswordAuthentication no$" /etc/ssh/sshd_config 2>/dev/null && \
    [[ -f /etc/ssh/sshd_config.d/hardening.conf ]]
}

apply_ssh_hardening() {
    log_step "Backing up SSH config..."
    backup_file "/etc/ssh/sshd_config"
    backup_file "/etc/ssh/sshd_config.d/hardening.conf"

    log_step "Writing hardened sshd_config..."
    cat > /etc/ssh/sshd_config << SSHEOF
# === VPS Max Security — Hardened SSH Config ===
# Generated: $(date +%F)
Port ${SSH_PORT}
AddressFamily inet
ListenAddress 0.0.0.0

HostKey /etc/ssh/ssh_host_ed25519_key
HostKey /etc/ssh/ssh_host_rsa_key

PermitRootLogin no
PasswordAuthentication no
ChallengeResponseAuthentication no
KbdInteractiveAuthentication no
UsePAM yes
PubkeyAuthentication yes
AuthenticationMethods publickey

AllowUsers ${ADMIN_USER}

MaxAuthTries ${MAX_SSH_RETRIES}
MaxSessions 3
MaxStartups 3:50:10
LoginGraceTime 30
ClientAliveInterval 300
ClientAliveCountMax 2

X11Forwarding no
AllowTcpForwarding no
AllowAgentForwarding no
AllowStreamLocalForwarding no
PermitTunnel no
GatewayPorts no
PermitUserEnvironment no
HostbasedAuthentication no
IgnoreRhosts yes

SyslogFacility AUTH
LogLevel VERBOSE

Banner /etc/issue.net
Subsystem sftp /usr/lib/openssh/sftp-server
SSHEOF

    log_step "Applying cryptographic hardening..."
    cp "${VMS_DIR}/configs/sshd_hardening.conf" /etc/ssh/sshd_config.d/hardening.conf

    log_step "Removing weak DH moduli..."
    if [[ -f /etc/ssh/moduli ]]; then
        awk '$5 >= 3071' /etc/ssh/moduli > /etc/ssh/moduli.safe
        mv -f /etc/ssh/moduli.safe /etc/ssh/moduli
    fi

    log_step "Setting login banner..."
    cp "${VMS_DIR}/configs/issue.net" /etc/issue.net

    log_step "Validating SSH config..."
    if sshd -t; then
        log_success "SSH config valid. Restarting SSH..."
        systemctl restart ssh
    else
        log_error "SSH config INVALID! Restoring backup..."
        restore_latest "/etc/ssh/sshd_config"
        rm -f /etc/ssh/sshd_config.d/hardening.conf
        systemctl restart ssh
        return 1
    fi

    chmod 600 /etc/ssh/sshd_config
    log_success "SSH hardened"
}

audit_ssh_hardening() {
    [[ -f /etc/ssh/sshd_config ]] && \
    grep -q "^PermitRootLogin no$" /etc/ssh/sshd_config 2>/dev/null && \
    grep -q "^PasswordAuthentication no$" /etc/ssh/sshd_config 2>/dev/null && \
    grep -q "^X11Forwarding no$" /etc/ssh/sshd_config 2>/dev/null && \
    [[ -f /etc/ssh/sshd_config.d/hardening.conf ]] && \
    grep -q "sntrup761" /etc/ssh/sshd_config.d/hardening.conf 2>/dev/null
}
