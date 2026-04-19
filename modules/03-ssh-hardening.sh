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

    # Detect OpenSSH version — mlkem768x25519-sha256 (default PQ KEX) requires 9.9+.
    # sshd will silently drop unknown algorithms from the KEX list, so the config
    # remains valid on older versions — this is only an advisory warning.
    local ssh_ver
    ssh_ver="$(sshd -V 2>&1 | grep -oE 'OpenSSH_[0-9]+\.[0-9]+' | head -1 | sed 's/OpenSSH_//')"
    if [[ -n "${ssh_ver}" ]]; then
        local ssh_major ssh_minor
        ssh_major="${ssh_ver%%.*}"
        ssh_minor="${ssh_ver##*.}"
        if (( ssh_major < 9 || (ssh_major == 9 && ssh_minor < 9) )); then
            log_warn "OpenSSH ${ssh_ver} detected — post-quantum mlkem768x25519-sha256 requires 9.9+."
            log_warn "Config will still apply; for full PQ protection install from ppa:openssh/ppa or noble-backports."
        fi
    fi

    local VMS_ADDRESS_FAMILY="inet"
    [[ "${ENABLE_IPV6}" == "true" ]] && VMS_ADDRESS_FAMILY="any"

    log_step "Writing hardened sshd_config..."
    cat > /etc/ssh/sshd_config << SSHEOF
Include /etc/ssh/sshd_config.d/*.conf
# === VPS Max Security — Hardened SSH Config ===
# Generated: $(date +%F)
Port ${SSH_PORT}
AddressFamily ${VMS_ADDRESS_FAMILY}
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
        backup_file "/etc/ssh/moduli"
        awk '$5 >= 3071' /etc/ssh/moduli > /etc/ssh/moduli.safe
        mv -f /etc/ssh/moduli.safe /etc/ssh/moduli
    fi

    log_step "Setting login banner..."
    backup_file "/etc/issue.net"
    cp "${VMS_DIR}/configs/issue.net" /etc/issue.net

    chmod 600 /etc/ssh/sshd_config

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
    log_success "SSH hardened"
}

audit_ssh_hardening() {
    [[ -f /etc/ssh/sshd_config ]] && \
    grep -q "^PermitRootLogin no$" /etc/ssh/sshd_config 2>/dev/null && \
    grep -q "^PasswordAuthentication no$" /etc/ssh/sshd_config 2>/dev/null && \
    grep -q "^X11Forwarding no$" /etc/ssh/sshd_config 2>/dev/null && \
    [[ -f /etc/ssh/sshd_config.d/hardening.conf ]] && \
    # Either ML-KEM (PQ, OpenSSH 9.9+) or NTRU Prime (OpenSSH 9.0+) qualifies
    grep -qE "mlkem768|sntrup761" /etc/ssh/sshd_config.d/hardening.conf 2>/dev/null
    # Tip: validate externally with `ssh-audit localhost -p <SSH_PORT>`
}
