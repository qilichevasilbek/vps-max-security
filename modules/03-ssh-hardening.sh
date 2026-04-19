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

# Filter an algorithm directive in hardening.conf down to only those
# algorithms the local sshd actually supports. OpenSSH < 9.9 errors out on
# unknown algorithms in KexAlgorithms / Ciphers / MACs (it does NOT silently
# drop them, contrary to a common assumption), so the hardened template
# must be reduced to the local intersection before sshd -t is run.
_vms_filter_ssh_algos() {
    local conf="$1" directive="$2" query="$3"
    local supported current filtered algo

    supported="$(sshd -Q "${query}" 2>/dev/null)"
    [[ -z "${supported}" ]] && return 0

    current="$(grep -E "^${directive} " "${conf}" 2>/dev/null | head -1 | sed "s/^${directive} //")"
    [[ -z "${current}" ]] && return 0

    filtered=""
    IFS=',' read -ra _algos <<< "${current}"
    for algo in "${_algos[@]}"; do
        if printf '%s\n' "${supported}" | grep -qFx "${algo}"; then
            filtered+="${algo},"
        fi
    done
    filtered="${filtered%,}"

    if [[ -z "${filtered}" ]]; then
        log_warn "${directive}: no configured algorithms supported by local sshd — leaving template unchanged"
        return 0
    fi
    if [[ "${filtered}" != "${current}" ]]; then
        log_step "${directive}: filtered to ${filtered}"
        sed -i "s|^${directive} .*|${directive} ${filtered}|" "${conf}"
    fi
}

apply_ssh_hardening() {
    log_step "Backing up SSH config..."
    backup_file "/etc/ssh/sshd_config"
    backup_file "/etc/ssh/sshd_config.d/hardening.conf"

    # Detect OpenSSH version. mlkem768x25519-sha256 (default PQ KEX) requires 9.9+.
    # The hardening template will be filtered below against `sshd -Q` so older
    # OpenSSH (e.g., 9.6 on Ubuntu 24.04 base) still applies a valid subset.
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

    log_step "Filtering algorithms to those supported by local sshd..."
    _vms_filter_ssh_algos /etc/ssh/sshd_config.d/hardening.conf KexAlgorithms kex
    _vms_filter_ssh_algos /etc/ssh/sshd_config.d/hardening.conf Ciphers cipher
    _vms_filter_ssh_algos /etc/ssh/sshd_config.d/hardening.conf MACs mac
    _vms_filter_ssh_algos /etc/ssh/sshd_config.d/hardening.conf HostKeyAlgorithms HostKeyAlgorithms
    _vms_filter_ssh_algos /etc/ssh/sshd_config.d/hardening.conf PubkeyAcceptedAlgorithms PubkeyAcceptedAlgorithms
    _vms_filter_ssh_algos /etc/ssh/sshd_config.d/hardening.conf CASignatureAlgorithms CASignatureAlgorithms

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
