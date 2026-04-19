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
#
# Defensive: every external command is `|| true`-guarded so that `set -e`
# at the top of vps-max-security can never make this function exit early
# and leave a half-filtered config in place.
_vms_filter_ssh_algos() {
    local conf="$1" directive="$2" query="$3"
    local supported="" current="" filtered="" algo=""

    # `sshd -Q` for unrecognized query types returns non-zero; under set -e
    # an unguarded substitution would abort the function. `|| true` makes
    # the assignment unconditional and the absent-list case turns into an
    # empty `supported`, which we handle below.
    supported="$(sshd -Q "${query}" 2>/dev/null || true)"
    if [[ -z "${supported}" ]]; then
        log_warn "${directive}: \`sshd -Q ${query}\` returned nothing — cannot validate, leaving as-is"
        return 0
    fi

    current="$(grep -E "^${directive} " "${conf}" 2>/dev/null | head -1 | sed "s/^${directive} //" || true)"
    [[ -z "${current}" ]] && return 0

    IFS=',' read -ra _algos <<< "${current}" || true
    for algo in "${_algos[@]}"; do
        if printf '%s\n' "${supported}" | grep -qFx "${algo}" 2>/dev/null; then
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

    # Detect OpenSSH version so we can opt into ML-KEM only when supported.
    # The base template ships *without* mlkem768x25519-sha256 because OpenSSH
    # 9.6 (Ubuntu 24.04 base) rejects the entire KexAlgorithms line on any
    # unknown entry. We prepend it below if sshd is 9.9+.
    local ssh_ver="" ssh_major=0 ssh_minor=0 ssh_pq_capable="false"
    ssh_ver="$(sshd -V 2>&1 | grep -oE 'OpenSSH_[0-9]+\.[0-9]+' | head -1 | sed 's/OpenSSH_//' || true)"
    if [[ -n "${ssh_ver}" ]]; then
        ssh_major="${ssh_ver%%.*}"
        ssh_minor="${ssh_ver##*.}"
        if (( ssh_major > 9 || (ssh_major == 9 && ssh_minor >= 9) )); then
            ssh_pq_capable="true"
        else
            log_warn "OpenSSH ${ssh_ver} detected — ML-KEM PQ KEX requires 9.9+."
            log_warn "Falling back to NTRU Prime hybrid (sntrup761x25519). For full PQ install from noble-backports or ppa:openssh/ppa."
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

    if [[ "${ssh_pq_capable}" == "true" ]]; then
        log_step "OpenSSH ${ssh_ver} supports ML-KEM — prepending mlkem768x25519-sha256 to KexAlgorithms"
        sed -i 's|^KexAlgorithms |KexAlgorithms mlkem768x25519-sha256,|' /etc/ssh/sshd_config.d/hardening.conf
    fi

    log_step "Filtering algorithms to those supported by local sshd (safety net)..."
    _vms_filter_ssh_algos /etc/ssh/sshd_config.d/hardening.conf KexAlgorithms kex
    _vms_filter_ssh_algos /etc/ssh/sshd_config.d/hardening.conf Ciphers cipher
    _vms_filter_ssh_algos /etc/ssh/sshd_config.d/hardening.conf MACs mac

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
