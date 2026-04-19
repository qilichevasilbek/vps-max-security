#!/bin/bash
# Module 05: Fail2Ban intrusion prevention (Docker-aware)
#
# Bans hit the DOCKER-USER iptables chain so they also block traffic to
# container-published ports. Requires modules/04-firewall.sh to have
# installed the DOCKER-USER chain first.

check_fail2ban() {
    systemctl is-active fail2ban &>/dev/null && \
    [[ -f /etc/fail2ban/jail.local ]] && \
    grep -q "port = ${SSH_PORT}" /etc/fail2ban/jail.local 2>/dev/null && \
    grep -q "chain=DOCKER-USER" /etc/fail2ban/jail.local 2>/dev/null
}

apply_fail2ban() {
    log_step "Installing Fail2Ban..."
    apt install fail2ban -y

    log_step "Installing custom filters (nginx-4xx-scanner, django-admin)..."
    install -d -m 755 /etc/fail2ban/filter.d
    backup_file "/etc/fail2ban/filter.d/nginx-4xx-scanner.conf"
    cp "${VMS_DIR}/configs/fail2ban-filters/nginx-4xx-scanner.conf" \
       /etc/fail2ban/filter.d/nginx-4xx-scanner.conf
    backup_file "/etc/fail2ban/filter.d/django-admin.conf"
    cp "${VMS_DIR}/configs/fail2ban-filters/django-admin.conf" \
       /etc/fail2ban/filter.d/django-admin.conf

    # Ensure the log paths referenced by our jails exist. Fail2Ban will
    # refuse to start if a jail's logpath is missing; these stubs let it
    # come up cleanly even before the app starts writing.
    install -d -m 755 /var/log/nginx
    install -d -m 755 /var/log/django
    touch /var/log/nginx/access.log /var/log/nginx/error.log 2>/dev/null || true
    touch /var/log/django/auth.log 2>/dev/null || true

    log_step "Writing jail config..."
    backup_file "/etc/fail2ban/jail.local"
    # Use install_config to expand ${BAN_DURATION_SECS}/${MAX_SSH_RETRIES}/${SSH_PORT}
    install_config "${VMS_DIR}/configs/fail2ban-jail.conf" /etc/fail2ban/jail.local || true

    log_step "Enabling and starting Fail2Ban..."
    systemctl enable fail2ban
    systemctl reload-or-restart fail2ban || {
        log_warn "Fail2Ban failed to restart — check 'journalctl -u fail2ban'"
        log_warn "Common cause: a jail references a logpath not yet present."
    }

    log_success "Fail2Ban configured (banaction -> DOCKER-USER chain)"
}

audit_fail2ban() {
    systemctl is-active fail2ban &>/dev/null && \
    [[ -f /etc/fail2ban/jail.local ]] && \
    grep -q "enabled = true" /etc/fail2ban/jail.local 2>/dev/null && \
    grep -q "chain=DOCKER-USER" /etc/fail2ban/jail.local 2>/dev/null
}
