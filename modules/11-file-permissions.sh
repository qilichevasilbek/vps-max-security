#!/bin/bash
# Module 11: Restrict file permissions

check_file_permissions() {
    local crontab_perm
    crontab_perm="$(stat -c '%a' /etc/crontab 2>/dev/null)"
    [[ "${crontab_perm}" == "700" ]] && \
    [[ "$(stat -c '%a' /etc/ssh/sshd_config 2>/dev/null)" == "600" ]]
}

apply_file_permissions() {
    log_step "Restricting cron permissions..."
    chmod 700 /etc/crontab 2>/dev/null || true
    chmod 700 /etc/cron.d 2>/dev/null || true
    chmod 700 /etc/cron.daily 2>/dev/null || true
    chmod 700 /etc/cron.hourly 2>/dev/null || true
    chmod 700 /etc/cron.weekly 2>/dev/null || true
    chmod 700 /etc/cron.monthly 2>/dev/null || true

    log_step "Restricting SSH directory permissions..."
    chmod 700 /etc/ssh 2>/dev/null || true
    chmod 600 /etc/ssh/sshd_config 2>/dev/null || true

    log_step "Setting restrictive umask..."
    if ! grep -q "umask 027" /etc/profile 2>/dev/null; then
        backup_file "/etc/profile"
        echo 'umask 027' >> /etc/profile
    fi

    log_success "File permissions restricted"
}

audit_file_permissions() {
    [[ "$(stat -c '%a' /etc/crontab 2>/dev/null)" == "700" ]] && \
    [[ "$(stat -c '%a' /etc/ssh/sshd_config 2>/dev/null)" == "600" ]] && \
    [[ "$(stat -c '%a' /etc/ssh 2>/dev/null)" == "700" ]]
}
