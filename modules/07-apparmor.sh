#!/bin/bash
# Module 07: AppArmor enforcement

check_apparmor() {
    dpkg -l apparmor-utils &>/dev/null && \
    aa-status &>/dev/null && \
    [[ "$(aa-status 2>/dev/null | grep -c 'enforce')" -gt 0 ]]
}

apply_apparmor() {
    log_step "Installing AppArmor utilities and profiles..."
    apt install apparmor-utils apparmor-profiles apparmor-profiles-extra -y

    log_step "Enforcing all AppArmor profiles..."
    aa-enforce /etc/apparmor.d/* 2>/dev/null || true

    log_success "AppArmor profiles enforced"
}

audit_apparmor() {
    aa-status &>/dev/null && \
    [[ "$(aa-status 2>/dev/null | grep -c 'enforce')" -gt 0 ]] && \
    [[ "$(aa-status 2>/dev/null | grep -c 'complain')" -eq 0 ]]
}
