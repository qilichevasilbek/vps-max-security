#!/bin/bash
# Module 07: AppArmor enforcement

# Parse `aa-status` summary lines to extract the count for a given mode.
# `aa-status` always emits a line like "N profiles are in <mode> mode."
# regardless of whether N is zero, so the previous `grep -c 'complain'`
# check always matched the descriptive line and reported failure even on a
# fully-enforced system. We extract the leading number instead.
_vms_aa_count() {
    local mode="$1"
    aa-status 2>/dev/null \
        | awk -v m="${mode}" '$0 ~ ("^[0-9]+ profiles are in " m " mode\\.") {print $1; exit}'
}

check_apparmor() {
    dpkg -s apparmor-utils &>/dev/null || return 1
    aa-status &>/dev/null || return 1
    local enforce_n complain_n
    enforce_n="$(_vms_aa_count enforce)"
    complain_n="$(_vms_aa_count complain)"
    [[ "${enforce_n:-0}" -gt 0 ]] && [[ "${complain_n:-1}" -eq 0 ]]
}

apply_apparmor() {
    log_step "Installing AppArmor utilities and profiles..."
    apt install apparmor-utils apparmor-profiles apparmor-profiles-extra -y

    log_step "Enforcing all AppArmor profiles..."
    aa-enforce /etc/apparmor.d/* 2>/dev/null || true

    log_success "AppArmor profiles enforced"
}

audit_apparmor() {
    aa-status &>/dev/null || return 1
    local enforce_n complain_n
    enforce_n="$(_vms_aa_count enforce)"
    complain_n="$(_vms_aa_count complain)"
    [[ "${enforce_n:-0}" -gt 0 ]] && [[ "${complain_n:-1}" -eq 0 ]]
}
