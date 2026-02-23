#!/bin/bash
# wizard.sh — Interactive configuration wizard with defaults

wizard_run() {
    ui_banner "VPS MAX SECURITY — Configuration Wizard"

    echo -e "${DIM}  Press Enter to accept defaults shown in brackets.${NC}"
    echo ""

    # Load existing config for defaults
    config_load

    SSH_PORT="$(ui_prompt "SSH port" "${SSH_PORT}")"
    ADMIN_USER="$(ui_prompt "Admin username" "${ADMIN_USER}")"

    if ui_yesno "Enable IPv6?" "${ENABLE_IPV6:0:1}"; then
        ENABLE_IPV6="true"
    else
        ENABLE_IPV6="false"
    fi

    FIREWALL_PORTS="$(ui_prompt "Additional firewall ports" "${FIREWALL_PORTS}")"
    MAX_SSH_RETRIES="$(ui_prompt "Max SSH retries before ban" "${MAX_SSH_RETRIES}")"
    BAN_DURATION_HOURS="$(ui_prompt "Ban duration in hours" "${BAN_DURATION_HOURS}")"
    DNS_PROVIDER="$(ui_choice "DNS provider" "cloudflare quad9 google" "${DNS_PROVIDER}")"

    if ui_yesno "Run ALL hardening modules?" "Y"; then
        RUN_ALL_MODULES="true"; export RUN_ALL_MODULES
    else
        RUN_ALL_MODULES="false"; export RUN_ALL_MODULES
    fi

    if ui_yesno "Perform dry-run first?" "Y"; then
        WIZARD_DRY_RUN="true"
    else
        WIZARD_DRY_RUN="false"
    fi

    # Validate
    if ! config_validate; then
        log_error "Invalid configuration. Please fix the errors above."
        return 1
    fi

    # Show summary
    ui_config_summary

    # Confirm
    if ! ui_confirm "Apply these settings?"; then
        log_warn "Aborted by user."
        exit 0
    fi

    # Save config
    config_save
    config_compute

    # If they chose dry-run first, do that
    if [[ "${WIZARD_DRY_RUN}" == "true" ]]; then
        DRY_RUN="true"; export DRY_RUN
        log_info "Starting dry-run..."
        module_run_all
        DRY_RUN="false"; export DRY_RUN
        echo ""
        if ! ui_confirm "Dry-run complete. Apply for real?"; then
            log_warn "Aborted after dry-run."
            exit 0
        fi
    fi
}
