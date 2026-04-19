#!/bin/bash
# wizard.sh — 3-question profile-based setup wizard
#
# Design principles:
#   • Auto-detect everything possible (Docker, SSH port, admin user, IPv6)
#   • 3 questions for the common case (profile, SSH port, admin user)
#   • Power users edit /etc/vps-max-security/config.conf directly
#   • Never ask about DNS, ban duration, SHM, IPv6 — sane defaults handle it

wizard_run() {
    ui_banner "VPS MAX SECURITY v${VMS_VERSION}"

    # Load existing config for defaults (wizard overwrites below)
    config_load

    # ── Auto-detection ──────────────────────────────────────
    local detected_docker detected_ssh detected_user detected_ipv6 detected_containers

    detected_docker="$(detect_docker)"
    detected_ssh="$(detect_ssh_port)"
    detected_user="$(detect_admin_user)"
    detected_ipv6="$(detect_ipv6)"
    detected_containers="$(detect_container_count)"

    # Show what we detected
    echo -e "  ${GREEN}✓${NC} Ubuntu $(grep -oP 'VERSION_ID="\K[^"]+' /etc/os-release 2>/dev/null || echo '24.04')"
    if [[ "${detected_docker}" == "true" ]]; then
        local dver
        dver="$(docker version --format '{{.Server.Version}}' 2>/dev/null || echo '?')"
        echo -e "  ${GREEN}✓${NC} Docker ${dver} (${detected_containers} container$([ "${detected_containers}" != "1" ] && echo s) running)"
    else
        echo -e "  ${DIM}○ Docker not detected (firewall will protect host services only)${NC}"
    fi
    echo -e "  ${GREEN}✓${NC} SSH on port ${detected_ssh}, user: ${detected_user}"
    echo ""

    # Pre-fill from auto-detect (user can override)
    SSH_PORT="${SSH_PORT:-${detected_ssh}}"
    ADMIN_USER="${ADMIN_USER:-${detected_user}}"
    ENABLE_IPV6="${detected_ipv6}"

    # ── Question 1: Profile ─────────────────────────────────
    echo -e "  ${BOLD}Choose your server profile:${NC}"
    echo ""
    echo -e "    ${CYAN}1)${NC} Web Server        — TCP 80, 443 only"
    echo -e "    ${CYAN}2)${NC} Web + Realtime    — TCP 80, 443 + UDP 3478, 50000-50100"
    echo -e "    ${CYAN}3)${NC} Custom            — You specify exact ports"
    echo ""

    local profile_num
    case "${PROFILE}" in
        web)      profile_num="1" ;;
        realtime) profile_num="2" ;;
        custom)   profile_num="3" ;;
        *)        profile_num="1" ;;
    esac
    profile_num="$(ui_prompt "Profile" "${profile_num}")"

    case "${profile_num}" in
        1) PROFILE="web" ;;
        2) PROFILE="realtime" ;;
        3) PROFILE="custom" ;;
        *)
            log_warn "Invalid choice '${profile_num}', defaulting to Web Server."
            PROFILE="web"
            ;;
    esac

    # Apply profile to set port defaults
    profile_apply

    # If custom, ask for ports
    if [[ "${PROFILE}" == "custom" ]]; then
        echo ""
        echo -e "  ${DIM}Comma-separated. Ranges OK (e.g. 8080:8090). Leave UDP empty if not needed.${NC}"
        PUBLIC_TCP_PORTS="$(ui_prompt "Public TCP ports" "${PUBLIC_TCP_PORTS:-80,443}")"
        PUBLIC_UDP_PORTS="$(ui_prompt "Public UDP ports" "${PUBLIC_UDP_PORTS:-}")"
    fi

    echo ""

    # ── Question 2: SSH port ────────────────────────────────
    SSH_PORT="$(ui_prompt "SSH port" "${SSH_PORT}")"

    # ── Question 3: Admin user ──────────────────────────────
    ADMIN_USER="$(ui_prompt "Admin user" "${ADMIN_USER}")"

    echo ""

    # ── Validate ────────────────────────────────────────────
    if ! config_validate; then
        log_error "Invalid configuration. Please fix the errors above."
        return 1
    fi

    # ── Summary + confirm ───────────────────────────────────
    ui_config_summary

    if ! ui_confirm "Apply these settings?"; then
        log_warn "Aborted by user."
        exit 0
    fi

    # Save config
    config_save
    config_compute

    # Offer dry-run
    if ui_yesno "Dry-run first? (preview changes before applying)" "Y"; then
        local saved_dry_run="${DRY_RUN:-false}"
        DRY_RUN="true"; export DRY_RUN
        log_info "Starting dry-run..."
        module_run_all
        DRY_RUN="${saved_dry_run}"; export DRY_RUN
        echo ""
        if ! ui_confirm "Dry-run complete. Apply for real?"; then
            log_warn "Aborted after dry-run."
            exit 0
        fi
    fi
}
