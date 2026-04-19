#!/bin/bash
# ui.sh — Terminal prompts, progress display, summary tables

# Prompt for a value with a default
# Usage: result=$(ui_prompt "SSH port" "2222")
ui_prompt() {
    local label="$1" default="$2" value
    read -rp "  ${label} [${default}]: " value
    echo "${value:-${default}}"
}

# Prompt for yes/no with default
# Usage: ui_yesno "Enable IPv6?" "n" && echo "yes"
ui_yesno() {
    local label="$1" default="$2" value
    local hint
    if [[ "${default}" == "y" || "${default}" == "Y" ]]; then
        hint="Y/n"
    else
        hint="y/N"
    fi
    read -rp "  ${label} [${hint}]: " value
    value="${value:-${default}}"
    [[ "${value}" =~ ^[Yy] ]]
}

# Prompt for choice from list
# Usage: result=$(ui_choice "DNS provider" "cloudflare quad9 google" "cloudflare")
ui_choice() {
    local label="$1" options="$2" default="$3" value
    read -rp "  ${label} (${options// /\/}) [${default}]: " value
    value="${value:-${default}}"
    # Validate choice
    local valid=false
    for opt in ${options}; do
        if [[ "${value}" == "${opt}" ]]; then
            valid=true
            break
        fi
    done
    if [[ "${valid}" != "true" ]]; then
        echo "${default}"
    else
        echo "${value}"
    fi
}

# Display a header banner
ui_banner() {
    local title="$1"
    echo ""
    echo -e "${BOLD}══════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}  ${title}${NC}"
    echo -e "${BOLD}══════════════════════════════════════════════════${NC}"
    echo ""
}

# Display a section header
ui_section() {
    local num="$1" title="$2"
    echo ""
    echo -e "${CYAN}── [${num}] ${title} ──${NC}"
}

# Display a summary table of configuration
ui_config_summary() {
    local profile_label="${PROFILE:-web}"
    case "${profile_label}" in
        web)      profile_label="Web Server" ;;
        realtime) profile_label="Web + Realtime" ;;
        custom)   profile_label="Custom" ;;
    esac

    local docker_label="No"
    [[ "${DOCKER_DETECTED:-false}" == "true" ]] && docker_label="Yes (auto)"

    echo ""
    echo -e "${BOLD}┌──────────────────────────────────────────────┐${NC}"
    echo -e "${BOLD}│           Configuration Summary               │${NC}"
    echo -e "${BOLD}├──────────────────────┬───────────────────────┤${NC}"
    printf "${BOLD}│${NC} %-20s ${BOLD}│${NC} %-21s ${BOLD}│${NC}\n" "Profile" "${profile_label}"
    printf "${BOLD}│${NC} %-20s ${BOLD}│${NC} %-21s ${BOLD}│${NC}\n" "SSH Port" "${SSH_PORT}"
    printf "${BOLD}│${NC} %-20s ${BOLD}│${NC} %-21s ${BOLD}│${NC}\n" "Admin User" "${ADMIN_USER}"
    printf "${BOLD}│${NC} %-20s ${BOLD}│${NC} %-21s ${BOLD}│${NC}\n" "Public TCP" "${PUBLIC_TCP_PORTS:-80,443}"
    printf "${BOLD}│${NC} %-20s ${BOLD}│${NC} %-21s ${BOLD}│${NC}\n" "Public UDP" "${PUBLIC_UDP_PORTS:-(none)}"
    printf "${BOLD}│${NC} %-20s ${BOLD}│${NC} %-21s ${BOLD}│${NC}\n" "Docker Firewall" "${docker_label}"
    echo -e "${BOLD}└──────────────────────┴───────────────────────┘${NC}"
    echo ""
}

# Confirmation prompt
ui_confirm() {
    local msg="${1:-Apply these settings?}"
    local answer
    read -rp "  ${msg} (yes/no): " answer
    [[ "${answer}" =~ ^[Yy]([Ee][Ss])?$ ]]
}

# Progress indicator for module execution
ui_module_start() {
    local num="$1" name="$2" desc="$3"
    echo -e "\n${BOLD}[${num}]${NC} ${CYAN}${desc}${NC}"
}

ui_module_result() {
    local status="$1" name="$2"
    case "${status}" in
        applied) echo -e "    ${GREEN}✓ ${name} applied${NC}" ;;
        skipped) echo -e "    ${DIM}○ ${name} already applied${NC}" ;;
        failed)  echo -e "    ${RED}✗ ${name} FAILED${NC}" ;;
        dry-run) echo -e "    ${BLUE}◌ ${name} (dry-run)${NC}" ;;
    esac
}

# Final summary
ui_complete() {
    local vps_ip
    vps_ip="$(hostname -I 2>/dev/null | awk '{print $1}')"
    vps_ip="${vps_ip:-YOUR_VPS_IP}"

    echo ""
    echo -e "${BOLD}══════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}${BOLD}  HARDENING COMPLETE!${NC}"
    echo -e "${BOLD}══════════════════════════════════════════════════${NC}"
    echo ""
    echo "  SSH Port:      ${SSH_PORT}"
    echo "  Admin User:    ${ADMIN_USER}"
    echo "  Firewall:      UFW + DOCKER-USER (TCP: ${PUBLIC_TCP_PORTS:-80,443})"
    if [[ -n "${PUBLIC_UDP_PORTS:-}" ]]; then
        echo "                 UDP: ${PUBLIC_UDP_PORTS}"
    fi
    echo "  Fail2Ban:      Active (${MAX_SSH_RETRIES} retries, ${BAN_DURATION_HOURS}h ban)"
    echo ""
    echo -e "${YELLOW}  NEXT STEPS:${NC}"
    echo ""
    echo "  1. TEST SSH in a NEW terminal (keep this one open!):"
    echo "     ssh -p ${SSH_PORT} ${ADMIN_USER}@${vps_ip}"
    echo ""
    echo "  2. Run a security audit:"
    echo "     sudo vps-max-security audit"
    echo ""
    echo "  3. REBOOT to apply all kernel changes:"
    echo "     sudo reboot"
    echo ""
    echo -e "  ${DIM}Config: /etc/vps-max-security/config.conf${NC}"
    echo -e "  ${DIM}Logs:   /etc/vps-max-security/hardening.log${NC}"
    echo -e "  ${DIM}Undo:   sudo vps-max-security rollback${NC}"
    echo ""
    echo -e "${RED}  DO NOT close this session until you verify login works!${NC}"
    echo -e "${BOLD}══════════════════════════════════════════════════${NC}"
}
