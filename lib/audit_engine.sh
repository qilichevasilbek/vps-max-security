#!/bin/bash
# audit_engine.sh — Security audit scoring framework (0-100)

# Weights for each module category (must sum to 100)
# Using a function for bash 3 compatibility (macOS testing)
_audit_weight() {
    case "$1" in
        system_update)      echo 5 ;;
        auto_updates)       echo 5 ;;
        ssh_hardening)      echo 15 ;;
        firewall)           echo 12 ;;
        fail2ban)           echo 8 ;;
        kernel_hardening)   echo 10 ;;
        apparmor)           echo 5 ;;
        file_integrity)     echo 5 ;;
        rootkit_scanners)   echo 3 ;;
        shared_memory)      echo 3 ;;
        file_permissions)   echo 5 ;;
        audit_daemon)       echo 5 ;;
        dns_security)       echo 3 ;;
        lynis)              echo 2 ;;
        service_cleanup)    echo 4 ;;
        login_security)     echo 5 ;;
        dheat_mitigation)   echo 2 ;;
        usb_hardening)      echo 1 ;;
        cve_patches)        echo 5 ;;
        log_protection)     echo 2 ;;
        *)                  echo 0 ;;
    esac
}

audit_run() {
    ui_banner "VPS MAX SECURITY — Security Audit"

    local total_score=0
    local max_score=0

    # Source and audit each module
    printf "${BOLD}%-25s %6s %8s %10s${NC}\n" "MODULE" "STATUS" "WEIGHT" "SCORE"
    echo "────────────────────────────────────────────────────────"

    while IFS= read -r file; do
        [[ -z "${file}" ]] && continue
        local name
        name="$(module_name_from_file "${file}")"
        local func
        func="$(module_func_name "${name}")"

        # Source the module
        # shellcheck disable=SC1090
        source "${file}"

        local weight_key="${name//-/_}"
        local weight
        weight="$(_audit_weight "${weight_key}")"
        ((max_score += weight)) || true

        if type "audit_${func}" &>/dev/null; then
            local pass=0
            if "audit_${func}" 2>/dev/null; then
                pass="${weight}"
                printf "${GREEN}%-25s   PASS %6d %8d${NC}\n" "${name}" "${weight}" "${pass}"
            else
                printf "${RED}%-25s   FAIL %6d %8d${NC}\n" "${name}" "${weight}" "0"
            fi
            ((total_score += pass)) || true
        else
            printf "${DIM}%-25s   N/A  %6d %8s${NC}\n" "${name}" "${weight}" "-"
        fi
    done < <(module_list_all)

    echo "────────────────────────────────────────────────────────"

    # Calculate percentage
    local percent=0
    if (( max_score > 0 )); then
        percent=$(( (total_score * 100) / max_score ))
    fi

    echo ""
    # Score display with color coding
    local score_color="${RED}"
    local grade="F"
    if (( percent >= 90 )); then
        score_color="${GREEN}"; grade="A"
    elif (( percent >= 80 )); then
        score_color="${GREEN}"; grade="B"
    elif (( percent >= 70 )); then
        score_color="${YELLOW}"; grade="C"
    elif (( percent >= 60 )); then
        score_color="${YELLOW}"; grade="D"
    fi

    echo -e "  Security Score: ${score_color}${BOLD}${percent}/100 (Grade: ${grade})${NC}"
    echo -e "  Points: ${total_score}/${max_score}"
    echo ""

    if (( percent < 80 )); then
        echo -e "${YELLOW}  Run 'sudo vps-max-security' to apply missing hardening.${NC}"
    else
        echo -e "${GREEN}  Your server is well-hardened!${NC}"
    fi
    echo ""
}
