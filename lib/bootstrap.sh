#!/bin/bash
# bootstrap.sh — First-run setup for brand-new VPSes
#
# Problem: you just bought a VPS (Contabo, Hetzner, Hostinger, DigitalOcean)
# and logged in as root with a password or provider SSH key. You have:
#   ✗ No admin user
#   ✗ No SSH key auth for the admin user
#   ✗ root login + password auth still enabled
#
# This bootstrap creates the admin user, copies SSH keys, and verifies
# everything works BEFORE the hardening modules disable root + password auth.

# Check if bootstrap is needed (admin user exists + has SSH keys)
bootstrap_needed() {
    local user="${1:-${ADMIN_USER:-deployer}}"
    # If user doesn't exist → need bootstrap
    if ! id "${user}" &>/dev/null; then
        return 0  # true, bootstrap needed
    fi
    # If user exists but no SSH keys → need bootstrap
    local home_dir
    home_dir="$(getent passwd "${user}" | cut -d: -f6)"
    home_dir="${home_dir:-/home/${user}}"
    if [[ ! -f "${home_dir}/.ssh/authorized_keys" ]] || [[ ! -s "${home_dir}/.ssh/authorized_keys" ]]; then
        return 0  # true, bootstrap needed
    fi
    return 1  # false, all good
}

# Run the bootstrap wizard — creates admin user + SSH keys
bootstrap_run() {
    local user="${ADMIN_USER}"

    echo ""
    echo -e "${YELLOW}══════════════════════════════════════════════════${NC}"
    echo -e "${YELLOW}  FIRST-TIME SETUP${NC}"
    echo -e "${YELLOW}══════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "  Your VPS needs an admin user with SSH keys before"
    echo -e "  hardening can begin (hardening disables root login"
    echo -e "  and password auth — you'd be locked out without this)."
    echo ""

    # ── Step 1: Create the admin user ───────────────────────
    if ! id "${user}" &>/dev/null; then
        log_step "Creating user '${user}'..."
        if [[ "${DRY_RUN}" == "true" ]]; then
            log_dry "Would create user '${user}'"
        else
            adduser --disabled-password --gecos "VPS Admin" "${user}"
            usermod -aG sudo "${user}"
            # Allow sudo without password (for deploy scripts / CI)
            echo "${user} ALL=(ALL) NOPASSWD:ALL" > "/etc/sudoers.d/${user}"
            chmod 440 "/etc/sudoers.d/${user}"
            log_success "User '${user}' created with sudo access"
        fi
    else
        log_success "User '${user}' already exists"
    fi

    # ── Step 2: Set up SSH keys ─────────────────────────────
    local home_dir
    home_dir="$(getent passwd "${user}" | cut -d: -f6 2>/dev/null)"
    home_dir="${home_dir:-/home/${user}}"
    local ssh_dir="${home_dir}/.ssh"
    local auth_keys="${ssh_dir}/authorized_keys"

    if [[ -f "${auth_keys}" ]] && [[ -s "${auth_keys}" ]]; then
        log_success "SSH keys already present for '${user}'"
        return 0
    fi

    if [[ "${DRY_RUN}" == "true" ]]; then
        log_dry "Would set up SSH keys for '${user}'"
        return 0
    fi

    # Try to copy keys from root (most providers put your key in root's authorized_keys)
    local root_keys="/root/.ssh/authorized_keys"
    if [[ -f "${root_keys}" ]] && [[ -s "${root_keys}" ]]; then
        echo ""
        echo -e "  ${GREEN}Found SSH keys in root's authorized_keys.${NC}"
        echo -e "  These were likely added by your VPS provider when you"
        echo -e "  uploaded your public key during server creation."
        echo ""

        if ui_yesno "Copy root's SSH keys to '${user}'?" "Y"; then
            mkdir -p "${ssh_dir}"
            cp "${root_keys}" "${auth_keys}"
            chown -R "${user}:${user}" "${ssh_dir}"
            chmod 700 "${ssh_dir}"
            chmod 600 "${auth_keys}"
            log_success "SSH keys copied from root to '${user}'"

            # Verify key count
            local key_count
            key_count="$(wc -l < "${auth_keys}" | tr -d ' ')"
            log_info "${key_count} key(s) installed for '${user}'"
            return 0
        fi
    fi

    # No root keys — ask user to paste their public key
    echo ""
    echo -e "  ${YELLOW}No SSH keys found to copy.${NC}"
    echo ""
    echo "  On your LOCAL machine, find your public key:"
    echo "    cat ~/.ssh/id_ed25519.pub"
    echo "  or"
    echo "    cat ~/.ssh/id_rsa.pub"
    echo ""
    echo "  Paste it here (one line, starts with 'ssh-'):"
    echo ""

    local pubkey
    read -rp "  Public key: " pubkey

    if [[ -z "${pubkey}" ]]; then
        log_error "No key provided. Cannot continue without SSH key auth."
        echo ""
        echo "  You can set it up manually and re-run:"
        echo "    ssh-copy-id -i ~/.ssh/id_ed25519.pub ${user}@YOUR_VPS_IP"
        echo "    sudo vps-max-security"
        echo ""
        return 1
    fi

    # Basic validation — must start with ssh-
    if [[ ! "${pubkey}" =~ ^ssh- ]]; then
        log_error "That doesn't look like an SSH public key (should start with 'ssh-')"
        return 1
    fi

    mkdir -p "${ssh_dir}"
    echo "${pubkey}" > "${auth_keys}"
    chown -R "${user}:${user}" "${ssh_dir}"
    chmod 700 "${ssh_dir}"
    chmod 600 "${auth_keys}"
    log_success "SSH key installed for '${user}'"

    echo ""
    echo -e "  ${YELLOW}IMPORTANT: Test this BEFORE continuing!${NC}"
    echo ""
    echo "  Open a NEW terminal and verify you can log in:"
    echo "    ssh -i ~/.ssh/id_ed25519 ${user}@$(hostname -I 2>/dev/null | awk '{print $1}')"
    echo ""

    if ! ui_yesno "Have you verified SSH login works for '${user}'?" "n"; then
        log_warn "Please test SSH login first, then re-run this tool."
        log_warn "If you proceed without testing and something breaks,"
        log_warn "use your VPS provider's console/VNC access to recover."
        echo ""
        if ! ui_confirm "Proceed anyway? (NOT recommended)"; then
            exit 0
        fi
    fi

    return 0
}
