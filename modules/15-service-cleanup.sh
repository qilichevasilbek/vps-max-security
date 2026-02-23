#!/bin/bash
# Module 15: Disable unnecessary services (reduce attack surface)

# Services that should not run on a VPS
readonly UNNECESSARY_SERVICES=(
    avahi-daemon
    cups
    bluetooth
    rpcbind
)

readonly UNNECESSARY_PACKAGES=(
    telnet
    rsh-client
    rsh-server
    xinetd
)

check_service_cleanup() {
    local found=false
    for svc in "${UNNECESSARY_SERVICES[@]}"; do
        if systemctl is-active "${svc}" &>/dev/null; then
            found=true
            break
        fi
    done
    [[ "${found}" == "false" ]]
}

apply_service_cleanup() {
    log_step "Disabling unnecessary services..."
    for svc in "${UNNECESSARY_SERVICES[@]}"; do
        if systemctl is-active "${svc}" &>/dev/null 2>&1 || systemctl is-enabled "${svc}" &>/dev/null 2>&1; then
            systemctl disable --now "${svc}" 2>/dev/null || true
            log_step "Disabled ${svc}"
        fi
    done

    log_step "Removing insecure packages..."
    for pkg in "${UNNECESSARY_PACKAGES[@]}"; do
        if dpkg -l "${pkg}" &>/dev/null 2>&1; then
            apt purge "${pkg}" -y 2>/dev/null || true
            log_step "Removed ${pkg}"
        fi
    done

    log_success "Unnecessary services disabled and insecure packages removed"
}

audit_service_cleanup() {
    local clean=true
    for svc in "${UNNECESSARY_SERVICES[@]}"; do
        if systemctl is-active "${svc}" &>/dev/null; then
            clean=false
            break
        fi
    done
    [[ "${clean}" == "true" ]]
}
