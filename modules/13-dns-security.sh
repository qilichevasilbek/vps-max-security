#!/bin/bash
# Module 13: DNS security (encrypted DNS resolvers)
# Uses opportunistic DoT — upgrades to TLS when available, falls back to plain
# DNS gracefully. Strict mode (yes) causes timeouts on many VPS providers.

check_dns_security() {
    [[ -f /etc/systemd/resolved.conf ]] && \
    grep -q "^DNS=" /etc/systemd/resolved.conf 2>/dev/null && \
    grep -q "DNSOverTLS=opportunistic" /etc/systemd/resolved.conf 2>/dev/null
}

apply_dns_security() {
    log_step "Configuring secure DNS (${DNS_PROVIDER})..."
    backup_file "/etc/systemd/resolved.conf"

    cat > /etc/systemd/resolved.conf << DNSEOF
[Resolve]
DNS=${DNS_PRIMARY}
FallbackDNS=${DNS_FALLBACK}
# opportunistic = use TLS when available, fall back to plain DNS
# this prevents timeout/resolution failures that break apt & Docker
DNSOverTLS=opportunistic
DNSSEC=allow-downgrade
DNSEOF

    log_step "Restarting DNS resolver..."
    systemctl restart systemd-resolved

    # Verify DNS works after change
    log_step "Verifying DNS resolution..."
    if ! resolvectl query ubuntu.com &>/dev/null 2>&1; then
        log_warn "DNS resolution test failed, waiting 3s and retrying..."
        sleep 3
        if ! resolvectl query ubuntu.com &>/dev/null 2>&1; then
            log_error "DNS still not working! Restoring backup..."
            restore_latest "/etc/systemd/resolved.conf"
            systemctl restart systemd-resolved
            return 1
        fi
    fi

    log_success "DNS configured with DNS-over-TLS opportunistic (${DNS_PROVIDER})"
}

audit_dns_security() {
    [[ -f /etc/systemd/resolved.conf ]] && \
    grep -q "^DNS=" /etc/systemd/resolved.conf 2>/dev/null && \
    grep -qE "DNSOverTLS=(opportunistic|yes)" /etc/systemd/resolved.conf 2>/dev/null
}
