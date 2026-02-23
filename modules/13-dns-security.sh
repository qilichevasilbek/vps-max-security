#!/bin/bash
# Module 13: DNS security (encrypted DNS resolvers)

check_dns_security() {
    [[ -f /etc/systemd/resolved.conf ]] && \
    grep -q "DNSOverTLS=yes" /etc/systemd/resolved.conf 2>/dev/null
}

apply_dns_security() {
    log_step "Configuring secure DNS (${DNS_PROVIDER})..."
    backup_file "/etc/systemd/resolved.conf"

    cat > /etc/systemd/resolved.conf << DNSEOF
[Resolve]
DNS=${DNS_PRIMARY}
FallbackDNS=${DNS_FALLBACK}
DNSOverTLS=yes
DNSSEC=allow-downgrade
DNSEOF

    log_step "Restarting DNS resolver..."
    systemctl restart systemd-resolved

    log_success "DNS configured with DNS-over-TLS (${DNS_PROVIDER})"
}

audit_dns_security() {
    [[ -f /etc/systemd/resolved.conf ]] && \
    grep -q "DNSOverTLS=yes" /etc/systemd/resolved.conf 2>/dev/null && \
    grep -q "DNSSEC=" /etc/systemd/resolved.conf 2>/dev/null
}
