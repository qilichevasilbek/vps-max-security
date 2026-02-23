#!/bin/bash
# Module 17: DHEat attack mitigation (SSH rate limiting via iptables)
# Source: ssh-audit.com — Connection throttling for DHEat DoS attack

check_dheat_mitigation() {
    iptables -C INPUT -p tcp --dport "${SSH_PORT}" -m state --state NEW -m recent --set 2>/dev/null && \
    iptables -C INPUT -p tcp --dport "${SSH_PORT}" -m state --state NEW -m recent --update --seconds 10 --hitcount 10 -j DROP 2>/dev/null
}

apply_dheat_mitigation() {
    log_step "Adding SSH connection rate limiting (anti-DHEat)..."

    # Rate limit: max 10 new connections per 10 seconds per IP
    iptables -I INPUT -p tcp --dport "${SSH_PORT}" -m state --state NEW -m recent --set
    iptables -I INPUT -p tcp --dport "${SSH_PORT}" -m state --state NEW -m recent --update --seconds 10 --hitcount 10 -j DROP

    log_step "Persisting iptables rules..."
    if command -v netfilter-persistent &>/dev/null; then
        netfilter-persistent save
    else
        apt install iptables-persistent -y
        netfilter-persistent save
    fi

    log_success "DHEat attack mitigation applied (SSH rate limiting)"
}

audit_dheat_mitigation() {
    iptables -L INPUT -n 2>/dev/null | grep -q "dpt:${SSH_PORT}.*recent"
}
