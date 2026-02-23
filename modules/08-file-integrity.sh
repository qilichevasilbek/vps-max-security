#!/bin/bash
# Module 08: File integrity monitoring (AIDE)

check_file_integrity() {
    dpkg -l aide &>/dev/null && \
    [[ -f /var/lib/aide/aide.db ]]
}

apply_file_integrity() {
    log_step "Installing AIDE..."
    apt install aide -y

    log_step "Initializing AIDE database (this may take a few minutes)..."
    aideinit 2>/dev/null || true

    if [[ -f /var/lib/aide/aide.db.new ]]; then
        cp /var/lib/aide/aide.db.new /var/lib/aide/aide.db
    fi

    log_success "AIDE file integrity monitoring initialized"
}

audit_file_integrity() {
    dpkg -l aide &>/dev/null && \
    [[ -f /var/lib/aide/aide.db ]]
}
