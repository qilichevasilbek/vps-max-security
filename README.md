# vps-max-security

Ubuntu VPS Maximum Security Hardening Toolkit. One command to harden a fresh Ubuntu 24.04 VPS with 20 security modules.

## Quick Install

```bash
curl -fsSL https://raw.githubusercontent.com/qilichevasilbek/vps-max-security/master/install.sh | sudo bash
```

Or clone manually:

```bash
git clone https://github.com/qilichevasilbek/vps-max-security.git
cd vps-max-security && sudo ./vps-max-security
```

## Prerequisites

- Ubuntu 24.04 LTS VPS
- Root or sudo access
- A non-root admin user with SSH key authentication already configured

## Usage

```bash
sudo vps-max-security                                    # Interactive wizard + apply
sudo vps-max-security --dry-run                          # Preview changes only
sudo vps-max-security --no-wizard                        # Skip wizard, use saved config
sudo vps-max-security --only ssh-hardening,firewall      # Run specific modules
sudo vps-max-security --skip system-update               # Skip specific modules
sudo vps-max-security audit                              # Security audit (0-100 score)
sudo vps-max-security status                             # Show applied modules
sudo vps-max-security update                             # Update the tool
sudo vps-max-security rollback                           # Restore from backups
sudo vps-max-security --version                          # Show version
sudo vps-max-security --help                             # Show help
```

## Interactive Wizard

The wizard runs on first use and pre-fills from previous config on re-runs:

```
SSH port [2222]:
Admin username [deployer]:
Enable IPv6? [n]:
Additional firewall ports [80,443]:
Max SSH retries before ban [3]:
Ban duration in hours [24]:
DNS provider (cloudflare/quad9/google) [cloudflare]:
Run ALL hardening modules? [Y/n]:
Perform dry-run first? [Y/n]:
```

## Security Modules

| # | Module | Description |
|---|--------|-------------|
| 01 | system-update | Full apt update/upgrade/dist-upgrade |
| 02 | auto-updates | Unattended security updates |
| 03 | ssh-hardening | SSH config + post-quantum crypto + banner |
| 04 | firewall | UFW default-deny + rate limiting |
| 05 | fail2ban | Intrusion prevention with recidive jail |
| 06 | kernel-hardening | sysctl network + kernel security params |
| 07 | apparmor | Mandatory access control enforcement |
| 08 | file-integrity | AIDE file integrity monitoring |
| 09 | rootkit-scanners | rkhunter + chkrootkit |
| 10 | shared-memory | /dev/shm noexec,nodev,nosuid |
| 11 | file-permissions | Restrict cron, SSH, umask |
| 12 | audit-daemon | auditd kernel-level auditing |
| 13 | dns-security | DNS-over-TLS with DNSSEC |
| 14 | lynis | Security auditing tool |
| 15 | service-cleanup | Disable unnecessary services |
| 16 | login-security | PAM hardening + password policies |
| 17 | dheat-mitigation | SSH rate limiting (anti-DHEat DoS) |
| 18 | usb-hardening | Block USB/Thunderbolt/UVC on VPS |
| 19 | cve-patches | Targeted CVE mitigations (2024-2026) |
| 20 | log-protection | Immutable logs + secure rotation |

## Idempotency

Every module has a `check_*()` function that runs before `apply_*()`. If the hardening is already in place, the module is skipped. Safe to run multiple times.

## Backups & Rollback

Every file modified gets backed up to `/etc/vps-max-security/backups/` with timestamps. To restore:

```bash
sudo vps-max-security rollback
```

## Security Audit

Run an audit to score your server (0-100):

```bash
sudo vps-max-security audit
```

Each module contributes weighted points. Score grades: A (90+), B (80+), C (70+), D (60+), F (<60).

## File Locations

| Path | Purpose |
|------|---------|
| `/etc/vps-max-security/config.conf` | User configuration |
| `/etc/vps-max-security/backups/` | File backups |
| `/etc/vps-max-security/state` | Module status tracking |
| `/etc/vps-max-security/hardening.log` | Execution log |

## CVEs Mitigated

- CVE-2025-21756 (Vsock VM escape)
- CVE-2024-1086 (nf_tables privilege escalation)
- CVE-2025-32463 (sudo chroot escalation)
- CVE-2024-53104 (UVC out-of-bounds write)
- CVE-2025-8941 (PAM race condition)
- DHEat SSH denial-of-service

## Sources

- [ssh-audit.com](https://ssh-audit.com) hardening guides (April 2025)
- [CIS Ubuntu Linux Benchmark](https://www.cisecurity.org/benchmark/ubuntu_linux) v2.0
- [Ubuntu Security Notices](https://ubuntu.com/security/notices) (Feb 2026)
- [CISA KEV Catalog](https://cisa.gov/known-exploited-vulnerabilities-catalog)

## License

MIT
