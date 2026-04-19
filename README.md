# vps-max-security

Ubuntu 24.04 VPS hardening toolkit for **Dockerized production workloads**. One command closes the 20 most impactful hardening gaps on a fresh server without breaking Docker networking, WebRTC media, or common container runtimes.

**⚠ 2.0.0 is a breaking release.** See [`CHANGELOG.md`](CHANGELOG.md) — the firewall now installs a default-DROP `DOCKER-USER` chain, `/dev/shm noexec` is opt-in, and SSH leads with post-quantum ML-KEM. Read before upgrading from 1.x.

## Why another hardening tool?

The default UFW setup on a Docker host has a **silent critical flaw**: Docker's DNAT rules run *before* UFW's filter INPUT chain, so `ufw default deny incoming` does **not** protect container ports published with `-p 0.0.0.0:PORT:PORT`. Every stock hardening guide misses this. This tool fixes it by installing a default-DROP `DOCKER-USER` chain via `/etc/ufw/after.rules`, survives docker restarts, and explicitly allowlists only the ports you configure.

Research and threat model: [`docs/research/FORTRESS-2026.md`](docs/research/FORTRESS-2026.md).

## Quick Install (2 commands)

You just bought a VPS from Contabo, Hetzner, Hostinger, DigitalOcean, etc. You have root access (password or SSH key from the provider). That's all you need.

```bash
# Step 1: Install the tool
curl -fsSL https://raw.githubusercontent.com/qilichevasilbek/vps-max-security/master/install.sh | sudo bash

# Step 2: Run it
sudo vps-max-security
```

The tool handles everything:
1. **Creates an admin user** if you only have root (auto-copies SSH keys from root)
2. **Asks 3 questions** (server profile, SSH port, admin user)
3. **Applies 20 hardening modules** (kernel, firewall, SSH, fail2ban, auditd...)
4. **Installs DOCKER-USER firewall** if Docker is detected (blocks exposed container ports)
5. **Shows next steps** (test SSH, reboot)

Or clone manually:

```bash
git clone https://github.com/qilichevasilbek/vps-max-security.git
cd vps-max-security && sudo ./vps-max-security
```

## Prerequisites

- Ubuntu 24.04 LTS VPS (Contabo, Hetzner, Hostinger, DigitalOcean, Linode, Vultr, etc.)
- Root or sudo access
- That's it. The tool creates the admin user and sets up SSH keys if they don't exist yet.

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

3 questions. Auto-detects Docker, SSH port, admin user, IPv6. Power users edit `/etc/vps-max-security/config.conf` for advanced settings.

```
══════════════════════════════════════════════════
  VPS MAX SECURITY v2.0.0
══════════════════════════════════════════════════

  ✓ Ubuntu 24.04 LTS
  ✓ Docker 27.5.1 (4 containers running)
  ✓ SSH on port 22, user: deployer

  Choose your server profile:

    1) Web Server        — TCP 80, 443 only
    2) Web + Realtime    — TCP 80, 443 + UDP 3478, 50000-50100
    3) Custom            — You specify exact ports

  Profile [1]:
  SSH port [2222]:
  Admin user [deployer]:

  Apply? (yes/no):
  Dry-run first? [Y/n]:
```

**Profiles:**
- **Web Server** — 90% of deployments. HTTP + HTTPS only. Everything else firewalled.
- **Web + Realtime** — for WebRTC (LiveKit, Jitsi, mediasoup), VoIP, game servers. Adds STUN/TURN + UDP media range.
- **Custom** — asks for TCP and UDP port lists. Full control.

## Security Modules

| # | Module | Description |
|---|--------|-------------|
| 01 | system-update | Full apt update/upgrade/dist-upgrade |
| 02 | auto-updates | Unattended security updates |
| 03 | ssh-hardening | SSH config + **ML-KEM post-quantum KEX** (OpenSSH 9.9+) + banner |
| 04 | firewall | UFW + **default-DROP `DOCKER-USER` chain** (Docker-safe) |
| 05 | fail2ban | sshd + **nginx (4xx/botsearch/limit-req/badbots)** + **django-admin** + recidive, bans via DOCKER-USER |
| 06 | kernel-hardening | Docker-safe sysctl + `br_netfilter` autoload + core dump lockdown |
| 07 | apparmor | Mandatory access control enforcement |
| 08 | file-integrity | AIDE file integrity monitoring |
| 09 | rootkit-scanners | rkhunter + chkrootkit |
| 10 | shared-memory | /dev/shm nodev,nosuid (noexec opt-in — breaks Chromium/LiveKit egress) |
| 11 | file-permissions | Restrict cron, SSH, umask |
| 12 | audit-daemon | auditd with **Docker host ruleset** (dockerd/containerd/runc/ptrace/mount/rootcmd) |
| 13 | dns-security | DNS-over-TLS with DNSSEC |
| 14 | lynis | Security auditing tool |
| 15 | service-cleanup | Disable unnecessary services |
| 16 | login-security | PAM hardening + password policies |
| 17 | dheat-mitigation | SSH rate limiting (anti-DHEat DoS) |
| 18 | usb-hardening | USB/Thunderbolt/UVC + **kernel module blacklist** (DCCP/SCTP/RDS/TIPC/etc., snapd-aware) |
| 19 | cve-patches | Detection + advice: runc ≥1.2.8, OpenSSH ≥9.8p1, kernel + Livepatch recs |
| 20 | log-protection | Immutable logs + secure rotation |

## Docker Compatibility

This tool is **designed for Ubuntu 24.04 VPSs running multiple Docker Compose stacks**. Specifically tested against Django/Daphne, Node.js, PostgreSQL, Redis, Celery, Nginx, and self-hosted LiveKit (WebRTC).

Docker-required sysctls are **never** disabled:
- `net.ipv4.ip_forward=1`, `net.bridge.bridge-nf-call-iptables=1` — required for container networking.
- `kernel.unprivileged_userns_clone=1` — required by Docker, Podman, Chromium sandbox.
- `rp_filter=2` (loose, not strict) — strict breaks multi-bridge asymmetric routing.
- `yama.ptrace_scope=1` (not 2) — 2 breaks `docker exec strace`, Sentry native, py-spy.

Things that *could* break Docker if applied naively — and the tool's mitigation:
- `/dev/shm noexec` is **opt-in** (breaks Chromium/Puppeteer/LiveKit egress).
- `br_netfilter` is forced to load at boot so `bridge-nf-call-*` sysctls apply on first boot.
- `squashfs` is **not** blacklisted if snapd is present.
- Firewall uses `DOCKER-USER` chain, not UFW INPUT — bans + allowlists apply to container ports.

If you run LiveKit, answer **YES** at the "Running LiveKit (WebRTC)?" wizard prompt to open TURN + media UDP range (default 50000-50100). Run LiveKit in `network_mode: host` so the kernel handles the UDP port range directly rather than 10 000 docker-proxy processes.

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

## CVEs Mitigated / Detected

- **CVE-2024-6387** regreSSHion — OpenSSH pre-auth RCE (detected by module 19)
- **CVE-2024-21626** runc Leaky Vessels — container escape (detected by module 19)
- **CVE-2024-1086** nf_tables UAF LPE — CISA KEV, ransomware-used
- **CVE-2024-3094** xz backdoor — Ubuntu 24.04 stable was never affected
- **CVE-2024-53104** UVC out-of-bounds write (module 18 blacklist)
- **CVE-2025-21756** vsock UAF (module 19 blocks vsock module)
- **CVE-2025-31133 / 52565 / 52881** runc Nov 2025 trio (detected by module 19)
- **CVE-2025-38352** POSIX CPU timer race, CISA KEV, exploited in the wild (module 19 recommends Livepatch)
- **CVE-2025-32463** sudo chroot escalation
- **CVE-2025-8941** PAM race condition
- **DHEat** SSH denial-of-service (module 17)

## Further Reading

- [`docs/research/FORTRESS-2026.md`](docs/research/FORTRESS-2026.md) — full 13-section Docker-compatible hardening report driving this release.
- [`docs/research/CODEBASE-GAPS.md`](docs/research/CODEBASE-GAPS.md) — per-module gap analysis.
- [`CHANGELOG.md`](CHANGELOG.md) — what changed in 2.0.0 and why.

## Sources

- [ssh-audit.com](https://ssh-audit.com) hardening guides (April 2026)
- [OpenSSH Post-Quantum Cryptography](https://www.openssh.org/pq.html)
- [Docker Docs — Packet filtering and firewalls](https://docs.docker.com/engine/network/packet-filtering-firewalls/)
- [LiveKit Docs — Ports and firewall](https://docs.livekit.io/transport/self-hosting/ports-firewall/)
- [CIS Docker Benchmark](https://www.cisecurity.org/benchmark/docker) (Aug 2025 update)
- [CIS Ubuntu Linux Benchmark](https://www.cisecurity.org/benchmark/ubuntu_linux) v1.0 for 24.04
- [Ubuntu Security Notices](https://ubuntu.com/security/notices)
- [CISA KEV Catalog](https://cisa.gov/known-exploited-vulnerabilities-catalog)
- [runc security advisories](https://github.com/opencontainers/runc/security/advisories)

## License

MIT
