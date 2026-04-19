# Changelog

All notable changes to `vps-max-security` are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.0] — 2026-04-12

### BREAKING — read before upgrading

- **Firewall now installs a default-DROP `DOCKER-USER` iptables chain.**
  Previously, Docker's DNAT rules bypassed UFW entirely, so `ufw default
  deny incoming` did **not** protect any container published with
  `-p 0.0.0.0:PORT:PORT`. The new chain enforces an explicit allowlist:
  only the TCP ports listed in `FIREWALL_PORTS` (and LiveKit ports when
  `LIVEKIT_ENABLED=true`) reach containers. **If you rely on an
  unpublished compose port being reachable from the internet, it will
  stop working.** Fix: either add the port to `FIREWALL_PORTS` in the
  wizard, or bind the port to `127.0.0.1` in your compose file.

- **`/dev/shm noexec` is now OPT-IN** (was always-on). It breaks
  Chromium / Puppeteer / Playwright and LiveKit egress with a chromium
  recorder. New wizard prompt `Enforce /dev/shm noexec?` defaults to
  `no`. To restore the previous 1.x behavior, set `SHM_NOEXEC=true`.

- **SSH config now leads with post-quantum `mlkem768x25519-sha256`.**
  Requires OpenSSH ≥ 9.9 to take effect. Ubuntu 24.04 base ships 9.6p1
  — install `noble-backports` or `ppa:openssh/ppa` for full PQ. Older
  sshd silently ignores the unknown algorithm; the config still loads.

- **`fail2ban` `banaction` changed from `ufw` to
  `iptables-allports[chain=DOCKER-USER]`.** Bans now also block
  container-published ports. Requires module 04 to have installed the
  DOCKER-USER chain first (it does, in the default run order).

- **Nginx/Django log directories are auto-created.** Module 05 now
  creates `/var/log/nginx/` and `/var/log/django/` with stub files so
  Fail2Ban can start before applications write their first line. These
  directories should be bind-mounted from your containers so Fail2Ban
  actually reads real logs.

### Added

- **`configs/docker-user.rules.tmpl`** — template for the DOCKER-USER
  allowlist (SYN hashlimit, connlimit, loopback + bridge RETURN rules,
  LiveKit media range).
- **`configs/modules-load-br_netfilter.conf`** — forces `br_netfilter`
  to load at boot so `bridge-nf-call-iptables` sysctls apply on first
  boot instead of failing silently.
- **`configs/limits-nocore.conf`** — disables core dumps system-wide
  (prevents secret leakage from Django/Node crashes).
- **Fail2Ban custom filters:**
  - `configs/fail2ban-filters/nginx-4xx-scanner.conf` — bans hosts
    generating high volumes of 4xx responses (bot probing).
  - `configs/fail2ban-filters/django-admin.conf` — parses Django's
    `django.security.*` auth logger for brute-force attempts.
- **Fail2Ban jails added:** `nginx-http-auth`, `nginx-botsearch`,
  `nginx-badbots`, `nginx-limit-req`, `nginx-4xx-scanner`,
  `django-admin`. The `recidive` jail now bans for 30 days.
- **auditd Docker host ruleset** (Neo23x0-derived): watches dockerd,
  containerd, runc, `/etc/docker`, `/var/lib/docker`,
  `/var/run/docker.sock`, identity files, kernel module load, ptrace
  (code/data/register injection), mount/umount2, rootcmd
  (euid=0 auid≥1000).
- **Kernel module blacklist** (`configs/blacklist-hardening.conf`):
  DCCP, SCTP, RDS, TIPC, n-hdlc, ax25, netrom, x25, rose, decnet,
  econet, af_802154, IPX, AppleTalk, CAN, ATM, cramfs, freevxfs, jffs2,
  hfs, hfsplus, udf, firewire-core, thunderbolt, bluetooth, btusb.
  **squashfs is conditionally added only when snapd is NOT present**.
- **CVE detection** (module 19 is now detection-oriented):
  - runc version check (warns if < 1.2.8 for CVE-2025-31133 / 52565 /
    52881).
  - OpenSSH version check (warns if < 9.8p1 for regreSSHion CVE-2024-6387).
  - Canonical Livepatch recommendation for CVE-2025-38352 (POSIX CPU
    timer race, CISA KEV, exploited in the wild).
- **Wizard prompts:**
  - `Running LiveKit (WebRTC)?` → opens TURN + UDP media range.
  - `LiveKit UDP media range START/END` (defaults 50000–50100).
  - `Enforce /dev/shm noexec?` with Chromium/LiveKit warning.
- **New config variables:** `LIVEKIT_ENABLED`, `LIVEKIT_UDP_RANGE_START`,
  `LIVEKIT_UDP_RANGE_END`, `SHM_NOEXEC`.
- **Research documentation** (`docs/research/`):
  - `FORTRESS-2026.md` — full 13-section Docker-compatible fortress
    report with threat model, copy-paste configs, 25 gotchas, sources.
  - `CODEBASE-GAPS.md` — per-module gap analysis driving this release.

### Changed

- **`configs/sshd_hardening.conf`** — `KexAlgorithms` now leads with
  `mlkem768x25519-sha256`. `HostKeyAlgorithms` + `PubkeyAcceptedAlgorithms`
  now include `sk-ssh-ed25519@openssh.com` for FIDO2 hardware keys.
  `CASignatureAlgorithms` added for SSH CA-based auth.
- **`configs/sysctl-hardening.conf`** — added
  `net.bridge.bridge-nf-call-arptables=1`, `fs.protected_hardlinks=1`,
  `fs.protected_symlinks=1`, `fs.protected_fifos=2`,
  `fs.protected_regular=2`, `kernel.perf_event_paranoid=3`. Added
  explicit "MUST NOT DISABLE" comment block listing the Docker-required
  keys (`ip_forward`, `bridge-nf`, `unprivileged_userns_clone`).
- **`modules/06-kernel-hardening.sh`** now installs
  `/etc/modules-load.d/br_netfilter.conf`, runs `modprobe br_netfilter`
  at apply time, installs `limits-nocore.conf`, masks
  `systemd-coredump.socket`, and sets `kernel.core_pattern=|/bin/false`.
- **`modules/03-ssh-hardening.sh`** now detects OpenSSH version and
  advises installing `ppa:openssh/ppa` if < 9.9.
- **`modules/05-fail2ban.sh`** now installs custom filters, creates log
  path stubs, and ships a much larger jail set.
- **`modules/10-shared-memory.sh`** default is now `nosuid,nodev` only;
  `noexec` is opt-in via `SHM_NOEXEC=true`.
- **`modules/12-audit-daemon.sh`** audit function now verifies the
  `docker` and `rootcmd` rule keys are loaded.
- **`modules/18-usb-hardening.sh`** now ships the full rare-module
  blacklist; conditionally excludes squashfs if snapd is present.
- **`modules/19-cve-patches.sh`** is now detection + recommendation
  oriented; re-runs every time so new upstream advisories are picked up.

### Fixed

- First-boot `sysctl --system` silently failing to set
  `net.bridge.bridge-nf-call-iptables` when `br_netfilter` had not yet
  been loaded.
- Audit check for SSH hardening that looked only for `sntrup761` —
  now accepts either `mlkem768` or `sntrup761`.

### Security

- DOCKER-USER default-DROP closes the single largest class of
  accidental port-exposure misconfigurations on Docker hosts.
- Fail2Ban bans now block container-published ports via the
  DOCKER-USER chain, not just host services.
- Core dumps disabled to prevent secret leakage from Django/Node
  process memory on crashes.

---

## [1.0.0] — 2026-02-XX

- Initial release: 20 security modules covering SSH, UFW, sysctl,
  fail2ban, apparmor, AIDE, rkhunter/chkrootkit, auditd,
  unattended-upgrades, DNS-over-TLS, PAM password policy, DHEat
  mitigation, USB/Thunderbolt/UVC blocking, CVE patches, log
  protection.
