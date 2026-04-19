# Codebase Gap Analysis — vps-max-security vs Fortress-2026

Mapping current 20 modules to the fortress report findings. Identifies what's covered, what's missing, and what needs to change for Docker + LiveKit compatibility.

**Legend:** ✅ covered — ⚠ partial / needs update — ❌ missing — 🆕 new module required

---

## Existing Module Audit

| # | Module | Status | Changes Needed (ref § in FORTRESS-2026) |
|---|---|---|---|
| 01 | system-update | ✅ | Blacklist `docker-ce`/`containerd.io` from unattended-upgrades (§1.7). Keep Docker upgrades manual. |
| 02 | auto-updates | ⚠ | Add Automatic-Reboot true + 03:00 window; add `Package-Blacklist` for docker-*; integrate `needrestart` auto-mode config (§1.7). |
| 03 | ssh-hardening | ⚠ | **Must add** `mlkem768x25519-sha256` to KexAlgorithms (§2.2). Add OpenSSH PPA path for ≥9.9 on 24.04. Strip moduli <3071. Add `AuthenticationMethods publickey`. Enable ssh-audit self-test. |
| 04 | firewall | ❌ **CRITICAL REWRITE** | Current UFW rules are bypassed by Docker. Must install DOCKER-USER chain with default DROP (§3.3). Add Cloudflare ipset integration (§3.12). Add LiveKit UDP range 50000-50100 allowance. Add SYN rate limit + connlimit. Add `ip6tables: true` awareness. |
| 05 | fail2ban | ⚠ | Change `banaction` → `iptables-allports[chain=DOCKER-USER]` (§9.1). Add nginx-4xx-scanner, nginx-badbots, nginx-limit-req, django-admin custom jails with filters. Add systemd backend option for journald. |
| 06 | kernel-hardening | ⚠ | Current `configs/sysctl-hardening.conf` must add **Docker-required** entries: `net.ipv4.ip_forward=1`, `net.bridge.bridge-nf-call-iptables=1`, `kernel.unprivileged_userns_clone=1`. Change `rp_filter` from 1 → 2 (strict breaks Docker multi-bridge). Ensure `br_netfilter` loaded at boot via `/etc/modules-load.d/docker.conf`. `yama.ptrace_scope=1` not 2. `unprivileged_bpf_disabled=1` with note about Falco. See §1.1. |
| 07 | apparmor | ⚠ | Keep docker-default. Add per-service custom profiles for Nginx/Postgres/Redis/LiveKit (§1.3). Ship template profiles in `configs/apparmor/`. |
| 08 | file-integrity (AIDE) | ⚠ | **Must exclude** `/var/lib/docker`, `/var/lib/containerd`, `/var/lib/docker/overlay2` or daily diffs are unreadable (§9.2). |
| 09 | rootkit-scanners | ⚠ | Keep as compliance checkbox. Document in README that Falco/Tetragon are modern replacements (§9.3). |
| 10 | shared-memory | ⚠ | `/dev/shm noexec` breaks Chromium/Puppeteer and LiveKit egress. Make noexec opt-in with warning; default to nosuid,nodev only. Document container workaround via `--tmpfs /dev/shm:rw,exec` (§1.2). |
| 11 | file-permissions | ✅ | OK as-is. |
| 12 | audit-daemon | ❌ **REWRITE RULES** | Current `configs/auditd-rules.conf` lacks Docker-specific watches. Replace with Neo23x0-derived Docker host ruleset (§9.4): dockerd, containerd, runc, `/etc/docker`, `/var/lib/docker`, `/var/run/docker.sock`, module load, ptrace, mount, rootcmd. Exclude Docker overlay noise. |
| 13 | dns-security | ✅ | OK. |
| 14 | lynis | ✅ | Target hardening index ≥85. |
| 15 | service-cleanup | ✅ | OK. |
| 16 | login-security | ✅ | OK. |
| 17 | dheat-mitigation | ✅ | Recent commit already migrated state→conntrack. |
| 18 | usb-hardening | ✅ | Align blacklist with §1.4 — **do not blacklist squashfs** if snapd present. |
| 19 | cve-patches | ⚠ | Expand to cover 2025–2026 container-relevant CVEs: runc CVE-2025-31133/52565/52881 (verify runc ≥1.2.8), CVE-2025-38352 POSIX timer (livepatch), CVE-2025-21756 vsock. See §13.1. |
| 20 | log-protection | ⚠ | Add exclusion pattern for Docker container logs / overlay so immutable flags don't break log driver writes. |

---

## Missing Modules (new)

### 🆕 21-docker-daemon-hardening
**Purpose:** Deploy hardened `/etc/docker/daemon.json` — the keystone for a Docker host.
**Reference:** §4.1.
**What it does:**
- Backs up existing `daemon.json`.
- Writes: `icc:false`, `no-new-privileges:true`, `live-restore:true`, `userland-proxy:false`, `iptables:true`, `ip6tables:true`, `log-driver:json-file` with 10m/5 rotation, `default-ulimits`, `init:true`, `default-address-pools`.
- **Optional prompt** for `userns-remap:default` (warn about bind-mount ownership + LiveKit host networking conflict).
- Installs custom seccomp profile at `/etc/docker/seccomp-default.json`.
- `systemctl restart docker` (skipped in dry-run).
**Risk:** daemon restart drops containers unless `live-restore` was already on.

### 🆕 22-docker-user-chain
**Purpose:** Install default-DROP DOCKER-USER iptables chain — the real Docker firewall.
**Reference:** §3.2, §3.3.
**What it does:**
- Appends `DOCKER-USER` rules to `/etc/ufw/after.rules` (loopback, bridge subnets, Cloudflare ipset match, LiveKit ports 7880/7881/7882/3478/443 UDP/50000-50100 UDP, SYN hashlimit, connlimit, default DROP).
- Creates empty `cf-v4` / `cf-v6` ipsets at install so rules don't reference missing sets on first run.
- Installs `/usr/local/sbin/cf-ipset-update.sh` (§3.12) + cron every 6h.
- Configurable: which ports to expose, CIDR allowlists.
- `ufw reload` to apply.
**Wizard prompts:** Cloudflare-only mode? (y/n) LiveKit enabled? UDP media port range?

### 🆕 23-container-runtime-scan
**Purpose:** Daily Trivy/Grype scan of running container images; alert on HIGH/CRITICAL.
**Reference:** §4.6, §11.2.
**What it does:**
- Installs Trivy (apt repo) + Grype (binary).
- Creates `/etc/cron.daily/trivy-scan` that iterates `docker ps --format '{{.Image}}'` and writes JSON to `/var/log/trivy/`.
- Emails findings or writes summary to `/var/log/vps-max-security/vuln-summary.log`.
**Default:** warn-only (exit 0); strict mode exits 1 in audit engine.

### 🆕 24-cosign-verify
**Purpose:** Verify cosign signatures on images before `docker compose up`.
**Reference:** §4.5, §11.3.
**What it does:**
- Installs cosign binary.
- Deploys `/etc/vps-max-security/cosign-policy.yaml` with allowed signer identities.
- Installs `/usr/local/sbin/vps-docker-up` wrapper: verifies every image in the compose file via `cosign verify --certificate-identity-regexp ...` before running `docker compose up -d`.
- Documented but opt-in (many existing stacks use unsigned images).

### 🆕 25-compose-audit
**Purpose:** Audit every `docker-compose.yml` on the host for security gotchas.
**Reference:** §3.5, §3.6, §4.4, §4.9.
**What it does:**
- Scans `/srv/*/docker-compose.yml` (or user-configured paths).
- Flags:
  - `ports:` without `127.0.0.1:` prefix on common DB/cache ports (5432/6379/27017/11211/9200).
  - Missing `cap_drop: [ALL]`.
  - Missing `no-new-privileges: true`.
  - Missing `pids_limit` / `mem_limit`.
  - `privileged: true`.
  - `/var/run/docker.sock` bind mounts (warn, suggest socket-proxy).
  - `network_mode: host` on non-LiveKit services.
  - Missing `read_only: true` (info only — not always practical).
  - Missing image digest pin (`@sha256:`).
- Outputs report to `/var/log/vps-max-security/compose-audit-$(date +%F).txt`.
- Contributes 10 points to audit engine score.

### 🆕 26-tailscale-bastion (optional)
**Purpose:** Install Tailscale and migrate SSH to tailnet-only.
**Reference:** §2.7, §13.5.
**What it does:**
- Installs `tailscale` via official repo.
- Prompts for auth key (or `--authkey` arg).
- After successful `tailscale up`, modifies sshd_config drop-in to `ListenAddress 100.64.0.0/10` (or specific tailnet IP).
- Closes port 22 in UFW / cloud provider firewall (requires user confirmation — could lock out).
- **Critical safety:** dry-run must be supported; rollback must keep 22 open until tailnet verified.

### 🆕 27-crowdsec
**Purpose:** Deploy CrowdSec as Fail2Ban successor with community blocklist.
**Reference:** §9.6.
**What it does:**
- Installs `crowdsecurity/crowdsec` via official apt repo (or Docker).
- Enables collections: linux, nginx, sshd, base-http-scenarios, http-cve, appsec-virtual-patching.
- Installs `cs-firewall-bouncer` with iptables (DOCKER-USER chain).
- Option to enroll in free CrowdSec Console.
- Coexists with Fail2Ban initially; migration path documented.

### 🆕 28-backup-restic
**Purpose:** Deploy restic + systemd timer for hourly encrypted backups to offsite.
**Reference:** §10.3.
**What it does:**
- Installs restic.
- Prompts for: repo URL (B2/S3/SFTP), access keys, password (stored in `/etc/restic/passwd` mode 600).
- Writes `/usr/local/sbin/restic-backup.sh` (Postgres stream dump → restic, Docker volumes, retention, integrity check, optional second-repo mirror, Healthchecks.io ping).
- Systemd timer hourly with 15m randomization.
- Monthly restore-drill script (optional).

### 🆕 29-secrets-sops (optional, nice-to-have)
**Purpose:** Install SOPS + age for git-committable encrypted secrets.
**Reference:** §7.6, §11.
**What it does:**
- Installs `sops` + `age` binaries.
- Generates age keypair if none present.
- Documents `.sops.yaml` config template.
- No forced changes — opt-in for teams ready to adopt.

### 🆕 30-loki-logging (optional)
**Purpose:** Deploy Loki + Promtail + Grafana for log aggregation.
**Reference:** §9.5.
**What it does:**
- Writes `docker-compose.logging.yml` to `/srv/vps-max-security/logging/`.
- Configures Docker daemon `log-driver: loki` as default (with fallback).
- Ships Promtail config with journald + Nginx + Docker container scrapes.
- Grafana with Grafana admin password from Docker secret.
- Behind Cloudflare Access or Tailscale-only.

---

## Config File Updates

| File | Change |
|---|---|
| `configs/sysctl-hardening.conf` | Rewrite per §1.1 — add Docker-required bridge/forwarding entries; switch to `rp_filter=2`; add `yama.ptrace_scope=1`; add bpf hardening; add fs.protected_*. |
| `configs/sshd_hardening.conf` | Add `mlkem768x25519-sha256` as first KEX; add `CASignatureAlgorithms`; set `AuthenticationMethods publickey`; `LogLevel VERBOSE`. |
| `configs/fail2ban-jail.conf` | Add `banaction = iptables-allports[chain=DOCKER-USER]`; add nginx-4xx-scanner, nginx-badbots, nginx-limit-req, django-admin jails. |
| `configs/auditd-rules.conf` | Replace with Docker-host ruleset (§9.4). |
| `configs/daemon.json` (new) | Hardened Docker daemon config. |
| `configs/docker-user.rules` (new) | DOCKER-USER chain template. |
| `configs/apparmor/docker-nginx` (new) | Custom AppArmor profile template. |
| `configs/apparmor/docker-postgres` (new) | " |
| `configs/apparmor/docker-redis` (new) | " |
| `configs/apparmor/docker-livekit` (new) | " |
| `configs/seccomp-default.json` (new) | Custom seccomp baseline (can start as Docker default copy). |
| `configs/blacklist-hardening.conf` (new) | Kernel module blacklist (§1.4). Omit `squashfs` if snapd present. |
| `configs/renovate.json` (new) | Reference Renovate config for image/dep digest pinning (§11.1). |
| `configs/restic-backup.sh` (new) | Backup script template. |
| `configs/crowdsec/acquis.d/nginx.yaml` (new) | CrowdSec log acquisition config. |

---

## Wizard Prompts to Add

Extend `lib/wizard.sh` with:

1. **Docker mode enabled?** (y/n) — gates modules 21-25.
2. **Cloudflare in front?** (y/n) — gates CF ipset integration in firewall.
3. **LiveKit enabled?** (y/n) — gates UDP media port range opening.
4. **LiveKit UDP range start/end** (default 50000-50100).
5. **Use rootless Docker for web stack?** (y/n + warn if LiveKit selected).
6. **Enable userns-remap?** (y/n + warn about bind mount ownership).
7. **Tailscale for SSH?** (y/n + prompt for auth key).
8. **Backup destination** (B2 / Wasabi / rsync.net / Hetzner / skip).
9. **Secondary backup destination** (same list + skip).
10. **Compose files to audit** (paths, comma-separated).

---

## Audit Engine Weights (recalibrate)

Current (from `lib/audit_engine.sh`): SSH=15, Firewall=12, Kernel=10, ...

**Proposed Docker-aware weights (total 100):**

| Category | Weight | Modules |
|---|---|---|
| Docker daemon hardening | 14 | 21 |
| DOCKER-USER firewall chain | 12 | 22 |
| SSH (PQ KEX + keys only) | 12 | 03 |
| Kernel hardening (Docker-safe) | 10 | 06 |
| Container image scanning | 8 | 23 |
| Compose audit (per-service caps/limits) | 8 | 25 |
| Auditd with Docker rules | 6 | 12 |
| Fail2Ban / CrowdSec | 6 | 05, 27 |
| AppArmor profiles | 5 | 07 |
| Backups (restic + offsite) | 5 | 28 |
| CVE patches (runc, kernel, OpenSSH) | 5 | 19 |
| DNS / Auto-updates | 4 | 02, 13 |
| File integrity (AIDE) | 3 | 08 |
| USB/module blacklist | 2 | 18 |

---

## Breaking-Change Migration Notes

Running the refactored tool against an existing hardened server will:

1. **Change sysctl defaults** — `rp_filter` 1→2 may change packet handling; reboot recommended.
2. **Add DOCKER-USER default DROP** — will immediately cut traffic to any container not on the allowlist. **Must** run `--dry-run` first and review the rule set.
3. **Change `docker.json`** — triggers `systemctl restart docker` which drops containers unless `live-restore` was already on.
4. **Enable `userland-proxy: false`** — existing high-port-range publishes (e.g., LiveKit without `network_mode: host`) will behave differently. Prompt before enabling.
5. **Install cf-ipset cron** — requires outbound HTTPS to `cloudflare.com/ips-v4` every 6h.
6. **Tailscale module** can lock you out if port 22 is closed before tailnet reachability is verified. Must be interactive-only, never `--no-wizard`.

All breaking modules must call `confirm_breaking_change()` unless `--force` is passed.

---

## Implementation Order

Recommended rollout over 4 phases:

**Phase 1 — Critical fixes to existing modules (week 1):**
- Rewrite `configs/sysctl-hardening.conf` (§1.1).
- Update `modules/03-ssh-hardening.sh` for OpenSSH 9.9+ + ML-KEM.
- Rewrite `modules/04-firewall.sh` with DOCKER-USER chain.
- Update `modules/05-fail2ban.sh` banaction.
- Update `configs/auditd-rules.conf`.
- Fix `modules/10-shared-memory.sh` Chromium/LiveKit exception.
- Update `configs/sysctl-hardening.conf` to fix rp_filter + add Docker bridge sysctls.
- Add `br_netfilter` to `/etc/modules-load.d/`.

**Phase 2 — New Docker-focused modules (week 2-3):**
- Add `modules/21-docker-daemon-hardening.sh` + `configs/daemon.json`.
- Add `modules/22-docker-user-chain.sh` + `configs/docker-user.rules` + cf-ipset integration.
- Add `modules/25-compose-audit.sh`.
- Ship AppArmor profile templates.

**Phase 3 — Monitoring & supply chain (week 4-5):**
- Add `modules/23-container-runtime-scan.sh` (Trivy/Grype).
- Add `modules/27-crowdsec.sh`.
- Add `modules/28-backup-restic.sh`.
- Update `modules/19-cve-patches.sh` for runc Nov-2025 CVEs.

**Phase 4 — Optional hardening (month 2):**
- Add `modules/24-cosign-verify.sh`.
- Add `modules/26-tailscale-bastion.sh`.
- Add `modules/29-secrets-sops.sh`.
- Add `modules/30-loki-logging.sh`.
- Recalibrate audit engine weights.
- Update wizard with new prompts.

---

## What the User Should NOT Do

Explicit anti-patterns to warn about in the tool and docs:

1. ❌ Don't set `net.ipv4.ip_forward=0` — kills Docker.
2. ❌ Don't set `rp_filter=1` on a Docker host with multiple bridge networks.
3. ❌ Don't blacklist `squashfs` if snapd is installed.
4. ❌ Don't mount `/var/run/docker.sock` into any container without Tecnativa socket-proxy.
5. ❌ Don't use `network_mode: host` except for LiveKit.
6. ❌ Don't use `--privileged` on any production container.
7. ❌ Don't use `:latest` image tags in production compose files.
8. ❌ Don't put JWT tokens in WebSocket URL query strings.
9. ❌ Don't put secrets in environment variables that appear in `docker inspect`.
10. ❌ Don't run rootless Docker with LiveKit — slirp4netns is slow for UDP media.
11. ❌ Don't run AI coding agents with `--dangerously-skip-permissions` on a box with production credentials (s1ngularity lesson).
12. ❌ Don't trust `ufw default deny incoming` to protect container ports.
