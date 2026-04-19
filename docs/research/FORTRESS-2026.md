# VPS Fortress — Docker-Compatible Security Hardening (2026)

**Target:** Ubuntu 24.04 LTS VPS running 4–6 Docker Compose stacks (Django/Daphne, Node, PostgreSQL, Redis, Celery, Nginx, LiveKit WebRTC with public UDP media).
**Date:** April 2026.
**Audience:** Senior DevOps. Every recommendation tagged **[MUST]**, **[SHOULD]**, or **[NICE]**.

---

## Executive Summary

The single biggest risk on this class of deployment is **not SSH brute force** — it is the **UFW↔Docker bypass** (§3.1), followed by **supply chain** (§11), and **runc container escape CVEs** (§13.1). A default Ubuntu + Docker install *looks* hardened while publishing every container port straight to the internet. This report fixes that and twelve adjacent failure modes.

### Top 10 Actions by Impact

| # | Action | Effort | Impact | Section |
|---|---|---|---|---|
| 1 | Bind private container ports to `127.0.0.1` and enforce DOCKER-USER chain with default-DROP | Low | Critical | §3.3, §3.5 |
| 2 | Run LiveKit with `network_mode: host`; minimize UDP range to 50000–50100 | Low | High | §3.9, §8 |
| 3 | `cap_drop: [ALL]` + `no-new-privileges:true` + `read_only: true` + tmpfs on every container | Medium | High | §4.4 |
| 4 | Pin every image by `@sha256:` digest; Renovate auto-bumps; cosign verify in CI | Medium | High | §11.1–11.3 |
| 5 | Upgrade to OpenSSH 9.9+/10.0 with `mlkem768x25519-sha256` PQ-first KEX; SSH via Tailscale only | Low | High | §2 |
| 6 | Cloudflare proxy for HTTP/WSS; restrict origin 80/443 to CF ipset via daily cron; media UDP bypasses CF | Medium | High | §3.12 |
| 7 | Hardened `/etc/docker/daemon.json` with `userns-remap`, `icc:false`, `live-restore`, `userland-proxy:false`, `ip6tables:true` | Low | High | §4.1 |
| 8 | Patch runc ≥ 1.2.8 / 1.3.3 (Nov-2025 CVE trio); enable unattended-upgrades + livepatch | Low | Critical | §13.1 |
| 9 | CrowdSec (or Fail2Ban) + auditd Docker ruleset + CSP nonces + JWT httpOnly refresh cookie | Medium | High | §7, §9 |
| 10 | restic hourly backups to two offsite destinations + monthly restore drill | Medium | High | §10 |

### Priority Roadmap

- **Week 1 (emergency):** items 1, 2, 5, 8 — closes the biggest holes.
- **Week 2–3:** 3, 6, 7, 9 — hardens containers and the edge.
- **Month 2:** 4, 10 + Nginx/Django hardening, CSP, CrowdSec.
- **Quarterly:** CIS/Lynis scans, restore drills, dependency audits, pentest from external host.

---

## Threat Model (Ranked)

| # | Threat | Likelihood | Impact | Primary mitigations |
|---|---|---|---|---|
| 1 | **Published container port discovered and exploited** (UFW bypass + vulnerable app) | High | Critical | §3.3, §3.5, §4, §11 |
| 2 | **Supply chain compromise** of a pip/npm/Docker base image (Shai-Hulud-class) | High | Critical | §11 |
| 3 | **Runc / containerd container escape** via known CVE on unpatched host | Medium | Critical | §13.1, §4.1 |
| 4 | **Django/Node app-layer RCE** via dependency CVE or upload bug | Medium | High | §7 |
| 5 | **Credential theft** via log/env leakage (JWT in URLs, secrets in images) | High | High | §7.4, §11 |
| 6 | **SSH brute force / CVE-2024-6387 regreSSHion** | Medium | Critical | §2 |
| 7 | **LiveKit room hijack or TURN abuse** | Medium | High | §8 |
| 8 | **Database exfiltration** via SQL injection (ORM escape hatches) or misconfigured `pg_hba.conf` | Low-Med | Critical | §6 |
| 9 | **Volumetric DDoS** on HTTP or UDP media | Medium | Medium | §3.10, §3.12 |
| 10 | **Backup tamper / ransomware** | Low | Critical | §10 |
| 11 | **Insider / lost laptop** with long-lived SSH keys | Low | High | §2.4, §2.5 |
| 12 | **Host kernel LPE** from a container (CVE-2024-1086 nf_tables class) | Medium | Critical | §1.9, §13.1 |

---

# Section 1 — OS-Level Hardening (Docker-Compatible)

## 1.1 sysctl — what's safe, what MUST stay

Docker's bridge networking is non-negotiable on several sysctls. Getting these wrong silently breaks container-to-container traffic, container-to-internet NAT, or LiveKit's UDP media path.

**Must stay enabled for Docker:**

| sysctl | Required value | Why |
|---|---|---|
| `net.ipv4.ip_forward` | `1` | Docker NATs container traffic. |
| `net.ipv6.conf.all.forwarding` | `1` (if IPv6) | Same, v6 side. |
| `net.bridge.bridge-nf-call-iptables` | `1` | Bridged traffic must traverse iptables so DOCKER-USER matches. Requires `br_netfilter` module. |
| `net.bridge.bridge-nf-call-ip6tables` | `1` | v6 equivalent. |
| `kernel.unprivileged_userns_clone` | `1` (default on 24.04) | Docker, Podman, Chromium sandbox need user namespaces. **Setting to 0 breaks Docker.** |

**Known 24.04 footgun:** `br_netfilter` is not auto-loaded at boot, so sysctl-on-boot errors out. Fix: drop `br_netfilter` into `/etc/modules-load.d/docker.conf` so it loads *before* `systemd-sysctl.service`.

### Copy-paste `/etc/sysctl.d/99-vps-hardening.conf`

```ini
# === VPS Fortress — Docker-compatible sysctl (2026) ===
# Safe for Docker 27+, LiveKit, Podman.

#--- Network: SYN flood / spoofing ---
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 5
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_keepalive_time = 600
net.ipv4.tcp_keepalive_intvl = 60
net.ipv4.tcp_keepalive_probes = 3

# LOOSE rp_filter — strict (=1) breaks Docker multi-bridge asymmetric routing
net.ipv4.conf.all.rp_filter = 2
net.ipv4.conf.default.rp_filter = 2

net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0

net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0

net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1

#--- REQUIRED for Docker: DO NOT CHANGE ---
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1
net.bridge.bridge-nf-call-iptables = 1
net.bridge.bridge-nf-call-ip6tables = 1
net.bridge.bridge-nf-call-arptables = 1

#--- Kernel hardening ---
kernel.dmesg_restrict = 1
kernel.kptr_restrict = 2
kernel.unprivileged_bpf_disabled = 1
net.core.bpf_jit_harden = 2
kernel.randomize_va_space = 2
kernel.yama.ptrace_scope = 1       # 2 breaks strace/gdb/Sentry native
kernel.sysrq = 0
kernel.perf_event_paranoid = 3
fs.suid_dumpable = 0
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
fs.protected_fifos = 2
fs.protected_regular = 2

# DO NOT DISABLE — Docker / Chromium / Podman need this:
# kernel.unprivileged_userns_clone = 1
```

```bash
echo 'br_netfilter' | sudo tee /etc/modules-load.d/br_netfilter.conf
sudo modprobe br_netfilter
sudo sysctl --system
```

**Caveats:**
- `yama.ptrace_scope=2` blocks `docker exec … strace`, Sentry native, py-spy. Use `1` on a Docker host.
- `unprivileged_bpf_disabled=1` breaks Falco/Cilium running as non-root; use `2` (cap-restricted) if you run eBPF tooling.

## 1.2 Filesystem — noexec/nosuid/nodev

`/etc/fstab`:
```
tmpfs  /tmp      tmpfs  defaults,nosuid,nodev,noexec,size=2G,mode=1777  0 0
tmpfs  /dev/shm  tmpfs  defaults,nosuid,nodev,noexec,size=512M          0 0
tmpfs  /var/tmp  tmpfs  defaults,nosuid,nodev,noexec,size=1G            0 0
```

Or systemd drop-in: `sudo systemctl edit tmp.mount` → set `Options=mode=1777,strictatime,nosuid,nodev,noexec,size=2G`.

**What breaks:**

| Mount | Flag | Breaks | Workaround |
|---|---|---|---|
| `/tmp` | `noexec` | apt on some PPAs, pip wheel builds, snap refreshes | `TMPDIR=/root/build` for builds; or container `--tmpfs /tmp:rw,exec` |
| `/dev/shm` | `noexec` | **Chromium/Puppeteer/Playwright/Selenium crash**; LiveKit egress with chromium recorder breaks | `--disable-dev-shm-usage` or container `--tmpfs /dev/shm:rw,exec,size=1g` |
| `/var/tmp` | `noexec` | DKMS kernel module rebuilds | Rebuild in `/root/build` |

**Docker escape hatch:** `docker run --tmpfs /tmp:rw,exec,nosuid,nodev,size=512m` gives a container its own exec-allowed tmpfs not inheriting host noexec.

**[MUST]** `/tmp`, `/var/tmp` nosuid,nodev,noexec; **[MUST]** `/dev/shm` nosuid,nodev; **[SHOULD]** add `noexec` on `/dev/shm` after verifying Chromium/LiveKit-egress stack.

## 1.3 AppArmor vs SELinux on Ubuntu 24.04

Stick with AppArmor. Ubuntu 24.04 ships AppArmor 4.0; Docker auto-loads `docker-default`. **Gaps:** permits writes to many procfs paths; treats all containers identically; doesn't restrict egress per-app.

Custom profile workflow:
```bash
sudo mkdir -p /etc/apparmor.d/containers
sudoedit /etc/apparmor.d/containers/docker-nginx
sudo apparmor_parser -r -W /etc/apparmor.d/containers/docker-nginx
docker run --security-opt "apparmor=docker-nginx" nginx:alpine
```

### Template `/etc/apparmor.d/containers/docker-nginx`

```
#include <tunables/global>

profile docker-nginx flags=(attach_disconnected,mediate_deleted) {
  #include <abstractions/base>
  #include <abstractions/nameservice>

  network inet tcp,
  network inet udp,
  network inet6 tcp,
  network inet6 udp,
  network netlink raw,

  capability net_bind_service,
  capability setuid,
  capability setgid,
  capability dac_override,
  capability chown,

  /usr/sbin/nginx mrix,
  /etc/nginx/** r,
  /var/log/nginx/** rw,
  /var/cache/nginx/** rwk,
  /run/nginx.pid rwk,
  /usr/share/nginx/** r,
  /etc/ssl/** r,

  deny /proc/sys/** wklx,
  deny /proc/sysrq-trigger rwklx,
  deny /proc/mem rwklx,
  deny /proc/kmem rwklx,
  deny /proc/kcore rwklx,
  deny /sys/[^f]*/** wklx,
  deny /sys/f[^s]*/** wklx,
  deny /sys/fs/[^c]*/** wklx,
  deny /sys/fs/c[^g]*/** wklx,
  deny /sys/fs/cg[^r]*/** wklx,
  deny /sys/firmware/** rwklx,
  deny /sys/kernel/security/** rwklx,
  deny mount,
  deny ptrace,
  deny @{PROC}/* w,
}
```

Create one per stack (`docker-postgres`, `docker-redis`, `docker-livekit`).

**[MUST]** keep docker-default; **[SHOULD]** per-service profiles for internet-exposed containers.

## 1.4 Kernel Module Blacklist

`/etc/modprobe.d/blacklist-hardening.conf`:
```
install dccp     /bin/false
install sctp     /bin/false
install rds      /bin/false
install tipc     /bin/false
install n-hdlc   /bin/false
install ax25     /bin/false
install netrom   /bin/false
install x25      /bin/false
install rose     /bin/false
install decnet   /bin/false
install econet   /bin/false
install af_802154 /bin/false
install ipx      /bin/false
install appletalk /bin/false
install psnap    /bin/false
install p8023    /bin/false
install p8022    /bin/false
install can      /bin/false
install atm      /bin/false

install cramfs   /bin/false
install freevxfs /bin/false
install jffs2    /bin/false
install hfs      /bin/false
install hfsplus  /bin/false
install udf      /bin/false
# install squashfs /bin/false   # DO NOT blacklist if snapd is installed

install usb-storage   /bin/false
install firewire-core /bin/false
install thunderbolt   /bin/false
install bluetooth     /bin/false
install btusb         /bin/false
```
`sudo update-initramfs -u`

**Gotcha:** `squashfs` — snap uses it. Only blacklist if you've purged snap.

## 1.5 userns-remap — 2026 verdict

**What breaks** (structural, not bugs):
1. Bind mounts: host `postgres:postgres` (UID 999) unreadable to remapped container root (100999). Must `chown 100999` or use named volumes.
2. `--net=host`, `--pid=host`, `--userns=host` per-container override works.
3. Images that `chown` at build sometimes fail.
4. LiveKit egress + GPU containers typically need `--userns=host`.

**Verdict:** Stable, but operational friction pushes small teams toward **rootless Docker** (preferred for new stacks) + `no-new-privileges` + AppArmor + seccomp + non-root `USER` in every Dockerfile.

**[MUST]** `no-new-privileges: true` regardless; **[SHOULD]** userns-remap for new greenfield stacks without host-networking services.

## 1.6 Core dumps, ptrace, hidepid, dmesg

```ini
# /etc/sysctl.d/99-vps-hardening.conf
fs.suid_dumpable = 0
```
```
# /etc/security/limits.d/10-nocore.conf
* hard core 0
* soft core 0
```
```bash
sudo systemctl mask systemd-coredump.socket
echo 'kernel.core_pattern=|/bin/false' | sudo tee /etc/sysctl.d/50-coredump.conf
```

`hidepid=2` is risky — breaks monitoring agents (DO agent, Prometheus node-exporter). If used, prefer `hidepid=invisible,gid=proc` and add monitor user to `proc` group.

**[MUST]** coredumps off — they routinely leak Django/Node secrets.

## 1.7 unattended-upgrades, needrestart, Livepatch

`/etc/apt/apt.conf.d/50unattended-upgrades`:
```
Unattended-Upgrade::Allowed-Origins {
    "${distro_id}:${distro_codename}-security";
    "${distro_id}ESMApps:${distro_codename}-apps-security";
    "${distro_id}ESM:${distro_codename}-infra-security";
    "${distro_id}:${distro_codename}-updates";
};
Unattended-Upgrade::Package-Blacklist { "docker-ce"; "docker-ce-cli"; "containerd.io"; };
Unattended-Upgrade::DevRelease "false";
Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "true";
Unattended-Upgrade::Automatic-Reboot-WithUsers "false";
Unattended-Upgrade::Automatic-Reboot-Time "03:00";
Unattended-Upgrade::MinimalSteps "true";
```
Docker packages blacklisted because minor Docker bumps restart containerd → blips every container.

`/etc/needrestart/needrestart.conf`: `$nrconf{restart} = 'a'; $nrconf{kernelhints} = 0;`.

**Canonical Livepatch:** free tier covers 5 machines. Applies critical kernel CVEs without reboot — exactly the mitigation for **CVE-2025-38352** (POSIX CPU timer race, CISA KEV, actively exploited, container-relevant).
```bash
sudo pro attach <token>
sudo pro enable livepatch
```

## 1.9 Recent Kernel CVEs (2025–2026)

| CVE | Summary | Container impact |
|---|---|---|
| CVE-2025-38352 | POSIX CPU timer race, CISA KEV, exploited ITW | LPE from container |
| CVE-2025-21756 | vsock UAF | LPE / VM escape |
| CVE-2024-1086 | nf_tables UAF, actively exploited ransomware | LPE |
| CVE-2024-6387 | OpenSSH "regreSSHion" pre-auth RCE | Remote root |

**[MUST]** unattended-upgrades + monthly reboot window + Livepatch.

---

# Section 2 — SSH Hardening (2026)

## 2.1 OpenSSH version state

- **OpenSSH 9.9** (Sep 2024) added `mlkem768x25519-sha256` ML-KEM hybrid KEX.
- **OpenSSH 10.0** (Apr 2025) made it the **default**.
- **OpenSSH 10.1** warns when non-PQ selected.
- Ubuntu 24.04 base pocket ships 9.6p1 — use `noble-backports` or `ppa:openssh/ppa` for ≥9.9 to get ML-KEM.

## 2.2 ssh-audit A+ algorithm set

- **KexAlgorithms:** `mlkem768x25519-sha256,sntrup761x25519-sha512@openssh.com,sntrup761x25519-sha512,curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group-exchange-sha256,diffie-hellman-group18-sha512,diffie-hellman-group16-sha512`
- **Ciphers:** `chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr`
- **MACs:** `hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,umac-128-etm@openssh.com`
- **HostKeyAlgorithms:** `sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512,rsa-sha2-256,*-cert-v01@openssh.com`

Strip weak DH moduli: `awk '$5 >= 3071' /etc/ssh/moduli > /etc/ssh/moduli.safe && mv /etc/ssh/moduli.safe /etc/ssh/moduli`.

## 2.3 Copy-paste `/etc/ssh/sshd_config.d/99-hardening.conf`

```
Port 22
AddressFamily inet
Protocol 2

HostKey /etc/ssh/ssh_host_ed25519_key
HostKey /etc/ssh/ssh_host_rsa_key

KexAlgorithms mlkem768x25519-sha256,sntrup761x25519-sha512@openssh.com,sntrup761x25519-sha512,curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group-exchange-sha256,diffie-hellman-group18-sha512,diffie-hellman-group16-sha512
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,umac-128-etm@openssh.com
HostKeyAlgorithms sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512,rsa-sha2-256,ssh-ed25519-cert-v01@openssh.com,sk-ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256-cert-v01@openssh.com
PubkeyAcceptedAlgorithms sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512,rsa-sha2-256,ssh-ed25519-cert-v01@openssh.com,sk-ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256-cert-v01@openssh.com
CASignatureAlgorithms ssh-ed25519,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,sk-ssh-ed25519@openssh.com,sk-ecdsa-sha2-nistp256@openssh.com,rsa-sha2-512,rsa-sha2-256

PermitRootLogin no
PasswordAuthentication no
KbdInteractiveAuthentication no
ChallengeResponseAuthentication no
PubkeyAuthentication yes
HostbasedAuthentication no
IgnoreRhosts yes
UsePAM yes
AuthenticationMethods publickey
AllowUsers deploy ops

MaxAuthTries 3
MaxSessions 3
MaxStartups 3:50:10
LoginGraceTime 20
ClientAliveInterval 300
ClientAliveCountMax 2

X11Forwarding no
AllowTcpForwarding no
AllowAgentForwarding no
AllowStreamLocalForwarding no
PermitTunnel no
GatewayPorts no
PermitUserEnvironment no
PermitUserRC no

SyslogFacility AUTH
LogLevel VERBOSE
Banner /etc/issue.net
Subsystem sftp /usr/lib/openssh/sftp-server -f AUTHPRIV -l INFO
```

Validate: `sudo sshd -t && sudo systemctl reload ssh && ssh-audit localhost`.

## 2.4 SSH CA (short-lived certs)

For teams >2 engineers, replace per-host `authorized_keys` with a CA:

```bash
ssh-keygen -t ed25519 -f ssh_user_ca -C "vps-user-ca"
# Server:
sudo install -m 644 ssh_user_ca.pub /etc/ssh/ssh_user_ca.pub
# sshd_config: TrustedUserCAKeys /etc/ssh/ssh_user_ca.pub
#              RevokedKeys /etc/ssh/revoked_keys

# Issue 4h cert:
ssh-keygen -s ssh_user_ca -I "alice@$(date +%s)" -n deploy,ops -V +4h alice_ed25519.pub
```
For >5 engineers use **step-ca** or **Vault SSH secrets engine** — OIDC-driven, 1-8h TTLs.

## 2.5 FIDO2 hardware keys

```bash
# Resident, PIN-required, portable
ssh-keygen -t ed25519-sk -O resident -O verify-required -O application=ssh:vps \
  -C "alice@yubikey-$(date +%Y%m)" -f ~/.ssh/id_ed25519_sk
```
Compatible: YubiKey 5 (fw ≥5.2.3), SoloKey v2, Nitrokey 3, Token2. **[MUST]** for anyone with sudo on production.

## 2.6 MFA with TOTP

```bash
sudo apt install libpam-google-authenticator
google-authenticator -t -d -f -r 3 -R 30 -w 3
```
`/etc/pam.d/sshd` first line: `auth required pam_google_authenticator.so nullok`
`sshd_config`: `AuthenticationMethods publickey,keyboard-interactive:pam`

## 2.7 Port knocking vs bastion — 2026 verdict

fwknop is essentially displaced by Tailscale SSH and WireGuard bastions. The 2026 pattern:
1. SSH `ListenAddress 100.64.0.0/10` (Tailscale CIDR) or WireGuard iface.
2. Cloud firewall: port 22 closed to internet.
3. Tailscale ACLs for who can reach which tag.
Free for ≤100 devices / 3 users.

## 2.8 endlessh tarpit

~120 bytes RAM per trapped bot, ~2 Kbps aggregate. Move real SSH to a high port first, then:
```bash
sudo apt install endlessh
sudo setcap 'cap_net_bind_service=+ep' /usr/bin/endlessh
sudo systemctl edit endlessh    # Port=22
sudo systemctl enable --now endlessh
```
**[NICE]** — essentially free log-noise reduction.

---

# Section 3 — Firewall Architecture for Docker Hosts

## 3.1 The UFW ↔ Docker bypass (READ THIS FIRST)

Docker inserts DNAT rules in `nat PREROUTING`, rewriting `dst=<vps-ip>:3000` → `dst=<container-ip>:3000` **before** routing. The packet is then *forwarded* to the container — it never traverses `filter INPUT`, so UFW's `default deny incoming` is irrelevant. Any `docker run -p 0.0.0.0:3000:3000` publishes to the internet regardless of UFW state.

**[MUST]** Never assume `ufw default deny incoming` protects container ports. It does not.

## 3.2 Docker's iptables chains

| Chain | Purpose | User-editable |
|---|---|---|
| `DOCKER` | Auto-managed DNAT + ACCEPT | No (flushed on daemon reload) |
| `DOCKER-USER` | Invoked **first** from FORWARD, survives restarts | **Yes** |
| `DOCKER-ISOLATION-STAGE-1/2` | Cross-network isolation | No |
| `DOCKER-INGRESS` | Swarm routing mesh | No |

`DOCKER-USER` is the only chain you own.

## 3.3 DOCKER-USER allowlist — copy-paste `/etc/ufw/after.rules` tail

```bash
*filter
:DOCKER-USER - [0:0]

# Established return traffic
-A DOCKER-USER -m conntrack --ctstate RELATED,ESTABLISHED -j RETURN

# Loopback + inter-container on docker bridges
-A DOCKER-USER -i lo -j RETURN
-A DOCKER-USER -s 172.16.0.0/12 -j RETURN
-A DOCKER-USER -s 10.0.0.0/8    -j RETURN

# Cloudflare → Nginx only
-A DOCKER-USER -m set --match-set cf-v4 src -p tcp -m multiport --dports 80,443 -j RETURN

# LiveKit (must bypass Cloudflare — WebRTC UDP cannot be proxied)
-A DOCKER-USER -p tcp --dport 7880 -j RETURN
-A DOCKER-USER -p tcp --dport 7881 -j RETURN
-A DOCKER-USER -p udp --dport 7882 -j RETURN
-A DOCKER-USER -p udp --dport 3478 -j RETURN
-A DOCKER-USER -p udp --dport 443  -j RETURN
-A DOCKER-USER -p udp --dport 50000:50100 -j RETURN

# SYN rate limit for HTTP/HTTPS
-A DOCKER-USER -p tcp --syn -m multiport --dports 80,443 \
   -m hashlimit --hashlimit-name http-syn --hashlimit-mode srcip \
   --hashlimit-above 50/sec --hashlimit-burst 100 -j DROP

# Per-IP concurrent cap
-A DOCKER-USER -p tcp --syn -m connlimit --connlimit-above 100 --connlimit-mask 32 -j DROP

# DROP everything else destined for containers
-A DOCKER-USER -j DROP
COMMIT
```

## 3.4 chaifeng/ufw-docker (optional helper)

```bash
sudo wget -O /usr/local/bin/ufw-docker \
  https://github.com/chaifeng/ufw-docker/raw/master/ufw-docker
sudo chmod +x /usr/local/bin/ufw-docker
sudo ufw-docker install
sudo systemctl restart ufw

sudo ufw-docker allow nginx 443/tcp
sudo ufw-docker allow livekit 7880/tcp
sudo ufw route allow proto tcp from 10.0.0.0/8 to any port 5432
```

## 3.5 The simplest fix: bind to 127.0.0.1

```yaml
services:
  db:
    ports:
      - "127.0.0.1:5432:5432"   # not "5432:5432"
```

**[MUST]** Audit every `ports:` in every compose file. If not meant public, prefix `127.0.0.1:` or switch to `expose:` only.

## 3.6 `expose` vs `ports`

- `ports:` publishes to host NAT (the UFW bypass hole).
- `expose:` is metadata — reachable only to other containers on the same user-defined bridge.

For Postgres/Redis/Celery/Django — `expose:` only. Nginx alone publishes `0.0.0.0`.

## 3.7 nftables vs iptables state (2026)

- Docker 27/28 (2024–2025): still uses `iptables-nft` shim.
- Docker 29 (late 2025): **experimental** native `--firewall-backend=nftables`.
- **Current verdict:** stay on iptables backend; nftables backend lacks Swarm support and breaks `ufw-docker`. Plan to migrate 2026–2027.

## 3.8 Docker 28 changes you must know

- **`ip6tables: true` now respects DOCKER-USER for IPv6** — previously an UFW blind spot.
- **Direct routing mode** (`--direct-routing`) skips docker-proxy on hosts with routable container paths.
- **Rule generation refactored** — `iptables -S` is readable again.

**[MUST]** `ip6tables: true` in `daemon.json` if VPS has IPv6 — otherwise an IPv6-enabled host still leaks ports.

## 3.9 LiveKit firewall rules

| Port | Proto | Purpose |
|---|---|---|
| 7880 | TCP | Signaling (front with Nginx TLS) |
| 7881 | TCP | ICE/TCP fallback |
| 7882 | UDP | ICE/UDP |
| 3478 | UDP | STUN/TURN |
| 443 | UDP | TURN/UDP on 443 (rarely blocked) |
| 50000–50100 | UDP | Media range (minimize — default 10k is overkill) |

**UDP range exposure through Docker:** publishing 10 000 UDP ports creates 10 000 userland-proxy processes (~1 GB RAM). Two correct approaches:

1. **`network_mode: host`** for LiveKit only — official recommendation.
2. `--userland-proxy=false` + explicit publishes.

```yaml
services:
  livekit:
    image: livekit/livekit-server:v1.10.1
    network_mode: host
    command: --config /etc/livekit.yaml
    volumes:
      - ./livekit.yaml:/etc/livekit.yaml:ro
```

Trade-off: host-networking LiveKit can't join other compose networks or use service DNS. That's fine.

## 3.10 SYN flood & connection limits

```bash
-A DOCKER-USER -p tcp --syn -m hashlimit --hashlimit-name syn-per-ip \
   --hashlimit-mode srcip --hashlimit-above 20/sec --hashlimit-burst 50 -j DROP
-A DOCKER-USER -p tcp -m connlimit --connlimit-above 200 --connlimit-mask 32 -j REJECT
-A DOCKER-USER -m conntrack --ctstate INVALID -j DROP
-A DOCKER-USER -p tcp ! --syn -m conntrack --ctstate NEW -j DROP
```

For real DDoS: synproxy on 80/443, or outsource to Cloudflare (preferred).

## 3.11 GeoIP blocking 2026

MaxMind GeoLite2 now requires a free account. Alternatives: **DB-IP Country Lite** (no account), **ipdeny.com** lists, **chr0mag/geoipsets** Python tool (both iptables and nftables).

**[MUST]** Do this at Cloudflare WAF, not origin, if you're using CF.

## 3.12 Cloudflare proxy + LiveKit split architecture

| Traffic | Hostname | Cloudflare |
|---|---|---|
| Django/Nginx HTTPS | `app.example.com` | Proxied (orange) |
| LiveKit signaling WSS | `livekit.example.com` | Proxied (orange) |
| LiveKit media UDP | `rtc.example.com` | **DNS-only (grey)** — CF doesn't proxy arbitrary UDP |

Restrict origin 80/443 to Cloudflare IPs via daily cron:

`/usr/local/sbin/cf-ipset-update.sh`:
```bash
#!/bin/bash
set -euo pipefail
ipset create cf-v4 hash:net -exist
ipset create cf-v6 hash:net family inet6 -exist
tmp4=$(mktemp); tmp6=$(mktemp)
curl -fsS https://www.cloudflare.com/ips-v4 -o "$tmp4"
curl -fsS https://www.cloudflare.com/ips-v6 -o "$tmp6"
ipset flush cf-v4 && while read -r n; do ipset add cf-v4 "$n"; done < "$tmp4"
ipset flush cf-v6 && while read -r n; do ipset add cf-v6 "$n"; done < "$tmp6"
rm -f "$tmp4" "$tmp6"
```
Cron: `17 */6 * * * /usr/local/sbin/cf-ipset-update.sh` (every 6h, not daily — CF adds prefixes).

---

# Section 4 — Docker Security (Container Level)

## 4.1 Complete `/etc/docker/daemon.json`

```json
{
  "icc": false,
  "userns-remap": "default",
  "no-new-privileges": true,
  "live-restore": true,
  "userland-proxy": false,
  "iptables": true,
  "ip6tables": true,
  "ip-forward": true,
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "10m",
    "max-file": "5",
    "compress": "true"
  },
  "default-ulimits": {
    "nofile": { "Name": "nofile", "Soft": 4096, "Hard": 8192 },
    "nproc":  { "Name": "nproc",  "Soft": 2048, "Hard": 4096 }
  },
  "default-runtime": "runc",
  "seccomp-profile": "/etc/docker/seccomp-default.json",
  "init": true,
  "default-address-pools": [
    { "base": "172.30.0.0/16", "size": 24 }
  ]
}
```

| Key | Why |
|---|---|
| `icc: false` | No inter-container comms on default bridge |
| `userns-remap` | Container root → unprivileged host UID |
| `no-new-privileges` | Blocks setuid escalation |
| `live-restore` | Containers stay up across daemon restarts (patch versions only) |
| `userland-proxy: false` | Eliminates per-port proxy process; required for LiveKit sanity |
| `ip6tables: true` | DOCKER-USER covers IPv6 too |
| `log-opts` | Prevents runaway JSON logs filling disk |
| `init: true` | tini reaps zombies, SIGTERM propagates |

## 4.2 Seccomp

Docker's default profile blocks ~60 syscalls (`keyctl`, `ptrace`, `mount`, `reboot`, `kexec_load`). `no-new-privileges: true` is the 80/20 win — with it enabled, the stock profile blocks most escapes.

Audit actual syscall usage:
```bash
docker run --rm --cap-add SYS_PTRACE --security-opt seccomp=unconfined \
  myapp strace -c -f -e trace=all myapp-entrypoint
```

## 4.3 Capabilities per service

| Service | `cap_drop` | `cap_add` |
|---|---|---|
| Nginx (80/443) | ALL | `NET_BIND_SERVICE` |
| Postgres | ALL | (none) |
| Redis | ALL | (none) |
| Node | ALL | (none) |
| Django/Gunicorn/Daphne | ALL | (none) |
| Celery | ALL | (none) |
| LiveKit | ALL | `SYS_NICE` (optional RT) |

**Gotcha:** dropping `SETUID/SETGID` breaks entrypoints using `su`/`gosu`. Fix: run as non-root user directly with `user: "1000:1000"`.

## 4.4 Read-only root FS + tmpfs — hardened compose

```yaml
x-security-defaults: &sec
  read_only: true
  security_opt:
    - no-new-privileges:true
    - seccomp=/etc/docker/seccomp-default.json
  cap_drop: [ALL]
  pids_limit: 200
  restart: unless-stopped

services:
  nginx:
    <<: *sec
    image: nginx:1.27-alpine@sha256:...
    cap_add: [NET_BIND_SERVICE]
    tmpfs:
      - /tmp:size=64M,mode=1777
      - /var/cache/nginx:size=128M,mode=0755,uid=101,gid=101
      - /var/run:size=16M,mode=0755,uid=101,gid=101
    ports:
      - "0.0.0.0:80:80"
      - "0.0.0.0:443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf:ro
      - static:/usr/share/nginx/html:ro
    networks: [edge, app]
    mem_limit: 256m
    cpus: 1.0

  django:
    <<: *sec
    image: myorg/django:${TAG}@sha256:...
    user: "1000:1000"
    tmpfs: [/tmp:size=256M]
    volumes:
      - static:/app/staticfiles
      - media:/app/media
    secrets: [django_secret_key, db_password]
    expose: ["8000"]
    networks: [app, db]
    mem_limit: 1g
    cpus: 2.0
    depends_on:
      postgres: { condition: service_healthy }

  postgres:
    <<: *sec
    image: postgres:16-alpine@sha256:...
    user: "70:70"
    tmpfs:
      - /tmp:size=64M
      - /var/run/postgresql:size=16M,uid=70,gid=70
    volumes:
      - pgdata:/var/lib/postgresql/data
    environment:
      POSTGRES_PASSWORD_FILE: /run/secrets/db_password
    secrets: [db_password]
    expose: ["5432"]
    networks: [db]
    mem_limit: 2g
    cpus: 2.0
    healthcheck:
      test: ["CMD", "pg_isready", "-U", "app"]
      interval: 10s

  redis:
    <<: *sec
    image: redis:7-alpine@sha256:...
    user: "999:999"
    command: ["redis-server", "--save", "", "--appendonly", "no",
              "--maxmemory", "256mb", "--maxmemory-policy", "allkeys-lru"]
    tmpfs: [/data:size=8M]
    expose: ["6379"]
    networks: [app]
    mem_limit: 384m

  livekit:
    image: livekit/livekit-server:v1.10.1@sha256:...
    read_only: true
    security_opt: [no-new-privileges:true]
    cap_drop: [ALL]
    cap_add: [SYS_NICE]
    pids_limit: 500
    network_mode: host
    command: ["--config", "/etc/livekit.yaml"]
    volumes: [./livekit.yaml:/etc/livekit.yaml:ro]
    tmpfs: [/tmp:size=128M]
    mem_limit: 2g
    cpus: 4.0

  docker-socket-proxy:
    image: tecnativa/docker-socket-proxy:0.3
    read_only: true
    security_opt: [no-new-privileges:true]
    cap_drop: [ALL]
    cap_add: [CHOWN, SETGID, SETUID]
    environment:
      CONTAINERS: 1
      IMAGES: 1
      NETWORKS: 1
      POST: 0
      EXEC: 0
      VOLUMES: 0
    tmpfs: [/run, /tmp]
    volumes: [/var/run/docker.sock:/var/run/docker.sock:ro]
    networks: [socket-proxy]
    expose: ["2375"]
    mem_limit: 64m

volumes:
  pgdata:
  static:
  media:

networks:
  edge: { driver: bridge }
  app:  { driver: bridge }
  db:   { driver: bridge, internal: true }   # no internet egress from Postgres
  socket-proxy: { driver: bridge, internal: true }

secrets:
  db_password: { file: ./secrets/db_password.txt }
  django_secret_key: { file: ./secrets/django_secret.txt }
```

## 4.5 Cosign signing + verification

```bash
# CI (keyless OIDC)
COSIGN_EXPERIMENTAL=1 cosign sign --yes ghcr.io/myorg/django@sha256:...

# Host (pre-pull)
cosign verify \
  --certificate-identity-regexp "https://github.com/myorg/.*" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  ghcr.io/myorg/django@sha256:...
```

## 4.6 Image scanning

Daily cron:
```bash
#!/bin/bash
set -e
for img in $(docker ps --format '{{.Image}}' | sort -u); do
  trivy image --severity HIGH,CRITICAL --exit-code 0 \
    --format json --output "/var/log/trivy/$(date +%F)-$(echo $img|tr '/:' '_').json" "$img"
done
```

**2026 caveat:** Trivy release infra was briefly compromised in March 2026. Pin to verified release; use Grype as second opinion.

## 4.7 Multi-stage distroless Dockerfile

```dockerfile
FROM python:3.12-slim AS builder
WORKDIR /build
COPY requirements.txt .
RUN pip install --prefix=/install --no-cache-dir -r requirements.txt

FROM gcr.io/distroless/python3-debian12@sha256:... AS runtime
COPY --from=builder /install /usr/local
COPY --chown=nonroot:nonroot . /app
WORKDIR /app
USER nonroot
ENTRYPOINT ["python", "-m", "gunicorn", "app.wsgi"]
```

## 4.8 Docker socket protection

Mounting `/var/run/docker.sock` = root on host. Use **Tecnativa/docker-socket-proxy** with env-var allowlist; expose over an `internal: true` network.

## 4.9 Resource limits (every service)

```yaml
mem_limit: 512m
memswap_limit: 512m   # disable swap inside
cpus: 1.5
pids_limit: 200       # CRITICAL — default is unlimited = fork bomb
ulimits:
  nofile: { soft: 2048, hard: 4096 }
  nproc: 512
```

## 4.10 Rootless Docker 2026 verdict

**Web stack (Django/Node/Postgres/Nginx/Redis):** Production ready, 3-5% overhead.
**LiveKit:** **Avoid rootless.** slirp4netns/rootlesskit are slow for high-PPS UDP media. Run LiveKit on separate VPS in root mode, or keep whole host root + `userns-remap`.

## 4.11 Compose secrets (non-Swarm)

File-based secrets → mounted tmpfs at `/run/secrets/<name>`. Not in `docker inspect`, `/proc/*/environ`, image layers, or compose logs. Combine with **SOPS + age** for git-committable encrypted secret files.

---

# Section 5 — Nginx / TLS Hardening

## 5.1 Tool choice 2026

- **Nginx 1.27+** with libmodsecurity3 + OWASP CRS 4.x — reference for LiveKit.
- **Caddy** with `coraza-caddy` — better auto-HTTPS and native Go WAF; valid for greenfield.
- **Traefik** — magical Docker labels, but Coraza WASM plugin is ~23x slower than commercial — avoid if WAF needed.

## 5.2 Hardened `/etc/nginx/nginx.conf`

```nginx
user www-data;
worker_processes auto;
worker_rlimit_nofile 65535;
pid /run/nginx.pid;

events { worker_connections 8192; multi_accept on; use epoll; }

http {
    server_tokens off;
    more_clear_headers Server;                 # nginx-extras
    underscores_in_headers off;
    ignore_invalid_headers on;
    client_body_timeout 10s;
    client_header_timeout 10s;
    client_max_body_size 25m;
    large_client_header_buffers 4 8k;
    send_timeout 10s;
    keepalive_timeout 65s;
    keepalive_requests 1000;

    include /etc/nginx/mime.types;
    default_type application/octet-stream;

    log_format main escape=json '{'
        '"time":"$time_iso8601","remote_addr":"$remote_addr",'
        '"request":"$request_method $uri",'      # NOTE: $uri (no args) — don't log query strings
        '"status":$status,"bytes":$body_bytes_sent,'
        '"ref":"$http_referer","ua":"$http_user_agent",'
        '"xff":"$http_x_forwarded_for","rid":"$request_id","rt":$request_time}';
    access_log /var/log/nginx/access.log main buffer=32k flush=5s;
    error_log  /var/log/nginx/error.log warn;

    gzip on; gzip_vary on; gzip_proxied any; gzip_comp_level 5;
    gzip_min_length 1024;
    gzip_types application/json application/javascript text/css text/plain
               application/xml image/svg+xml application/wasm;

    # --- TLS: Mozilla Intermediate ---
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers off;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305;
    ssl_ecdh_curve X25519:secp384r1;
    ssl_session_timeout 1d;
    ssl_session_cache shared:MozSSL:10m;
    ssl_session_tickets off;
    ssl_dhparam /etc/nginx/dhparam.pem;   # ffdhe2048

    ssl_stapling on;
    ssl_stapling_verify on;
    ssl_trusted_certificate /etc/letsencrypt/live/example.com/chain.pem;
    resolver 1.1.1.1 9.9.9.9 valid=300s ipv6=off;
    resolver_timeout 5s;

    # --- Rate limit zones ---
    limit_req_zone  $binary_remote_addr zone=auth:10m   rate=5r/m;
    limit_req_zone  $binary_remote_addr zone=api:10m    rate=60r/m;
    limit_req_zone  $binary_remote_addr zone=static:10m rate=300r/s;
    limit_conn_zone $binary_remote_addr zone=concpip:10m;
    limit_conn_zone $server_name       zone=concsrv:10m;
    limit_req_status 429;
    limit_conn_status 429;

    # ModSecurity + CRS 4.x
    modsecurity on;
    modsecurity_rules_file /etc/nginx/modsec/main.conf;

    # Real IP from Cloudflare
    set_real_ip_from 10.0.0.0/8;
    real_ip_header X-Forwarded-For;
    real_ip_recursive on;

    server {
        listen 80 default_server;
        server_name _;
        location /.well-known/acme-challenge/ { root /var/www/certbot; }
        location / { return 301 https://$host$request_uri; }
    }

    upstream django_asgi { server django:8000 fail_timeout=10s max_fails=3; keepalive 32; }
    upstream livekit     { server livekit:7880; keepalive 32; }

    server {
        listen 443 ssl default_server;
        http2 on; http3 on;
        add_header Alt-Svc 'h3=":443"; ma=86400' always;

        server_name example.com www.example.com;
        ssl_certificate     /etc/letsencrypt/live/example.com/fullchain.pem;
        ssl_certificate_key /etc/letsencrypt/live/example.com/privkey.pem;

        # Security headers
        add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
        add_header X-Content-Type-Options    "nosniff" always;
        add_header X-Frame-Options           "DENY"    always;
        add_header Referrer-Policy           "strict-origin-when-cross-origin" always;
        add_header Cross-Origin-Opener-Policy     "same-origin" always;
        add_header Cross-Origin-Resource-Policy   "same-site"  always;
        add_header X-Permitted-Cross-Domain-Policies "none" always;
        # NOTE: CSP is issued by Django (nonce-based); don't add a static CSP here.
        add_header Permissions-Policy "camera=(), microphone=(), geolocation=(), payment=(), usb=(), interest-cohort=()" always;

        limit_conn concpip 50;
        limit_conn concsrv 4000;

        location /static/ {
            alias /srv/static/;
            access_log off;
            limit_req zone=static burst=500 nodelay;
            expires 30d;
            add_header Cache-Control "public, immutable";
        }

        location ^~ /sekret-admin-8f2c/ {
            allow 10.0.0.0/8;
            allow 203.0.113.0/24;
            deny  all;
            limit_req zone=auth burst=5 nodelay;
            proxy_pass http://django_asgi;
            include /etc/nginx/snippets/proxy_common.conf;
        }

        location ~ ^/(api/v1/auth/(login|register|password-reset)|accounts/login) {
            limit_req zone=auth burst=3 nodelay;
            proxy_pass http://django_asgi;
            include /etc/nginx/snippets/proxy_common.conf;
        }

        location /api/ {
            limit_req zone=api burst=40 nodelay;
            proxy_pass http://django_asgi;
            include /etc/nginx/snippets/proxy_common.conf;
        }

        location /ws/ {
            proxy_pass http://django_asgi;
            proxy_http_version 1.1;
            proxy_set_header Upgrade $http_upgrade;
            proxy_set_header Connection "upgrade";
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
            proxy_read_timeout 3600s;
            proxy_send_timeout 3600s;
            proxy_buffering off;
        }

        location /livekit/ {
            proxy_pass http://livekit/;
            proxy_http_version 1.1;
            proxy_set_header Upgrade $http_upgrade;
            proxy_set_header Connection "upgrade";
            proxy_set_header Host $host;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
            proxy_read_timeout 3600s;
            proxy_send_timeout 3600s;
            send_timeout       3600s;
            proxy_buffering off;
        }

        location /room/ {
            # Override global Permissions-Policy for rooms that need camera/mic
            add_header Permissions-Policy "camera=(self), microphone=(self), display-capture=(self)" always;
            proxy_pass http://django_asgi;
            include /etc/nginx/snippets/proxy_common.conf;
        }

        location / {
            proxy_pass http://django_asgi;
            include /etc/nginx/snippets/proxy_common.conf;
        }

        location ~* /(\.git|\.env|wp-login|xmlrpc\.php|phpmyadmin) { return 444; }
    }
}
```

`/etc/nginx/snippets/proxy_common.conf`:
```nginx
proxy_http_version 1.1;
proxy_request_buffering on;
proxy_set_header Host              $host;
proxy_set_header X-Real-IP         $remote_addr;
proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
proxy_set_header X-Forwarded-Proto $scheme;
proxy_set_header X-Forwarded-Host  $host;
proxy_set_header X-Request-ID      $request_id;
proxy_set_header Connection        "";
proxy_read_timeout 60s;
proxy_send_timeout 60s;
proxy_connect_timeout 5s;
```

## 5.3 CSP for Django + React + LiveKit

**Gotcha:** `COEP: require-corp` breaks third-party embeds (YouTube, Stripe, cross-origin images without CORP headers). Only enable if you need `SharedArrayBuffer`. Basic LiveKit does NOT require it.

Issue CSP from Django via `django-csp` 4.0 with nonce (see §7.1).

```
Content-Security-Policy:
  default-src 'none';
  base-uri 'self';
  form-action 'self';
  frame-ancestors 'none';
  script-src 'self' 'nonce-{NONCE}' 'strict-dynamic' https: 'unsafe-inline';
  style-src  'self' 'nonce-{NONCE}' 'unsafe-inline';
  img-src    'self' data: blob: https://uploads.example.com;
  font-src   'self' data:;
  connect-src 'self' https://api.example.com wss://example.com wss://livekit.example.com;
  media-src  'self' blob: mediastream:;
  worker-src 'self' blob:;
  child-src  'self' blob:;
  object-src 'none';
  upgrade-insecure-requests;
  report-uri /csp-report/
```

Key notes:
- `'strict-dynamic'` + nonce: modern browsers ignore the `https:`/`'unsafe-inline'` fallbacks. Those are for legacy clients.
- `connect-src wss:` required for LiveKit.
- `media-src blob:` + `mediastream:` for WebRTC streams.
- `worker-src blob:` — LiveKit spawns audio worklet from Blob URL.
- React: `inlineRuntimeChunk: false` in Vite/CRA or use nonce-injection.

## 5.4 CAA + CT monitoring

```
example.com. 300 IN CAA 0 issue "letsencrypt.org"
example.com. 300 IN CAA 0 issuewild "letsencrypt.org"
example.com. 300 IN CAA 0 iodef "mailto:secops@example.com"
```
Monitor `https://crt.sh/?q=%25.example.com` weekly via cron diff.

## 5.5 Certbot in Docker

```yaml
certbot:
  image: certbot/certbot:v2.11.0
  volumes:
    - ./letsencrypt:/etc/letsencrypt
    - ./certbot-www:/var/www/certbot
  entrypoint: >
    /bin/sh -c 'trap exit TERM;
    while :; do
      certbot renew --webroot -w /var/www/certbot --quiet --deploy-hook "nginx -s reload";
      sleep 12h;
    done'
```
Wildcards need DNS-01 via `certbot-dns-cloudflare` or acme.sh.

## 5.6 ModSecurity + CRS 4.x

Start **PL1** with `DETECTION_PARANOIA=2` (PL2 logs but doesn't block). Two weeks of tuning, then promote to PL2 blocking. Expect 10-20% CPU overhead. Django admin and uploads will trip 920170, 949110, 932100 — use `SecRuleRemoveByIdForRequest` scoped per-URL.

## 5.7 Request smuggling prevention

`proxy_http_version 1.1`, `underscores_in_headers off`, `ignore_invalid_headers on`, `proxy_request_buffering on`. Keep Nginx and Daphne/uvicorn HTTP parser behavior in sync — don't HTTP/2 on Nginx and HTTP/1.0 upstream.

---

# Section 6 — Database Security

## 6.1 PostgreSQL hardened `postgresql.conf`

```ini
listen_addresses = '*'
port = 5432
max_connections = 200
superuser_reserved_connections = 3

ssl = on
ssl_cert_file = '/etc/ssl/postgres/server.crt'
ssl_key_file  = '/etc/ssl/postgres/server.key'
ssl_ca_file   = '/etc/ssl/postgres/ca.crt'
ssl_min_protocol_version = 'TLSv1.3'
ssl_prefer_server_ciphers = on
ssl_ciphers = 'ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305'
ssl_ecdh_curve = 'X25519:prime256v1'

password_encryption = 'scram-sha-256'

statement_timeout = '30s'
idle_in_transaction_session_timeout = '60s'
lock_timeout = '5s'
idle_session_timeout = '15min'
tcp_keepalives_idle = 60
tcp_keepalives_interval = 10
tcp_keepalives_count = 6

log_destination = 'stderr,csvlog'
logging_collector = on
log_connections = on
log_disconnections = on
log_hostname = off
log_line_prefix = '%m [%p] %q%u@%d/%a '
log_statement = 'ddl'
log_min_duration_statement = 500
log_checkpoints = on
log_lock_waits = on
log_temp_files = 0

row_security = on
shared_preload_libraries = 'pg_stat_statements,auto_explain'
pg_stat_statements.track = all
```

## 6.2 `pg_hba.conf`

```
local     all            postgres                             peer
local     all            all                                  scram-sha-256

hostssl   replication    replicator      10.0.5.0/24          scram-sha-256             clientcert=verify-full

hostssl   appdb          app_rw          10.0.1.0/24          scram-sha-256
hostssl   appdb          app_ro          10.0.1.0/24          scram-sha-256
hostssl   appdb          app_migrate     10.0.1.10/32         scram-sha-256
hostssl   appdb          pgbouncer       10.0.1.20/32         scram-sha-256

host      all            all             0.0.0.0/0            reject
host      all            all             ::/0                 reject
```

Role separation:
```sql
CREATE ROLE app_ro  LOGIN PASSWORD 'xxx' CONNECTION LIMIT 50;
CREATE ROLE app_rw  LOGIN PASSWORD 'yyy' CONNECTION LIMIT 50;
CREATE ROLE app_migrate LOGIN PASSWORD 'zzz' CONNECTION LIMIT 2;
GRANT CONNECT ON DATABASE appdb TO app_ro, app_rw, app_migrate;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO app_ro;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO app_rw;
GRANT ALL ON SCHEMA public TO app_migrate;
```

**[SHOULD]** TLS even on internal Docker networks (single-tenant); **[MUST]** multi-tenant.

## 6.3 Redis 7.4 hardened `redis.conf`

```conf
bind 0.0.0.0 -::*
protected-mode yes
port 0
tls-port 6379
tls-cert-file /etc/redis/tls/redis.crt
tls-key-file  /etc/redis/tls/redis.key
tls-ca-cert-file /etc/redis/tls/ca.crt
tls-auth-clients yes
tls-protocols "TLSv1.3"
tls-ciphersuites TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256
tcp-backlog 511
timeout 300
tcp-keepalive 60

# ACL (2026: prefer over rename-command which is DEPRECATED)
user default off
user app on >REDACTED ~app:* ~celery:* ~cache:* &* +@read +@write +@stream +@hash +@list +@set +@sortedset +@connection -@dangerous -flushall -flushdb -keys -config -debug -script -eval
user celery on >REDACTED ~celery:* &* +@read +@write +@list +@connection
user readonly on >REDACTED ~* +@read +@connection

maxmemory 1gb
maxmemory-policy allkeys-lru
lazyfree-lazy-eviction yes
lazyfree-lazy-expire yes

appendonly yes
appendfsync everysec
aof-use-rdb-preamble yes

slowlog-log-slower-than 10000
slowlog-max-len 1024
latency-monitor-threshold 100
```

**2026 gotcha:** `rename-command` is deprecated; use ACL categories. CVE-2025-21605 (unauthenticated output buffer growth) fixed in 7.4.x — stay current.

## 6.4 PgBouncer

```ini
[databases]
appdb = host=postgres port=5432 dbname=appdb

[pgbouncer]
listen_addr = 0.0.0.0
listen_port = 6432
auth_type = scram-sha-256
auth_file = /etc/pgbouncer/userlist.txt
auth_query = SELECT usename, passwd FROM pgbouncer.get_auth($1)
pool_mode = transaction
max_client_conn = 500
default_pool_size = 25
server_tls_sslmode = verify-full
server_tls_ca_file = /etc/ssl/pg-ca.crt
client_tls_sslmode = require
client_tls_cert_file = /etc/ssl/bouncer.crt
client_tls_key_file  = /etc/ssl/bouncer.key
ignore_startup_parameters = extra_float_digits,search_path
```
TLS on both legs — not optional.

## 6.5 Django ORM escape-hatch CI ban

Pre-commit patterns to ban or require review label:
```
\.extra\(
\.raw\(
RawSQL\(
cursor\.execute\(.*%.*%
cursor\.execute\(f"
cursor\.execute\(.*\.format\(
```
`ruff` with bandit S608/S611.

---

# Section 7 — Application Security (Django + Node)

## 7.1 Django `settings.py` security block

```python
DEBUG = False
ALLOWED_HOSTS = ["example.com", "www.example.com", "api.example.com"]

SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")
USE_X_FORWARDED_HOST = True
USE_X_FORWARDED_PORT = True

SECURE_SSL_REDIRECT = True
SECURE_HSTS_SECONDS = 63_072_000
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True
SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_REFERRER_POLICY = "strict-origin-when-cross-origin"
SECURE_CROSS_ORIGIN_OPENER_POLICY = "same-origin"
X_FRAME_OPTIONS = "DENY"

SESSION_COOKIE_SECURE = True
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = "Lax"
SESSION_COOKIE_NAME = "__Host-sessionid"
SESSION_COOKIE_AGE = 60 * 60 * 12
CSRF_COOKIE_SECURE = True
CSRF_COOKIE_HTTPONLY = False   # React needs to read
CSRF_COOKIE_SAMESITE = "Lax"
CSRF_COOKIE_NAME = "__Host-csrftoken"
CSRF_TRUSTED_ORIGINS = [
    "https://example.com", "https://www.example.com", "https://api.example.com",
]

DATA_UPLOAD_MAX_MEMORY_SIZE = 5 * 1024 * 1024
DATA_UPLOAD_MAX_NUMBER_FIELDS = 1000
FILE_UPLOAD_MAX_MEMORY_SIZE = 5 * 1024 * 1024
FILE_UPLOAD_PERMISSIONS = 0o640
FILE_UPLOAD_DIRECTORY_PERMISSIONS = 0o750

# django-csp 4.0
INSTALLED_APPS += ["csp"]
MIDDLEWARE.insert(0, "csp.middleware.CSPMiddleware")
from csp.constants import NONCE, SELF, STRICT_DYNAMIC, NONE
CONTENT_SECURITY_POLICY = {
    "DIRECTIVES": {
        "default-src":  [NONE],
        "base-uri":     [SELF],
        "form-action":  [SELF],
        "frame-ancestors": [NONE],
        "script-src":   [SELF, NONCE, STRICT_DYNAMIC, "https:", "'unsafe-inline'"],
        "style-src":    [SELF, NONCE, "'unsafe-inline'"],
        "img-src":      [SELF, "data:", "blob:", "https://uploads.example.com"],
        "font-src":     [SELF, "data:"],
        "connect-src":  [SELF, "https://api.example.com",
                         "wss://example.com", "wss://livekit.example.com"],
        "media-src":    [SELF, "blob:", "mediastream:"],
        "worker-src":   [SELF, "blob:"],
        "child-src":    [SELF, "blob:"],
        "object-src":   [NONE],
        "upgrade-insecure-requests": True,
        "report-uri":   ["/csp-report/"],
    },
}

CORS_ALLOWED_ORIGINS = ["https://example.com", "https://www.example.com"]
CORS_ALLOW_CREDENTIALS = True
CORS_ALLOW_ALL_ORIGINS = False

PASSWORD_HASHERS = [
    "django.contrib.auth.hashers.Argon2PasswordHasher",
    "django.contrib.auth.hashers.ScryptPasswordHasher",
    "django.contrib.auth.hashers.PBKDF2PasswordHasher",
]

from datetime import timedelta
SIMPLE_JWT = {
    "ACCESS_TOKEN_LIFETIME": timedelta(minutes=10),
    "REFRESH_TOKEN_LIFETIME": timedelta(days=7),
    "ROTATE_REFRESH_TOKENS": True,
    "BLACKLIST_AFTER_ROTATION": True,
    "UPDATE_LAST_LOGIN": True,
    "ALGORITHM": "RS256",
    "SIGNING_KEY": open("/run/secrets/jwt.key").read(),
    "VERIFYING_KEY": open("/run/secrets/jwt.pub").read(),
    "AUDIENCE": "example.com",
    "ISSUER":   "api.example.com",
    "JTI_CLAIM": "jti",
}

REST_FRAMEWORK = {
    "DEFAULT_THROTTLE_CLASSES": [
        "rest_framework.throttling.AnonRateThrottle",
        "rest_framework.throttling.UserRateThrottle",
    ],
    "DEFAULT_THROTTLE_RATES": {
        "anon": "60/min", "user": "600/min",
        "login": "5/min", "register": "3/hour",
    },
}
ADMIN_URL = os.environ["ADMIN_URL"]   # "sekret-admin-8f2c/"
```

**Commonly missed:**
- `SECURE_PROXY_SSL_HEADER` without Nginx *unconditionally* setting `X-Forwarded-Proto` = client-spoofable → CSRF bypass.
- `CSRF_TRUSTED_ORIGINS` is **mandatory** for cross-subdomain POST in Django 4+.
- `__Host-` cookie prefix requires Secure + Path=/ + no Domain.

## 7.2 JWT — the real 2026 answer

1. **Refresh token:** `HttpOnly; Secure; SameSite=Strict; Path=/api/auth/refresh` cookie, 7 days, rotated every refresh, blacklist added to Redis.
2. **Access token:** 5-15 min, JSON response body, React **memory only** — gone on tab close.
3. **RS256** asymmetric: API signs with private key; Celery workers verify with public key, cannot mint.

The "localStorage JWT" pattern is dead.

## 7.3 WebSocket auth: first-message pattern

**Do not** put `?token=` in wss URLs — Nginx access logs persist query strings.

1. Client connects anonymous.
2. Server opens connection, starts 5s auth timer.
3. Client sends first frame `{"type":"auth","token":"<access>"}`.
4. Server validates, upgrades scope, cancels timer.
5. Mid-session token refresh via `token_refresh_required` frame.

## 7.4 File uploads

- **Presigned S3/B2/R2 URLs** via django-storages — browser uploads direct, VPS disk never touches bytes.
- Local fallback: `python-magic` for content-type (not filename), Pillow re-encode (strips EXIF, breaks polyglots), zip bomb detection by uncompressed size.
- **Never** serve uploads from app origin — use `uploads.example.com` subdomain with `CSP: sandbox; default-src 'none'`, `X-Content-Type-Options: nosniff`, `Content-Disposition: attachment`.

## 7.5 Dependencies

- Python: `pip-compile --generate-hashes`, `pip-audit`, Safety.
- Node: `npm ci` + `npm audit --audit-level=high`, **Socket.dev** (behavioral).
- Renovate > Dependabot for grouped updates + auto-merge patch.

## 7.6 Secrets

- **SOPS + age** — encrypted YAML in git. age key in YubiKey via `age-plugin-yubikey`.
- **Infisical** self-hosted when you need rotation + audit + RBAC.
- Vault only at >10 engineers with compliance.

## 7.7 Django admin hardening

- Custom URL from env var (pointed to by Nginx).
- `allow`/`deny` IP list at Nginx.
- `django-otp` + `django-two-factor-auth` enforced via middleware.
- `django-admin-honeypot` at `/admin/` for scan detection.
- `django-axes` brute-force lockout, Redis-backed.

---

# Section 8 — LiveKit / WebRTC Security

## 8.1 Version

Current line: **v1.10.x**. Pin specific tag (`livekit/livekit-server:v1.10.1@sha256:...`).

## 8.2 Hardened `livekit.yaml`

```yaml
port: 7880
bind_addresses:
  - "127.0.0.1"        # CRITICAL — signaling bound to loopback, Nginx terminates TLS

rtc:
  tcp_port: 7881
  port_range_start: 50000
  port_range_end:   50100   # minimize — 100 ports handles 50 publishers
  use_external_ip: true
  use_ice_lite: false
  enable_loopback_candidate: false

keys:
  # Load from env or file, never commit:
  # APIxxxxx: <64-char>   # openssl rand -base64 48

room:
  auto_create: false      # CRITICAL — backend must CreateRoom first
  max_participants: 20
  empty_timeout: 300
  departure_timeout: 20
  enabled_codecs:
    - mime: audio/opus
    - mime: video/vp8
    - mime: video/h264

turn:
  enabled: true
  domain: turn.example.com
  tls_port: 5349          # or 443 for corporate firewall bypass
  cert_file: /etc/livekit/tls/fullchain.pem
  key_file:  /etc/livekit/tls/privkey.pem
  external_tls: false

webhook:
  api_key: APIxxxxx
  urls: [https://api.example.com/livekit/webhook]

logging:
  level: info
  json: true

limit:
  num_tracks: 50
  bytes_per_sec: 1500000
```

**Why these choices:**
- `auto_create: false` blocks room-squatting — backend must call `RoomService.CreateRoom` before minting tokens.
- Narrow UDP range: 10k default → 100 here.
- Signaling on loopback: all TLS/rate-limit/WAF at Nginx.

## 8.3 Token minting (server-side ONLY)

```python
def mint_join_token(user, room_name):
    at = api.AccessToken(settings.LK_API_KEY, settings.LK_API_SECRET) \
        .with_identity(f"u_{user.id}") \
        .with_name(user.display_name) \
        .with_metadata(json.dumps({"role": user.role})) \
        .with_ttl(datetime.timedelta(minutes=10)) \
        .with_grants(api.VideoGrants(
            room_join=True, room=room_name,
            can_publish=user.role != "viewer",
            can_subscribe=True, can_publish_data=True,
            can_update_own_metadata=False,
        ))
    return at.to_jwt()
```

- TTL ≤ 10 min (SDK auto-renews).
- Room names = UUIDv4 or HMAC, never sequential.
- Secret via Docker secret, never baked in image.

## 8.4 Egress recording → S3

Never store recordings on VPS. Egress writes to S3-compatible with SSE-S3/SSE-C. Playback via presigned URLs ≤15 min expiry. No public buckets.

## 8.5 Port exposure matrix

| Port | Proto | Exposure |
|---|---|---|
| 443 | TCP | Public (Nginx → signaling + API) |
| 443 or 5349 | TCP | Public (TURN-TLS) |
| 50000-50100 | UDP | Public (media — cannot CF-proxy) |
| 7880/7881 | TCP | Docker internal only |
| 6379 | TCP | Docker internal only |

---

# Section 9 — Intrusion Detection & Monitoring

## 9.1 Fail2Ban `/etc/fail2ban/jail.local`

On Docker host, Fail2Ban runs on host, reads logs via bind-mount or journald backend. Ban action targets DOCKER-USER chain:

```ini
[DEFAULT]
ignoreip   = 127.0.0.1/8 ::1 10.0.0.0/8 <MGMT_IP>/32
bantime    = 1h
findtime   = 10m
maxretry   = 5
backend    = systemd
banaction  = iptables-allports[chain=DOCKER-USER]
destemail  = security@example.com
sender     = fail2ban@example.com
action     = %(action_mwl)s

[sshd]
enabled  = true
port     = ssh
maxretry = 3
bantime  = 24h

[nginx-http-auth]
enabled  = true
port     = http,https
logpath  = /var/log/nginx/error.log

[nginx-botsearch]
enabled  = true
port     = http,https
logpath  = /var/log/nginx/access.log
maxretry = 2

[nginx-badbots]
enabled  = true
port     = http,https
logpath  = /var/log/nginx/access.log
filter   = nginx-badbots
maxretry = 1
bantime  = 7d

[nginx-limit-req]
enabled  = true
port     = http,https
logpath  = /var/log/nginx/error.log
maxretry = 10
findtime = 2m

[nginx-4xx-scanner]
enabled  = true
port     = http,https
logpath  = /var/log/nginx/access.log
filter   = nginx-4xx-scanner
maxretry = 20
findtime = 5m
bantime  = 12h

[django-admin]
enabled  = true
port     = http,https
logpath  = /var/log/django/auth.log
filter   = django-admin
maxretry = 5
findtime = 10m
bantime  = 24h

[recidive]
enabled  = true
logpath  = /var/log/fail2ban.log
bantime  = 30d
findtime = 7d
maxretry = 3
```

`/etc/fail2ban/filter.d/nginx-4xx-scanner.conf`:
```ini
[Definition]
failregex = ^<HOST> .* "(?:GET|POST|HEAD) [^"]+" (?:400|401|403|404|405|444) .*$
ignoreregex = .*(robots\.txt|favicon\.ico|apple-touch-icon).*
```

## 9.2 AIDE

Exclude Docker overlay — otherwise daily diffs are unreadable.
```conf
!/var/lib/docker
!/var/lib/containerd
!/var/lib/docker/overlay2
!/proc
!/sys
!/tmp
!/var/log
!/var/cache
!/run

/etc           NORMAL
/bin           NORMAL
/sbin          NORMAL
/usr/bin       NORMAL
/usr/sbin      NORMAL
/root          NORMAL
/home          NORMAL
/boot          NORMAL
```
Cron: `0 4 * * * root /usr/bin/aide --check | mail -s "AIDE $(hostname)" security@example.com`.

## 9.3 rkhunter/chkrootkit 2026

Honest: **nice to have**, mostly 2010-era signatures, noisy FPs. Modern replacements:
- **Falco** — detection (syscall parsing), ~300 MB RAM, mature rules.
- **Tetragon** — detection + enforcement (eBPF+LSM), <1% overhead.
- **Wazuh** — OSSEC fork, HIDS+SIEM, 500 MB+.

For single VPS: auditd + CrowdSec + Fail2Ban is usually enough; add Falco or Tetragon if threat model justifies.

## 9.4 auditd `/etc/audit/rules.d/99-docker-hardening.rules`

```
-D
-b 8192
-f 1
--backlog_wait_time 60000

-w /usr/bin/dockerd            -p x   -k docker
-w /usr/bin/docker             -p x   -k docker
-w /usr/bin/containerd         -p x   -k docker
-w /usr/bin/runc               -p x   -k docker
-w /etc/docker                 -p wa  -k docker
-w /var/lib/docker             -p wa  -k docker
-w /var/run/docker.sock        -p rwxa -k docker_socket
-w /etc/docker/daemon.json     -p wa  -k docker

-w /etc/passwd   -p wa -k identity
-w /etc/shadow   -p wa -k identity
-w /etc/group    -p wa -k identity
-w /etc/gshadow  -p wa -k identity
-w /etc/sudoers   -p wa -k sudoers
-w /etc/sudoers.d -p wa -k sudoers

-w /etc/ssh/sshd_config -p wa -k sshd
-w /root/.ssh           -p wa -k ssh_keys

-a always,exit -F arch=b64 -S init_module,finit_module,delete_module -F auid!=-1 -k modules

-a always,exit -F arch=b64 -S ptrace -F a0=0x4 -k code_injection
-a always,exit -F arch=b64 -S ptrace -F a0=0x5 -k data_injection
-a always,exit -F arch=b64 -S ptrace -F a0=0x6 -k register_injection

-a always,exit -F arch=b64 -S mount,umount2 -F auid!=-1 -k mount

-a always,exit -F arch=b64 -F euid=0 -F auid>=1000 -F auid!=-1 -S execve -k rootcmd
-a always,exit -F arch=b32 -F euid=0 -F auid>=1000 -F auid!=-1 -S execve -k rootcmd

-w /etc/hosts       -p wa -k hosts
-w /etc/resolv.conf -p wa -k resolv
-w /etc/crontab     -p wa -k cron
-w /etc/cron.d      -p wa -k cron

# -e 2   # immutable until reboot, enable in prod
```

## 9.5 Log aggregation — Loki + Promtail + Grafana

2026 consensus for single-VPS: **PLG stack**. Loki indexes labels only → ~512 MB total vs 4GB+ for Elastic.

Use Docker's native `loki` log driver on every app container:
```json
{ "log-driver": "loki",
  "log-opts": {
    "loki-url": "http://loki:3100/loki/api/v1/push",
    "loki-batch-size": "400",
    "labels": "service,env"
  }}
```

## 9.6 CrowdSec — modern Fail2Ban replacement

Behavior-based + ~1M-IP community blocklist. Bouncers for Nginx/iptables/Cloudflare.

```yaml
crowdsec:
  image: crowdsecurity/crowdsec:v1.6.4
  environment:
    COLLECTIONS: >-
      crowdsecurity/linux crowdsecurity/nginx crowdsecurity/sshd
      crowdsecurity/base-http-scenarios crowdsecurity/http-cve
      crowdsecurity/appsec-virtual-patching
  volumes:
    - crowdsec-db:/var/lib/crowdsec/data/
    - crowdsec-config:/etc/crowdsec/
    - /var/log:/var/log:ro
    - /var/log/nginx:/var/log/nginx:ro

crowdsec-firewall-bouncer:
  image: crowdsecurity/cs-firewall-bouncer:latest
  network_mode: host
  cap_add: [NET_ADMIN, NET_RAW]
  depends_on: [crowdsec]
```

**[SHOULD]** Run CrowdSec alongside Fail2Ban during migration, then drop Fail2Ban once coverage is trusted.

## 9.7 Network IDS

- **Suricata** — IDS mode, solid for <1Gbit VPS.
- **CrowdSec + AppSec** — 90% of web IDS with zero tuning. **Default recommendation.**
- **Zeek** — too heavy for small VPS.

## 9.8 Uptime monitoring

- **Uptime Kuma** (self-hosted Docker).
- **Healthchecks.io** — dead-man's switch for cron (restic timer).
- External synthetic (UptimeRobot/BetterStack) — so you know when VPS itself is off.

---

# Section 10 — Backup & Disaster Recovery

## 10.1 Tool selection 2026

| Tool | Verdict |
|---|---|
| **restic** | **Default.** AES-256, dedup, 15+ backends, active. |
| **pgBackRest** | **Must for serious Postgres** — PITR + WAL streaming. |
| **borgbackup** | Solid, single-host repos, append-only mode for ransomware. |
| **kopia** | Alternative with GUI. |
| **rclone + age** | Config files only. |

## 10.2 Off-site (3-2-1 rule)

| Provider | Price | Notes |
|---|---|---|
| Backblaze B2 | ~$6/TB/mo | Free egress to Cloudflare |
| Wasabi | $6.99/TB/mo | No egress, 90-day min retention |
| rsync.net | ~$12/TB/mo | ZFS snapshots, immutable retention — **best DR** |
| Hetzner Storage Box | €3.81/TB/mo | Cheap EU |

**[MUST]** Two destinations.

## 10.3 restic backup script + systemd timer

`/etc/restic/env`:
```bash
export RESTIC_REPOSITORY="b2:prod-backups:/vps01"
export RESTIC_PASSWORD_FILE="/etc/restic/passwd"
export B2_ACCOUNT_ID="xxx"
export B2_ACCOUNT_KEY="xxx"
export RESTIC_REPOSITORY2="sftp:de1234@de1234.rsync.net:vps01"
```

`/usr/local/sbin/restic-backup.sh`:
```bash
#!/usr/bin/env bash
set -euo pipefail
umask 077
source /etc/restic/env

HOST=$(hostname -s)
LOCK=/var/lock/restic-backup.lock
exec 9>"$LOCK"; flock -n 9 || { echo "already running"; exit 0; }

# 1. Postgres streaming dump
docker exec -i postgres pg_dumpall --clean --if-exists -U postgres \
  | zstd -T0 -3 \
  | restic backup --stdin --stdin-filename "pg-${HOST}-$(date +%F).sql.zst" \
      --tag postgres --host "$HOST"

# 2. Docker volumes + app data
restic backup \
  /var/lib/docker/volumes/livekit_data \
  /var/lib/docker/volumes/redis_data \
  /srv/nginx/conf.d /srv/app/media /etc \
  --exclude-caches --exclude '/etc/shadow-' \
  --tag filesystem --host "$HOST"

# 3. Retention
restic forget --prune \
  --keep-hourly 24 --keep-daily 14 \
  --keep-weekly 8 --keep-monthly 12 --keep-yearly 3

# 4. Integrity
if [[ $(date +%d) == "01" ]]; then
  restic check --read-data-subset=10%
else
  restic check
fi

# 5. Mirror
if [[ -n "${RESTIC_REPOSITORY2:-}" ]]; then
  restic copy --from-repo "$RESTIC_REPOSITORY2" || true
fi

# 6. Dead-man's switch
curl -fsS --retry 3 "https://hc-ping.com/${HC_UUID}" >/dev/null || true
```

`/etc/systemd/system/restic-backup.timer`:
```ini
[Unit]
Description=Hourly restic backup
[Timer]
OnCalendar=hourly
Persistent=true
RandomizedDelaySec=15m
[Install]
WantedBy=timers.target
```

## 10.4 Postgres PITR with pgBackRest

Sidecar container sharing PGDATA volume; `archive_command = 'pgbackrest --stanza=main archive-push %p'`; weekly full + nightly incr to S3. Restore: `pgbackrest restore --type=time --target="2026-04-11 13:45:00+00"`.

## 10.5 Restore drills

- **[MUST]** monthly automated restore to throwaway container; diff file counts; pipe pg_dumpall through `pg_restore --list` to verify parseable.
- **[SHOULD]** cosign-sign restic snapshot manifests.
- **[NICE]** print restic password on paper, seal in safe.

## 10.6 Compromise runbook

```
0. ASSUME BREACH.
1. ISOLATE: ufw default deny outgoing; docker network disconnect --all
2. SNAPSHOT (forensics): provider disk snapshot BEFORE touching anything
3. ROTATE: SSH host+user keys, all API keys, TLS certs, restic password
4. REBUILD: fresh VPS from cloud-init + Ansible + vps-max-security
5. RESTORE DATA (not binaries) from known-clean restic snapshot
6. TIMELINE: Loki logs, auditd keys (docker/identity/rootcmd/ptrace/mount),
             CrowdSec decisions.log for first-seen hostile IP
7. POSTMORTEM + DISCLOSURE
```

## 10.7 IaC

Every hardening decision in a git repo (Ansible or idempotent bash). cloud-init for T-0 bootstrap. This repo (`vps-max-security`) is exactly this pattern.

---

# Section 11 — Supply Chain Security

## 11.1 Pin by digest, not tag

```dockerfile
# BAD
FROM python:3.12-slim

# GOOD
FROM python:3.12-slim@sha256:a866731a6b71c4a194a845d86e06568725e430ed21821d0c52e4efb385cf6c6f
```
```yaml
services:
  postgres:
    image: postgres:16@sha256:4ec37d360b00...
```

Renovate config (`renovate.json`):
```json
{
  "extends": ["config:recommended", "docker:pinDigests"],
  "packageRules": [
    {
      "matchDatasources": ["docker"],
      "pinDigests": true, "automerge": true,
      "automergeType": "branch",
      "matchUpdateTypes": ["digest", "patch"]
    },
    {
      "matchManagers": ["pip_requirements", "poetry", "npm"],
      "rangeStrategy": "pin",
      "lockFileMaintenance": { "enabled": true, "schedule": ["before 5am on monday"] }
    }
  ],
  "vulnerabilityAlerts": { "enabled": true, "labels": ["security"] }
}
```

## 11.2 SBOM + scanning

```bash
syft packages docker:myapp:$(git rev-parse --short HEAD) \
  -o spdx-json=sbom.spdx.json -o cyclonedx-json=sbom.cdx.json

grype sbom:sbom.spdx.json --fail-on high

trivy image --format cyclonedx --output sbom.cdx.json myapp:sha-abc123
trivy image --severity HIGH,CRITICAL --exit-code 1 myapp:sha-abc123

cosign attest --predicate sbom.cdx.json --type cyclonedx \
  ghcr.io/me/myapp@sha256:...
```

## 11.3 Cosign keyless OIDC signing (GitHub Actions)

```yaml
permissions:
  id-token: write
  contents: read
  packages: write
jobs:
  build:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@v4
      - uses: docker/login-action@v3
        with: { registry: ghcr.io, username: ${{ github.actor }}, password: ${{ secrets.GITHUB_TOKEN }} }
      - uses: docker/build-push-action@v6
        id: build
        with: { push: true, tags: ghcr.io/${{ github.repository }}:${{ github.sha }} }
      - uses: sigstore/cosign-installer@v3
      - name: Sign
        run: |
          cosign sign --yes \
            ghcr.io/${{ github.repository }}@${{ steps.build.outputs.digest }}
```

VPS verification:
```bash
cosign verify ghcr.io/me/myapp@sha256:abc... \
  --certificate-identity-regexp="https://github.com/me/myapp/.github/workflows/build-sign.yml@refs/heads/main" \
  --certificate-oidc-issuer="https://token.actions.githubusercontent.com"
```

## 11.4 Base image choice 2026

| Base | Size | CVE surface | 2026 verdict |
|---|---|---|---|
| `ubuntu:24.04` | ~78 MB | High | Only if apt needed at runtime |
| `debian:12-slim` | ~75 MB | Med-high | Reasonable default |
| `python:3.12-slim` | ~125 MB | Med | Convenient |
| `alpine:3.20` | ~8 MB | Low | musl Python wheel surprises |
| `gcr.io/distroless/python3-debian12` | ~50 MB | Low | Good for prod, no shell |
| **Chainguard `cgr.dev/chainguard/python:latest`** | ~30-50 MB | **Near zero** | **Best 2026 option** — continuously rebuilt, signed, SBOM attached |

## 11.5 CI/CD security

- **No long-lived SSH keys.** Use OIDC + registry-pull model: CI pushes signed image to ghcr.io; VPS runs systemd timer that cosign-verifies and `docker compose pull && up -d`. No inbound SSH from CI.
- Mirror Docker Hub to **Zot** (30 MB binary, cosign-aware) or ghcr.io to avoid rate limits.

## 11.6 Git SSH commit signing

```bash
git config --global gpg.format ssh
git config --global user.signingkey ~/.ssh/id_ed25519.pub
git config --global commit.gpgsign true
git config --global tag.gpgsign true
echo "me@example.com $(cat ~/.ssh/id_ed25519.pub)" > ~/.config/git/allowed_signers
git config --global gpg.ssh.allowedSignersFile ~/.config/git/allowed_signers
```
GitHub: add same key as Signing Key; branch protection "Require signed commits" on `master`.

## 11.7 Dependency pinning with hashes

- Python: `pip-compile --generate-hashes`, `pip install --require-hashes`.
- Node: `package-lock.json` integrity sha512, `npm ci`.
- Rust: `Cargo.lock` + cargo-vet.

## 11.8 Recent supply chain incidents (lessons)

| Incident | Date | Lesson |
|---|---|---|
| **xz backdoor** (CVE-2024-3094) | Mar 2024 | Multi-year maintainer social engineering. Ubuntu 24.04 stable was NOT affected. |
| **s1ngularity/Nx** | Aug 2025 | Malicious `nx` releases used `claude`/`gemini --dangerously-skip-permissions` to exfil wallets/SSH keys. **Never run AI CLIs with skip-perm flags on boxes with real secrets.** |
| **Shai-Hulud worm** | Nov 2025 | Self-replicating npm worm — 25k+ repos infected. Scope npm tokens narrowly, granular per-package, 2FA-on-publish. |
| **runc Leaky Vessels** | Jan 2024 | CVE-2024-21626 + BuildKit CVEs. Old runc in CI = as dangerous as in prod. |

---

# Section 12 — Compliance & Audit

## 12.1 CIS Docker Benchmark 2026

Updated August 2025 for Docker Server v28, 27 recommendations. Key families:
- **1.x Host:** dedicated `/var/lib/docker` partition, auditd for Docker files.
- **2.x Daemon:** `icc=false`, `userns-remap`, `no-new-privileges`, `live-restore`, TLS on remote socket, seccomp, default ulimit, log-driver.
- **4.x Images:** create user, trusted base, scan, COPY not ADD, no `:latest`, HEALTHCHECK.
- **5.x Runtime:** AppArmor/SELinux, no `--privileged`, read-only FS, limited caps, `--pids-limit`, restart policy, no host ns sharing, no socket mount.

Run:
```bash
docker run --rm --net host --pid host --userns host --cap-add audit_control \
  -v /etc:/etc:ro -v /usr/bin/containerd:/usr/bin/containerd:ro \
  -v /usr/bin/runc:/usr/bin/runc:ro -v /usr/lib/systemd:/usr/lib/systemd:ro \
  -v /var/lib:/var/lib:ro -v /var/run/docker.sock:/var/run/docker.sock:ro \
  docker/docker-bench-security
```

## 12.2 CIS Ubuntu 24.04 + OpenSCAP

```bash
sudo apt install -y libopenscap8 ssg-debderived
oscap xccdf eval \
  --profile xccdf_org.ssgproject.content_profile_cis_level2_server \
  --results /var/log/oscap/results-$(date +%F).xml \
  --report  /var/log/oscap/report-$(date +%F).html \
  /usr/share/xml/scap/ssg/content/ssg-ubuntu2404-ds.xml
```

## 12.3 Lynis

`sudo lynis audit system --quick` — target **hardening index ≥ 85**.

## 12.4 Audit checklist

**Weekly (automated):** unattended-upgrades, Trivy scan, Grype SBOM diff, fail2ban status, journald warnings, `docker system prune`.

**Monthly:** docker-bench-security diff, Lynis diff, secret rotation (>90 days), Renovate backlog, backup restore verification, cosign verify, aide check, sudo/authorized_keys audit.

**Quarterly:** full OpenSCAP CIS L2, kernel/runc/containerd version check, rotate registry tokens+PATs+CF tokens, external nmap scan, IAM review, DR drill.

**Annually:** re-read full CIS benchmarks, re-baseline waivers, threat model review, retire unused accounts/services.

---

# Section 13 — Emerging Threats 2025–2026

## 13.1 Must-know CVEs

| CVE | Date | Component | Impact | Fixed in |
|---|---|---|---|---|
| **CVE-2024-3094** | Mar 2024 | `xz-utils`/liblzma | Backdoored sshd RCE | xz 5.4.x; 24.04 stable never shipped 5.6.x |
| **CVE-2024-21626** | Jan 2024 | runc ≤1.1.11 "Leaky Vessels" | Container escape via fd leak | runc 1.1.12 |
| **CVE-2024-23651/52/53** | Jan 2024 | BuildKit ≤0.12.4 | Race + priv container | BuildKit 0.12.5 |
| **CVE-2024-1086** | Jan 2024 | Linux nf_tables UAF | LPE to root, CISA KEV, ransomware-used | 6.1.76/6.6.15/6.8+ |
| **CVE-2024-6387 "regreSSHion"** | Jul 2024 | OpenSSH 8.5–9.8p1 | Pre-auth root RCE | OpenSSH 9.8p1 |
| **CVE-2025-21756** | Feb 2025 | Linux vsock UAF | LPE / VM escape | 6.6.79/6.12.16/6.13.4 |
| **CVE-2025-9074** | Aug 2025 | Docker Desktop Win/macOS <4.44.3 | Unauthenticated Engine API at 192.168.65.7:2375 → host takeover | 4.44.3 (dev machines only) |
| **CVE-2025-31133** | Nov 2025 | runc ≤1.2.7/1.3.2 | `maskedPaths` race → write to host /proc | 1.2.8/1.3.3/1.4.0-rc.3 |
| **CVE-2025-52565** | Nov 2025 | runc ≤1.2.7/1.3.2 | `/dev/console` bind-mount race → host write | 1.2.8/1.3.3/1.4.0-rc.3 |
| **CVE-2025-52881** | Nov 2025 | runc ≤1.2.7/1.3.2 | Arbitrary /proc write, bypasses LSM | 1.2.8/1.3.3/1.4.0-rc.3 |
| **CVE-2025-38352** | 2025 | Linux POSIX CPU timer race, CISA KEV | LPE, ITW exploitation | current LTS |

**Action items from this table:**
1. `apt upgrade` + reboot monthly — Ubuntu 24.04 patches all above.
2. **`docker version` must show runc ≥ 1.2.8 / 1.3.3.** Distro `docker.io` historically lags — use docker-ce repo.
3. `sshd -V` ≥ 9.8p1, ideally ≥10.0 for default PQ KEX.

## 13.2 Container escape techniques still working

1. **`/proc/self/exe` overwrite** (runc class) — keep runc current.
2. **Symlink races on bind mounts** — `:ro` everywhere.
3. **Capability misuse** — `CAP_SYS_ADMIN`, `CAP_SYS_MODULE`, `CAP_NET_ADMIN`. `cap_drop: [ALL]`.
4. **Writable cgroup v1 release_agent** — mitigated by Ubuntu 24.04 cgroup v2 default. Verify: `stat -fc %T /sys/fs/cgroup` → `cgroup2fs`.
5. **`--privileged`, `--pid=host`, `--ipc=host`, `--net=host`** — audit and remove.
6. **Docker socket mount** — use socket-proxy.
7. **Missing `userns-remap`** — enable.

## 13.3 Post-quantum crypto 2026

- **SSH:** OpenSSH ≥9.9 `mlkem768x25519-sha256`; default in 10.0.
- **TLS:** Chrome/Firefox/BoringSSL shipped `X25519MLKEM768` default early 2025. OpenSSL 3.5 (Apr 2025) first OpenSSL with PQ KEM.
- **For this VPS:** Terminate TLS at **Cloudflare** (already speaks PQ hybrids to browsers). Or build nginx + OpenSSL 3.5 for origin PQ.

## 13.4 eBPF runtime security — Tetragon vs Falco

| | Tetragon | Falco |
|---|---|---|
| Focus | Detection + **enforcement** (SIGKILL) | Detection/alerting |
| Overhead | <1% (lowest CPU) | <5% (lowest RAM) |
| Accuracy | Catches shell-redirect writes Falco misses | Mature rule library |
| Single-VPS | Excellent — lightweight | Excellent — fastest time to value |

**Recommendation:** **Falco** for solo-operator (larger community ruleset), **Tetragon** if you want blocking not alerting. Don't run both.

## 13.5 Zero trust on single VPS

**Don't deploy Istio/Linkerd.** Instead:
- **Mgmt plane:** Tailscale (free ≤100 devices/3 users) — port 22 closed on internet.
- **Web plane:** Cloudflare Tunnel + Cloudflare Access — no inbound 80/443 at all. SSO for Grafana/pgAdmin/Django admin.
- **Internal:** `internal: true` Docker networks for DB/Redis. Per-service least-privilege DB users.

## 13.6 AI/LLM threats

If Django/Node calls OpenAI/Anthropic:
- **Prompt injection** → delimit user content, never put secrets in prompts, treat LLM output as untrusted (never exec/SQL).
- **Indirect injection** via fetched content → sanitize, sandbox tool exec.
- **SSRF via LLM tool calls** → allowlist egress at container/Docker network level.
- **`s1ngularity` lesson:** never run AI coding agents with `--dangerously-skip-permissions` on boxes with production credentials.

---

# Known Conflicts & Gotchas (the ones that bite)

1. **UFW ↔ Docker bypass** — Docker publishes container ports regardless of `ufw default deny incoming`. Fix: bind to 127.0.0.1 or DOCKER-USER default DROP.
2. **sysctl `net.ipv4.ip_forward=0`** — breaks all Docker networking.
3. **sysctl `rp_filter=1` (strict)** — breaks Docker multi-bridge asymmetric routing. Use `=2` (loose).
4. **`br_netfilter` not auto-loaded on boot** → sysctl-on-boot errors. Fix: `/etc/modules-load.d/docker.conf`.
5. **`yama.ptrace_scope=2`** — breaks `docker exec strace`, Sentry native, py-spy.
6. **`unprivileged_bpf_disabled=1`** — breaks Falco/Cilium as non-root.
7. **`/dev/shm noexec`** — breaks Chromium/Puppeteer; LiveKit egress with chromium recorder. Mitigate with `--disable-dev-shm-usage` or per-container tmpfs.
8. **`userns-remap`** — bind-mount ownership mismatch; incompatible with `--net=host`/`--pid=host`; LiveKit on host networking needs `--userns=host` override.
9. **`network_mode: host` for LiveKit** — can't join compose networks or use service DNS. Accept the trade.
10. **`userland-proxy: false` + publishing 10k UDP ports** — still expensive. Use `network_mode: host` for LiveKit instead.
11. **Cloudflare doesn't proxy UDP** — WebRTC media MUST bypass CF. DNS-only (grey cloud) on rtc subdomain.
12. **Cloudflare ipset cron too infrequent** — CF adds prefixes; run every 6h not daily.
13. **`COEP: require-corp`** — breaks YouTube embeds, Stripe iframes, cross-origin images without CORP. Only enable if `SharedArrayBuffer` needed. Basic LiveKit does NOT need it.
14. **`SECURE_PROXY_SSL_HEADER`** without Nginx unconditionally overwriting — client-spoofable → CSRF bypass.
15. **`CSRF_COOKIE_HTTPONLY=True`** — breaks React fetch reading the cookie.
16. **JWT in wss URL query string** — persists in Nginx access logs forever. Use first-message auth.
17. **Multi-worker Django rate limit without Redis backend** — each worker has its own counter = effectively no limit.
18. **`CORS_ALLOW_CREDENTIALS=True` + permissive origin regex** — subdomain takeover → auth bypass.
19. **Postgres TLS with `sslmode=verify-ca`** — mitm possible. Use `verify-full`.
20. **Redis `rename-command` in 2026** — deprecated. Use ACL `-@dangerous`.
21. **WebSocket `proxy_read_timeout` default 60s** — LiveKit idle rooms disconnect. Set `3600s`.
22. **CIS Docker Bench maps to v1.6** — v1.7 (Aug 2025) only covered by commercial scanners or custom InSpec.
23. **docker.io distro package lags** — use `docker-ce` repo for faster runc updates.
24. **rootless Docker + LiveKit** — slirp4netns is slow for UDP media. Run LiveKit in rootful mode on a separate VPS.
25. **Trivy release infra March 2026 compromise** — pin to verified release, use Grype as second opinion.

---

# Sources

Full source list with URLs — see per-section references in `/docs/research/sections/*.md`. Primary authoritative sources:

- [Docker Docs: Packet filtering & firewalls](https://docs.docker.com/engine/network/packet-filtering-firewalls/)
- [Docker Docs: userns-remap](https://docs.docker.com/engine/security/userns-remap/)
- [Docker Docs: AppArmor](https://docs.docker.com/engine/security/apparmor/)
- [Docker Docs: Rootless mode](https://docs.docker.com/engine/security/rootless/)
- [Docker Engine v28/v29 release notes](https://docs.docker.com/engine/release-notes/)
- [LiveKit Docs: Ports & firewall](https://docs.livekit.io/transport/self-hosting/ports-firewall/)
- [LiveKit config-sample.yaml](https://github.com/livekit/livekit/blob/master/config-sample.yaml)
- [OpenSSH 10.0 release + PQ page](https://www.openssh.com/pq.html)
- [ssh-audit.com Hardening Guides](https://www.ssh-audit.com/hardening_guides.html)
- [OWASP CRS Paranoia Levels](https://coreruleset.org/docs/2-how-crs-works/2-2-paranoia_levels/)
- [Mozilla SSL Configuration Generator](https://ssl-config.mozilla.org/)
- [django-csp 4.0 Migration Guide](https://django-csp.readthedocs.io/en/latest/migration-guide.html)
- [PostgreSQL 17 pg_hba.conf authentication](https://www.postgresql.org/docs/current/auth-pg-hba-conf.html)
- [Redis Security Docs](https://redis.io/docs/latest/operate/oss_and_stack/management/security/)
- [CIS Docker Benchmark](https://www.cisecurity.org/benchmark/docker)
- [CIS Benchmarks August 2025 Update](https://www.cisecurity.org/insights/blog/cis-benchmarks-august-2025-update)
- [runc CVE-2025-31133/52565/52881 GHSA](https://github.com/opencontainers/runc/security/advisories/GHSA-cgrx-mc8f-2prm)
- [Sigstore cosign signing](https://docs.sigstore.dev/cosign/signing/signing_with_containers/)
- [Chainguard Images overview](https://edu.chainguard.dev/chainguard/chainguard-images/overview/)
- [CrowdSec Nginx bouncer docs](https://docs.crowdsec.net/u/bouncers/nginx/)
- [Neo23x0 auditd rules](https://github.com/Neo23x0/auditd)
- [chaifeng/ufw-docker](https://github.com/chaifeng/ufw-docker)
- [Tecnativa docker-socket-proxy](https://github.com/Tecnativa/docker-socket-proxy)
- [pgBackRest user guide](https://pgbackrest.org/user-guide.html)
- [Tetragon](https://tetragon.io/)
- [Ubuntu Livepatch](https://ubuntu.com/security/livepatch)
- [NVD CVE database](https://nvd.nist.gov/)
- [Ubuntu Security Notices](https://ubuntu.com/security/notices)
