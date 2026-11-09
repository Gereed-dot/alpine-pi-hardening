# Hardening a Raspberry Pi 400 Running Alpine Linux

A hands-on baseline-hardening project: take a working Alpine Linux desktop on a Raspberry Pi 400, measure its attack surface, apply four controls (limited admin access, a default-drop firewall, key-only SSH, a patching routine), and verify each one with before/after evidence.

## Summary

| Control | Before | After | Evidence |
|---|---|---|---|
| Attack surface | Only `sshd` listening (22), password login enabled | Same single port, now behind a default-drop firewall | `01`, `03` |
| Admin access | Root password used for administration | Day-to-day work as a normal user; root only through `doas`, password required | `02` |
| Firewall | None | `nftables`, input policy `drop`, allow only what is needed | `03`, `06` |
| SSH | Password authentication on | Key-only (ed25519 + passphrase), root login off, 3 auth attempts | `04`, `05` |
| Persistence | Not verified | Rebooted; firewall and SSH settings survived | `06` |
| Patching | Manual | Routine `apk update && apk upgrade`, plus a helper for kernel updates on this board | below |

## Environment

- Raspberry Pi 400 (BCM2711), Alpine Linux 3.24, kernel `6.18.60-0-rpi`, installed in "sys" mode on the SD card
- Desktop: XFCE with LightDM, KMS graphics, PulseAudio, Bluetooth
- Administered over SSH from a Windows PC
- Network: Wi-Fi on a home LAN (no port forwarding; not exposed to the internet)

Hostnames, addresses, usernames and key fingerprints are redacted or replaced with placeholders: `<PI_IP>` for the Pi's address and `<user>` for the non-root account.

## Method

For each control I followed the same loop: record the current state, make one change, verify it works, and only then move on. For the one change that could lock me out (SSH), I kept a logged-in session open and tested from a separate new window before closing anything. The Pi's own monitor and keyboard were the last-resort recovery path.

---

## 1. Baseline

Before changing anything I captured what was listening, what was running, and the effective SSH configuration.

```
ss -tulpn
rc-status
grep -vE "^#|^$" /etc/ssh/sshd_config
```

![Baseline](screenshots/01-baseline-before.png)

**Findings**

- The only listening service is `sshd`, on TCP 22 for IPv4 and IPv6. The attack surface was already small.
- `sshd_config` did not set `PasswordAuthentication`, so password login was enabled by default.
- `chronyd` and `ntpd` were both running. Only one is needed, so I removed the redundant one (see step 6).
- Forwarding options (`AllowTcpForwarding`, `GatewayPorts`, `X11Forwarding`) were already set to `no`.

`ss` is not in BusyBox on Alpine; it comes from the `iproute2-ss` package.

## 2. Limited administrative access (`doas`)

Alpine uses `doas` instead of `sudo`. The account used day to day is a normal user, and root access goes through `doas` with a password prompt.

```
apk add doas
echo "permit persist <user> as root" > /etc/doas.d/<user>.conf
chmod 600 /etc/doas.d/<user>.conf
```

Verification, as the normal user:

```
doas whoami      # prompts for the user's password, prints: root
```

![doas](screenshots/02-doas-limited-admin.png)

**Notes**

- `persist` caches the authentication for a short time. A stricter rule can limit the account to specific commands, for example `permit persist <user> as root cmd apk`.
- The account is also in the `wheel` group, and the package ships `/etc/doas.d/20-wheel.conf`, so two rules grant the same access. That is harmless but redundant; a tighter setup would keep only one.
- Running `doas` from a root shell is pointless (root does not need it) and just prompts for root's password, which I did by mistake while testing. The test that matters is from the normal user.

## 3. Firewall (`nftables`)

Because the baseline showed only SSH listening, the policy is simple: drop all inbound traffic except what is needed.

`/etc/nftables.nft`:

```
#!/usr/sbin/nft -f
flush ruleset
table inet filter {
  chain input {
    type filter hook input priority 0; policy drop;
    iif lo accept
    ct state established,related accept
    ct state invalid drop
    ip protocol icmp accept
    ip6 nexthdr icmpv6 accept
    tcp dport 22 accept
    udp sport 67 udp dport 68 accept
  }
  chain forward { type filter hook forward priority 0; policy drop; }
  chain output { type filter hook output priority 0; policy accept; }
}
```

**Why each rule is there**

- `policy drop` on input: anything not explicitly allowed is refused.
- `iif lo`, `established,related`: loopback and replies to connections the Pi started.
- `ct state invalid drop`: malformed or out-of-state packets.
- `icmp` / `icmpv6`: ping and, importantly, IPv6 neighbour discovery, which breaks without ICMPv6.
- `tcp dport 22`: SSH.
- `udp sport 67 dport 68`: DHCP replies. The Pi gets its address over Wi-Fi by DHCP, and a default-drop policy would otherwise block lease renewals.
- `forward` drop: the Pi is not a router.

**Safe rollout**

```
apk add nftables
nft -c -f /etc/nftables.nft     # syntax check only, no changes applied
nft -f /etc/nftables.nft        # load
nft list ruleset
```

A brand-new SSH connection from a second window confirmed port 22 was still reachable. Only then did I make it permanent:

```
rc-update add nftables default
rc-service nftables save
```

![Ruleset](screenshots/03-nftables-ruleset.png)

An already-open SSH session survives a new firewall because of the `established` rule, so it proves nothing about new connections. Testing a fresh connection is the real check.

## 4. Key-only SSH

Generated an ed25519 key with a passphrase on the Windows machine and installed the public key:

```
ssh-keygen -t ed25519
type %USERPROFILE%\.ssh\id_ed25519.pub | ssh <user>@<PI_IP> "mkdir -p ~/.ssh && chmod 700 ~/.ssh && cat >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys"
```

Logged in with the key from a new window (a passphrase prompt and no account-password prompt) **before** touching the server config. Then, on the Pi, a drop-in file (the main config already includes `/etc/ssh/sshd_config.d/*.conf`):

`/etc/ssh/sshd_config.d/hardening.conf`:

```
PermitRootLogin no
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
MaxAuthTries 3
```

```
sshd -t                    # prints nothing when the config is valid
rc-service sshd reload     # reload keeps existing sessions alive
```

**Verification from the Windows machine**

```
ssh -o PubkeyAuthentication=no <user>@<PI_IP>
# Permission denied (publickey).
```

![Key-only SSH](screenshots/04-key-only-ssh-proof.png)

Active settings on the host, and the services running:

![SSH settings and services](screenshots/05-sshd-config-services.png)

## 5. Persistence check

A control that disappears at reboot is not a control. After rebooting with `doas reboot`:

- Key login still worked (passphrase prompt, no password prompt).
- The firewall ruleset was loaded without any manual step.
- `nftables` showed as enabled in the default runlevel (`rc-update show | grep nftables`).

![After reboot](screenshots/06-after-reboot.png)

## 6. Reducing services

`chronyd` already handles time synchronisation, so the redundant BusyBox `ntpd` was stopped and removed from the default runlevel (visible at the end of the last screenshot):

```
doas rc-service ntpd stop
doas rc-update del ntpd default
```

## 7. Patching

Routine:

```
apk update
apk upgrade
```

**A board-specific gotcha.** The Raspberry Pi firmware boots from the FAT partition mounted at `/media/mmcblk0p1`, not from `/boot` on the root filesystem. A `linux-rpi` upgrade writes the new kernel to `/boot`, so the firmware would keep booting the old kernel with no matching modules (no GPU, Wi-Fi or Bluetooth). I noticed this before rebooting by comparing file dates in both locations, and wrote a small helper that copies the kernel, initramfs, device trees and overlays to the real boot partition, verifying each copy with `cmp` before swapping it in:

```sh
#!/bin/sh
set -e
B=/media/mmcblk0p1
mountpoint -q $B || mount $B
rm -rf $B/cache
for f in vmlinuz-rpi initramfs-rpi; do
  cp /boot/$f $B/boot/$f.new
  cmp /boot/$f $B/boot/$f.new
  mv -f $B/boot/$f.new $B/boot/$f
done
cp /boot/*.dtb $B/
cp /boot/overlays/* $B/overlays/
sync
echo "Boot partition updated:"
ls -l $B/boot
```

It lives at `/usr/local/bin/sync-boot` and is run as root after any `apk upgrade` that lists `linux-rpi`. The boot partition is only ~129 MB, so the helper also clears the package cache to keep headroom.

---

## Problems I hit and how I handled them

Good operational notes are as much about recovery as success.

- **Boot partition full.** Writing the graphics overlay to `usercfg.txt` failed with "No space left on device". I diagnosed it with `df` and `du`, removed the unneeded install-media `apks` folder, and protected the files the Pi cannot boot without.
- **Config in the wrong place.** My first overlay edit went to `/boot`, which is just a folder on the root filesystem, so the firmware ignored it. Checking `mount` and `/proc/cmdline` showed the real boot partition.
- **NetworkManager broke Wi-Fi.** Starting it took over the Wi-Fi interface without my network credentials and dropped the SSH session. I recovered from the Pi's monitor by stopping it, removing it from the runlevel, and restarting Alpine's own `wpa_supplicant` and `networking` services. I chose to keep the original, working network stack.
- **Credentials typed into a shell.** While working I twice typed a password at a visible prompt instead of the hidden one. It was not executed as a command, but it landed in terminal scrollback, so I treated it as exposed: I changed the password and cropped those lines out of every screenshot in this write-up.
- **A "remove duplicate line" command removed the only line.** I deleted the last line of a config file assuming there were two copies, and removed the one correct entry. I caught it with `grep -c` and re-added it. The lesson: count first, then edit.

## Limitations and next steps

Being honest about what this does not cover:

- SSH is allowed from anywhere on the local network. Restricting it to the home subnet would be tighter (`ip saddr <lan>/24 tcp dport 22 accept`, plus an IPv6 equivalent).
- No brute-force protection such as `fail2ban`. Key-only login makes password guessing moot, but rate limiting would still reduce log noise.
- The output chain is `accept`. An egress allow-list would limit what a compromised process could reach.
- No file-integrity monitoring, central logging, or alerting.
- The `doas` rules overlap (`wheel` plus a per-user rule) and could be reduced to one.
- The private key lives on one machine. A second, offline backup would remove a single point of failure.
- A scheduled `apk update` check with a notification would replace the manual patching habit.

## What this demonstrates

Measuring before changing, least privilege, default-deny network policy, safe rollout of changes that can lock you out, verification of every control (including across a reboot), and documenting failures and trade-offs rather than only successes.
