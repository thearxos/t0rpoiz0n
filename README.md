# t0rpoiz0n

**Tor Transparent Proxy + MAC Spoofing for Arch Linux**

Author: **0xb0rn3 | oxbv1** · Version: **1.2.0**

---

## Features

- Transparent Tor proxy — routes all system TCP traffic through Tor
- MAC address spoofing with 10 vendor profiles
- IPv6 disabled during operation to prevent leaks
- DNS routed through Tor's DNSPort (no DNS leaks)
- Blocks DNS-over-HTTPS (DoH), DNS-over-TLS, and QUIC/HTTP3
- Smart iptables backend detection — works with both `iptables-nft` and `iptables-legacy`
- nft native fallback for Tor traffic exemption on kernel/nft combos that reject owner matching in NAT
- Auto-generates backend-appropriate rules on every start
- One-command install and setup

---

## Requirements

- Arch Linux (or Arch-based distro)
- `tor`, `iptables`, `macchanger` — installed automatically if missing
- Root access

---

## Installation

```bash
git clone https://github.com/0xb0rn3/t0rpoiz0n.git
cd t0rpoiz0n
chmod +x run
sudo ./run --install
```

After installation, `t0rpoiz0n` is available system-wide.

---

## Usage

```
sudo t0rpoiz0n -s                   # Start transparent proxy
sudo t0rpoiz0n -s -m                # Start + spoof MAC
sudo t0rpoiz0n -s -m -v apple       # Start + spoof MAC as Apple
sudo t0rpoiz0n -k                   # Stop and restore clearnet
sudo t0rpoiz0n -r                   # New Tor circuit
sudo t0rpoiz0n -c                   # Check status
sudo t0rpoiz0n -m -v samsung        # Spoof MAC only
sudo t0rpoiz0n -i wlan0 -s -m       # Specify interface
sudo t0rpoiz0n --setup              # Re-run setup
```

### Options

| Flag | Description |
|------|-------------|
| `-s` | Start transparent proxy |
| `-k` | Stop proxy and restore clearnet |
| `-r` | Restart Tor (new circuit / new IP) |
| `-c` | Check Tor status and connection |
| `-m` | Change MAC address |
| `-v VENDOR` | MAC vendor prefix |
| `-i IFACE` | Network interface (auto-detected if omitted) |
| `--setup` | Re-run first-time setup |

### MAC Vendors

`apple` · `asus` · `dell` · `google` · `hp` · `huawei` · `lenovo` · `motorola` · `nokia` · `samsung`

---

## How It Works

```
Application traffic
        ↓
iptables OUTPUT chain
        ↓ (owner=tor → RETURN, bypasses redirect)
Tor TransPort :9040
        ↓
Tor network (3 hops)
        ↓
Exit node → Destination
```

DNS queries are redirected to Tor's DNSPort on :53. IPv6 is disabled system-wide
while the proxy is active. On stop, all rules are flushed and the original DNS and
IPv6 state are restored.

---

## Browser Configuration

Use **Tor Browser** for best results. If using Firefox:

| Setting | Value |
|---------|-------|
| `network.trr.mode` | `5` |
| `network.http.http3.enabled` | `false` |
| `media.peerconnection.enabled` | `false` |

---

## Upgrading

```bash
cd ~/t0rpoiz0n
cp ~/Downloads/t0rpoiz0n.py ./t0rpoiz0n.py
sudo cp ./t0rpoiz0n.py /usr/local/bin/t0rpoiz0n
sudo chmod +x /usr/local/bin/t0rpoiz0n
sudo t0rpoiz0n --setup
```

---

## Uninstall

```bash
sudo ./run --uninstall
# or
sudo bash cleanup.sh
```

---

## Troubleshooting

**Tor service won't start**

```bash
sudo journalctl -u tor-t0rpoiz0n.service -n 30 --no-pager
sudo t0rpoiz0n --setup
```

**No internet after starting**

- 
sudo t0rpoiz0n -c     # check status
sudo t0rpoiz0n -r     # try a new circuit
sudo t0rpoiz0n -k && sudo t0rpoiz0n -s   # full restart
```

**MAC change fails**

```bash
ip link show          # find interface name
sudo t0rpoiz0n -m -i wlan0
```

**Verify Tor is working** (run as a regular user, not root)

```bash
curl https://check.torproject.org/api/ip
# Expected: {"IsTor": true, "IP": "..."}
```

---

## Security Notes

**Protected against:** IP leaks · DNS leaks · IPv6 leaks · MAC address tracking (optional)

**Not protected against:** WebRTC leaks (use browser extension) · Application-level IP hardcoding · Timing attacks · Malware

---

## Changelog
### v1.2.0 ADDED 3 tiers! :
```bash
- Tier 1 — Kernel & firewall hardening (harden_sysctl())
  
13 sysctl parameters applied on start, saved to sysctl.json, fully restored on stop: TCP timestamps off, ICMP redirects disabled, source routing disabled, echo ignore, broadcast ping ignore, full ASLR, reverse path filtering, martian packet logging. INPUT and FORWARD chains now default to DROP — only loopback and ESTABLISHED/RELATED inbound are allowed. Outbound ICMP blocked (OS fingerprint surface). NTP blocked outbound (timing correlation). Clearnet leak window closed by setting OUTPUT DROP before flushing rules, so there's no open moment between flush and reapply.
  
- Tier 2 — System-level anonymisation
harden_hostname() — replaces hostname with ghost-4821 style random token on start, restores on stop. Prevents mDNS/DHCP leaks. harden_timezone() — switches to UTC on start, restores original on stop. harden_swap() — swapoff -a on start so keys/decrypted data can't be paged to disk, swapon -a on stop. Clock sync — chronyc makestep (or ntpdate fallback) runs before the firewall seals so NTP never escapes through the Tor session. Bridge support — -b flag accepts an obfs4 bridge line, written into torrc with UseBridges 1 + ClientTransportPlugin obfs4.

- Tier 3 — Tor-level hardening
Stream isolation — both SocksPort and TransPort now carry IsolateSOCKSAuth IsolateDestAddr IsolateDestPort (plus IsolateClientAddr IsolateClientProtocol on TransPort), so each destination gets a separate circuit. Guard pinning — -g FINGERPRINT writes EntryNodes + StrictNodes 1 into torrc, eliminating guard rotation as an attack surface.
--no-harden flag — skips all of the above for debugging without reverting.
-c status output now shows hostname, timezone, swap state, TCP timestamps, and INPUT policy so you can verify hardening is active at a glance.
  ```

### v1.1.3

- **Fixed:** `HardwareAccel 1` was an invalid torrc option in modern Tor — caused `--verify-config` to fail and prevented the service from ever starting
- **Fixed:** Removed `User tor` from torrc — the `--uid-owner tor` iptables exemption requires Tor to actually run as that user; without it, Tor's own traffic got redirected back to port 9040 causing an infinite routing loop and failed bootstrapping
- **Fixed:** `NoNewPrivileges=yes` and `AmbientCapabilities` in the systemd service conflicted with Tor's own privilege dropping via the `User` directive
- **Fixed:** `restart_tor()` reported success regardless of whether Tor was actually running — now verifies `systemctl is-active` and prints journal output on failure
- **Added:** `nft_ensure_tor_exemption()` — native nft fallback for kernels that reject `--uid-owner` in the NAT table via iptables-restore
- **Refactor:** Full rewrite — 815 lines → 532 lines. Print helpers (`ok`, `info`, `warn`, `err`), `Backend` class replacing three globals, rule strings as module constants, all dead code removed

### v1.1.2
- Automatic iptables backend detection (nft vs legacy)
- Smart backend switching via update-alternatives

### v1.1.1
- Auto-loads iptables kernel modules
- Auto-update checker (GitHub, every 24h)

### v1.1.0
- Blocked DNS-over-HTTPS and QUIC/HTTP3 to prevent browser IP leaks

### v1.0.0
- Initial release

---

## Credits

- [Tor Project](https://www.torproject.org/) — the network and daemon
- [brainfucksec](https://github.com/brainfucksec) — original archtorify concept
- [Debajyoti0-0](https://github.com/Debajyoti0-0) — ToriFY MAC spoofing inspiration

---

*Built for the security research community. Use responsibly and legally.*
