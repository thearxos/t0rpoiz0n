#!/usr/bin/env python3
"""
ArxOS AnonKit - Tor transparent proxy, MAC spoofing, VPN->Tor, Snowflake
Author : 0xb0rn3 | oxbv1
Version: 0.0.1
Target : Arch Linux
"""

import os
import sys
import time
import subprocess
import random
import json
import string
import argparse
from pathlib import Path
from typing import Optional

# ── Colours ───────────────────────────────────────────────────────────────────

class C:
    RED    = '\033[31m'
    GREEN  = '\033[32m'
    YELLOW = '\033[33m'
    CYAN   = '\033[36m'
    BOLD   = '\033[1m'
    RESET  = '\033[0m'

def ok(msg):   print(f"{C.GREEN}[✓] {msg}{C.RESET}")
def info(msg): print(f"{C.CYAN}[*] {msg}{C.RESET}")
def warn(msg): print(f"{C.YELLOW}[!] {msg}{C.RESET}")
def err(msg):  print(f"{C.RED}[✗] {msg}{C.RESET}")

# ── Paths ─────────────────────────────────────────────────────────────────────

DATA_DIR      = Path("/usr/share/t0rpoiz0n")
BACKUP_DIR    = Path("/var/lib/t0rpoiz0n/backups")
RULES_FILE    = DATA_DIR / "iptables.rules"
TORRC         = Path("/etc/tor/torrc")
SERVICE       = Path("/etc/systemd/system/tor-t0rpoiz0n.service")
HARDEN_STATE  = BACKUP_DIR / "harden_state.json"

# ── MAC vendor OUI prefixes ───────────────────────────────────────────────────

MAC_VENDORS = {
    'apple':    '00:03:93', 'asus':     '9C:5C:8E',
    'dell':     '00:06:5B', 'google':   '00:1A:11',
    'hp':       '00:0B:CD', 'huawei':   '00:18:82',
    'lenovo':   '00:21:5C', 'motorola': '00:0A:28',
    'nokia':    '00:19:2D', 'samsung':  '94:51:03',
}

# ── Kernel hardening parameters ───────────────────────────────────────────────
# Applied on start, restored on stop from saved state.

_SYSCTL_HARDENING = {
    # TCP timestamps leak system uptime → correlation attacks
    'net.ipv4.tcp_timestamps':                '0',
    # Prevent ICMP redirect attacks
    'net.ipv4.conf.all.accept_redirects':     '0',
    'net.ipv4.conf.default.accept_redirects': '0',
    'net.ipv4.conf.all.send_redirects':       '0',
    'net.ipv4.conf.default.send_redirects':   '0',
    # Disable source routing (used in spoofing attacks)
    'net.ipv4.conf.all.accept_source_route':  '0',
    # Don't respond to pings (reduce fingerprint surface)
    'net.ipv4.icmp_echo_ignore_all':          '1',
    # Reverse path filtering — drop packets with impossible source addresses
    'net.ipv4.conf.all.rp_filter':            '1',
    'net.ipv4.conf.default.rp_filter':        '1',
    # Full ASLR
    'kernel.randomize_va_space':              '2',
}

# ── iptables backend state ────────────────────────────────────────────────────

class Backend:
    cmd     = "iptables"
    restore = "iptables-restore"
    is_nft  = False

def detect_backend() -> bool:
    info("Detecting iptables backend...")
    for cmd, restore, is_nft in [
        ("iptables-nft",    "iptables-nft-restore",    True),
        ("iptables-legacy", "iptables-legacy-restore",  False),
        ("iptables",        "iptables-restore",          False),
    ]:
        if run(f"{cmd} -L -n 2>/dev/null", check=False).returncode == 0:
            Backend.cmd, Backend.restore, Backend.is_nft = cmd, restore, is_nft
            ok(f"Using {cmd} ({'nftables' if is_nft else 'legacy'} backend)")
            return True
    warn("No working iptables backend found; defaulting to iptables-nft")
    Backend.cmd, Backend.restore, Backend.is_nft = \
        "iptables-nft", "iptables-nft-restore", True
    return False

# ── Shell helper ──────────────────────────────────────────────────────────────

def run(cmd: str, check: bool = True) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(cmd, shell=True, check=check,
                              capture_output=True, text=True)
    except subprocess.CalledProcessError as e:
        if check:
            err(f"Command failed: {cmd}")
            if e.stderr.strip():
                print(f"  {e.stderr.strip()}")
        raise

# ── Banner ────────────────────────────────────────────────────────────────────

_BANNER = r"""
        ▄▀█ █▀█ ▀▄▀ █▀█ █▀   ▄▀█ █▄░█ █▀█ █▄░█ █▄▀ █ ▀█▀
        █▀█ █▀▄ █░█ █▄█ ▄█   █▀█ █░▀█ █▄█ █░▀█ █░█ █ ░█░

     REAL-WORLD OPSEC   ·   Tor · MAC · VPN→Tor · Snowflake   ·   v0.0.1
"""

def banner():
    print(f"{C.CYAN}{C.BOLD}{_BANNER}{C.RESET}")

# ── Preflight ─────────────────────────────────────────────────────────────────

def require_root():
    if os.geteuid() != 0:
        err("This tool must be run as root")
        sys.exit(1)

def check_deps() -> bool:
    missing = [p for p in ('tor', 'iptables', 'macchanger')
               if run(f"which {p}", check=False).returncode != 0]
    if missing:
        err(f"Missing: {', '.join(missing)}")
        warn(f"Install: sudo pacman -S {' '.join(missing)}")
        return False
    return True

# ── Network interface ─────────────────────────────────────────────────────────

def default_interface() -> Optional[str]:
    for cmd in (
        "ip route | grep default | awk '{print $5}' | head -1",
        "ip link show | grep -v 'lo:' | grep 'state UP' | awk '{print $2}' | tr -d ':' | head -1",
    ):
        r = run(cmd, check=False)
        if r.returncode == 0 and r.stdout.strip():
            return r.stdout.strip()
    return None

# ── MAC spoofing ──────────────────────────────────────────────────────────────

def random_mac(vendor: Optional[str] = None) -> str:
    tail   = ':'.join(f'{random.randint(0,255):02x}' for _ in range(3))
    prefix = MAC_VENDORS.get((vendor or '').lower())
    return f"{prefix}:{tail}" if prefix else \
           ':'.join(f'{random.randint(0,255):02x}' for _ in range(6))

def change_mac(interface: str, vendor: Optional[str] = None) -> bool:
    info(f"Changing MAC on {interface}...")
    mac = random_mac(vendor)
    run(f"ip link set {interface} down", check=False)
    r = run(f"macchanger -m {mac} {interface}", check=False)
    run(f"ip link set {interface} up",   check=False)
    if r.returncode == 0:
        ok(f"MAC → {mac}")
        return True
    err("Failed to change MAC")
    return False

# ── iptables rules ────────────────────────────────────────────────────────────

# NAT table: REDIRECT, RETURN only — no REJECT here.
_RULES_NAT = """\
*nat
:PREROUTING  ACCEPT [0:0]
:INPUT       ACCEPT [0:0]
:OUTPUT      ACCEPT [0:0]
:POSTROUTING ACCEPT [0:0]
-A OUTPUT -p udp --dport 53 -j REDIRECT --to-ports 53
-A OUTPUT -p tcp --dport 53 -j REDIRECT --to-ports 53
-A OUTPUT -m owner --uid-owner tor -j RETURN
-A OUTPUT -d 127.0.0.0/8    -j RETURN
-A OUTPUT -d 192.168.0.0/16 -j RETURN
-A OUTPUT -d 10.0.0.0/8     -j RETURN
-A OUTPUT -d 172.16.0.0/12  -j RETURN
-A OUTPUT -p tcp -j REDIRECT --to-ports 9040
COMMIT
"""

# nft backend filter: INPUT DROP, ICMP blocked, NTP blocked,
# DoT/QUIC/DoH blocked. ipv6-icmp handled via native nft.
_FILTER_NFT = """\
*filter
:INPUT   DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT  ACCEPT [0:0]
-A INPUT  -i lo -j ACCEPT
-A OUTPUT -o lo -j ACCEPT
-A INPUT  -m state --state ESTABLISHED,RELATED -j ACCEPT
-A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
-A OUTPUT -p icmp -j DROP
-A OUTPUT -p udp --dport 123 -j REJECT
-A OUTPUT -p tcp --dport 853 -j REJECT
-A OUTPUT -p udp --dport 853 -j REJECT
-A OUTPUT -p udp --dport 443 -j REJECT
-A OUTPUT -p udp --dport 53 -d 127.0.0.1 -j ACCEPT
-A OUTPUT -p tcp --dport 53 -d 127.0.0.1 -j ACCEPT
-A OUTPUT -p tcp --dport 9040 -j ACCEPT
-A OUTPUT -p tcp --dport 9050 -j ACCEPT
-A OUTPUT -p udp -j REJECT
COMMIT
"""

# legacy backend filter: same as nft + ipv6-icmp blocking + owner matching
_FILTER_LEGACY = """\
*filter
:INPUT   DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT  ACCEPT [0:0]
-A INPUT   -p ipv6-icmp -j DROP
-A OUTPUT  -p ipv6-icmp -j DROP
-A FORWARD -p ipv6-icmp -j DROP
-A INPUT  -i lo -j ACCEPT
-A OUTPUT -o lo -j ACCEPT
-A INPUT  -m state --state ESTABLISHED,RELATED -j ACCEPT
-A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
-A OUTPUT -m owner --uid-owner tor -j ACCEPT
-A OUTPUT -p icmp -j DROP
-A OUTPUT -p udp --dport 123 -j REJECT
-A OUTPUT -p tcp --dport 853 -j REJECT
-A OUTPUT -p udp --dport 853 -j REJECT
-A OUTPUT -p udp --dport 443 -j REJECT
-A OUTPUT -p udp --dport 53 -d 127.0.0.1 -j ACCEPT
-A OUTPUT -p tcp --dport 53 -d 127.0.0.1 -j ACCEPT
-A OUTPUT -p tcp --dport 9040 -j ACCEPT
-A OUTPUT -p tcp --dport 9050 -j ACCEPT
-A OUTPUT -p udp -j REJECT
COMMIT
"""

def write_rules() -> Path:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    RULES_FILE.write_text(_RULES_NAT + "\n" + (_FILTER_NFT if Backend.is_nft else _FILTER_LEGACY))
    ok(f"Rules written → {RULES_FILE}")
    return RULES_FILE

# ── Pre-start lockdown ────────────────────────────────────────────────────────

def apply_prelockdown():
    """
    Block cleartext DNS and all non-loopback TCP before Tor starts.
    Closes the leak window between resolv.conf change and full rules going up.
    Tor's own traffic (uid=tor) is exempt so it can reach the network to bootstrap.
    """
    run(f"{Backend.cmd} -I OUTPUT 1 -p udp --dport 53 ! -d 127.0.0.1 -j DROP", check=False)
    run(f"{Backend.cmd} -I OUTPUT 2 -p tcp --dport 53 ! -d 127.0.0.1 -j DROP", check=False)

def remove_prelockdown():
    """Remove the temporary pre-start lockdown rules (superseded by full rules)."""
    run(f"{Backend.cmd} -D OUTPUT -p udp --dport 53 ! -d 127.0.0.1 -j DROP 2>/dev/null",
        check=False)
    run(f"{Backend.cmd} -D OUTPUT -p tcp --dport 53 ! -d 127.0.0.1 -j DROP 2>/dev/null",
        check=False)

# ── nft-only helpers ──────────────────────────────────────────────────────────

def nft_block_ipv6():
    """Block IPv6 / IPv6-ICMP via native nft (nftables backend only)."""
    info("Blocking IPv6 via nft...")
    run("nft list table inet filter 2>/dev/null || nft add table inet filter", check=False)
    run("nft add chain inet filter output { type filter hook output priority 0 \\; }", check=False)
    run("nft add rule  inet filter output meta l4proto ipv6-icmp drop", check=False)
    run("nft add rule  inet filter output ip6 version 6 drop",          check=False)
    ok("IPv6 blocked via nft")

def nft_ensure_tor_exemption():
    """
    Fallback: some kernel/nft combos reject --uid-owner in nat via iptables-restore.
    If the rule didn't stick, inject an equivalent exemption via native nft.
    """
    r = run("iptables-nft -t nat -L OUTPUT -n | grep -i owner", check=False)
    if r.returncode == 0 and r.stdout.strip():
        return
    warn("Owner rule missing from nat table; injecting via native nft...")
    uid = run("id -u tor 2>/dev/null", check=False)
    if uid.returncode != 0 or not uid.stdout.strip():
        err("Cannot resolve 'tor' uid — Tor traffic may loop!")
        return
    run(f"nft insert rule ip nat output meta skuid {uid.stdout.strip()} return 2>/dev/null || true",
        check=False)
    ok(f"Tor exemption injected (uid {uid.stdout.strip()})")

# ── Hardening ─────────────────────────────────────────────────────────────────

def harden():
    """
    Apply system hardening for the session:
    - Kernel sysctl parameters
    - Strict INPUT DROP firewall policy
    - Disable swap (prevent sensitive data paging to disk)
    - Randomise hostname (prevent mDNS/DHCP deanonymisation)
    - Set timezone to UTC (prevent timezone-based fingerprinting)
    """
    info("Applying system hardening...")
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    state: dict = {}

    # 1. Sysctl hardening — save originals, apply hardened values
    for param, val in _SYSCTL_HARDENING.items():
        r = run(f"sysctl -n {param} 2>/dev/null", check=False)
        if r.returncode == 0:
            state[f"sysctl_{param}"] = r.stdout.strip()
        run(f"sysctl -w {param}={val} >/dev/null 2>&1", check=False)
    ok("Kernel parameters hardened")

    # 2. Disable swap — sensitive data (creds, keys, decrypted traffic) can page to disk
    swap = run("swapon --show --noheadings 2>/dev/null", check=False)
    if swap.stdout.strip():
        state['swap_was_active'] = True
        run("swapoff -a 2>/dev/null", check=False)
        ok("Swap disabled")
    else:
        state['swap_was_active'] = False

    # 3. Randomise hostname — leaks through mDNS, DHCP, NetBIOS, some app-layer protocols
    r = run("hostname", check=False)
    state['hostname'] = r.stdout.strip() if r.returncode == 0 else ""
    rnd = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
    new_hostname = f"host-{rnd}"
    run(f"hostnamectl set-hostname {new_hostname} 2>/dev/null", check=False)
    ok(f"Hostname → {new_hostname}")

    # 4. Set timezone to UTC — local timezone is a deanonymisation data point
    r = run("timedatectl show --property=Timezone --value 2>/dev/null", check=False)
    state['timezone'] = r.stdout.strip() if r.returncode == 0 else "UTC"
    if state['timezone'] != "UTC":
        run("timedatectl set-timezone UTC 2>/dev/null", check=False)
        ok(f"Timezone → UTC  (was {state['timezone']})")

    HARDEN_STATE.write_text(json.dumps(state, indent=2))
    ok("System hardening complete")


def unharden():
    """Restore all pre-session system state saved by harden()."""
    info("Restoring pre-session system state...")

    if not HARDEN_STATE.exists():
        warn("No hardening state found — nothing to restore")
        return

    state = json.loads(HARDEN_STATE.read_text())

    # Restore sysctl
    for param in _SYSCTL_HARDENING:
        key = f"sysctl_{param}"
        if key in state:
            run(f"sysctl -w {param}={state[key]} >/dev/null 2>&1", check=False)
    ok("Kernel parameters restored")

    # Re-enable swap
    if state.get('swap_was_active'):
        run("swapon -a 2>/dev/null", check=False)
        ok("Swap re-enabled")

    # Restore hostname
    if state.get('hostname'):
        run(f"hostnamectl set-hostname {state['hostname']} 2>/dev/null", check=False)
        ok(f"Hostname restored → {state['hostname']}")

    # Restore timezone
    tz = state.get('timezone', '')
    if tz and tz != "UTC":
        run(f"timedatectl set-timezone {tz} 2>/dev/null", check=False)
        ok(f"Timezone restored → {tz}")

    HARDEN_STATE.unlink(missing_ok=True)
    ok("System state restored")

# ── Config generators ─────────────────────────────────────────────────────────

def write_torrc(bridge: Optional[str] = None, pin_guards: bool = False):
    """
    Write torrc with hardened defaults.
    bridge : obfs4 bridge line e.g. "obfs4 1.2.3.4:443 <fingerprint> cert=..."
    pin_guards: minimise guard rotation (reduces guard discovery attack surface)
    """
    torrc = """\
# t0rpoiz0n — auto-generated torrc

User tor

# Stream isolation — separate circuit per client, protocol, destination, and SOCKS auth.
# This prevents cross-application traffic correlation.
SocksPort 9050 IsolateSOCKSAuth IsolateDestAddr IsolateDestPort
TransPort 9040 IsolateClientAddr IsolateClientProtocol IsolateDestAddr IsolateDestPort IsolateSOCKSAuth

DNSPort   53

# Belt-and-suspenders IPv6 disable alongside kernel-level block
ClientUseIPv6 0

DataDirectory  /var/lib/tor
CacheDirectory /var/cache/tor

# Minimal logging — no connection metadata written to disk
Log notice syslog
SafeLogging 1
AvoidDiskWrites 1

# Not a relay
ORPort        0
BandwidthRate  1 MB
BandwidthBurst 2 MB
"""

    if bridge:
        torrc += f"\n# Pluggable transport bridge (bypasses DPI)\nUseBridges 1\nBridge {bridge}\n"
        bl = bridge.lower()
        if bl.startswith("obfs4"):
            torrc += "ClientTransportPlugin obfs4 exec /usr/bin/obfs4proxy\n"
        elif bl.startswith("snowflake"):
            torrc += f"ClientTransportPlugin snowflake exec {snowflake_bin()}\n"
        elif bl.startswith("meek"):
            torrc += "ClientTransportPlugin meek_lite exec /usr/bin/obfs4proxy\n"

    if pin_guards:
        # Minimise guard rotation to reduce guard discovery attack surface.
        # NumEntryGuards=1 + long GuardLifetime = same entry guard across sessions.
        torrc += """\

# Guard node pinning — reduces guard discovery / path-bias attacks
UseEntryGuards 1
NumEntryGuards 1
GuardLifetime 12 months
"""

    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    if TORRC.exists():
        run(f"cp {TORRC} {BACKUP_DIR}/torrc.backup", check=False)
    TORRC.write_text(torrc)
    TORRC.chmod(0o644)


_SERVICE = """\
[Unit]
Description=ArxOS AnonKit Tor Transparent Proxy
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/tor -f /etc/tor/torrc
ExecReload=/bin/kill -HUP $MAINPID
KillSignal=SIGINT
TimeoutSec=60
Restart=on-failure
RestartSec=5
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
"""

def write_service():
    SERVICE.write_text(_SERVICE)
    SERVICE.chmod(0o644)
    run("systemctl daemon-reload")
    run("setcap 'cap_net_bind_service=+ep' /usr/bin/tor")

# ── Bootstrap helpers ─────────────────────────────────────────────────────────

def wait_for_dns_port(timeout: int = 45) -> bool:
    """
    Poll until Tor's DNSPort on :53 is confirmed listening.
    Returns True when ready, False on timeout.
    This ensures DNS queries can't escape cleartext before Tor is actually ready.
    """
    for _ in range(timeout):
        r = run("ss -ulnp 2>/dev/null | grep -q ':53'", check=False)
        if r.returncode == 0:
            return True
        time.sleep(1)
    return False

# ── First-time setup ──────────────────────────────────────────────────────────

def setup(bridge: Optional[str] = None, pin_guards: bool = False) -> bool:
    print(f"\n{C.CYAN}{'='*60}\n[*] First-Time Setup\n{'='*60}{C.RESET}\n")

    info("Checking dependencies...")
    if not check_deps():
        return False
    ok("Dependencies OK")

    for d in (DATA_DIR, BACKUP_DIR, Path("/etc/t0rpoiz0n")):
        d.mkdir(parents=True, exist_ok=True)
        d.chmod(0o755)

    detect_backend()
    write_rules()

    info("Writing torrc...")
    write_torrc(bridge=bridge, pin_guards=pin_guards)
    run("mkdir -p /var/lib/tor /var/cache/tor",         check=False)
    run("chown -R tor:tor /var/lib/tor /var/cache/tor", check=False)
    ok("Tor config written")

    info("Installing systemd service...")
    write_service()
    ok("Service installed")

    print(f"\n{C.GREEN}[✓] Setup complete!{C.RESET}\n")
    return True

# ── Proxy lifecycle ───────────────────────────────────────────────────────────

def start(bridge: Optional[str] = None, pin_guards: bool = False) -> bool:
    print(f"\n{C.CYAN}{'='*60}\n[*] Starting Transparent Proxy\n{'='*60}{C.RESET}\n")

    detect_backend()
    run("systemctl stop tor-t0rpoiz0n.service 2>/dev/null", check=False)
    run("killall tor 2>/dev/null",                          check=False)
    time.sleep(1)

    # Harden kernel, swap, hostname, timezone before anything hits the network
    harden()

    info("Disabling IPv6...")
    run("sysctl -w net.ipv6.conf.all.disable_ipv6=1 >/dev/null 2>&1")
    run("sysctl -w net.ipv6.conf.default.disable_ipv6=1 >/dev/null 2>&1")
    ok("IPv6 disabled")

    # Set DNS to localhost and apply pre-lockdown to close the startup leak window
    run(f"cp /etc/resolv.conf {BACKUP_DIR}/resolv.conf.backup", check=False)
    Path("/etc/resolv.conf").write_text("nameserver 127.0.0.1\n")
    ok("DNS → 127.0.0.1")
    apply_prelockdown()

    # Write torrc with session options, then start Tor
    info("Writing torrc...")
    write_torrc(bridge=bridge, pin_guards=pin_guards)
    run("chown -R tor:tor /var/lib/tor /var/cache/tor", check=False)

    info("Starting Tor service...")
    r = run("systemctl start tor-t0rpoiz0n.service", check=False)
    if r.returncode != 0:
        err("Tor failed to start")
        run("journalctl -u tor-t0rpoiz0n.service -n 20 --no-pager", check=False)
        remove_prelockdown()
        return False
    time.sleep(3)
    ok("Tor service started")

    # Wait for DNSPort to actually be listening before opening the firewall
    info("Waiting for Tor DNSPort to be ready...")
    if wait_for_dns_port():
        ok("Tor DNSPort listening on :53")
    else:
        warn("Tor DNSPort not confirmed ready — DNS may briefly fail")

    # Apply full iptables rules (removes pre-lockdown rules in the process)
    info("Applying iptables rules...")
    for cmd in (f"{Backend.cmd} -F", f"{Backend.cmd} -X",
                f"{Backend.cmd} -t nat -F", f"{Backend.cmd} -t nat -X"):
        run(cmd, check=False)

    write_rules()
    try:
        run(f"{Backend.restore} < {RULES_FILE}")
        ok(f"Rules applied via {Backend.cmd}")
    except subprocess.CalledProcessError:
        err("Failed to apply iptables rules")
        return False

    if Backend.is_nft:
        nft_block_ipv6()
        nft_ensure_tor_exemption()

    ok("Transparent proxy active")

    if bridge:
        ok(f"Bridge active: {bridge[:40]}...")
    if pin_guards:
        ok("Guard node pinning enabled")

    print(f"\n{C.YELLOW}Browser tip:{C.RESET} use Tor Browser, or in Firefox set:")
    print("  network.trr.mode = 5  |  http3.enabled = false  |  peerconnection.enabled = false\n")
    return True


def stop():
    print(f"\n{C.CYAN}{'='*60}\n[*] Stopping Transparent Proxy\n{'='*60}{C.RESET}\n")

    detect_backend()
    run("systemctl stop tor-t0rpoiz0n.service", check=False)
    ok("Tor stopped")

    for cmd in (f"{Backend.cmd} -F", f"{Backend.cmd} -X",
                f"{Backend.cmd} -t nat -F", f"{Backend.cmd} -t nat -X",
                f"{Backend.cmd} -P INPUT ACCEPT",
                f"{Backend.cmd} -P FORWARD ACCEPT",
                f"{Backend.cmd} -P OUTPUT ACCEPT"):
        run(cmd, check=False)
    ok("iptables flushed")

    if Backend.is_nft:
        run("nft delete table inet filter 2>/dev/null", check=False)

    run("sysctl -w net.ipv6.conf.all.disable_ipv6=0 >/dev/null 2>&1",     check=False)
    run("sysctl -w net.ipv6.conf.default.disable_ipv6=0 >/dev/null 2>&1", check=False)
    ok("IPv6 re-enabled")

    backup = BACKUP_DIR / "resolv.conf.backup"
    if backup.exists():
        run(f"cp {backup} /etc/resolv.conf", check=False)
        ok("DNS restored")

    # Restore all hardening changes
    unharden()

    print(f"\n{C.GREEN}[✓] Clearnet restored{C.RESET}\n")


def new_circuit() -> bool:
    info("Restarting Tor for new circuit...")
    r = run("systemctl restart tor-t0rpoiz0n.service", check=False)
    if r.returncode != 0:
        err("Restart failed")
        run("journalctl -u tor-t0rpoiz0n.service -n 10 --no-pager", check=False)
        return False
    time.sleep(5)
    if run("systemctl is-active tor-t0rpoiz0n.service", check=False).stdout.strip() != "active":
        err("Service not active after restart")
        run("journalctl -u tor-t0rpoiz0n.service -n 10 --no-pager", check=False)
        return False
    ok("New circuit established")
    status()
    return True


def status() -> bool:
    print(f"\n{C.CYAN}{'='*60}\n[*] Tor Status\n{'='*60}{C.RESET}\n")

    detect_backend()

    if run("systemctl is-active tor-t0rpoiz0n.service", check=False).stdout.strip() != "active":
        err("Tor service: Inactive")
        return False
    ok("Tor service: Active")

    # Show active hardening state
    if HARDEN_STATE.exists():
        try:
            state = json.loads(HARDEN_STATE.read_text())
            hostname = run("hostname", check=False).stdout.strip()
            tz       = run("timedatectl show --property=Timezone --value 2>/dev/null",
                           check=False).stdout.strip()
            swap_out = run("swapon --show --noheadings 2>/dev/null", check=False).stdout.strip()
            ok(f"Hardening: active  ·  hostname={hostname}  ·  tz={tz}  ·  "
               f"swap={'off' if not swap_out else 'on'}")
        except Exception:
            pass

    r = run("curl -s --socks5 127.0.0.1:9050 https://check.torproject.org/api/ip", check=False)
    if r.returncode == 0:
        try:
            data = json.loads(r.stdout)
            if data.get('IsTor'):
                ok(f"Connected through Tor  ·  exit IP: {data.get('IP', '?')}")
            else:
                err("NOT going through Tor!")
        except json.JSONDecodeError:
            warn("Could not parse Tor check response")
    else:
        warn("Could not reach check.torproject.org")

    bs = run("journalctl -u tor-t0rpoiz0n.service -n 3 --no-pager | grep -i bootstrap",
             check=False)
    if bs.stdout.strip():
        print(f"\n{C.CYAN}Bootstrap:{C.RESET}\n{bs.stdout.strip()}")

    stats = run(f"{Backend.cmd} -L -n -v | head -20", check=False)
    if stats.returncode == 0:
        print(f"\n{C.CYAN}iptables ({Backend.cmd}):{C.RESET}\n{stats.stdout}")

    print(f"{C.YELLOW}Tip:{C.RESET} run  sudo anonkit --safe  for a full leak + VPN→Tor safety test\n")
    return True


def detect_vpn():
    """(active, kind, iface): a tun/WireGuard tunnel that could carry traffic before Tor."""
    r = run("ip -o link show up 2>/dev/null", check=False)
    for m in re.finditer(r'^\d+:\s+([^:@\s]+)', r.stdout or "", re.M):
        i = m.group(1).strip(); low = i.lower()
        if low.startswith(("tun", "tap", "wg", "nordlynx", "proton", "mullvad", "azwg")):
            kind = "WireGuard" if low.startswith(("wg", "nordlynx", "proton", "mullvad", "azwg")) else "OpenVPN/tun"
            return True, kind, i
    return False, "", ""


def network_safety() -> bool:
    """Deep, user-facing 'am I actually safe?' test — routing, leaks, kill-switch, ISP visibility."""
    print(f"\n{C.CYAN}{'='*60}\n[*] Network Safety Test\n{'='*60}{C.RESET}\n")
    detect_backend()
    safe = True

    if run("systemctl is-active tor-t0rpoiz0n.service", check=False).stdout.strip() != "active":
        err("Tor service is not active — you are NOT protected. Start it: sudo anonkit -s")
        return False

    # 1. SOCKS path exits via Tor
    r = run("curl -s --max-time 12 --socks5-hostname 127.0.0.1:9050 https://check.torproject.org/api/ip", check=False)
    try:
        d = json.loads(r.stdout)
        ok(f"Tor SOCKS path confirmed · exit {d.get('IP','?')}") if d.get("IsTor") else (err("SOCKS path is NOT exiting via Tor"), )
        if not d.get("IsTor"): safe = False
    except Exception:
        warn("Could not reach check.torproject.org over SOCKS"); safe = False

    # 2. Default route (transparent proxy) is captured by Tor — the real leak test
    r2 = run("curl -s --max-time 12 https://check.torproject.org/api/ip", check=False)
    try:
        d2 = json.loads(r2.stdout)
        if d2.get("IsTor"): ok(f"Default route captured by Tor — no clearnet leak · {d2.get('IP','?')}")
        else: err(f"LEAK — clearnet traffic exits as {d2.get('IP','?')}; your real IP is exposed"); safe = False
    except Exception:
        warn("Could not verify transparent-proxy capture")

    # 3. DNS leak
    try: resolv = Path("/etc/resolv.conf").read_text()
    except Exception: resolv = ""
    if "127.0.0.1" in resolv or "::1" in resolv: ok("DNS resolves locally through Tor — no DNS leak")
    else: err("DNS may leak — /etc/resolv.conf is not pointed at 127.0.0.1"); safe = False

    # 4. IPv6 leak
    v6  = run("sysctl -n net.ipv6.conf.all.disable_ipv6 2>/dev/null", check=False).stdout.strip()
    v6r = run("ip -6 route show default 2>/dev/null", check=False).stdout.strip()
    if v6 == "1" or not v6r: ok("IPv6 disabled/blocked — no IPv6 leak")
    else: err("IPv6 has a default route and may leak outside Tor"); safe = False

    # 5. Kill-switch (fail-closed)
    pol = run(f"{Backend.cmd} -L OUTPUT -n 2>/dev/null | head -1", check=False).stdout
    if "policy DROP" in pol: ok("Kill-switch active — OUTPUT defaults to DROP (fail-closed if Tor dies)")
    else: warn("OUTPUT policy is not DROP — a Tor crash could briefly leak traffic")

    # 6. ISP visibility / VPN→Tor posture
    vpn, kind, iface = detect_vpn()
    try: bridged = "UseBridges 1" in TORRC.read_text()
    except Exception: bridged = False
    print(f"\n{C.CYAN}ISP visibility:{C.RESET}")
    if vpn:
        ok(f"VPN tunnel up ({kind} · {iface}) → VPN→Tor: your ISP sees the VPN, not Tor. Ideal.")
    elif bridged:
        ok("obfs4 bridge in use → Tor traffic is disguised from your ISP's DPI.")
    else:
        warn("No VPN and no bridge — your ISP can SEE that you connect to Tor (not what you do).")
        print(f"{C.YELLOW}    Tip:{C.RESET} the safe order is VPN → Tor. Connect a trusted VPN FIRST, then")
        print( "         start AnonKit: your ISP then only sees encrypted VPN traffic, never Tor.")
        print( "         (Alternative without a VPN: an obfs4 bridge —  sudo anonkit -s -b 'obfs4 ...')")

    # 7. MAC posture
    ifc = default_interface()
    if ifc:
        mac = run(f"cat /sys/class/net/{ifc}/address 2>/dev/null", check=False).stdout.strip()
        info(f"{ifc} MAC: {mac}  ·  spoof with -m before joining untrusted Wi-Fi")

    print(f"\n{C.CYAN}Browser:{C.RESET} this test can't see WebRTC/canvas fingerprinting — use a hardened")
    print( "         browser (Tor Browser / the ARXOS browser) for anonymous web sessions.\n")

    if safe:
        print(f"{C.GREEN}{'='*60}\n[✓] VERDICT: traffic is routed through Tor and sealed — you are SAFE.\n{'='*60}{C.RESET}\n")
    else:
        print(f"{C.RED}{'='*60}\n[✗] VERDICT: AT RISK — fix the red items above before trusting this link.\n{'='*60}{C.RESET}\n")
    return safe

# ── Snowflake bridge (free, no account, hides Tor from the ISP over WebRTC) ─────
SNOWFLAKE_BRIDGE = (
    "snowflake 192.0.2.3:80 2B280B23E1107BB62ABFC40DDCC8824814F80A72 "
    "fingerprint=2B280B23E1107BB62ABFC40DDCC8824814F80A72 "
    "url=https://1098762253.rsc.cdn77.org/ fronts=www.cdn77.com,www.phpmyadmin.net "
    "ice=stun:stun.l.google.com:19302,stun:stun.antisip.com:3478,stun:stun.epygi.com:3478,"
    "stun:stun.sonetel.com:3478,stun:stun.voipgate.com:3478 utls-imitate=hellorandomizedalpn")

def snowflake_bin() -> str:
    for p in ("/usr/bin/snowflake-client", "/usr/bin/snowflake",
              os.path.expanduser("~/go/bin/snowflake-client")):
        if os.path.exists(p): return p
    r = run("command -v snowflake-client snowflake 2>/dev/null", check=False)
    out = (r.stdout or "").strip().splitlines()
    return out[0] if out else "/usr/bin/snowflake-client"

def ensure_snowflake() -> bool:
    if os.path.exists(snowflake_bin()) or run("command -v snowflake-client", check=False).returncode == 0:
        return True
    info("Installing the Snowflake client (one-time)...")
    for cmd in ("pacman -S --noconfirm --needed snowflake",
                "yay -S --noconfirm --needed snowflake-bin",
                "yay -S --noconfirm --needed snowflake",
                "GOBIN=/usr/bin go install gitlab.torproject.org/tpo/anti-censorship/"
                "pluggable-transports/snowflake/v2/client@latest"):
        run(cmd, check=False)
        if run("command -v snowflake-client", check=False).returncode == 0 or os.path.exists(snowflake_bin()):
            ok("snowflake-client installed"); return True
    err("could not install snowflake-client (try: yay -S snowflake)")
    return False


# ── Entry point ───────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(
        description='ArxOS AnonKit - Tor transparent proxy, MAC spoofing, VPN->Tor, Snowflake',
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument('-s', '--start',       action='store_true', help='Start transparent proxy')
    ap.add_argument('-k', '--stop',        action='store_true', help='Stop transparent proxy')
    ap.add_argument('-r', '--restart',     action='store_true', help='New Tor circuit')
    ap.add_argument('-c', '--check',       action='store_true', help='Check status')
    ap.add_argument('-m', '--mac',         action='store_true', help='Spoof MAC address')
    ap.add_argument('-v', '--vendor',      metavar='VENDOR',    help='MAC vendor (e.g. apple)')
    ap.add_argument('-i', '--interface',   metavar='IFACE',     help='Network interface')
    ap.add_argument('-b', '--bridge',      metavar='BRIDGE',    help='Tor bridge line (obfs4 etc.)')
    ap.add_argument('--pin-guards',        action='store_true', help='Pin entry guards (reduces guard discovery attacks)')
    ap.add_argument('--safe',              action='store_true', help='Deep network safety + leak test (real IP, DNS, IPv6, VPN→Tor, kill-switch)')
    ap.add_argument('--snowflake',         action='store_true', help='Start Tor over a Snowflake bridge (free, no account) to hide Tor from your ISP')
    ap.add_argument('--setup',             action='store_true', help='Re-run first-time setup')
    args = ap.parse_args()

    banner()
    require_root()

    if args.snowflake:
        if not ensure_snowflake():
            sys.exit(1)
        if not args.bridge:
            args.bridge = SNOWFLAKE_BRIDGE
        args.start = True
        info("Snowflake bridge selected - hiding Tor from your ISP (free, no account, over WebRTC)")

    if args.setup or not DATA_DIR.exists():
        if not setup(bridge=args.bridge, pin_guards=args.pin_guards):
            sys.exit(1)
        if args.setup:
            sys.exit(0)

    if args.mac:
        iface = args.interface or default_interface()
        if not iface:
            err("Could not detect network interface")
            sys.exit(1)
        change_mac(iface, args.vendor)
        if not args.start:
            sys.exit(0)

    if args.start:
        sys.exit(0 if start(bridge=args.bridge, pin_guards=args.pin_guards) else 1)
    elif args.stop:
        stop()
    elif args.restart:
        sys.exit(0 if new_circuit() else 1)
    elif args.check:
        sys.exit(0 if status() else 1)
    elif args.safe:
        sys.exit(0 if network_safety() else 1)
    else:
        ap.print_help()
        print(f"\n{C.CYAN}Examples:{C.RESET}")
        print("  sudo anonkit -s                    # start")
        print("  sudo anonkit -s -m -v apple        # start + spoof MAC")
        print("  sudo anonkit -s --pin-guards        # start with guard pinning")
        print("  sudo anonkit -s -b 'obfs4 ...'     # start with bridge")
        print("  sudo anonkit -c                    # check status")
        print("  sudo anonkit --safe                # full leak + VPN→Tor safety test")
        print("  sudo anonkit -r                    # new identity")
        print(f"  sudo anonkit -k                    # stop\n")
        print(f"{C.CYAN}Vendors:{C.RESET} {', '.join(sorted(MAC_VENDORS))}\n")

if __name__ == "__main__":
    main()
