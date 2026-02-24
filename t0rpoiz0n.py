#!/usr/bin/env python3
"""
t0rpoiz0n - Tor Transparent Proxy + MAC Spoofing
Author : 0xb0rn3 | oxbv1
Version: 1.1.3
Target : Arch Linux
"""

import os
import sys
import time
import subprocess
import random
import json
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

DATA_DIR   = Path("/usr/share/t0rpoiz0n")
BACKUP_DIR = Path("/var/lib/t0rpoiz0n/backups")
RULES_FILE = DATA_DIR / "iptables.rules"
TORRC      = Path("/etc/tor/torrc")
SERVICE    = Path("/etc/systemd/system/tor-t0rpoiz0n.service")

# ── MAC vendor OUI prefixes ───────────────────────────────────────────────────

MAC_VENDORS = {
    'apple':    '00:03:93', 'asus':     '9C:5C:8E',
    'dell':     '00:06:5B', 'google':   '00:1A:11',
    'hp':       '00:0B:CD', 'huawei':   '00:18:82',
    'lenovo':   '00:21:5C', 'motorola': '00:0A:28',
    'nokia':    '00:19:2D', 'samsung':  '94:51:03',
}

# ── iptables backend state ────────────────────────────────────────────────────

class Backend:
    cmd     = "iptables"
    restore = "iptables-restore"
    is_nft  = False

def detect_backend() -> bool:
    """Probe for the best available iptables backend and update Backend.*."""
    info("Detecting iptables backend...")
    candidates = [
        ("iptables-nft",    "iptables-nft-restore",    True),
        ("iptables-legacy", "iptables-legacy-restore",  False),
        ("iptables",        "iptables-restore",          False),
    ]
    for cmd, restore, is_nft in candidates:
        r = run(f"{cmd} -L -n 2>/dev/null", check=False)
        if r.returncode == 0:
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
   /$$      /$$$$$$                                /$$            /$$$$$$
  | $$     /$$$_  $$                              |__/           /$$$_  $$
 /$$$$$$  | $$$$\ $$  /$$$$$$   /$$$$$$   /$$$$$$  /$$ /$$$$$$$$| $$$$\ $$ /$$$$$$$
|_  $$_/  | $$ $$ $$ /$$__  $$ /$$__  $$ /$$__  $$| $$|____ /$$/| $$ $$ $$| $$__  $$
  | $$    | $$\ $$$$| $$  \__/| $$  \ $$| $$  \ $$| $$   /$$$$/ | $$\ $$$$| $$  \ $$
  | $$ /$$| $$ \ $$$| $$      | $$  | $$| $$  | $$| $$  /$$__/  | $$ \ $$$| $$  | $$
  |  $$$$/|  $$$$$$/| $$      | $$$$$$$/|  $$$$$$/| $$ /$$$$$$$$|  $$$$$$/| $$  | $$
   \___/   \______/ |__/      | $$____/  \______/ |__/|________/ \______/ |__/  |__/
                              | $$
                              |__/
          TOR PROXY & MAC SPOOFING FRAMEWORK  ·  v1.1.3  ·  by oxbv1
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
        "ip route | grep default | awk '{print $5}'",
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

_RULES_NAT = """\
*nat
:PREROUTING  ACCEPT [0:0]
:INPUT       ACCEPT [0:0]
:OUTPUT      ACCEPT [0:0]
:POSTROUTING ACCEPT [0:0]
-A OUTPUT -p udp --dport 53  -j REDIRECT --to-ports 53
-A OUTPUT -p tcp --dport 53  -j REDIRECT --to-ports 53
-A OUTPUT -p tcp --dport 853 -j REJECT
-A OUTPUT -p udp --dport 853 -j REJECT
-A OUTPUT -p udp --dport 443 -j REJECT
-A OUTPUT -m owner --uid-owner tor -j RETURN
-A OUTPUT -d 127.0.0.0/8    -j RETURN
-A OUTPUT -d 192.168.0.0/16 -j RETURN
-A OUTPUT -d 10.0.0.0/8     -j RETURN
-A OUTPUT -d 172.16.0.0/12  -j RETURN
-A OUTPUT -p tcp -j REDIRECT --to-ports 9040
COMMIT
"""

# nft backend: ipv6-icmp handled via native nft; no owner match needed in filter
_FILTER_NFT = """\
*filter
:INPUT   ACCEPT [0:0]
:FORWARD ACCEPT [0:0]
:OUTPUT  ACCEPT [0:0]
-A INPUT  -i lo -j ACCEPT
-A OUTPUT -o lo -j ACCEPT
-A INPUT  -m state --state ESTABLISHED,RELATED -j ACCEPT
-A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
-A OUTPUT -p udp --dport 53 -d 127.0.0.1 -j ACCEPT
-A OUTPUT -p tcp --dport 53 -d 127.0.0.1 -j ACCEPT
-A OUTPUT -p tcp --dport 9040 -j ACCEPT
-A OUTPUT -p tcp --dport 9050 -j ACCEPT
-A OUTPUT -p udp -j REJECT
COMMIT
"""

# legacy backend: full owner matching and ipv6-icmp blocking supported
_FILTER_LEGACY = """\
*filter
:INPUT   ACCEPT [0:0]
:FORWARD ACCEPT [0:0]
:OUTPUT  ACCEPT [0:0]
-A INPUT   -p ipv6-icmp -j DROP
-A OUTPUT  -p ipv6-icmp -j DROP
-A FORWARD -p ipv6-icmp -j DROP
-A INPUT  -i lo -j ACCEPT
-A OUTPUT -o lo -j ACCEPT
-A INPUT  -m state --state ESTABLISHED,RELATED -j ACCEPT
-A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
-A OUTPUT -m owner --uid-owner tor -j ACCEPT
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
    Some kernel/nft combos reject --uid-owner in the nat table via iptables-restore.
    If the rule didn't stick, inject an equivalent exemption via native nft.
    """
    r = run("iptables-nft -t nat -L OUTPUT -n | grep -i owner", check=False)
    if r.returncode == 0 and r.stdout.strip():
        return  # rule present — nothing to do

    warn("Owner rule missing from nat table; injecting via native nft...")
    uid = run("id -u tor 2>/dev/null", check=False)
    if uid.returncode != 0 or not uid.stdout.strip():
        err("Cannot resolve 'tor' uid — Tor traffic may loop!")
        return
    run(f"nft insert rule ip nat output meta skuid {uid.stdout.strip()} return 2>/dev/null || true",
        check=False)
    ok(f"Tor exemption injected (uid {uid.stdout.strip()})")

# ── Config generators ─────────────────────────────────────────────────────────

_TORRC = """\
# t0rpoiz0n — auto-generated torrc

User tor

SocksPort 9050
TransPort 9040 IsolateClientAddr IsolateClientProtocol IsolateDestAddr IsolateDestPort
DNSPort   53

DataDirectory  /var/lib/tor
CacheDirectory /var/cache/tor

Log notice syslog
AvoidDiskWrites 1

ORPort        0
BandwidthRate  1 MB
BandwidthBurst 2 MB
"""

_SERVICE = """\
[Unit]
Description=t0rpoiz0n Tor Transparent Proxy
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

def write_torrc():
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    if TORRC.exists():
        run(f"cp {TORRC} {BACKUP_DIR}/torrc.backup", check=False)
    TORRC.write_text(_TORRC)
    TORRC.chmod(0o644)

def write_service():
    SERVICE.write_text(_SERVICE)
    SERVICE.chmod(0o644)
    run("systemctl daemon-reload")
    run("setcap 'cap_net_bind_service=+ep' /usr/bin/tor")

# ── First-time setup ──────────────────────────────────────────────────────────

def setup() -> bool:
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
    write_torrc()
    run("mkdir -p /var/lib/tor /var/cache/tor",         check=False)
    run("chown -R tor:tor /var/lib/tor /var/cache/tor", check=False)
    ok("Tor config written")

    info("Installing systemd service...")
    write_service()
    ok("Service installed")

    print(f"\n{C.GREEN}[✓] Setup complete!{C.RESET}\n")
    return True

# ── Proxy lifecycle ───────────────────────────────────────────────────────────

def start() -> bool:
    print(f"\n{C.CYAN}{'='*60}\n[*] Starting Transparent Proxy\n{'='*60}{C.RESET}\n")

    detect_backend()
    run("systemctl stop tor-t0rpoiz0n.service 2>/dev/null", check=False)
    run("killall tor 2>/dev/null",                          check=False)
    time.sleep(1)

    info("Disabling IPv6...")
    run("sysctl -w net.ipv6.conf.all.disable_ipv6=1 >/dev/null 2>&1")
    run("sysctl -w net.ipv6.conf.default.disable_ipv6=1 >/dev/null 2>&1")
    ok("IPv6 disabled")

    run(f"cp /etc/resolv.conf {BACKUP_DIR}/resolv.conf.backup", check=False)
    Path("/etc/resolv.conf").write_text("nameserver 127.0.0.1\n")
    ok("DNS → 127.0.0.1")

    info("Starting Tor service...")
    r = run("systemctl start tor-t0rpoiz0n.service", check=False)
    if r.returncode != 0:
        err("Tor failed to start")
        run("journalctl -u tor-t0rpoiz0n.service -n 20 --no-pager", check=False)
        return False
    time.sleep(3)
    ok("Tor service started")

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

    info("Waiting for Tor to bootstrap...")
    for _ in range(30):
        if run("systemctl is-active tor-t0rpoiz0n.service", check=False).stdout.strip() == "active":
            time.sleep(2)
            break
        time.sleep(1)
    ok("Transparent proxy active")

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

    bs = run("journalctl -u tor-t0rpoiz0n.service -n 3 --no-pager | grep -i bootstrap", check=False)
    if bs.stdout.strip():
        print(f"\n{C.CYAN}Bootstrap:{C.RESET}\n{bs.stdout.strip()}")

    stats = run(f"{Backend.cmd} -L -n -v | head -15", check=False)
    if stats.returncode == 0:
        print(f"\n{C.CYAN}iptables ({Backend.cmd}):{C.RESET}\n{stats.stdout}")

    print(f"{C.YELLOW}Tip:{C.RESET} verify as a regular user — curl https://check.torproject.org/api/ip\n")
    return True

# ── Entry point ───────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(
        description='t0rpoiz0n — Tor transparent proxy + MAC spoofing',
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument('-s', '--start',     action='store_true', help='Start transparent proxy')
    ap.add_argument('-k', '--stop',      action='store_true', help='Stop transparent proxy')
    ap.add_argument('-r', '--restart',   action='store_true', help='New Tor circuit')
    ap.add_argument('-c', '--check',     action='store_true', help='Check status')
    ap.add_argument('-m', '--mac',       action='store_true', help='Spoof MAC address')
    ap.add_argument('-v', '--vendor',    metavar='VENDOR',    help='MAC vendor (e.g. apple)')
    ap.add_argument('-i', '--interface', metavar='IFACE',     help='Network interface')
    ap.add_argument('--setup',           action='store_true', help='Re-run first-time setup')
    args = ap.parse_args()

    banner()
    require_root()

    if args.setup or not DATA_DIR.exists():
        if not setup():
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
        sys.exit(0 if start() else 1)
    elif args.stop:
        stop()
    elif args.restart:
        sys.exit(0 if new_circuit() else 1)
    elif args.check:
        sys.exit(0 if status() else 1)
    else:
        ap.print_help()
        print(f"\n{C.CYAN}Examples:{C.RESET}")
        print("  sudo t0rpoiz0n -s              # start")
        print("  sudo t0rpoiz0n -s -m -v apple  # start + spoof MAC")
        print("  sudo t0rpoiz0n -c              # check status")
        print("  sudo t0rpoiz0n -r              # new identity")
        print(f"  sudo t0rpoiz0n -k              # stop\n")
        print(f"{C.CYAN}Vendors:{C.RESET} {', '.join(sorted(MAC_VENDORS))}\n")

if __name__ == "__main__":
    main()
