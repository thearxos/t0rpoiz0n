#!/usr/bin/env bash
set -e; D="$(cd "$(dirname "$0")" && pwd)"; S=""; [ "$(id -u)" -ne 0 ] && S=sudo
$S install -Dm755 "$D/t0rpoiz0n.py"      /usr/local/bin/t0rpoiz0n
$S install -Dm755 "$D/t0rctl"            /usr/local/bin/t0rctl
$S install -Dm755 "$D/t0r-gui"           /usr/local/bin/t0r-gui
$S install -Dm644 "$D/arxos-anon.desktop" /usr/share/applications/arxos-anon.desktop
for p in tor iptables macchanger yad; do command -v "$p" >/dev/null 2>&1 || $S pacman -S --noconfirm --needed "$p" >/dev/null 2>&1 || true; done
echo "t0rpoiz0n + t0rctl (TUI) + t0r-gui (GUI) + panel launcher installed"

# ---- ArxOS-AnonKit GUI + VPN->Tor engine ----
_S=""; [ "$(id -u)" -ne 0 ] && _S=sudo
_D2="$(cd "$(dirname "$0")" && pwd)"
[ -f "$_D2/t0r-gui" ]      && $_S install -m755 "$_D2/t0r-gui"      /usr/local/bin/t0r-gui
[ -f "$_D2/arxos-vpntor" ] && $_S install -m755 "$_D2/arxos-vpntor" /usr/local/bin/arxos-vpntor
$_S pacman -S --noconfirm --needed python-gobject gtk3 openvpn polkit >/dev/null 2>&1 || true
echo "ArxOS-AnonKit GUI installed"
