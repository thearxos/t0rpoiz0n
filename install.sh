#!/usr/bin/env bash
# ArxOS AnonKit installer
D=$(cd "$(dirname "$0")" && pwd); S=""; [ "$(id -u)" -ne 0 ] && S=sudo
$S install -Dm755 "$D/anonkit.py" /usr/local/bin/anonkit
$S ln -sf /usr/local/bin/anonkit /usr/local/bin/t0rpoiz0n   # compat for the tor-t0rpoiz0n service + callers
[ -f "$D/t0r-gui" ]      && $S install -m755 "$D/t0r-gui"      /usr/local/bin/t0r-gui
[ -f "$D/arxos-vpntor" ] && $S install -m755 "$D/arxos-vpntor" /usr/local/bin/arxos-vpntor
$S pacman -S --noconfirm --needed tor iptables macchanger python-gobject gtk3 openvpn polkit >/dev/null 2>&1 || true
echo "ArxOS AnonKit installed"
