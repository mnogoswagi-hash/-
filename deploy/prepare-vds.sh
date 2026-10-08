#!/usr/bin/env bash
set -euo pipefail

# Run manually on a dedicated Ubuntu 22.04+/Debian 12+ VDS, after review.
# Installs system prerequisites and creates a NEW dedicated wg-brawl interface.
# It never starts the gateway/bot or adds guessed game ranges or credentials.
if [[ $EUID -ne 0 ]]; then
  printf '%s\n' 'Run this script as root on your VDS.' >&2
  exit 1
fi
if [[ $# -ne 0 ]]; then
  printf '%s\n' 'No positional arguments. Optional WG_PORT, WG_CLIENT_SUBNET, WG_GATEWAY_ADDRESS environment settings.' >&2
  exit 1
fi
if [[ -e /etc/wireguard/wg-brawl.conf ]] || { command -v ip >/dev/null && ip link show wg-brawl >/dev/null 2>&1; }; then
  printf '%s\n' 'Existing wg-brawl configuration/interface found; preserving it. Review it manually instead of overwriting.' >&2
  exit 1
fi
if [[ -e /etc/sysctl.d/80-brawl-vpn.conf ]] || [[ -e /etc/tmpfiles.d/brawl-vpn.conf ]]; then
  printf '%s\n' 'Existing Brawl sysctl/tmpfiles setup found; preserving it. Complete and verify those files manually.' >&2
  exit 1
fi
command -v apt-get >/dev/null || { printf '%s\n' 'Only Debian/Ubuntu apt-based VDS systems are supported.' >&2; exit 1; }
command -v python3 >/dev/null || { printf '%s\n' 'Install Python 3.10+ first.' >&2; exit 1; }
python3 - <<'PY'
import ipaddress
import json
import os
import shutil
import subprocess
import sys

if sys.version_info < (3, 10):
    raise SystemExit("Python 3.10+ is required; use Ubuntu 22.04+ or Debian 12+")
port = os.environ.get("WG_PORT", "51820")
if not port.isdecimal() or not 1 <= int(port) <= 65535:
    raise SystemExit("WG_PORT must be between 1 and 65535")
network = ipaddress.ip_network(os.environ.get("WG_CLIENT_SUBNET", "10.66.0.0/24"), strict=True)
address = ipaddress.ip_address(os.environ.get("WG_GATEWAY_ADDRESS", "10.66.0.1"))
private = [ipaddress.ip_network(value) for value in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]
if network.version != 4 or not 16 <= network.prefixlen <= 30 or not any(network.subnet_of(value) for value in private):
    raise SystemExit("Use an RFC1918 IPv4 subnet /16 through /30")
if address not in network or address in (network.network_address, network.broadcast_address):
    raise SystemExit("WG_GATEWAY_ADDRESS must be a usable address in WG_CLIENT_SUBNET")
if shutil.which("ip"):
    routes = json.loads(subprocess.run(["ip", "-4", "-j", "route", "show", "table", "main"], check=True, capture_output=True, text=True).stdout)
    for route in routes:
        destination = route.get("dst", "default")
        if destination != "default" and network.overlaps(ipaddress.ip_network(destination, strict=False)):
            raise SystemExit("WG_CLIENT_SUBNET overlaps an existing VDS route; choose a different private subnet")
PY

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install --yes --no-install-recommends wireguard-tools iptables ipset iproute2 python3-venv openssl kmod
for module in wireguard ip_set_hash_ip xt_set nf_conntrack nf_nat; do
  modprobe "$module"
done
# Load the host-selected IPv4/IPv6 iptables backend before service sandboxing.
iptables -w 5 -S >/dev/null
iptables -w 5 -t nat -S >/dev/null
ip6tables -w 5 -S >/dev/null

python3 - <<'PY'
import ipaddress
import os
from pathlib import Path
import subprocess

os.umask(0o077)
directory = Path("/etc/wireguard")
directory.mkdir(mode=0o700, exist_ok=True)
path = directory / "wg-brawl.conf"
network = ipaddress.ip_network(os.environ.get("WG_CLIENT_SUBNET", "10.66.0.0/24"), strict=True)
address = ipaddress.ip_address(os.environ.get("WG_GATEWAY_ADDRESS", "10.66.0.1"))
port = int(os.environ.get("WG_PORT", "51820"))
private = subprocess.run(["wg", "genkey"], check=True, capture_output=True, text=True).stdout.strip()
public = subprocess.run(["wg", "pubkey"], check=True, input=private + "\n", capture_output=True, text=True).stdout.strip()
# Exclusive creation protects an existing configuration, even after a race.
with path.open("x") as file:
    file.write(f"[Interface]\nPrivateKey = {private}\nAddress = {address}/{network.prefixlen}\nListenPort = {port}\nSaveConfig = false\n")
print(f"WG_SERVER_PUBLIC_KEY={public}")
print(f"WG_CLIENT_SUBNET={network}")
print(f"WG_GATEWAY_ADDRESS={address}")
print(f"WireGuard UDP port: {port}; permit this in the VDS provider firewall.")
PY

install -d -m 0700 /etc/brawl-vpn /var/lib/brawl-vpn
if ! id brawl-vpn >/dev/null 2>&1; then
  useradd --system --user-group --home-dir /nonexistent --shell /usr/sbin/nologin brawl-vpn
fi
install -d -o brawl-vpn -g brawl-vpn -m 0700 /var/lib/brawl-vpn-bot
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
printf '%s\n' 'net.ipv4.ip_forward = 1' > /etc/sysctl.d/80-brawl-vpn.conf
sysctl -p /etc/sysctl.d/80-brawl-vpn.conf
install -m 0644 "$script_dir/brawl-vpn-tmpfiles.conf" /etc/tmpfiles.d/brawl-vpn.conf
systemd-tmpfiles --create /etc/tmpfiles.d/brawl-vpn.conf
printf '%s\n' 'Prerequisites prepared. Install the project at /opt/brawl-vpn, fill private bot/gateway env files, then install and start the reviewed systemd units. No services started.'
