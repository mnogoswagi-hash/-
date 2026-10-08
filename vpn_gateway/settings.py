from __future__ import annotations

import base64
import ipaddress
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Mapping


def valid_public_key(value: str) -> str:
    try:
        decoded = base64.b64decode(value, validate=True)
    except ValueError as error:
        raise ValueError("WG_SERVER_PUBLIC_KEY must be a WireGuard public key") from error
    if len(decoded) != 32 or decoded == bytes(32):
        raise ValueError("WG_SERVER_PUBLIC_KEY must be a nonzero 32-byte public key")
    return value


def interface_name(value: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,15}", value):
        raise ValueError("Invalid network interface name")
    return value


def public_endpoint(value: str) -> str:
    # This service deliberately supports IPv4 client profiles only.
    host, separator, port = value.rpartition(":")
    if not separator or not port.isdecimal() or not 1 <= int(port) <= 65535:
        raise ValueError("WG_ENDPOINT must be a public host:UDP-port")
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        if not re.fullmatch(r"(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}", host):
            raise ValueError("WG_ENDPOINT must contain a public IPv4 address or DNS hostname") from None
    else:
        if address.version != 4 or not address.is_global:
            raise ValueError("WG_ENDPOINT must be publicly routable IPv4")
    return value


@dataclass(frozen=True)
class Settings:
    api_token: str = field(repr=False)
    server_public_key: str
    endpoint: str
    game_cidrs: tuple[ipaddress.IPv4Network, ...]
    interface: str = "wg-brawl"
    public_interface: str = "eth0"
    client_subnet: ipaddress.IPv4Network = ipaddress.IPv4Network("10.66.0.0/24")
    gateway_address: ipaddress.IPv4Address = ipaddress.IPv4Address("10.66.0.1")
    database: Path = Path("/var/lib/brawl-vpn/gateway.sqlite")
    reconcile_seconds: int = 15

    def __post_init__(self) -> None:
        if len(self.api_token) < 32 or not self.api_token.isascii() or any(character.isspace() for character in self.api_token) or self.api_token in {"change-me", "replace-me"}:
            raise ValueError("VPN_API_TOKEN must be a random token of at least 32 characters")
        valid_public_key(self.server_public_key)
        public_endpoint(self.endpoint)
        interface_name(self.interface)
        interface_name(self.public_interface)
        if self.interface == self.public_interface:
            raise ValueError("WG_INTERFACE and WG_PUBLIC_INTERFACE must be different")
        private_ranges = (ipaddress.ip_network("10.0.0.0/8"), ipaddress.ip_network("172.16.0.0/12"), ipaddress.ip_network("192.168.0.0/16"))
        if self.client_subnet.version != 4 or not 16 <= self.client_subnet.prefixlen <= 30 or not any(self.client_subnet.subnet_of(network) for network in private_ranges):
            raise ValueError("WG_CLIENT_SUBNET must be an RFC1918 IPv4 subnet between /16 and /30")
        if self.gateway_address not in self.client_subnet or self.gateway_address in (self.client_subnet.network_address, self.client_subnet.broadcast_address):
            raise ValueError("WG_GATEWAY_ADDRESS must be a usable address in WG_CLIENT_SUBNET")
        if not self.game_cidrs:
            raise ValueError("GAME_ALLOWED_CIDRS is required; no game IP addresses are guessed")
        if len(self.game_cidrs) > 128:
            raise ValueError("GAME_ALLOWED_CIDRS supports at most 128 networks")
        for network in self.game_cidrs:
            if network.version != 4 or network.prefixlen < 16 or not network.network_address.is_global or not network.broadcast_address.is_global:
                raise ValueError("GAME_ALLOWED_CIDRS must contain reviewed public IPv4 ranges of /16 or narrower")
        if any(a.overlaps(b) for index, a in enumerate(self.game_cidrs) for b in self.game_cidrs[index + 1:]):
            raise ValueError("GAME_ALLOWED_CIDRS must not overlap")
        if not self.database.is_absolute() or not self.database.name.endswith(".sqlite"):
            raise ValueError("VPN_GATEWAY_DATABASE must be an absolute .sqlite file path")
        if not 1 <= self.reconcile_seconds <= 60:
            raise ValueError("VPN_RECONCILE_SECONDS must be between 1 and 60")

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> Settings:
        env = os.environ if env is None else env
        if env.get("WG_EXCLUSIVE_INTERFACE", "").lower() != "true":
            raise ValueError("Set WG_EXCLUSIVE_INTERFACE=true only for a dedicated gateway-managed interface")
        required = ("VPN_API_TOKEN", "WG_SERVER_PUBLIC_KEY", "WG_ENDPOINT", "WG_PUBLIC_INTERFACE", "GAME_ALLOWED_CIDRS")
        missing = [name for name in required if not env.get(name, "").strip()]
        if missing:
            raise ValueError("Missing gateway settings: " + ", ".join(missing))
        cidrs = tuple(ipaddress.ip_network(value.strip(), strict=True) for value in env["GAME_ALLOWED_CIDRS"].split(",") if value.strip())
        return cls(
            api_token=env["VPN_API_TOKEN"],
            server_public_key=env["WG_SERVER_PUBLIC_KEY"],
            endpoint=env["WG_ENDPOINT"],
            game_cidrs=cidrs,
            interface=env.get("WG_INTERFACE", "wg-brawl"),
            public_interface=env["WG_PUBLIC_INTERFACE"],
            client_subnet=ipaddress.ip_network(env.get("WG_CLIENT_SUBNET", "10.66.0.0/24"), strict=True),
            gateway_address=ipaddress.ip_address(env.get("WG_GATEWAY_ADDRESS", "10.66.0.1")),
            database=Path(env.get("VPN_GATEWAY_DATABASE", "/var/lib/brawl-vpn/gateway.sqlite")),
            reconcile_seconds=int(env.get("VPN_RECONCILE_SECONDS", "15")),
        )
