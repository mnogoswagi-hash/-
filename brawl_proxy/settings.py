from __future__ import annotations

import base64
import ipaddress
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Mapping


# Explicit networks avoid dependence on downloaded GeoIP/GeoSite files.
BLOCKED_NETWORKS = (
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
    "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24",
    "192.88.99.0/24", "192.168.0.0/16", "198.18.0.0/15",
    "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4", "::/0",
)


def public_ipv4(value: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return isinstance(value, ipaddress.IPv4Address) and value.is_global and not value.is_multicast and not value.is_reserved


def hostname(value: str) -> str:
    if not re.fullmatch(r"(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}", value):
        raise ValueError("A valid public DNS hostname is required")
    return value.lower()


def host_port(value: str) -> tuple[str, int]:
    host, separator, port = value.rpartition(":")
    if not separator or not port.isdecimal() or not 1 <= int(port) <= 65535:
        raise ValueError("Expected a public IPv4 or DNS host followed by a port")
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        hostname(host)
    else:
        if not public_ipv4(address):
            raise ValueError("A publicly routable IPv4 endpoint is required")
    return host, int(port)


def reality_key(value: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9_-]{43}=?", value):
        raise ValueError("Reality keys must be base64url-encoded 32-byte values")
    try:
        decoded = base64.b64decode(value.rstrip("=") + "=", altchars=b"-_", validate=True)
    except ValueError:
        raise ValueError("Invalid Reality key encoding") from None
    if len(decoded) != 32 or decoded == bytes(32) or base64.urlsafe_b64encode(decoded).decode().rstrip("=") != value.rstrip("="):
        raise ValueError("Invalid Reality key encoding")
    return value.rstrip("=")


@dataclass(frozen=True)
class Settings:
    api_token: str = field(repr=False)
    endpoint: str
    private_key: str = field(repr=False)
    public_key: str = field(repr=False)
    short_id: str = field(repr=False)
    server_name: str = "www.microsoft.com"
    target: str = "www.microsoft.com:443"
    game_cidrs: tuple[ipaddress.IPv4Network, ...] = ()
    xray_binary: Path = Path("/usr/local/bin/brawl-xray")
    database: Path = Path("/var/lib/brawl-proxy/proxy.sqlite")
    runtime_config: Path = Path("/var/lib/brawl-proxy/runtime.json")
    max_users: int = 1000
    reconcile_seconds: int = 5

    def __post_init__(self) -> None:
        if not 32 <= len(self.api_token) <= 512 or not self.api_token.isascii() or any(character.isspace() for character in self.api_token):
            raise ValueError("VPN_API_TOKEN must contain at least 32 ASCII characters without spaces")
        _, port = host_port(self.endpoint)
        if port != 443:
            raise ValueError("XRAY_ENDPOINT must use TCP port 443")
        object.__setattr__(self, "private_key", reality_key(self.private_key))
        object.__setattr__(self, "public_key", reality_key(self.public_key))
        if not re.fullmatch(r"[A-Fa-f0-9]{16}", self.short_id):
            raise ValueError("XRAY_SHORT_ID must contain exactly 16 hexadecimal characters")
        hostname(self.server_name)
        target_host, target_port = host_port(self.target)
        if target_port != 443 or target_host.lower() != self.server_name.lower():
            raise ValueError("XRAY_TARGET must match XRAY_SERVER_NAME on TLS port 443")
        if len(self.game_cidrs) > 128:
            raise ValueError("GAME_ALLOWED_CIDRS supports at most 128 reviewed public IPv4 networks")
        for index, network in enumerate(self.game_cidrs):
            if not isinstance(network, ipaddress.IPv4Network) or network.prefixlen < 16 or not public_ipv4(network.network_address) or not public_ipv4(network.broadcast_address) or any(network.overlaps(other) for other in self.game_cidrs[index + 1:]):
                raise ValueError("GAME_ALLOWED_CIDRS must contain nonoverlapping public IPv4 /16 or narrower networks")
        for path in (self.xray_binary, self.database, self.runtime_config):
            if not path.is_absolute():
                raise ValueError("Xray binary and state paths must be absolute")
        if self.database.suffix != ".sqlite" or self.runtime_config.suffix != ".json" or self.database.parent != self.runtime_config.parent:
            raise ValueError("Proxy database and runtime JSON must share a dedicated state directory")
        if not 1 <= self.max_users <= 1000 or not 1 <= self.reconcile_seconds <= 5:
            raise ValueError("PROXY_MAX_USERS must be 1..1000 and PROXY_RECONCILE_SECONDS 1..5")

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> Settings:
        env = os.environ if env is None else env
        required = ("VPN_API_TOKEN", "XRAY_ENDPOINT", "XRAY_PRIVATE_KEY", "XRAY_PUBLIC_KEY", "XRAY_SHORT_ID")
        missing = [name for name in required if not env.get(name, "").strip()]
        if missing:
            raise ValueError("Missing proxy settings: " + ", ".join(missing))
        raw_cidrs = env.get("GAME_ALLOWED_CIDRS", "").strip()
        try:
            cidrs = tuple(ipaddress.ip_network(value.strip(), strict=True) for value in raw_cidrs.split(",")) if raw_cidrs else ()
        except ValueError:
            raise ValueError("Invalid GAME_ALLOWED_CIDRS") from None
        return cls(api_token=env["VPN_API_TOKEN"], endpoint=env["XRAY_ENDPOINT"], private_key=env["XRAY_PRIVATE_KEY"], public_key=env["XRAY_PUBLIC_KEY"], short_id=env["XRAY_SHORT_ID"], server_name=env.get("XRAY_SERVER_NAME", "www.microsoft.com"), target=env.get("XRAY_TARGET", "www.microsoft.com:443"), game_cidrs=cidrs, xray_binary=Path(env.get("XRAY_BINARY", "/usr/local/bin/brawl-xray")), database=Path(env.get("PROXY_DATABASE", "/var/lib/brawl-proxy/proxy.sqlite")), runtime_config=Path(env.get("PROXY_RUNTIME_CONFIG", "/var/lib/brawl-proxy/runtime.json")), max_users=int(env.get("PROXY_MAX_USERS", "1000")), reconcile_seconds=int(env.get("PROXY_RECONCILE_SECONDS", "5")))
