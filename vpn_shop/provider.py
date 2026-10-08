from __future__ import annotations

import base64
import ipaddress
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from urllib.parse import parse_qsl, unquote, urlsplit
from uuid import UUID

import httpx

from .config import validate_api_url


class VPNUnavailable(RuntimeError):
    pass


MAX_INCY_CONNECTION_URI = 2048
MAX_INCY_ROUTING_LINK = 16384
MAX_INCY_ROUTING_BYTES = 12288
INCY_PROXY_SITES = (
    "domain:brawlstarsgame.com",
    "domain:brawlstars.com",
    "full:id.supercell.com",
    "full:cdn.id.supercell.com",
    "full:security.id.supercell.com",
    "full:assets.social.supercell.com",
    "full:sdk.social.supercell.com",
    "full:cdn.supercell.com",
    "full:brawlstars.inbox.supercell.com",
)
INCY_REQUIRED_PROXY_SITES = frozenset(INCY_PROXY_SITES[:2])
INCY_ROUTING_FIXED_FIELDS = {
    "Name": "Brawl Stars",
    "GlobalProxy": "false",
    "DomainStrategy": "IPIfNonMatch",
    "FakeDNS": "true",
    "RemoteDNSType": "DoU",
    "RemoteDNSIP": "1.1.1.1",
    "DomesticDNSType": "DoU",
    "DomesticDNSIP": "1.1.1.1",
}


def _public_ipv4(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return (
        isinstance(address, ipaddress.IPv4Address)
        and address.is_global
        and not address.is_multicast
        and not address.is_reserved
    )


def _valid_dns_hostname(hostname: str) -> bool:
    # Hostname syntax does not prove that DNS resolves to a public address.
    if not hostname or len(hostname) > 253 or not hostname.isascii():
        return False
    labels = hostname.lower().split(".")
    return (
        len(labels) >= 2
        and not all(label.isdigit() for label in labels)
        and labels[-1] not in {"localhost", "local", "internal", "invalid", "test", "example"}
        and bool(re.fullmatch(r"[a-z]{2,63}|xn--[a-z0-9-]{1,59}", labels[-1]))
        and all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
                for label in labels)
    )


def _validate_connection_uri(uri: object) -> str:
    if not isinstance(uri, str) or not 1 <= len(uri) <= MAX_INCY_CONNECTION_URI:
        raise ValueError("Invalid Incy connection URI")
    if not uri.isascii() or any(character.isspace() for character in uri):
        raise ValueError("Invalid Incy connection URI")
    if re.search(r"%(?![0-9a-fA-F]{2})", uri):
        raise ValueError("Invalid Incy connection URI")
    decoded = unquote(uri, encoding="utf-8", errors="strict")
    if any(ord(character) < 32 or ord(character) == 127 or character in "<>\"'`"
           for character in decoded):
        raise ValueError("Invalid Incy connection URI")
    url = urlsplit(uri)
    if (
        url.scheme != "vless" or not url.username or url.password is not None
        or url.netloc.count("@") != 1 or url.path or unquote(url.fragment) != "Brawl Stars"
        or url.port is None or not 1 <= url.port <= 65535 or not url.hostname
    ):
        raise ValueError("Invalid Incy connection URI")
    identifier = UUID(url.username)
    if identifier.version != 4 or str(identifier) != url.username.lower():
        raise ValueError("Invalid Incy connection identifier")
    try:
        address = ipaddress.ip_address(url.hostname)
    except ValueError:
        if not _valid_dns_hostname(url.hostname):
            raise ValueError("Invalid Incy connection endpoint") from None
    else:
        if not _public_ipv4(address) or str(address) != url.hostname:
            raise ValueError("Invalid Incy connection endpoint")
    pairs = parse_qsl(url.query, keep_blank_values=True, strict_parsing=True, max_num_fields=16)
    values = dict(pairs)
    expected = {
        "encryption": "none", "security": "reality", "type": "tcp",
        "flow": "xtls-rprx-vision", "fp": "chrome", "spx": "/",
    }
    if (len(pairs) != len(values) or set(values) != set(expected) | {"sni", "pbk", "sid"}
            or any(values[key] != value for key, value in expected.items())
            or not _valid_dns_hostname(values["sni"])):
        raise ValueError("Invalid Incy Reality parameters")
    public_key = values["pbk"]
    if not re.fullmatch(r"[A-Za-z0-9_-]{43}", public_key):
        raise ValueError("Invalid Incy Reality key")
    key_bytes = base64.b64decode(public_key + "=", altchars=b"-_", validate=True)
    if (len(key_bytes) != 32 or not any(key_bytes)
            or base64.urlsafe_b64encode(key_bytes).decode().rstrip("=") != public_key):
        raise ValueError("Invalid Incy Reality key")
    if not re.fullmatch(r"[0-9a-fA-F]{16}", values["sid"]):
        raise ValueError("Invalid Incy Reality short identifier")
    return uri


def validate_incy_routing(routing: object) -> None:
    """Validate the same restricted routing policy used by the Incy gateway."""
    if not isinstance(routing, dict) or set(routing) != (
        set(INCY_ROUTING_FIXED_FIELDS) | {"ProxySites", "ProxyIp", "DnsHosts"}
    ):
        raise ValueError("Invalid Incy routing profile")
    if any(type(routing[key]) is not str or routing[key] != value
           for key, value in INCY_ROUTING_FIXED_FIELDS.items()):
        raise ValueError("Invalid Incy routing defaults")
    sites = routing["ProxySites"]
    if (not isinstance(sites, list) or not len(INCY_REQUIRED_PROXY_SITES) <= len(sites)
            <= len(INCY_PROXY_SITES) or not all(type(site) is str for site in sites)
            or len(set(sites)) != len(sites) or not set(sites).issubset(INCY_PROXY_SITES)
            or not INCY_REQUIRED_PROXY_SITES.issubset(sites)):
        raise ValueError("Invalid Incy proxy destinations")
    if type(routing["DnsHosts"]) is not dict or routing["DnsHosts"]:
        raise ValueError("Invalid Incy DNS overrides")
    ips = routing["ProxyIp"]
    if not isinstance(ips, list) or len(ips) > 128:
        raise ValueError("Invalid Incy proxy address list")
    networks: list[ipaddress.IPv4Network] = []
    for value in ips:
        if not isinstance(value, str) or "/" not in value:
            raise ValueError("Invalid Incy proxy network")
        network = ipaddress.ip_network(value, strict=True)
        if (not isinstance(network, ipaddress.IPv4Network) or network.prefixlen < 16
                or str(network) != value or not _public_ipv4(network.network_address)
                or not _public_ipv4(network.broadcast_address)
                or any(network.overlaps(existing) for existing in networks)):
            raise ValueError("Invalid Incy proxy network")
        networks.append(network)


def _unique_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate Incy routing property")
        result[key] = value
    return result


def _reject_json_constant(_value: str) -> None:
    raise ValueError("Invalid Incy routing JSON")


def _validate_routing_link(link: object) -> str:
    prefix = "incy://routing/onadd/"
    if (not isinstance(link, str) or len(link) > MAX_INCY_ROUTING_LINK
            or not link.startswith(prefix)):
        raise ValueError("Invalid Incy routing link")
    encoded = link[len(prefix):]
    if (not re.fullmatch(r"[A-Za-z0-9+/_-]+={0,2}", encoded)
            or (any(character in encoded for character in "-_")
                and any(character in encoded for character in "+/"))):
        raise ValueError("Invalid Incy routing encoding")
    raw = base64.b64decode(encoded + "=" * (-len(encoded) % 4), altchars=b"-_", validate=True)
    if len(raw) > MAX_INCY_ROUTING_BYTES:
        raise ValueError("Incy routing profile is too large")
    canonical = (base64.urlsafe_b64encode(raw) if any(character in encoded for character in "-_")
                 else base64.b64encode(raw)).decode()
    if encoded.rstrip("=") != canonical.rstrip("="):
        raise ValueError("Invalid Incy routing encoding")
    routing = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_json_object,
                         parse_constant=_reject_json_constant)
    validate_incy_routing(routing)
    return link


@dataclass(frozen=True)
class VPNAccess:
    android_config: str = field(default="", repr=False)
    ios_config: str = field(default="", repr=False)
    kind: str = "wireguard"
    connection_uri: str | None = field(default=None, repr=False)
    routing_link: str | None = field(default=None, repr=False)


class VPNClient:
    def __init__(self, base_url: str, token: str, *, transport=None):
        self.client = httpx.AsyncClient(
            base_url=validate_api_url(base_url) + "/",
            headers={"Authorization": f"Bearer {token}"},
            timeout=httpx.Timeout(20.0, connect=5.0),
            follow_redirects=False,
            trust_env=False,
            transport=transport,
        )

    async def health(self) -> bool:
        try:
            response = await self.client.get("health", timeout=3.0)
            response.raise_for_status()
            return response.json().get("ready") is True
        except (httpx.HTTPError, ValueError, AttributeError):
            return False

    async def prepare_access(self, user_id: int, *, payment_pending: bool = False) -> bool:
        """Reserve capacity before invoice; approved checkouts hold it until payment arrives."""
        try:
            response = await self.client.post(
                "prepare", json={"user_id": user_id, "payment_pending": payment_pending},
                timeout=3.0,
            )
            response.raise_for_status()
            return response.json().get("ready") is True
        except (httpx.HTTPError, ValueError, AttributeError):
            return False

    async def ensure_access(self, user_id: int, expires_at: datetime) -> VPNAccess:
        if expires_at.tzinfo is None or expires_at <= datetime.now(timezone.utc):
            raise ValueError("Access expiration must be in the future with an explicit timezone")
        try:
            response = await self.client.post(
                "access", json={"user_id": user_id, "expires_at": expires_at.isoformat()}
            )
            response.raise_for_status()
            data = response.json(object_pairs_hook=_unique_json_object,
                                 parse_constant=_reject_json_constant)
            if not isinstance(data, dict):
                raise ValueError("Invalid gateway response")
            kind = data.get("kind", "wireguard")
            if kind == "incy":
                if set(data) != {"kind", "connection_uri", "routing_link"}:
                    raise ValueError("Invalid Incy gateway response")
                return VPNAccess(
                    kind="incy",
                    connection_uri=_validate_connection_uri(data["connection_uri"]),
                    routing_link=_validate_routing_link(data["routing_link"]),
                )
            if kind != "wireguard" or data.get("connection_uri") or data.get("routing_link"):
                raise ValueError("Invalid gateway response kind")
            android, ios = data["android_config"], data["ios_config"]
            if not all(isinstance(value, str) and "PrivateKey = " in value
                       and "[Peer]" in value for value in (android, ios)):
                raise ValueError("Invalid gateway response")
            return VPNAccess(android, ios)
        except (httpx.HTTPError, ValueError, KeyError, TypeError, RecursionError):
            # Do not expose credentials, profile keys or raw response bodies in logs/chat.
            raise VPNUnavailable("VPN gateway did not issue a valid configuration") from None

    async def close(self) -> None:
        await self.client.aclose()
