from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit


def validate_api_url(value: str) -> str:
    url = urlsplit(value)
    if url.username or url.password or url.query or url.fragment:
        raise ValueError("VPN_API_URL must not contain credentials, query or fragment")
    if not url.hostname or url.scheme not in {"https", "http"}:
        raise ValueError("VPN_API_URL must be an HTTPS URL or loopback HTTP URL")
    if url.scheme == "http" and url.hostname not in {"127.0.0.1", "::1", "localhost"}:
        raise ValueError("Unencrypted VPN_API_URL is allowed only on loopback")
    return value.rstrip("/")


@dataclass(frozen=True)
class Settings:
    bot_token: str = field(repr=False)
    stars_price: int
    vpn_api_url: str
    vpn_api_token: str = field(repr=False)
    support_username: str
    admin_ids: tuple[int, ...] = ()
    database_path: Path = Path("data/shop.sqlite")
    plan_days: int = 30
    rub_price: int = 200

    @classmethod
    def from_env(cls) -> Settings:
        required = ["BOT_TOKEN", "STARS_PRICE", "VPN_API_URL", "VPN_API_TOKEN", "SUPPORT_USERNAME"]
        missing = [name for name in required if not os.environ.get(name, "").strip()]
        if missing:
            raise ValueError("Missing required settings: " + ", ".join(missing))
        token = os.environ["BOT_TOKEN"].strip()
        if not re.fullmatch(r"[0-9]+:[A-Za-z0-9_-]{20,}", token):
            raise ValueError("BOT_TOKEN has an invalid format")
        try:
            price = int(os.environ["STARS_PRICE"])
        except ValueError:
            raise ValueError("STARS_PRICE must be a positive integer") from None
        if not 1 <= price <= 100_000:
            raise ValueError("STARS_PRICE must be between 1 and 100000")
        username = os.environ["SUPPORT_USERNAME"].strip().removeprefix("@")
        if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{4,31}", username):
            raise ValueError("SUPPORT_USERNAME must be a Telegram username")
        api_token = os.environ["VPN_API_TOKEN"].strip()
        if len(api_token) < 32 or not api_token.isascii() or any(c.isspace() for c in api_token):
            raise ValueError("VPN_API_TOKEN must contain at least 32 ASCII characters without spaces")
        try:
            admins = tuple(int(x.strip()) for x in os.environ.get("ADMIN_IDS", "").split(",") if x.strip())
        except ValueError:
            raise ValueError("ADMIN_IDS must be comma-separated positive Telegram user IDs") from None
        if any(x <= 0 for x in admins):
            raise ValueError("ADMIN_IDS must be positive")
        return cls(
            bot_token=token,
            stars_price=price,
            vpn_api_url=validate_api_url(os.environ["VPN_API_URL"].strip()),
            vpn_api_token=api_token,
            support_username=username,
            admin_ids=admins,
            database_path=Path(os.environ.get("DATABASE_PATH", "data/shop.sqlite")),
        )

