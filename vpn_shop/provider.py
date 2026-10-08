from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone

import httpx

from .config import validate_api_url


class VPNUnavailable(RuntimeError):
    pass


@dataclass(frozen=True)
class VPNAccess:
    android_config: str = field(repr=False)
    ios_config: str = field(repr=False)


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
            data = response.json()
            android, ios = data["android_config"], data["ios_config"]
            if not all(isinstance(value, str) and "PrivateKey = " in value
                       and "[Peer]" in value for value in (android, ios)):
                raise ValueError("Invalid gateway response")
            return VPNAccess(android, ios)
        except (httpx.HTTPError, ValueError, KeyError, TypeError):
            # Do not expose credentials, profile keys or raw response bodies in logs/chat.
            raise VPNUnavailable("VPN gateway did not issue a valid configuration") from None

    async def close(self) -> None:
        await self.client.aclose()
