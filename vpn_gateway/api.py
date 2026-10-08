from __future__ import annotations

import asyncio
import hmac
import logging
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Annotated

from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

from .manager import AccessManager, CapacityError, GatewayUnavailable
from .settings import Settings

logger = logging.getLogger(__name__)


class AccessRequest(BaseModel):
    user_id: int = Field(strict=True, gt=0, le=2**63 - 1)
    expires_at: str = Field(min_length=20, max_length=40)


class PrepareRequest(BaseModel):
    user_id: int = Field(strict=True, gt=0, le=2**63 - 1)
    payment_pending: bool = Field(default=False, strict=True)


class AccessResponse(BaseModel):
    android_config: str
    ios_config: str


def create_app(settings: Settings | None = None, manager: AccessManager | None = None) -> FastAPI:
    settings = settings or Settings.from_env()
    manager = manager or AccessManager(settings)

    async def maintain() -> None:
        while True:
            await asyncio.sleep(settings.reconcile_seconds)
            try:
                await asyncio.to_thread(manager.reconcile if manager.ready else manager.initialize)
            except Exception:
                # Do not log command output, keys or full request/response bodies.
                logger.error("WireGuard reconciliation failed; gateway readiness is false")

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        await asyncio.to_thread(manager.initialize)
        task = asyncio.create_task(maintain(), name="wireguard-expiration")
        try:
            yield
        finally:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
            try:
                await asyncio.to_thread(manager.firewall.quarantine)
            finally:
                manager.close()

    app = FastAPI(title="Restricted Brawl VPN gateway", lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)

    def authorize(authorization: Annotated[str | None, Header()] = None) -> None:
        if not authorization or not authorization.startswith("Bearer ") or not hmac.compare_digest(authorization[7:], settings.api_token):
            raise HTTPException(status_code=401, detail="Unauthorized")

    @app.get("/health", dependencies=[Depends(authorize)])
    def health() -> dict[str, object]:
        ready = manager.health()
        return {"ready": ready, "capacity_available": manager.has_capacity(), "backend": "wireguard", "ipv6_supported": False, "game_restriction": "operator-reviewed-destination-cidrs", "checked_at": datetime.now(timezone.utc).isoformat()}

    @app.post("/prepare", dependencies=[Depends(authorize)])
    def prepare(body: PrepareRequest) -> dict[str, bool]:
        try:
            return manager.prepare(body.user_id, payment_pending=body.payment_pending)
        except ValueError as error:
            raise HTTPException(status_code=422, detail=str(error)) from error
        except CapacityError as error:
            raise HTTPException(status_code=503, detail="VPN client address capacity is exhausted") from error
        except Exception as error:
            raise HTTPException(status_code=503, detail="VPN gateway is not ready") from error

    @app.post("/access", response_model=AccessResponse, dependencies=[Depends(authorize)])
    def access(body: AccessRequest) -> dict[str, str]:
        try:
            return manager.access(body.user_id, body.expires_at)
        except ValueError as error:
            raise HTTPException(status_code=422, detail=str(error)) from error
        except CapacityError as error:
            raise HTTPException(status_code=503, detail="VPN client address capacity is exhausted") from error
        except GatewayUnavailable as error:
            raise HTTPException(status_code=503, detail="VPN gateway is not ready") from error
        except Exception as error:
            logger.error("WireGuard provisioning failed")
            raise HTTPException(status_code=503, detail="VPN provisioning temporarily unavailable") from error

    return app


def main() -> None:
    import uvicorn

    # Keep the privileged API local. Use an SSH tunnel or HTTPS reverse proxy.
    uvicorn.run(create_app(), host="127.0.0.1", port=8081, access_log=False, workers=1)


if __name__ == "__main__":
    main()
