from datetime import datetime, timedelta, timezone
import json

import httpx
import pytest

import vpn_shop.provider as provider
from vpn_shop.provider import VPNAccess, VPNClient, VPNUnavailable


NOW = datetime(2030, 1, 1, 12, tzinfo=timezone.utc)
TOKEN = "fake-gateway-token-never-a-real-credential"
CONFIG = "[Interface]\nPrivateKey = fake-key\nAddress = 10.66.0.2/32\n\n[Peer]\nPublicKey = fake-peer\n"


@pytest.fixture(autouse=True)
def fixed_provider_time(monkeypatch):
    class FrozenDatetime(datetime):
        @classmethod
        def now(cls, tz=None):
            return NOW if tz else NOW.replace(tzinfo=None)

    monkeypatch.setattr(provider, "datetime", FrozenDatetime)


@pytest.mark.asyncio
async def test_health_is_authenticated_and_only_explicit_ready_is_success():
    requests = []

    def gateway(request):
        requests.append(request)
        return httpx.Response(200, json={"ready": True})

    client = VPNClient("https://vpn.example/api", TOKEN, transport=httpx.MockTransport(gateway))
    try:
        assert await client.health() is True
    finally:
        await client.close()
    assert str(requests[0].url) == "https://vpn.example/api/health"
    assert requests[0].headers["Authorization"] == f"Bearer {TOKEN}"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("status", "body"),
    [(200, {"ready": False}), (200, {"ready": "true"}), (200, {"ready": 1}),
     (200, {}), (200, []), (200, None), (401, {"ready": True}),
     (500, {"ready": True}), (302, {"ready": True})],
)
async def test_health_fails_closed_for_unready_malformed_error_and_redirect(status, body):
    client = VPNClient(
        "http://127.0.0.1:8081", TOKEN,
        transport=httpx.MockTransport(lambda _: httpx.Response(status, json=body)),
    )
    try:
        assert await client.health() is False
    finally:
        await client.close()


@pytest.mark.asyncio
async def test_health_fails_closed_for_network_timeout_and_invalid_json():
    def timeout(request):
        raise httpx.ReadTimeout("temporary network failure", request=request)

    for transport in [
        httpx.MockTransport(timeout),
        httpx.MockTransport(lambda _: httpx.Response(200, text="not json")),
    ]:
        client = VPNClient("https://vpn.example", TOKEN, transport=transport)
        try:
            assert await client.health() is False
        finally:
            await client.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("payment_pending", [False, True])
async def test_prepare_access_reserves_user_with_authenticated_short_timeout(payment_pending):
    requests = []

    def gateway(request):
        requests.append(request)
        return httpx.Response(200, json={"ready": True})

    client = VPNClient("https://vpn.example/api", TOKEN, transport=httpx.MockTransport(gateway))
    try:
        assert await client.prepare_access(11, payment_pending=payment_pending) is True
    finally:
        await client.close()
    request = requests[0]
    assert request.method == "POST"
    assert str(request.url) == "https://vpn.example/api/prepare"
    assert request.headers["Authorization"] == f"Bearer {TOKEN}"
    assert json.loads(request.content) == {"user_id": 11, "payment_pending": payment_pending}
    assert set(request.extensions["timeout"].values()) == {3.0}


@pytest.mark.asyncio
async def test_prepare_access_defaults_to_unapproved_reservation():
    requests = []

    def gateway(request):
        requests.append(request)
        return httpx.Response(200, json={"ready": True})

    client = VPNClient("https://vpn.example", TOKEN, transport=httpx.MockTransport(gateway))
    try:
        assert await client.prepare_access(11) is True
    finally:
        await client.close()
    assert json.loads(requests[0].content)["payment_pending"] is False


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("status", "body"),
    [(200, {"ready": False}), (200, {"ready": "true"}), (200, {"ready": 1}),
     (200, {"currency": "XTR", "amount": 140}), (200, {}), (200, []), (200, None),
     (401, {"ready": True}), (409, {"ready": True}), (503, {"ready": True}),
     (302, {"ready": True})],
)
async def test_prepare_access_fails_closed_for_bad_readiness_error_or_redirect(status, body):
    client = VPNClient(
        "https://vpn.example", TOKEN,
        transport=httpx.MockTransport(lambda _: httpx.Response(status, json=body)),
    )
    try:
        assert await client.prepare_access(11, payment_pending=True) is False
    finally:
        await client.close()


@pytest.mark.asyncio
async def test_prepare_access_network_failure_and_invalid_json_do_not_expose_raw_data(caplog):
    def timeout(request):
        raise httpx.ReadTimeout("PRIVATE_SECRET gateway detail", request=request)

    for transport in [
        httpx.MockTransport(timeout),
        httpx.MockTransport(lambda _: httpx.Response(200, text="PRIVATE_SECRET invalid json")),
    ]:
        client = VPNClient("https://vpn.example", TOKEN, transport=transport)
        try:
            assert await client.prepare_access(11) is False
        finally:
            await client.close()
    assert "PRIVATE_SECRET" not in caplog.text
    assert TOKEN not in caplog.text


@pytest.mark.asyncio
async def test_ensure_access_posts_authenticated_user_and_exact_expiry_returns_both_profiles():
    requests = []
    expiry = NOW + timedelta(days=30)

    def gateway(request):
        requests.append(request)
        return httpx.Response(200, json={"android_config": CONFIG, "ios_config": CONFIG})

    client = VPNClient("https://vpn.example/api", TOKEN, transport=httpx.MockTransport(gateway))
    try:
        access = await client.ensure_access(11, expiry)
    finally:
        await client.close()
    assert access == VPNAccess(CONFIG, CONFIG)
    request = requests[0]
    assert request.method == "POST"
    assert str(request.url) == "https://vpn.example/api/access"
    assert request.headers["Authorization"] == f"Bearer {TOKEN}"
    assert json.loads(request.content) == {"user_id": 11, "expires_at": expiry.isoformat()}
    assert CONFIG not in repr(access)
    assert "fake-key" not in repr(access)


@pytest.mark.asyncio
@pytest.mark.parametrize("expiry", [NOW, NOW - timedelta(seconds=1), NOW.replace(tzinfo=None)])
async def test_ensure_access_refuses_expired_or_naive_dates_before_request(expiry):
    def unexpected_request(_):
        pytest.fail("Invalid expiration must not reach the gateway")

    client = VPNClient("https://vpn.example", TOKEN, transport=httpx.MockTransport(unexpected_request))
    try:
        with pytest.raises(ValueError, match="expiration"):
            await client.ensure_access(11, expiry)
    finally:
        await client.close()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("status", "body"),
    [(401, {"error": "PRIVATE_SECRET"}), (500, {"error": "PRIVATE_SECRET"}),
     (302, {"android_config": CONFIG, "ios_config": CONFIG}),
     (200, {}), (200, []), (200, None),
     (200, {"android_config": CONFIG, "ios_config": "bad PRIVATE_SECRET"}),
     (200, {"android_config": "PRIVATE_SECRET", "ios_config": CONFIG}),
     (200, {"android_config": 123, "ios_config": CONFIG})],
)
async def test_ensure_access_rejects_errors_redirects_and_invalid_configs_without_raw_leak(
    status, body
):
    client = VPNClient(
        "https://vpn.example", TOKEN,
        transport=httpx.MockTransport(lambda _: httpx.Response(status, json=body)),
    )
    try:
        with pytest.raises(VPNUnavailable) as caught:
            await client.ensure_access(11, NOW + timedelta(days=30))
        assert "PRIVATE_SECRET" not in str(caught.value)
        assert TOKEN not in str(caught.value)
        assert caught.value.__cause__ is None
        assert caught.value.__suppress_context__ is True
    finally:
        await client.close()


@pytest.mark.asyncio
async def test_ensure_access_handles_network_errors_and_invalid_json_without_raw_leak():
    def unavailable(request):
        raise httpx.ConnectError("PRIVATE_SECRET upstream details", request=request)

    for transport in [
        httpx.MockTransport(unavailable),
        httpx.MockTransport(lambda _: httpx.Response(200, text="PRIVATE_SECRET invalid json")),
    ]:
        client = VPNClient("https://vpn.example", TOKEN, transport=transport)
        try:
            with pytest.raises(VPNUnavailable) as caught:
                await client.ensure_access(11, NOW + timedelta(days=30))
            assert "PRIVATE_SECRET" not in str(caught.value)
            assert TOKEN not in str(caught.value)
        finally:
            await client.close()
