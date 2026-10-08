from datetime import datetime, timedelta, timezone
import base64
import json
from urllib.parse import urlencode

import httpx
import pytest

import vpn_shop.provider as provider
from vpn_shop.provider import VPNAccess, VPNClient, VPNUnavailable


NOW = datetime(2030, 1, 1, 12, tzinfo=timezone.utc)
TOKEN = "fake-gateway-token-never-a-real-credential"
CONFIG = "[Interface]\nPrivateKey = fake-key\nAddress = 10.66.0.2/32\n\n[Peer]\nPublicKey = fake-peer\n"
IDENTIFIER = "d9428888-122b-4ba4-940c-90c50b198c86"
REALITY_PUBLIC_KEY = base64.urlsafe_b64encode(bytes(range(1, 33))).decode().rstrip("=")


def incy_uri(*, endpoint="9.9.9.9:443", identifier=IDENTIFIER, **query_overrides):
    parameters = {
        "encryption": "none", "security": "reality", "type": "tcp",
        "flow": "xtls-rprx-vision", "sni": "www.microsoft.com", "fp": "chrome",
        "pbk": REALITY_PUBLIC_KEY, "sid": "0123456789abcdef", "spx": "/",
    }
    parameters.update(query_overrides)
    return f"vless://{identifier}@{endpoint}?{urlencode(parameters)}#Brawl%20Stars"


def incy_routing(**overrides):
    routing = {
        "Name": "Brawl Stars", "GlobalProxy": "false", "DomainStrategy": "IPIfNonMatch",
        "FakeDNS": "true", "RemoteDNSType": "DoU", "RemoteDNSIP": "1.1.1.1",
        "DomesticDNSType": "DoU", "DomesticDNSIP": "1.1.1.1", "DnsHosts": {},
        "ProxySites": [
            "domain:brawlstarsgame.com", "domain:brawlstars.com",
            "full:id.supercell.com", "full:cdn.id.supercell.com",
            "full:security.id.supercell.com",
            "full:assets.social.supercell.com", "full:sdk.social.supercell.com",
            "full:cdn.supercell.com", "full:brawlstars.inbox.supercell.com",
        ],
        "ProxyIp": [],
    }
    routing.update(overrides)
    return routing


def routing_link(routing=None, *, raw=None, urlsafe=False, padding=True):
    raw = json.dumps(routing if routing is not None else incy_routing()).encode() if raw is None else raw
    encoded = (base64.urlsafe_b64encode(raw) if urlsafe else base64.b64encode(raw)).decode()
    return "incy://routing/onadd/" + (encoded if padding else encoded.rstrip("="))


async def request_access(body):
    client = VPNClient(
        "https://vpn.example/api", TOKEN,
        transport=httpx.MockTransport(lambda _: httpx.Response(200, json=body)),
    )
    try:
        return await client.ensure_access(11, NOW + timedelta(days=30))
    finally:
        await client.close()


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


@pytest.mark.asyncio
@pytest.mark.parametrize("endpoint", ["9.9.9.9:443", "vpn.example.com:8443"])
async def test_incy_access_returns_separate_validated_key_and_restricted_routing(endpoint):
    uri, link = incy_uri(endpoint=endpoint), routing_link()
    access = await request_access({"kind": "incy", "connection_uri": uri, "routing_link": link})
    assert access.kind == "incy"
    assert access.connection_uri == uri
    assert access.routing_link == link
    assert access.android_config == access.ios_config == ""
    rendered = repr(access)
    assert IDENTIFIER not in rendered
    assert REALITY_PUBLIC_KEY not in rendered
    assert uri not in rendered
    assert link not in rendered


@pytest.mark.asyncio
async def test_wireguard_response_remains_compatible_with_typed_access_result():
    access = await request_access({"kind": "wireguard", "android_config": CONFIG, "ios_config": CONFIG})
    assert access == VPNAccess(CONFIG, CONFIG)
    assert access.kind == "wireguard"
    assert access.connection_uri is None and access.routing_link is None


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "body",
    [
        {"kind": "vless", "connection_uri": incy_uri(), "routing_link": routing_link()},
        {"kind": None, "android_config": CONFIG, "ios_config": CONFIG},
        {"kind": "incy", "android_config": CONFIG, "ios_config": CONFIG},
        {"kind": "incy", "connection_uri": CONFIG, "routing_link": routing_link()},
        {"kind": "incy", "connection_uri": incy_uri(), "routing_link": CONFIG},
        {"kind": "incy", "connection_uri": incy_uri(), "routing_link": None},
        {"kind": "wireguard", "android_config": CONFIG, "ios_config": CONFIG,
         "connection_uri": incy_uri()},
        {"kind": "incy", "connection_uri": incy_uri(), "routing_link": routing_link(),
         "android_config": CONFIG},
    ],
)
async def test_unknown_mixed_or_missing_access_formats_are_refused(body):
    with pytest.raises(VPNUnavailable):
        await request_access(body)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "uri",
    [
        incy_uri(identifier="not-a-uuid"),
        incy_uri(identifier="d9428888-122b-1ba4-940c-90c50b198c86"),
        incy_uri(identifier=IDENTIFIER + ":password"),
        incy_uri(identifier=IDENTIFIER + "@attacker.example.com"),
        incy_uri(endpoint="127.0.0.1:443"), incy_uri(endpoint="192.168.1.1:443"),
        incy_uri(endpoint="100.64.0.1:443"), incy_uri(endpoint="224.1.1.1:443"),
        incy_uri(endpoint="[::1]:443"), incy_uri(endpoint="[2606:4700:4700::1111]:443"),
        incy_uri(endpoint="localhost:443"), incy_uri(endpoint="vpn.internal:443"),
        incy_uri(endpoint="2130706433:443"), incy_uri(endpoint="0x7f000001:443"),
        incy_uri(endpoint="0177.0.0.1:443"), incy_uri(endpoint="9.9.9.999:443"),
        incy_uri(endpoint="bad_host.example.com:443"),
        incy_uri(endpoint="9.9.9.9"), incy_uri(endpoint="9.9.9.9:0"),
        incy_uri(endpoint="9.9.9.9:65536"), incy_uri(endpoint="9.9.9.9:notaport"),
        incy_uri().replace("vless://", "https://"),
        incy_uri().replace("?encryption", "/unwanted?encryption"),
        incy_uri().replace("#Brawl%20Stars", "#%3Cscript%3E"),
        incy_uri() + "\n", incy_uri().replace("#Brawl", "#%0ABrawl"),
        incy_uri().replace("#Brawl", "#%GG"),
        "vless://" + "x" * 2048,
    ],
)
async def test_incy_connection_rejects_invalid_identifiers_endpoints_and_unsafe_uri(uri):
    with pytest.raises(VPNUnavailable):
        await request_access({"kind": "incy", "connection_uri": uri, "routing_link": routing_link()})


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "changes",
    [{"encryption": "aes"}, {"security": "tls"}, {"type": "ws"}, {"flow": ""},
     {"fp": "random"}, {"sni": "localhost"}, {"sni": "www.microsoft.com\n"},
     {"pbk": "A" * 43}, {"pbk": REALITY_PUBLIC_KEY[:-1]}, {"pbk": "fake-key"},
     {"pbk": "PRIVATE_SECRET"}, {"sid": "short"}, {"sid": "z" * 16},
     {"spx": "/<script>"}, {"allowInsecure": "1"}],
)
async def test_incy_connection_requires_actual_reality_parameters(changes):
    with pytest.raises(VPNUnavailable) as caught:
        await request_access({"kind": "incy", "connection_uri": incy_uri(**changes),
                              "routing_link": routing_link()})
    assert "PRIVATE_SECRET" not in str(caught.value)
    assert IDENTIFIER not in str(caught.value)
    assert REALITY_PUBLIC_KEY not in str(caught.value)
    assert caught.value.__suppress_context__ is True


@pytest.mark.asyncio
@pytest.mark.parametrize("suffix", ["&security=reality", "&security=", "&pbk=fake", "&broken"])
async def test_incy_connection_refuses_duplicate_or_malformed_query(suffix):
    uri = incy_uri().replace("#Brawl", suffix + "#Brawl")
    with pytest.raises(VPNUnavailable):
        await request_access({"kind": "incy", "connection_uri": uri, "routing_link": routing_link()})


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "changes",
    [{"GlobalProxy": "true"}, {"GlobalProxy": False}, {"GlobalProxy": "FALSE"},
     {"Name": "Global proxy"}, {"DomainStrategy": "AsIs"}, {"FakeDNS": False},
     {"RemoteDNSType": "DoH"}, {"RemoteDNSIP": "8.8.8.8"},
     {"DomesticDNSType": "DoH"}, {"DomesticDNSIP": "127.0.0.1"},
     {"DnsHosts": {"game.example.com": "127.0.0.1"}}, {"DnsHosts": []},
     {"ProxySites": ["domain:brawlstarsgame.com"]},
     {"ProxySites": ["domain:brawlstarsgame.com", "domain:brawlstars.com", "domain:supercell.com"]},
     {"ProxySites": ["domain:brawlstarsgame.com", "domain:brawlstars.com", "regexp:.*"]},
     {"ProxySites": ["domain:brawlstarsgame.com", "domain:brawlstars.com", "domain:brawlstars.com"]},
     {"ProxySites": "domain:brawlstarsgame.com"}, {"ProxySites": [False, True]},
     {"DirectSites": []}, {"BlockSites": []}, {"GeoIpUrl": "https://evil.example.com/geodata"}],
)
async def test_incy_routing_refuses_global_fallback_unsafe_destinations_and_extra_rules(changes):
    with pytest.raises(VPNUnavailable):
        await request_access({"kind": "incy", "connection_uri": incy_uri(),
                              "routing_link": routing_link(incy_routing(**changes))})


@pytest.mark.asyncio
async def test_incy_routing_accepts_observed_supercell_id_login_and_cdn_hosts():
    routing = incy_routing(ProxySites=[
        "domain:brawlstarsgame.com", "domain:brawlstars.com", "full:id.supercell.com",
        "full:cdn.id.supercell.com", "full:security.id.supercell.com",
    ])
    link = routing_link(routing)
    access = await request_access({"kind": "incy", "connection_uri": incy_uri(), "routing_link": link})
    assert access.routing_link == link


@pytest.mark.asyncio
async def test_incy_routing_rejects_unverified_supercell_account_hostname():
    routing = incy_routing(ProxySites=[
        "domain:brawlstarsgame.com", "domain:brawlstars.com", "full:accounts.id.supercell.com",
    ])
    with pytest.raises(VPNUnavailable):
        await request_access({"kind": "incy", "connection_uri": incy_uri(),
                              "routing_link": routing_link(routing)})


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "ips",
    [["0.0.0.0/0"], ["8.0.0.0/8"], ["127.0.0.1/32"], ["10.0.0.0/24"],
     ["100.64.0.0/16"], ["224.0.0.0/16"], ["2606:4700:4700::1111/128"],
     ["8.8.8.8"], ["8.8.8.1/24"], ["8.8.8.0/24", "8.8.8.8/32"],
     ["8.8.8.8/32", "8.8.8.8/32"], [None], "8.8.8.8/32",
     ["9.9.9." + str(i) + "/32" for i in range(129)]],
)
async def test_incy_routing_refuses_private_broad_overlapping_or_unbounded_ip_routes(ips):
    with pytest.raises(VPNUnavailable):
        await request_access({"kind": "incy", "connection_uri": incy_uri(),
                              "routing_link": routing_link(incy_routing(ProxyIp=ips))})


@pytest.mark.asyncio
@pytest.mark.parametrize(("urlsafe", "padding"), [(False, True), (True, True), (True, False)])
async def test_incy_routing_accepts_bounded_encoding_and_operator_reviewed_public_ranges(
    urlsafe, padding
):
    routing = incy_routing(
        ProxySites=["domain:brawlstarsgame.com", "domain:brawlstars.com"],
        ProxyIp=["8.8.8.8/32", "1.1.1.0/24"],
    )
    link = routing_link(routing, urlsafe=urlsafe, padding=padding)
    access = await request_access({"kind": "incy", "connection_uri": incy_uri(), "routing_link": link})
    assert access.routing_link == link


@pytest.mark.asyncio
async def test_incy_routing_supports_128_reviewed_hosts_and_long_complete_link():
    routing = incy_routing(ProxyIp=["129.129.129." + str(i) + "/32" for i in range(128)])
    link = routing_link(routing)
    assert len(link) > 3500
    access = await request_access({"kind": "incy", "connection_uri": incy_uri(), "routing_link": link})
    assert access.routing_link == link


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "link",
    ["https://evil.example.com/profile", "incy://routing/onadd/not base64",
     "incy://routing/onadd/", "incy://routing/onadd/" + "A" * 16384,
     routing_link() + "?GlobalProxy=true", routing_link() + "\n",
     routing_link(raw=b"not JSON"), routing_link(raw=b"[]"),
     routing_link(raw=b'{"Name":"Brawl Stars","Name":"Global"}'),
     routing_link(raw=b'{"GlobalProxy":NaN}'),
     routing_link(raw=b'{"GlobalProxy":Infinity}'), routing_link(raw=b"\xff"),
     routing_link(raw=b"[" * 1500 + b"]" * 1500)],
)
async def test_incy_routing_refuses_malformed_duplicate_or_oversized_profiles(link):
    with pytest.raises(VPNUnavailable) as caught:
        await request_access({"kind": "incy", "connection_uri": incy_uri(), "routing_link": link})
    assert IDENTIFIER not in str(caught.value)
    assert caught.value.__cause__ is None


@pytest.mark.asyncio
async def test_gateway_outer_json_rejects_duplicate_kind_even_when_final_profile_is_valid():
    body = json.dumps({"kind": "incy", "connection_uri": incy_uri(), "routing_link": routing_link()})
    ambiguous = body.replace('{"kind": "incy"', '{"kind": "wireguard", "kind": "incy"')
    client = VPNClient(
        "https://vpn.example/api", TOKEN,
        transport=httpx.MockTransport(lambda _: httpx.Response(200, text=ambiguous)),
    )
    try:
        with pytest.raises(VPNUnavailable):
            await client.ensure_access(11, NOW + timedelta(days=30))
    finally:
        await client.close()
