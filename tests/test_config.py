import pytest

from vpn_shop.config import Settings, validate_api_url


@pytest.fixture
def configured_env(monkeypatch):
    values = {
        "BOT_TOKEN": "123456:local_test_bot_token_without_real_secrets",
        "STARS_PRICE": "140",
        "VPN_API_URL": "http://127.0.0.1:8081/",
        "VPN_API_TOKEN": "local-test-gateway-token-with-32-characters",
        "SUPPORT_USERNAME": "@vpn_support",
    }
    for key in [*values, "ADMIN_IDS", "DATABASE_PATH"]:
        monkeypatch.delenv(key, raising=False)
    for key, value in values.items():
        monkeypatch.setenv(key, value)
    return values


def test_settings_require_explicit_stars_price(configured_env, monkeypatch):
    monkeypatch.delenv("STARS_PRICE")
    with pytest.raises(ValueError, match="STARS_PRICE"):
        Settings.from_env()


@pytest.mark.parametrize("price", ["", "0", "-1", "100001", "140.5", "two hundred"])
def test_settings_refuse_invalid_star_amount(configured_env, monkeypatch, price):
    monkeypatch.setenv("STARS_PRICE", price)
    with pytest.raises(ValueError, match="STARS_PRICE"):
        Settings.from_env()


def test_settings_keep_30_days_200_ruble_label_and_explicit_star_amount(configured_env):
    settings = Settings.from_env()
    assert settings.plan_days == 30
    assert settings.rub_price == 200
    assert settings.stars_price == 140
    assert settings.support_username == "vpn_support"
    assert settings.vpn_api_url == "http://127.0.0.1:8081"


def test_setting_repr_does_not_expose_bot_or_gateway_credentials(configured_env):
    rendered = repr(Settings.from_env())
    assert configured_env["BOT_TOKEN"] not in rendered
    assert configured_env["VPN_API_TOKEN"] not in rendered


@pytest.mark.parametrize(
    "url",
    ["http://vpn.example:8081", "http://192.168.1.10:8081", "http://0.0.0.0:8081",
     "ftp://vpn.example", "https://", "https://user:password@vpn.example",
     "https://vpn.example?token=secret", "https://vpn.example#secret"],
)
def test_api_url_refuses_remote_cleartext_and_embedded_credentials(url):
    with pytest.raises(ValueError):
        validate_api_url(url)


@pytest.mark.parametrize(
    "url",
    ["https://vpn.example", "https://vpn.example/api/", "http://localhost:8081",
     "http://127.0.0.1:8081/", "http://[::1]:8081"],
)
def test_api_url_accepts_https_or_loopback_http(url):
    assert validate_api_url(url) == url.rstrip("/")


def test_settings_parse_secure_connection_admins_and_database(configured_env, monkeypatch, tmp_path):
    monkeypatch.setenv("VPN_API_URL", "https://vpn.example/api/")
    monkeypatch.setenv("ADMIN_IDS", "11, 22")
    monkeypatch.setenv("DATABASE_PATH", str(tmp_path / "shop.sqlite"))
    settings = Settings.from_env()
    assert settings.admin_ids == (11, 22)
    assert settings.vpn_api_url == "https://vpn.example/api"
    assert settings.database_path == tmp_path / "shop.sqlite"


@pytest.mark.parametrize("admins", ["0", "-2", "11,invalid"])
def test_settings_refuse_invalid_admin_ids(configured_env, monkeypatch, admins):
    monkeypatch.setenv("ADMIN_IDS", admins)
    with pytest.raises(ValueError, match="ADMIN_IDS"):
        Settings.from_env()


@pytest.mark.parametrize("token", ["too-short", "x" * 32 + "\nwith space"])
def test_settings_refuse_weak_or_whitespace_gateway_token(configured_env, monkeypatch, token):
    monkeypatch.setenv("VPN_API_TOKEN", token)
    with pytest.raises(ValueError, match="VPN_API_TOKEN"):
        Settings.from_env()
