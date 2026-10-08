from __future__ import annotations

import base64
import hashlib
import importlib.util
import io
import json
import os
import sqlite3
import stat
import sys
import zipfile
from contextlib import nullcontext
from datetime import datetime, timezone
from pathlib import Path
from uuid import UUID

import pytest

from vpn_shop.db import Store


spec = importlib.util.spec_from_file_location(
    "deploy_setup_incy", Path(__file__).resolve().parents[1] / "deploy" / "setup-incy.py"
)
deploy = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = deploy
spec.loader.exec_module(deploy)

# Synthetic test keys, not live credentials.
PRIVATE_KEY = base64.urlsafe_b64encode(bytes([33]) * 32).decode().rstrip("=")
PUBLIC_KEY = base64.urlsafe_b64encode(bytes([71]) * 32).decode().rstrip("=")
BOT_TOKEN = "123456789:test_token_without_real_credentials_12345"
API_TOKEN = "test_only_api_secret_not_for_a_live_service"


def archive_with(entries):
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, contents, mode in entries:
            entry = zipfile.ZipInfo(name)
            entry.create_system = 3
            entry.external_attr = mode << 16
            entry.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(entry, contents)
    return output.getvalue()


def executable_archive(contents=b"\x7fELFtest-only-binary"):
    return archive_with([("xray", contents, stat.S_IFREG | 0o755)])


def digest_for(contents):
    return "SHA2-256= " + hashlib.sha256(contents).hexdigest()


def private_file(path, contents):
    path.write_text(contents)
    path.chmod(0o600)
    return path


def test_valid_sha256_digest_and_verified_executable():
    binary = b"\x7fELFtest-only-binary"
    archive = executable_archive(binary)
    digest = digest_for(archive)
    assert deploy.parse_digest(digest) == hashlib.sha256(archive).hexdigest()
    assert deploy.verified_xray_archive(archive, digest) == binary


@pytest.mark.parametrize(
    "digest",
    ["", "f" * 64, "SHA256=" + "f" * 63, "SHA256=" + "f" * 65,
     "SHA256=" + "z" * 64, "SHA256=invalid"],
)
def test_invalid_sha256_digest_is_rejected(digest):
    with pytest.raises(deploy.SetupError):
        deploy.parse_digest(digest)


def test_wrong_archive_digest_prevents_using_binary():
    archive = executable_archive()
    with pytest.raises(deploy.SetupError):
        deploy.verified_xray_archive(archive, "SHA256=" + "0" * 64)


def test_sha256_is_selected_from_official_multi_algorithm_digest():
    digest = "a" * 64
    text = "MD5= " + "1" * 32 + "\nSHA1= " + "2" * 40 + "\nSHA2-256= " + digest.upper()
    assert deploy.parse_digest(text) == digest


def test_conflicting_sha256_checksums_are_rejected():
    with pytest.raises(deploy.SetupError):
        deploy.parse_digest("SHA256=" + "a" * 64 + "\nSHA2-256=" + "b" * 64)


@pytest.mark.parametrize(
    "entries",
    [
        [("readme.txt", b"no executable", stat.S_IFREG | 0o644)],
        [("xray", b"non-executable", stat.S_IFREG | 0o644)],
        [("xray", b"/etc/shadow", stat.S_IFLNK | 0o777)],
        [("../xray", b"\x7fELFtest", stat.S_IFREG | 0o755)],
        [
            ("xray", b"\x7fELFfirst", stat.S_IFREG | 0o755),
            ("xray", b"\x7fELFsecond", stat.S_IFREG | 0o755),
        ],
    ],
)
def test_unsafe_or_missing_archive_executable_is_rejected(entries):
    # Duplicate names are deliberate untrusted archive input.
    with pytest.warns(UserWarning) if len(entries) > 1 else nullcontext():
        archive = archive_with(entries)
    with pytest.raises(deploy.SetupError):
        deploy.verified_xray_archive(archive, digest_for(archive))


def test_invalid_zip_is_rejected_even_with_matching_checksum():
    archive = b"not a zip archive"
    with pytest.raises(deploy.SetupError):
        deploy.verified_xray_archive(archive, digest_for(archive))


def test_oversized_archive_binary_is_rejected_before_decompression(monkeypatch):
    monkeypatch.setattr(deploy, "MAX_XRAY_BINARY_BYTES", 32)
    archive = executable_archive(b"\x7fELF" + b"x" * 64)
    with pytest.raises(deploy.SetupError):
        deploy.verified_xray_archive(archive, digest_for(archive))


def test_oversized_archive_is_rejected(monkeypatch):
    monkeypatch.setattr(deploy, "MAX_ARCHIVE_BYTES", 32)
    archive = executable_archive()
    with pytest.raises(deploy.SetupError):
        deploy.verified_xray_archive(archive, digest_for(archive))


@pytest.mark.parametrize(
    "output",
    [
        f"PrivateKey: {PRIVATE_KEY}\nPassword (PublicKey): {PUBLIC_KEY}\n",
        f"Private key: {PRIVATE_KEY}\nPublic key: {PUBLIC_KEY}\n",
    ],
)
def test_x25519_parses_current_and_historical_xray_output(output):
    assert deploy.parse_x25519(output) == (PRIVATE_KEY, PUBLIC_KEY)


@pytest.mark.parametrize(
    "output",
    [
        f"PrivateKey: {PRIVATE_KEY}\n",
        f"Password (PublicKey): {PUBLIC_KEY}\n",
        f"PrivateKey: invalid-{PRIVATE_KEY}\nPassword (PublicKey): {PUBLIC_KEY}\n",
    ],
)
def test_bad_x25519_output_does_not_expose_keys(output):
    with pytest.raises(deploy.SetupError) as caught:
        deploy.parse_x25519(output)
    assert PRIVATE_KEY not in str(caught.value)
    assert PUBLIC_KEY not in str(caught.value)


def test_private_environment_is_loaded_without_logging_secrets(tmp_path, capsys):
    path = private_file(
        tmp_path / "bot.env",
        f"# local settings\nBOT_TOKEN={BOT_TOKEN}\nVPN_API_TOKEN={API_TOKEN}\nADMIN_IDS=11,22\n",
    )
    assert deploy.load_private_env(path) == {
        "BOT_TOKEN": BOT_TOKEN,
        "VPN_API_TOKEN": API_TOKEN,
        "ADMIN_IDS": "11,22",
    }
    captured = capsys.readouterr()
    assert captured.out == captured.err == ""


@pytest.mark.parametrize("mode", [0o400, 0o644, 0o640, 0o666])
def test_reading_nonprivate_environment_is_rejected(tmp_path, mode):
    path = private_file(tmp_path / "bot.env", f"BOT_TOKEN={BOT_TOKEN}\n")
    path.chmod(mode)
    with pytest.raises(deploy.SetupError) as caught:
        deploy.load_private_env(path)
    assert BOT_TOKEN not in str(caught.value)


def test_environment_owned_by_another_user_is_rejected(tmp_path, monkeypatch):
    path = private_file(tmp_path / "bot.env", f"BOT_TOKEN={BOT_TOKEN}\n")
    owner = path.stat().st_uid
    monkeypatch.setattr(deploy.os, "geteuid", lambda: owner + 1)
    with pytest.raises(deploy.SetupError) as caught:
        deploy.load_private_env(path)
    assert BOT_TOKEN not in str(caught.value)


def test_environment_symlink_is_rejected_without_touching_target(tmp_path):
    contents = f"BOT_TOKEN={BOT_TOKEN}\n"
    target = private_file(tmp_path / "original.env", contents)
    path = tmp_path / "bot.env"
    path.symlink_to(target)
    with pytest.raises(deploy.SetupError):
        deploy.load_private_env(path)
    assert path.is_symlink()
    assert target.read_text() == contents


def test_environment_directory_is_rejected(tmp_path):
    path = tmp_path / "bot.env"
    path.mkdir(mode=0o700)
    with pytest.raises(deploy.SetupError):
        deploy.load_private_env(path)


def test_environment_parse_failure_does_not_expose_source_line(tmp_path):
    path = private_file(tmp_path / "bot.env", f"BOT_TOKEN={BOT_TOKEN}\n{API_TOKEN}\n")
    with pytest.raises(deploy.SetupError) as caught:
        deploy.load_private_env(path)
    assert BOT_TOKEN not in str(caught.value)
    assert API_TOKEN not in str(caught.value)


def test_bot_environment_update_preserves_credentials_and_admins():
    original = {
        "BOT_TOKEN": BOT_TOKEN,
        "VPN_API_TOKEN": API_TOKEN,
        "ADMIN_IDS": "11, 22,11",
        "STARS_PRICE": "100",
        "PLAN_DAYS": "30",
        "DATABASE_PATH": "/var/lib/brawl-vpn-bot/shop.sqlite",
        "SUPPORT_USERNAME": "test_support",
        "VPN_API_URL": "https://old.example.com",
        "SALES_ENABLED": "true",
    }
    snapshot = original.copy()
    updated = deploy.update_bot_env(original, 22)
    assert original == snapshot
    assert updated["BOT_TOKEN"] == BOT_TOKEN
    assert updated["VPN_API_TOKEN"] == API_TOKEN
    assert updated["SALES_ENABLED"] == "false"
    assert updated["VPN_API_URL"] == "http://127.0.0.1:8081"
    assert updated["ADMIN_IDS"] == "11,22"
    for key in ("STARS_PRICE", "PLAN_DAYS", "DATABASE_PATH", "SUPPORT_USERNAME"):
        assert updated[key] == original[key]
    assert deploy.update_bot_env(updated, 33)["ADMIN_IDS"] == "11,22,33"


def test_atomic_environment_update_preserves_private_backup(tmp_path):
    path = private_file(tmp_path / "bot.env", f"BOT_TOKEN={BOT_TOKEN}\nSALES_ENABLED=true\n")
    original = path.read_bytes()
    deploy.atomic_private_env(path, {"BOT_TOKEN": BOT_TOKEN, "SALES_ENABLED": "false"})
    assert deploy.load_private_env(path) == {"BOT_TOKEN": BOT_TOKEN, "SALES_ENABLED": "false"}
    files = list(tmp_path.iterdir())
    backups = [candidate for candidate in files if candidate != path]
    assert len(backups) == 1
    assert backups[0].read_bytes() == original
    for candidate in files:
        assert not candidate.is_symlink()
        assert candidate.stat().st_mode & 0o777 == 0o600
        assert candidate.stat().st_uid == os.geteuid()


@pytest.mark.parametrize("dangling", [False, True])
def test_atomic_environment_write_never_follows_symlink(tmp_path, dangling):
    target = tmp_path / "target.env"
    original = f"BOT_TOKEN={BOT_TOKEN}\n"
    if not dangling:
        private_file(target, original)
    path = tmp_path / "bot.env"
    path.symlink_to(target)
    with pytest.raises(deploy.SetupError):
        deploy.atomic_private_env(path, {"BOT_TOKEN": "replacement"})
    assert path.is_symlink()
    if dangling:
        assert not target.exists()
    else:
        assert target.read_text() == original


def test_atomic_environment_write_rejects_line_injection_before_changes(tmp_path):
    path = private_file(tmp_path / "bot.env", f"BOT_TOKEN={BOT_TOKEN}\n")
    original = path.read_bytes()
    with pytest.raises(deploy.SetupError) as caught:
        deploy.atomic_private_env(path, {"BOT_TOKEN": BOT_TOKEN + "\nSALES_ENABLED=true"})
    assert BOT_TOKEN not in str(caught.value)
    assert path.read_bytes() == original
    assert list(tmp_path.iterdir()) == [path]


def test_reset_delivery_reissues_only_active_paid_access_without_extending_it(tmp_path):
    now = datetime(2030, 1, 1, tzinfo=timezone.utc)
    timestamp = now.timestamp()
    path = tmp_path / "shop.sqlite"
    store = Store(path, clock=lambda: now)
    try:
        for user_id in (11, 22, 33):
            order = store.create_order(user_id, user_id, "android", 100)
            paid = store.accept_payment(order.id, user_id, "XTR", 100, f"test-charge-{user_id}")
            store.mark_provisioned(user_id, paid.expires_at)
            store.mark_notified(user_id, paid.expires_at)
        store.connection.execute("UPDATE subscriptions SET expires_at=? WHERE user_id=22", (timestamp - 1,))
        store.connection.execute("UPDATE subscriptions SET expires_at=? WHERE user_id=33", (timestamp,))
        # A test/administrative grant without a payment must not become a migration job.
        store.connection.execute(
            "INSERT INTO subscriptions VALUES(?,?,?,?,?,?)",
            (44, 44, "ios", timestamp + 3600, timestamp + 3600, timestamp + 3600),
        )
        before_subscriptions = store.connection.execute(
            "SELECT * FROM subscriptions ORDER BY user_id"
        ).fetchall()
        before_payments = store.connection.execute("SELECT * FROM payments ORDER BY user_id").fetchall()
        before_orders = store.connection.execute("SELECT * FROM orders ORDER BY user_id").fetchall()
        # Store uses durable rows from the real schema, rather than a mock migration schema.
        before_subscriptions = [tuple(row) for row in before_subscriptions]
        before_payments = [tuple(row) for row in before_payments]
        before_orders = [tuple(row) for row in before_orders]
    finally:
        store.close()

    deploy.reset_active_deliveries(path, now=timestamp)

    with sqlite3.connect(path) as connection:
        after = connection.execute("SELECT * FROM subscriptions ORDER BY user_id").fetchall()
        assert after[0] == (*before_subscriptions[0][:4], None, None)
        assert after[1:] == before_subscriptions[1:]
        assert connection.execute("SELECT * FROM payments ORDER BY user_id").fetchall() == before_payments
        assert connection.execute("SELECT * FROM orders ORDER BY user_id").fetchall() == before_orders


def make_trusted_tree(tmp_path):
    root = tmp_path / "project"
    root.mkdir(mode=0o755)
    package = root / "brawl_proxy"
    package.mkdir(mode=0o755)
    (package / "manager.py").write_text("# test module\n")
    (package / "manager.py").chmod(0o644)
    return root


def test_complete_protected_project_tree_is_accepted(tmp_path):
    root = make_trusted_tree(tmp_path)
    deploy.assert_trusted_tree(root, owner_uid=os.geteuid())


@pytest.mark.parametrize("target", ["directory", "module"])
def test_trusted_tree_rejects_writable_descendant(tmp_path, target):
    root = make_trusted_tree(tmp_path)
    path = root / "brawl_proxy"
    if target == "module":
        path /= "manager.py"
    path.chmod(path.stat().st_mode | 0o020)
    with pytest.raises(deploy.SetupError):
        deploy.assert_trusted_tree(root, owner_uid=os.geteuid())


def test_trusted_tree_rejects_foreign_owner(tmp_path):
    root = make_trusted_tree(tmp_path)
    with pytest.raises(deploy.SetupError):
        deploy.assert_trusted_tree(root, owner_uid=os.geteuid() + 1)


@pytest.mark.parametrize("target", ["directory", "module"])
def test_trusted_tree_rejects_descendant_symlinks(tmp_path, target):
    root = make_trusted_tree(tmp_path)
    external = tmp_path / "external"
    external.mkdir(mode=0o755)
    if target == "directory":
        (root / "plugins").symlink_to(external, target_is_directory=True)
    else:
        external_module = external / "other.py"
        external_module.write_text("# test module\n")
        (root / "brawl_proxy" / "other.py").symlink_to(external_module)
    with pytest.raises(deploy.SetupError):
        deploy.assert_trusted_tree(root, owner_uid=os.geteuid())


def test_trusted_tree_allows_venv_lib64_link_only_to_its_lib(tmp_path):
    root = make_trusted_tree(tmp_path)
    venv = root / ".venv"
    venv.mkdir(mode=0o755)
    (venv / "lib").mkdir(mode=0o755)
    (venv / "lib64").symlink_to("lib", target_is_directory=True)
    deploy.assert_trusted_tree(root, owner_uid=os.geteuid(), venv=venv)


def test_trusted_tree_rejects_venv_lib64_redirect(tmp_path):
    root = make_trusted_tree(tmp_path)
    venv = root / ".venv"
    venv.mkdir(mode=0o755)
    external = tmp_path / "other-lib"
    external.mkdir(mode=0o755)
    (venv / "lib64").symlink_to(external, target_is_directory=True)
    with pytest.raises(deploy.SetupError):
        deploy.assert_trusted_tree(root, owner_uid=os.geteuid(), venv=venv)


def test_trusted_tree_allows_protected_venv_interpreter_link(tmp_path):
    root = make_trusted_tree(tmp_path)
    venv = root / ".venv"
    bin_directory = venv / "bin"
    bin_directory.mkdir(mode=0o755, parents=True)
    interpreter = bin_directory / "python3.12"
    interpreter.write_bytes(b"test interpreter")
    interpreter.chmod(0o755)
    (bin_directory / "python").symlink_to("python3.12")
    deploy.assert_trusted_tree(root, owner_uid=os.geteuid(), venv=venv)


def test_trusted_tree_rejects_writable_venv_interpreter_target(tmp_path):
    root = make_trusted_tree(tmp_path)
    venv = root / ".venv"
    bin_directory = venv / "bin"
    bin_directory.mkdir(mode=0o755, parents=True)
    interpreter = bin_directory / "python3.12"
    interpreter.write_bytes(b"test interpreter")
    interpreter.chmod(0o777)
    (bin_directory / "python").symlink_to("python3.12")
    with pytest.raises(deploy.SetupError):
        deploy.assert_trusted_tree(root, owner_uid=os.geteuid(), venv=venv)


@pytest.fixture
def installed_paths(tmp_path, monkeypatch):
    config = tmp_path / "config"
    config.mkdir(mode=0o700)
    binaries = tmp_path / "bin"
    binaries.mkdir(mode=0o755)
    binary = binaries / "brawl-xray"
    binary.write_bytes(b"\x7fELFtest binary")
    binary.chmod(0o755)
    state = tmp_path / "proxy-state"
    state.mkdir(mode=0o700)
    services = tmp_path / "services"
    services.mkdir(mode=0o755)
    unit = services / deploy.SERVICE_NAME
    unit.write_text("[Service]\nExecStart=/usr/bin/test\n")
    unit.chmod(0o644)
    now = datetime(2030, 1, 1, tzinfo=timezone.utc)
    database = tmp_path / "bot-state" / "shop.sqlite"
    store = Store(database, clock=lambda: now)
    try:
        order = store.create_order(11, 11, "android", 100)
        store.accept_payment(order.id, 11, "XTR", 100, "test-migration-payment")
    finally:
        store.close()
    bot = {
        "BOT_TOKEN": BOT_TOKEN,
        "VPN_API_TOKEN": API_TOKEN,
        "VPN_API_URL": "http://127.0.0.1:8081",
        "DATABASE_PATH": str(database),
        "SALES_ENABLED": "true",
        "ADMIN_IDS": "11",
        "STARS_PRICE": "100",
        "SUPPORT_USERNAME": "test_support",
    }
    gateway = {
        "VPN_API_TOKEN": API_TOKEN,
        "WG_ENDPOINT": "vpn.example.com:51820",
        "VPN_GATEWAY_DATABASE": str(tmp_path / "missing-old-gateway.sqlite"),
    }
    private_file(config / "bot.env", deploy.render_env(bot).decode())
    private_file(config / "gateway.env", deploy.render_env(gateway).decode())
    monkeypatch.setattr(deploy, "CONFIG_DIRECTORY", config)
    monkeypatch.setattr(deploy, "BINARY_PATH", binary)
    monkeypatch.setattr(deploy, "STATE_DIRECTORY", state)
    monkeypatch.setattr(deploy, "SERVICE_DIRECTORY", services)
    monkeypatch.setattr(deploy, "account_uid", lambda name, **kwargs: os.geteuid())
    return {
        "bot": bot,
        "gateway": gateway,
        "database": database,
        "binary": binary,
        "config": config,
        "state": state,
        "unit": unit,
    }


def test_healthy_existing_install_passes_without_writing(installed_paths):
    installed = installed_paths
    snapshots = {
        path: path.read_bytes()
        for path in (installed["database"], installed["unit"], installed["binary"])
    }
    assert deploy.preflight_existing_install(
        installed["bot"], installed["gateway"], None, installed["database"],
        owner_uid=os.geteuid(),
    ) == {11}
    assert {path: path.read_bytes() for path in snapshots} == snapshots


def test_preflight_preserves_confirmed_checkout_reservations(installed_paths):
    installed = installed_paths
    legacy_path = Path(installed["gateway"]["VPN_GATEWAY_DATABASE"])
    with sqlite3.connect(legacy_path) as connection:
        connection.execute("CREATE TABLE reservations (user_id INTEGER, reserved_until INTEGER)")
        connection.executemany("INSERT INTO reservations VALUES(?,?)", [(22, None), (33, 1)])
    legacy_path.chmod(0o600)
    assert deploy.preflight_existing_install(
        installed["bot"], installed["gateway"], None, installed["database"],
        owner_uid=os.geteuid(),
    ) == {11, 22}


@pytest.mark.parametrize(
    "unsafe_target",
    ["state", "state-symlink", "state-file-symlink", "binary", "binary-symlink",
     "unit", "unit-symlink", "database", "database-schema", "config"],
)
def test_unsafe_existing_install_refuses_migration_before_service_stop(
    installed_paths, unsafe_target, monkeypatch,
):
    installed = installed_paths
    if unsafe_target == "database-schema":
        installed["database"].unlink()
        with sqlite3.connect(installed["database"]) as connection:
            connection.execute("CREATE TABLE unrelated (value TEXT)")
        installed["database"].chmod(0o600)
    elif unsafe_target == "state-file-symlink":
        (installed["state"] / "runtime.json").symlink_to(installed["binary"])
    elif unsafe_target.endswith("-symlink"):
        path = installed[unsafe_target.removesuffix("-symlink")]
        original = path.with_name(path.name + ".original")
        path.rename(original)
        path.symlink_to(original, target_is_directory=original.is_dir())
    else:
        path = installed[unsafe_target]
        path.chmod(0o755 if unsafe_target == "config" else 0o666)

    calls = []
    original_preflight = deploy.preflight_existing_install
    monkeypatch.setattr(deploy, "assert_supported_host", lambda: None)
    monkeypatch.setattr(deploy, "assert_tcp443_available", lambda **kwargs: None)
    monkeypatch.setattr(deploy, "validate_bot", lambda values: installed["database"])
    monkeypatch.setattr(
        deploy, "preflight_existing_install",
        lambda *args, **kwargs: original_preflight(*args, **kwargs, owner_uid=os.geteuid()),
    )

    def fake_run(args, **kwargs):
        calls.append(args)
        return ""

    def no_download():
        raise AssertionError("Unsafe installations must fail before downloading executables")

    monkeypatch.setattr(deploy, "run", fake_run)
    monkeypatch.setattr(deploy, "release_binary", no_download)
    bot_before = (installed["config"] / "bot.env").read_bytes()
    with pytest.raises(deploy.SetupError):
        deploy.migrate(11)
    assert not any(call[:2] == ["systemctl", "stop"] for call in calls)
    assert (installed["config"] / "bot.env").read_bytes() == bot_before


def test_invalid_reality_key_pair_refuses_before_stopping_existing_services(
    installed_paths, monkeypatch,
):
    from brawl_proxy import manager

    installed = installed_paths
    proxy = deploy.new_proxy_env(installed["gateway"], (PRIVATE_KEY, PUBLIC_KEY))
    private_file(installed["config"] / "proxy.env", deploy.render_env(proxy).decode())
    calls = []
    checked = []

    def reject_pair(settings):
        checked.append(settings)
        raise manager.ProxyUnavailable("Invalid test-only key pair")

    monkeypatch.setattr(deploy, "assert_supported_host", lambda: None)
    monkeypatch.setattr(deploy, "validate_bot", lambda values: installed["database"])
    monkeypatch.setattr(deploy, "run", lambda args, **kwargs: calls.append(args) or "")
    monkeypatch.setattr(manager, "verify_key_pair", reject_pair)
    with pytest.raises(deploy.SetupError) as caught:
        deploy.migrate(11)
    assert len(checked) == 1
    assert checked[0].private_key == PRIVATE_KEY
    assert not any(call[:2] == ["systemctl", "stop"] for call in calls)
    assert PRIVATE_KEY not in str(caught.value)
    assert PUBLIC_KEY not in str(caught.value)


@pytest.mark.parametrize(
    "result, expected_ready",
    [
        ({"ready": True, "backend": "vless-reality"}, True),
        ({"ready": True, "backend": "wireguard"}, False),
        ({"ready": True}, False),
        ({"ready": 1, "backend": "vless-reality"}, False),
    ],
)
def test_health_requires_reality_backend_without_using_environment_http_proxy(
    monkeypatch, result, expected_ready,
):
    calls = []

    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

        def read(self, limit):
            assert limit == 65536
            return json.dumps(result).encode()

    class Opener:
        def open(self, request, timeout):
            assert request.full_url == "http://127.0.0.1:8081/health"
            assert timeout == 2
            assert request.get_header("Authorization") == f"Bearer {API_TOKEN}"
            calls.append(request)
            return Response()

    def build_opener(handler):
        assert isinstance(handler, deploy.urllib.request.ProxyHandler)
        assert handler.proxies == {}
        return Opener()

    ticks = iter([0, 0, 1])
    monkeypatch.setattr(deploy.time, "monotonic", lambda: next(ticks))
    monkeypatch.setattr(deploy.time, "sleep", lambda seconds: None)
    monkeypatch.setattr(deploy.urllib.request, "build_opener", build_opener)
    if expected_ready:
        deploy.wait_ready(API_TOKEN, seconds=1)
    else:
        with pytest.raises(deploy.SetupError):
            deploy.wait_ready(API_TOKEN, seconds=1)
    assert len(calls) == 1


@pytest.mark.parametrize(
    "port, hierarchy, service, allowed",
    [
        (8081, "system.slice", "brawl-vpn-gateway.service", True),
        (8081, "system.slice", "brawl-vpn-proxy.service", True),
        (8081, "system.slice", "brawl-vpn-proxy.service/worker", True),
        (8081, "system.slice", "brawl-vpn-gateway.service.evil", False),
        (8081, "system.slice", "brawl-vpn-proxy.service.evil", False),
        (8081, "user.slice/user-1000.slice/user@1000.service", "brawl-vpn-gateway.service", False),
        (8081, "user.slice/user-1000.slice/user@1000.service", "brawl-vpn-proxy.service", False),
        (443, "system.slice", "brawl-vpn-proxy.service", True),
        (443, "system.slice", "brawl-vpn-proxy.service.evil", False),
        (443, "user.slice/user-1000.slice/user@1000.service", "brawl-vpn-proxy.service", False),
    ],
)
def test_existing_listener_requires_exact_managed_service_cgroup(
    monkeypatch, port, hierarchy, service, allowed,
):
    listeners = (
        f'LISTEN 0 128 0.0.0.0:{port} 0.0.0.0:* users:(("python",pid=123,fd=1))'
    )
    monkeypatch.setattr(deploy, "run", lambda args: listeners)

    def cgroup(path, *args, **kwargs):
        assert path == Path("/proc/123/cgroup")
        return f"0::/{hierarchy}/{service}\n"

    monkeypatch.setattr(deploy.Path, "read_text", cgroup)

    def check_listener():
        if port == 8081:
            deploy.assert_api_port_available()
        else:
            deploy.assert_tcp443_available(rerun=True)

    if allowed:
        check_listener()
    else:
        with pytest.raises(deploy.SetupError):
            check_listener()


def proxy_database(tmp_path, entries=()):
    path = tmp_path / "proxy.sqlite"
    with sqlite3.connect(path) as connection:
        connection.execute("""CREATE TABLE users (
            user_id INTEGER PRIMARY KEY CHECK(user_id > 0),
            uuid TEXT NOT NULL UNIQUE,
            expires_at INTEGER NOT NULL DEFAULT 0,
            reserved_until INTEGER,
            created_at INTEGER NOT NULL
        )""")
        connection.executemany("INSERT INTO users VALUES(?,?,?,?,?)", entries)
    path.chmod(0o600)
    return path


def proxy_rows(path):
    with sqlite3.connect(path) as connection:
        return connection.execute("SELECT * FROM users ORDER BY user_id").fetchall()


def test_reservation_transfer_preserves_existing_identities_and_expiry(tmp_path):
    existing = [
        (11, "4c59c07c-0811-413a-982b-083ec404dbb9", 2345678900, None, 1234567890),
        (22, "6f4b9bfb-a33c-4b87-8747-a585d71f2f04", 0, None, 1234567890),
    ]
    path = proxy_database(tmp_path, existing)
    assert deploy.transfer_reservations(path, {11, 22, 33, 44}) == 2
    rows = proxy_rows(path)
    assert rows[:2] == existing
    assert [row[0] for row in rows[2:]] == [33, 44]
    for row in rows[2:]:
        assert str(UUID(row[1])) == row[1]
        assert UUID(row[1]).version == 4
        assert row[2:4] == (0, None)
    assert len({row[1] for row in rows}) == len(rows)
    assert deploy.transfer_reservations(path, {11, 22, 33, 44}) == 0
    assert proxy_rows(path) == rows


def test_transfer_promotes_existing_finite_hold_without_replacing_identity(tmp_path):
    existing = [(11, "4c59c07c-0811-413a-982b-083ec404dbb9", 0, 2345678900, 1234567890)]
    path = proxy_database(tmp_path, existing)
    assert deploy.transfer_reservations(path, {11}) == 0
    assert proxy_rows(path) == [(*existing[0][:3], None, existing[0][4])]


@pytest.mark.parametrize("invalid_id", [-11, 0])
def test_invalid_transfer_id_cannot_partially_reserve_users(tmp_path, invalid_id):
    path = proxy_database(tmp_path)
    with pytest.raises(deploy.SetupError):
        deploy.transfer_reservations(path, {11, 22, invalid_id})
    assert proxy_rows(path) == []


def test_full_pool_cannot_partially_reserve_migrating_users(tmp_path):
    existing = [(11, "4c59c07c-0811-413a-982b-083ec404dbb9", 0, 2345678900, 1234567890)]
    path = proxy_database(tmp_path, existing)
    with pytest.raises(deploy.SetupError):
        deploy.transfer_reservations(path, {11, 22, 33}, max_users=2)
    assert proxy_rows(path) == existing


@pytest.mark.parametrize(
    "uuid, expiry, reserved_until, created_at",
    [
        ("invalid-test-uuid", 0, None, 1234567890),
        ("4c59c07c-0811-113a-982b-083ec404dbb9", 0, None, 1234567890),
        ("4C59C07C-0811-413A-982B-083EC404DBB9", 0, None, 1234567890),
        ("4c59c07c-0811-413a-982b-083ec404dbb9", -1, None, 1234567890),
        ("4c59c07c-0811-413a-982b-083ec404dbb9", 0, 0, 1234567890),
        ("4c59c07c-0811-413a-982b-083ec404dbb9", 0, -1, 1234567890),
        ("4c59c07c-0811-413a-982b-083ec404dbb9", 0, None, "invalid-created-at"),
    ],
)
def test_existing_proxy_records_are_validated_without_mutation(
    tmp_path, uuid, expiry, reserved_until, created_at,
):
    existing = [(11, uuid, expiry, reserved_until, created_at)]
    path = proxy_database(tmp_path, existing)
    with pytest.raises(deploy.SetupError):
        deploy.proxy_user_ids(path)
    assert proxy_rows(path) == existing
