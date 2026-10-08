from __future__ import annotations

import base64
import getpass
import importlib.util
import json
import os
import sys
import warnings
from pathlib import Path

import pytest


spec = importlib.util.spec_from_file_location("deploy_configure_vds", Path(__file__).resolve().parents[1] / "deploy" / "configure-vds.py")
deploy = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = deploy
spec.loader.exec_module(deploy)

BOT_TOKEN = "123456789:" + "test_token_without_real_credentials_12345"
PRIVATE_KEY = base64.b64encode(bytes([51]) * 32).decode()
PUBLIC_KEY = base64.b64encode(bytes([81]) * 32).decode()


@pytest.fixture
def prepared(tmp_path):
    directory = tmp_path / "config"
    directory.mkdir(mode=0o700)
    wireguard = tmp_path / "wg-brawl.conf"
    wireguard.write_text(f"[Interface]\nPrivateKey = {PRIVATE_KEY}\nAddress = 10.67.0.1/24\nListenPort = 51820\nSaveConfig = false\n")
    wireguard.chmod(0o600)
    calls = []

    def run(args, stdin=None):
        calls.append((args, stdin))
        if args == ["wg", "pubkey"]:
            assert stdin == PRIVATE_KEY + "\n"
            assert PRIVATE_KEY not in args
            return PUBLIC_KEY
        if args == ["ip", "-4", "-j", "route", "show", "default"]:
            assert stdin is None
            return json.dumps([{"dst": "default", "gateway": "192.168.1.1", "dev": "ens3", "metric": 100}])
        raise AssertionError("Unexpected system command")

    return directory, wireguard, run, calls


def configure(prepared, *, cidrs="", token=BOT_TOKEN, **overrides):
    directory, wireguard, run, _ = prepared
    inputs = iter(["@my_support", "vpn.example.com", cidrs])
    outputs = []
    arguments = dict(configuration_directory=directory, wireguard_path=wireguard, run=run, prompt=lambda _: next(inputs), secret_prompt=lambda _: token, is_tty=lambda: True, effective_uid=lambda: 0, emit=outputs.append)
    arguments.update(overrides)
    return deploy.configure(**arguments), outputs


def read_env(path):
    return dict(line.split("=", 1) for line in path.read_text().splitlines())


def test_private_configs_share_token_and_selected_tariff(prepared):
    # Test-only destinations exercise validation; no game list is shipped.
    result, output = configure(prepared, cidrs="8.8.8.8/32, 1.1.1.0/24")
    bot = read_env(result.bot_path)
    gateway = read_env(result.gateway_path)
    assert bot["BOT_TOKEN"] == BOT_TOKEN
    assert bot["STARS_PRICE"] == "100"
    assert bot["SUPPORT_USERNAME"] == "my_support"
    assert bot["VPN_API_URL"] == "http://127.0.0.1:8081"
    assert bot["DATABASE_PATH"] == "/var/lib/brawl-vpn-bot/shop.sqlite"
    assert bot["VPN_API_TOKEN"] == gateway["VPN_API_TOKEN"]
    assert len(bot["VPN_API_TOKEN"]) >= 32
    assert gateway["WG_SERVER_PUBLIC_KEY"] == PUBLIC_KEY
    assert gateway["WG_PUBLIC_INTERFACE"] == "ens3"
    assert gateway["WG_CLIENT_SUBNET"] == "10.67.0.0/24"
    assert gateway["WG_GATEWAY_ADDRESS"] == "10.67.0.1"
    assert gateway["WG_ENDPOINT"] == "vpn.example.com:51820"
    assert gateway["GAME_ALLOWED_CIDRS"] == "8.8.8.8/32,1.1.1.0/24"
    assert result.stars_price == 100 and result.plan_days == 30
    for path in (result.bot_path, result.gateway_path):
        assert path.stat().st_mode & 0o777 == 0o600
    assert sorted(path.name for path in result.bot_path.parent.iterdir()) == ["bot.env", "gateway.env"]
    assert result.game_cidrs_configured
    assert not any(secret in "\n".join(output) for secret in (BOT_TOKEN, PRIVATE_KEY, bot["VPN_API_TOKEN"]))


def test_blank_game_ranges_keep_gateway_unconfigured(prepared):
    result, output = configure(prepared)
    values = read_env(result.gateway_path)
    assert values["GAME_ALLOWED_CIDRS"] == ""
    assert not result.game_cidrs_configured
    assert any("не принимает оплату" in line for line in output)
    with pytest.raises(ValueError, match="Missing gateway settings: GAME_ALLOWED_CIDRS"):
        deploy.GatewaySettings.from_env(values)


@pytest.mark.parametrize("target", ["bot.env", "gateway.env"])
def test_preserves_existing_configuration_before_prompts(prepared, target):
    directory, _, _, calls = prepared
    existing = directory / target
    existing.write_text("original configuration\n")

    def never_prompt(_):
        raise AssertionError("Must refuse existing settings before secret prompt")

    with pytest.raises(deploy.ConfigurationError, match="уже существует"):
        configure(prepared, prompt=never_prompt, secret_prompt=never_prompt)
    assert existing.read_text() == "original configuration\n"
    assert [path.name for path in directory.iterdir()] == [target]
    assert calls == []


def test_dangling_target_symlink_is_preserved(prepared):
    directory, _, _, calls = prepared
    target = directory / "bot.env"
    target.symlink_to(directory / "missing-target")
    with pytest.raises(deploy.ConfigurationError, match="уже существует"):
        configure(prepared)
    assert target.is_symlink()
    assert os.readlink(target) == str(directory / "missing-target")
    assert calls == []


def test_non_tty_refuses_without_changes_or_secret_input(prepared):
    directory, _, _, calls = prepared
    with pytest.raises(deploy.ConfigurationError, match="TTY"):
        configure(prepared, is_tty=lambda: False)
    assert list(directory.iterdir()) == []
    assert calls == []


def test_requires_root_before_reading_private_key(prepared):
    directory, _, _, calls = prepared
    with pytest.raises(deploy.ConfigurationError, match="sudo"):
        configure(prepared, effective_uid=lambda: 1234)
    assert list(directory.iterdir()) == []
    assert calls == []


def test_visible_getpass_fallback_is_blocked_before_token_input(prepared):
    directory, _, _, _ = prepared
    echo_attempt = []

    def unsafe_getpass(_):
        warnings.warn("echo unavailable", getpass.GetPassWarning)
        echo_attempt.append(True)
        return BOT_TOKEN

    with pytest.raises(deploy.ConfigurationError, match="Скрытый ввод") as caught:
        configure(prepared, secret_prompt=unsafe_getpass)
    assert echo_attempt == []
    assert BOT_TOKEN not in str(caught.value)
    assert list(directory.iterdir()) == []


def test_token_validation_does_not_echo_invalid_secret(prepared):
    directory, _, _, _ = prepared
    invalid_secret = "invalid_super_secret_token"
    with pytest.raises(deploy.ConfigurationError, match="BOT_TOKEN") as caught:
        configure(prepared, token=invalid_secret)
    assert invalid_secret not in str(caught.value)
    assert list(directory.iterdir()) == []


@pytest.mark.parametrize("cidrs", ["0.0.0.0/0", "10.0.0.0/24", "1.1.1.0/24,1.1.1.1/32", "1.1.1.0/24,", "1.1.1.0/24\nEVIL=value"])
def test_invalid_game_ranges_rejected_before_creating_files(prepared, cidrs):
    directory, _, _, _ = prepared
    with pytest.raises(deploy.ConfigurationError, match="GAME_ALLOWED_CIDRS"):
        configure(prepared, cidrs=cidrs)
    assert list(directory.iterdir()) == []


def test_wg_parser_never_exposes_secret_lines(prepared):
    directory, wireguard, run, _ = prepared
    wireguard.write_text(f"[Interface]\nPrivateKey = {PRIVATE_KEY}\nAddress = 10.67.0.1/24\nListenPort = 51820\n{PRIVATE_KEY}\n")
    with pytest.raises(deploy.ConfigurationError) as caught:
        deploy.read_wireguard(wireguard, run)
    assert PRIVATE_KEY not in str(caught.value)
    assert list(directory.iterdir()) == []


def test_rejects_insecure_or_symlink_wireguard_file(prepared):
    _, wireguard, run, _ = prepared
    wireguard.chmod(0o644)
    with pytest.raises(deploy.ConfigurationError, match="0600"):
        deploy.read_wireguard(wireguard, run)
    wireguard.chmod(0o600)
    target = wireguard.with_name("original.conf")
    wireguard.rename(target)
    wireguard.symlink_to(target)
    with pytest.raises(deploy.ConfigurationError):
        deploy.read_wireguard(wireguard, run)
    assert target.exists()


def test_detects_lowest_metric_egress_and_rejects_ambiguity():
    assert deploy.detect_egress(lambda args: json.dumps([{"dev": "eth9", "metric": 50}, {"dev": "ens3", "metric": 10}])) == "ens3"
    with pytest.raises(deploy.ConfigurationError):
        deploy.detect_egress(lambda args: json.dumps([{"dev": "eth9", "metric": 10}, {"dev": "ens3", "metric": 10}]))


def test_configuration_draft_repr_redacts_all_secrets(prepared):
    _, wireguard, run, _ = prepared
    draft = deploy.create_draft(bot_token=BOT_TOKEN, support_username="@my_support", public_host="vpn.example.com", game_cidrs="", wireguard=deploy.read_wireguard(wireguard, run), public_interface="ens3")
    assert BOT_TOKEN not in repr(draft)
    assert draft.bot_env["VPN_API_TOKEN"] not in repr(draft)


def test_second_commit_failure_rolls_back_only_new_files(prepared, monkeypatch):
    directory, _, _, _ = prepared
    original_link = deploy.os.link
    calls = []

    def failing_link(source, target, **kwargs):
        calls.append(target)
        if len(calls) == 2:
            raise OSError("synthetic disk error containing " + BOT_TOKEN)
        return original_link(source, target, **kwargs)

    monkeypatch.setattr(deploy.os, "link", failing_link)
    with pytest.raises(deploy.ConfigurationError) as caught:
        configure(prepared)
    assert BOT_TOKEN not in str(caught.value)
    assert list(directory.iterdir()) == []


def test_target_created_during_commit_is_never_overwritten_or_removed(prepared, monkeypatch):
    directory, _, _, _ = prepared
    original_link = deploy.os.link

    def raced_link(source, target, **kwargs):
        if target == "gateway.env":
            (directory / target).write_text("other process config\n")
        return original_link(source, target, **kwargs)

    monkeypatch.setattr(deploy.os, "link", raced_link)
    with pytest.raises(deploy.ConfigurationError):
        configure(prepared)
    assert (directory / "gateway.env").read_text() == "other process config\n"
    assert not (directory / "bot.env").exists()
    assert [path.name for path in directory.iterdir()] == ["gateway.env"]


def test_render_rejects_line_injection_before_any_writes(prepared):
    directory, _, _, _ = prepared
    draft = deploy.ConfigurationDraft({"BOT_TOKEN": BOT_TOKEN + "\nEVIL=value"}, {}, False)
    with pytest.raises(deploy.ConfigurationError):
        deploy.write_configuration(directory, draft)
    assert list(directory.iterdir()) == []


def test_command_failure_output_is_not_exposed(monkeypatch):
    class Failure:
        returncode = 1
        stdout = PRIVATE_KEY
        stderr = BOT_TOKEN

    monkeypatch.setattr(deploy.subprocess, "run", lambda *args, **kwargs: Failure())
    with pytest.raises(deploy.ConfigurationError) as caught:
        deploy.command_output(["wg", "pubkey"], PRIVATE_KEY + "\n")
    assert PRIVATE_KEY not in str(caught.value)
    assert BOT_TOKEN not in str(caught.value)
