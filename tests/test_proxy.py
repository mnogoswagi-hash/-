from __future__ import annotations

import base64
import io
import ipaddress
import json
import os
import subprocess
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import parse_qs, urlsplit
from uuid import UUID

import pytest
from fastapi.testclient import TestClient

from brawl_proxy.api import create_app
from brawl_proxy.manager import GAME_DOMAINS, AccessManager, CapacityError, ProxyUnavailable, verify_key_pair, wait_guardian_ready, write_heartbeat
from brawl_proxy.settings import BLOCKED_NETWORKS, Settings
from vpn_shop.provider import _validate_connection_uri, _validate_routing_link, validate_incy_routing


def key(seed):
    return base64.urlsafe_b64encode(bytes([seed]) * 32).decode().rstrip("=")


class FakeProcess:
    def __init__(self, events):
        self.stdin = io.StringIO()
        self.stdout = io.StringIO()
        self.returncode = None
        self.events = events
        self.leases = []
        self.events.append(("spawn", self))

    def poll(self):
        return self.returncode

    def terminate(self):
        self.events.append(("terminate", self))
        self.returncode = 0

    def wait(self, timeout):
        assert timeout <= 3
        self.events.append(("wait", self))
        return self.returncode

    def kill(self):
        self.events.append(("kill", self))
        self.returncode = -9


class FakeSystem:
    def __init__(self):
        self.events = []
        self.processes = []
        self.validations = []
        self.commands = []
        self.fail_validation = False
        self.fail_ack = False
        self.fail_lease = False
        self.checked_keys = 0

    def command(self, args):
        self.commands.append(args)
        if args[0] == "getent":
            return "8.8.4.4 STREAM vpn.example.com\n8.8.4.4 DGRAM\n8.8.4.4 RAW"
        assert args[1:4] == ["run", "-test", "-config"]
        # Native Xray infers the format and rejects an unrecognized .tmp suffix.
        if Path(args[4]).suffix != ".json":
            raise ProxyUnavailable("Xray cannot determine the config format")
        if self.fail_validation:
            raise RuntimeError("private diagnostic must not leak")
        config = json.loads(Path(args[4]).read_text())
        self.validations.append(config)
        self.events.append(("validate", config))
        return "Configuration OK"

    def spawn(self, args, **kwargs):
        assert args[1:3] == ["-m", "brawl_proxy.guardian"]
        assert kwargs["stdin"] == subprocess.PIPE
        assert kwargs["stderr"] == subprocess.DEVNULL
        process = FakeProcess(self.events)
        self.processes.append(process)
        return process

    def ready(self, process):
        assert process.leases, "Lease must arrive before readiness acknowledgement"
        if self.fail_ack:
            raise RuntimeError("sensitive startup stderr")
        self.events.append(("ack", process))

    def heartbeat(self, process, payload):
        if self.fail_lease:
            raise BrokenPipeError("sensitive pipe details")
        lease = json.loads(payload)
        assert set(lease) == {"ttl"} and 0 < lease["ttl"] <= 30
        process.leases.append(lease["ttl"])
        self.events.append(("lease", lease["ttl"]))

    def keys(self, settings):
        self.checked_keys += 1


@pytest.fixture
def settings(tmp_path):
    return Settings(api_token="x" * 40, endpoint="8.8.4.4:443", private_key=key(50), public_key=key(80), short_id="0123456789abcdef", database=tmp_path / "state" / "proxy.sqlite", runtime_config=tmp_path / "state" / "runtime.json", xray_binary=Path("/usr/local/bin/brawl-xray"))


def manager_for(settings, system, now):
    return AccessManager(settings, command=system.command, process_factory=system.spawn, ready_reader=system.ready, heartbeat_writer=system.heartbeat, key_checker=system.keys, clock=lambda: now[0], monotonic=lambda: now[0])


@pytest.fixture
def runtime(settings):
    system = FakeSystem()
    now = [1_800_000_000.0]
    manager = manager_for(settings, system, now)
    manager.initialize()
    yield manager, system, now
    manager.close()


def expiry(now, seconds=30 * 86400):
    return datetime.fromtimestamp(now + seconds, timezone.utc).isoformat()


def test_settings_requires_strong_auth_and_reality_metadata(settings):
    cases = ({"api_token": "short"}, {"api_token": "ю" * 40}, {"api_token": "x " * 20}, {"endpoint": "127.0.0.1:443"}, {"endpoint": "8.8.4.4:80"}, {"private_key": "bad"}, {"public_key": "A" * 43}, {"short_id": "12"}, {"server_name": "localhost"}, {"target": "example.com:443"}, {"max_users": 1001}, {"reconcile_seconds": 6})
    for changes in cases:
        with pytest.raises(ValueError):
            replace(settings, **changes)
    padded = replace(settings, private_key=settings.private_key + "=", public_key=settings.public_key + "=")
    assert padded.private_key == settings.private_key
    assert padded.public_key == settings.public_key


def test_settings_allows_domain_only_routing_and_rejects_broad_cidrs(settings):
    assert settings.game_cidrs == ()
    for cidrs in ((ipaddress.ip_network("0.0.0.0/0"),), (ipaddress.ip_network("10.0.0.0/24"),), (ipaddress.ip_network("224.0.0.0/24"),), (ipaddress.ip_network("2001:4860::/32"),), (ipaddress.ip_network("1.1.1.0/24"), ipaddress.ip_network("1.1.1.1/32"))):
        with pytest.raises(ValueError):
            replace(settings, game_cidrs=cidrs)


def test_settings_mapping_defaults_and_repr_do_not_leak_keys(settings):
    env = {"VPN_API_TOKEN": settings.api_token, "XRAY_ENDPOINT": settings.endpoint, "XRAY_PRIVATE_KEY": settings.private_key, "XRAY_PUBLIC_KEY": settings.public_key, "XRAY_SHORT_ID": settings.short_id}
    loaded = Settings.from_env(env)
    assert loaded.database == Path("/var/lib/brawl-proxy/proxy.sqlite")
    assert loaded.runtime_config == Path("/var/lib/brawl-proxy/runtime.json")
    assert loaded.max_users == 1000 and loaded.reconcile_seconds == 5
    assert loaded.game_cidrs == ()
    for secret in (settings.api_token, settings.private_key, settings.public_key, settings.short_id):
        assert secret not in repr(loaded)


def test_zero_clients_startup_is_ready_only_after_validation_and_ack(runtime):
    manager, system, _ = runtime
    assert manager.health()
    assert system.validations[0]["inbounds"][0]["settings"]["clients"] == []
    kinds = [kind for kind, _ in system.events]
    assert kinds.index("validate") < kinds.index("spawn") < kinds.index("lease") < kinds.index("ack")
    assert system.checked_keys == 1


def test_staged_configuration_retains_xray_json_format_and_is_removed(runtime):
    manager, system, _ = runtime
    validation = next(command for command in system.commands if command[1:4] == ["run", "-test", "-config"])
    staged = Path(validation[4])
    assert staged.suffix == ".json"
    assert staged.parent == manager.settings.runtime_config.parent
    assert not staged.exists()
    assert manager.settings.runtime_config.exists()


def test_dormant_checkout_does_not_create_an_xray_client(runtime):
    manager, system, _ = runtime
    assert manager.prepare(123) == {"ready": True}
    assert len(system.processes) == 1
    assert len(system.validations) == 1
    row = manager.connection.execute("SELECT * FROM users").fetchone()
    assert UUID(row["uuid"]).version == 4
    assert row["expires_at"] == 0
    assert row["reserved_until"] is not None
    manager.prepare(123, payment_pending=True)
    assert manager.connection.execute("SELECT reserved_until FROM users").fetchone()[0] is None


def test_paid_profiles_are_stable_and_accepted_by_bot_validator(runtime):
    manager, system, now = runtime
    manager.prepare(123, payment_pending=True)
    first = manager.access(123, expiry(now[0]))
    repeated = manager.access(123, expiry(now[0], 60))
    assert first == repeated
    assert first["kind"] == "incy"
    _validate_connection_uri(first["connection_uri"])
    _validate_routing_link(first["routing_link"])
    validate_incy_routing(manager.routing_profile())
    query = parse_qs(urlsplit(first["connection_uri"]).query)
    assert query["spx"] == ["/"]
    assert "spx=%2F" in first["connection_uri"]
    assert manager.connection.execute("SELECT expires_at FROM users").fetchone()[0] == now[0] + 30 * 86400
    assert len(system.validations[-1]["inbounds"][0]["settings"]["clients"]) == 1
    assert len(system.processes) == 2  # Initial zero-peer + first paid membership.


def test_game_only_policy_blocks_reserved_endpoint_ipv6_and_general_traffic(runtime):
    manager, system, _ = runtime
    config = system.validations[-1]
    assert config["inbounds"][0]["sniffing"] == {"enabled": False}
    assert config["routing"]["domainStrategy"] == "IPOnDemand"
    rules = config["routing"]["rules"]
    assert rules[0]["outboundTag"] == "blocked"
    assert set(BLOCKED_NETWORKS).issubset(rules[0]["ip"])
    assert "8.8.4.4/32" in rules[0]["ip"] and "::/0" in rules[0]["ip"]
    assert rules[1] == {"type": "field", "ip": ["1.1.1.1/32"], "port": "53", "network": "tcp,udp", "outboundTag": "game"}
    assert rules[2]["ip"] == ["1.1.1.1/32"] and rules[2]["outboundTag"] == "blocked"
    assert rules[3]["domain"] == list(GAME_DOMAINS)
    assert rules[3]["ip"] == ["0.0.0.0/0"]  # DNS must succeed before domain allows.
    assert rules[-1] == {"type": "field", "network": "tcp,udp", "outboundTag": "blocked"}
    assert config["outbounds"][0]["protocol"] == "blackhole"
    assert config["outbounds"][1]["settings"]["domainStrategy"] == "ForceIPv4"
    assert config["dns"]["queryStrategy"] == "UseIPv4"
    assert all("geoip:" not in json.dumps(rule) and "geosite:" not in json.dumps(rule) for rule in rules)
    assert manager.routing_profile()["GlobalProxy"] == "false"


def test_optional_reviewed_cidrs_match_server_and_client(settings):
    settings = replace(settings, game_cidrs=(ipaddress.ip_network("8.8.8.8/32"),))
    system, now = FakeSystem(), [1_800_000_000.0]
    manager = manager_for(settings, system, now)
    try:
        manager.initialize()
        rules = system.validations[-1]["routing"]["rules"]
        assert rules[-2]["ip"] == ["8.8.8.8/32"]
        assert manager.routing_profile()["ProxyIp"] == ["8.8.8.8/32"]
        _validate_routing_link(manager.routing_link())
    finally:
        manager.close()


def test_heartbeat_never_outlives_nearest_active_paid_expiry(runtime):
    manager, system, now = runtime
    manager.access(123, expiry(now[0], 11))
    assert max(system.processes[-1].leases) <= 11
    now[0] += 7
    manager.reconcile()
    assert system.processes[-1].leases[-1] == 4
    now[0] += 4
    old = system.processes[-1]
    assert not manager.health()
    assert old.poll() is not None
    manager.reconcile()
    assert manager.health()
    assert system.validations[-1]["inbounds"][0]["settings"]["clients"] == []
    assert system.processes[-1].leases[-1] == 30


def test_expiry_restarts_core_and_closes_existing_cached_connections(runtime):
    manager, system, now = runtime
    manager.access(123, expiry(now[0], 11))
    old = manager.process
    now[0] += 12
    manager.reconcile()
    assert old.poll() is not None
    events = system.events
    termination = next(index for index, event in enumerate(events) if event == ("terminate", old))
    subsequent_validation = next(index for index in range(termination + 1, len(events)) if events[index][0] == "validate")
    assert termination < subsequent_validation
    assert manager.process is not old
    assert system.validations[-1]["inbounds"][0]["settings"]["clients"] == []


def test_guardian_death_or_missing_maintenance_fails_closed(runtime):
    manager, system, now = runtime
    manager.process.returncode = 1
    assert not manager.health()
    with pytest.raises(ProxyUnavailable):
        manager.prepare(123)
    manager.reconcile()
    assert manager.health()
    process = manager.process
    now[0] += manager.settings.reconcile_seconds * 3 + 1
    assert not manager.health()
    assert process.poll() is not None


@pytest.mark.parametrize("failure", ["fail_validation", "fail_ack", "fail_lease"])
def test_runtime_failure_stops_core_and_never_returns_profiles(runtime, failure):
    manager, system, now = runtime
    old = manager.process
    setattr(system, failure, True)
    with pytest.raises(ProxyUnavailable, match="reconciliation failed") as caught:
        manager.access(123, expiry(now[0]))
    assert not manager.ready
    assert old.poll() is not None
    assert manager.process is None
    assert "sensitive" not in str(caught.value)
    assert "private diagnostic" not in str(caught.value)


def test_persisted_paid_uuid_rehydrates_and_expiry_is_never_shortened(runtime):
    manager, system, now = runtime
    original = manager.access(123, expiry(now[0], 730 * 86400))
    manager.close()
    restarted = manager_for(manager.settings, system, now)
    restarted.initialize()
    assert restarted.access(123, expiry(now[0], 60)) == original
    assert restarted.connection.execute("SELECT expires_at FROM users").fetchone()[0] == now[0] + 730 * 86400
    # Fixture cleans up these adopted live handles.
    manager.connection, manager.lock_fd, manager.process = restarted.connection, restarted.lock_fd, restarted.process


def test_capacity_reservations_are_atomic_and_preserve_accepted_payments(settings):
    settings = replace(settings, max_users=1)
    system, now = FakeSystem(), [1_800_000_000.0]
    manager = manager_for(settings, system, now)
    try:
        manager.initialize()
        manager.prepare(123)
        assert manager.health() and not manager.has_capacity()
        with pytest.raises(CapacityError):
            manager.prepare(456)
        now[0] += 3601
        manager.reconcile()
        manager.prepare(456, payment_pending=True)
        now[0] += 100 * 86400
        manager.reconcile()
        with pytest.raises(CapacityError):
            manager.prepare(123)
        manager.access(456, expiry(now[0], 60))
        now[0] += 61
        manager.reconcile()
        assert manager.prepare(456) == {"ready": True}
        with pytest.raises(CapacityError):
            manager.prepare(789)
    finally:
        manager.close()


def test_state_is_private_and_runtime_changes_fail_closed(runtime):
    manager, _, _ = runtime
    assert manager.settings.database.stat().st_mode & 0o777 == 0o600
    assert manager.settings.runtime_config.stat().st_mode & 0o777 == 0o640
    assert manager.settings.database.parent.stat().st_mode & 0o777 == 0o700
    manager.settings.runtime_config.write_text("{}\n")
    assert not manager.health()
    assert manager.process is None


def test_endpoint_hostname_is_resolved_and_its_ip_blocked(settings):
    settings = replace(settings, endpoint="vpn.example.com:443")
    system, now = FakeSystem(), [1_800_000_000.0]
    manager = manager_for(settings, system, now)
    try:
        manager.initialize()
        assert ["getent", "ahostsv4", "vpn.example.com"] in system.commands
        assert "8.8.4.4/32" in system.validations[-1]["routing"]["rules"][0]["ip"]
    finally:
        manager.close()


def test_private_endpoint_dns_cannot_start_core(settings):
    settings = replace(settings, endpoint="vpn.example.com:443")
    system, now = FakeSystem(), [1_800_000_000.0]
    system.command = lambda args: "127.0.0.1 STREAM vpn.example.com"
    manager = manager_for(settings, system, now)
    try:
        with pytest.raises(ProxyUnavailable):
            manager.initialize()
        assert system.processes == []
    finally:
        manager.close()


def test_rejects_expired_or_non_utc_provisioning(runtime):
    manager, _, now = runtime
    for value in (expiry(now[0], -1), "2026-10-08T12:00:00", "2026-10-08T12:00:00+04:00", "invalid"):
        with pytest.raises(ValueError):
            manager.access(123, value)


def test_openssl_pair_check_uses_private_stdin_and_redacts_errors(settings, monkeypatch):
    calls = []

    class Result:
        returncode = 0
        stdout = bytes.fromhex("302a300506032b656e032100") + base64.urlsafe_b64decode(settings.public_key + "=")

    def run(args, **kwargs):
        calls.append((args, kwargs))
        assert settings.private_key not in args
        assert kwargs["input"] == bytes.fromhex("302e020100300506032b656e04220420") + base64.urlsafe_b64decode(settings.private_key + "=")
        assert kwargs["timeout"] == 5
        return Result()

    monkeypatch.setattr(subprocess, "run", run)
    verify_key_pair(settings)
    assert len(calls) == 1
    Result.stdout = b"a secret diagnostic"
    with pytest.raises(ProxyUnavailable) as caught:
        verify_key_pair(settings)
    assert "secret diagnostic" not in str(caught.value)


def test_bounded_heartbeat_writer_sends_only_ttl_json():
    read_fd, write_fd = os.pipe()
    process = type("Process", (), {})()
    process.stdin = os.fdopen(write_fd, "w")
    try:
        write_heartbeat(process, '{"ttl":3.5}\n')
        assert os.read(read_fd, 256) == b'{"ttl":3.5}\n'
    finally:
        process.stdin.close()
        os.close(read_fd)


@pytest.mark.parametrize("message,expected_ready", [(b'{"ready":true}\n', True), (b'{"ready":1}\n', False), (b'{"ready":false}\n', False), (b'{"ready":true,"extra":1}\n', False)])
def test_readiness_protocol_requires_strict_true_ack(message, expected_ready):
    read_fd, write_fd = os.pipe()
    process = type("Process", (), {})()
    process.stdout = os.fdopen(read_fd, "rb")
    process.poll = lambda: None
    try:
        os.write(write_fd, message)
        if expected_ready:
            wait_guardian_ready(process)
        else:
            with pytest.raises(ProxyUnavailable):
                wait_guardian_ready(process)
    finally:
        process.stdout.close()
        os.close(write_fd)


def test_http_contract_auth_and_strict_types(settings):
    system, now = FakeSystem(), [1_800_000_000.0]
    manager = manager_for(settings, system, now)
    with TestClient(create_app(settings, manager)) as client:
        assert client.get("/health").status_code == 401
        headers = {"Authorization": "Bearer " + settings.api_token}
        assert client.get("/health", headers=headers).json() == {"ready": True, "capacity_available": True, "backend": "vless-reality"}
        assert client.post("/prepare", headers=headers, json={"user_id": 123, "payment_pending": True}).json() == {"ready": True}
        response = client.post("/access", headers=headers, json={"user_id": 123, "expires_at": expiry(now[0])})
        assert response.status_code == 200
        assert set(response.json()) == {"kind", "connection_uri", "routing_link"}
        assert client.post("/access", headers=headers, json={"user_id": True, "expires_at": expiry(now[0])}).status_code == 422
