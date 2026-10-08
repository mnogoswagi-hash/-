from __future__ import annotations

import base64
import ipaddress
from dataclasses import replace
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

from vpn_gateway.api import create_app
from vpn_gateway.firewall import Firewall
from vpn_gateway.manager import AccessManager, CapacityError, GatewayUnavailable
from vpn_gateway.settings import Settings
from vpn_gateway.system import Runner, SystemCommandError


def key(seed: int) -> str:
    return base64.b64encode(bytes([seed]) * 32).decode()


class FakeRunner(Runner):
    """Emulate privileged commands without touching real host networking."""

    def __init__(self, settings: Settings):
        self.settings = settings
        self.calls: list[list[str]] = []
        self.peers: dict[str, str] = {}
        self.generated = 0
        self.chains = {
            ("iptables", "filter"): {"FORWARD": [], "INPUT": []},
            ("iptables", "nat"): {"POSTROUTING": []},
            ("ip6tables", "filter"): {"FORWARD": [], "INPUT": []},
        }
        self.set_exists = False
        self.leases: dict[str, int] = {}
        self.fail_wg_set = False
        self.forward = "1"
        self.egress = settings.public_interface
        self.public_key = settings.server_public_key
        self.listen_port = settings.endpoint.rpartition(":")[2]

    def run(self, args, *, stdin=None, check=True):
        args = list(args)
        self.calls.append(args)
        if args[:2] == ["wg", "genkey"]:
            self.generated += 1
            return key(self.generated)
        if args[:2] == ["wg", "pubkey"]:
            assert stdin == key(self.generated) + "\n"
            return key(self.generated + 100)
        if args[:2] == ["wg", "show"]:
            if args[3] == "public-key":
                return self.public_key
            if args[3] == "listen-port":
                return self.listen_port
            return "\n".join(f"{public}\t{allowed}" for public, allowed in self.peers.items())
        if args[:2] == ["wg", "set"]:
            if self.fail_wg_set:
                raise SystemCommandError("wg failed")
            if args[5] == "remove":
                self.peers.pop(args[4], None)
            else:
                self.peers[args[4]] = args[6]
            return ""
        if args[:3] == ["ip", "-4", "route"]:
            return f"default via 192.168.1.1 dev {self.egress}"
        if args[:2] == ["ip", "-4"]:
            return f"8: {self.settings.interface} inet {self.settings.gateway_address}/{self.settings.client_subnet.prefixlen} scope global"
        if args[0] == "sysctl":
            return self.forward
        if args[0] in {"iptables-save", "ip6tables-save"}:
            binary = args[0].removesuffix("-save")
            table = args[2]
            chains = self.chains[(binary, table)]
            return "\n".join(" ".join(["-A", name, *rule]) for name, rules in chains.items() for rule in rules)
        if args[0] in {"iptables", "ip6tables"}:
            chains = self.chains[(args[0], args[4])]
            operation, chain = args[5:7]
            rest = args[7:]
            if operation == "-N":
                if chain in chains:
                    raise SystemCommandError("chain exists")
                chains[chain] = []
                return ""
            if chain not in chains:
                raise SystemCommandError("chain missing")
            rules = chains[chain]
            if operation == "-S":
                return "\n".join([f"-N {chain}", *(" ".join(["-A", chain, *rule]) for rule in rules)])
            if operation == "-C":
                if rest not in rules:
                    raise SystemCommandError("rule missing")
            elif operation == "-F":
                rules.clear()
            elif operation == "-A":
                rules.append(rest)
            elif operation == "-I":
                rules.insert(int(rest[0]) - 1, rest[1:])
            elif operation == "-R":
                rules[int(rest[0]) - 1] = rest[1:]
            elif operation == "-D":
                if len(rest) == 1 and rest[0].isdecimal():
                    rules.pop(int(rest[0]) - 1)
                else:
                    rules.remove(rest)
            return ""
        if args[0] == "ipset":
            if args[1] == "create":
                self.set_exists = True
            elif args[1] == "flush":
                self.leases.clear()
            elif args[1] == "add":
                self.leases[args[3]] = int(args[5])
            elif args[1] == "del":
                self.leases.pop(args[3], None)
            elif args[1] == "list":
                if not self.set_exists:
                    raise SystemCommandError("set missing")
                return "Name: brawl_active\nType: hash:ip\nHeader: family inet hashsize 1024 maxelem 65536 timeout 86400"
            return ""
        raise AssertionError(f"Unexpected command: {args}")


@pytest.fixture
def settings(tmp_path):
    # Deliberately arbitrary public TEST destinations; never shipped as game defaults.
    return Settings(api_token="x" * 40, server_public_key=key(200), endpoint="vpn.example.com:51820", game_cidrs=(ipaddress.ip_network("8.8.8.8/32"), ipaddress.ip_network("1.1.1.0/24")), database=tmp_path / "state" / "gateway.sqlite")


@pytest.fixture
def runtime(settings):
    now = [1_800_000_000.0]
    runner = FakeRunner(settings)
    manager = AccessManager(settings, runner, clock=lambda: now[0], monotonic=lambda: now[0])
    manager.initialize()
    yield manager, runner, now
    manager.close()


def expiry(now, seconds=30 * 86400):
    return datetime.fromtimestamp(now + seconds, tz=timezone.utc).isoformat()


def test_rejects_empty_or_unrestricted_game_ranges(settings):
    for ranges in ((), (ipaddress.ip_network("0.0.0.0/0"),), (ipaddress.ip_network("10.0.0.0/24"),), (ipaddress.ip_network("2001:4860::/32"),)):
        with pytest.raises(ValueError):
            replace(settings, game_cidrs=ranges)


def test_rejects_invalid_runtime_settings(settings):
    for values in ({"api_token": "short"}, {"api_token": "я" * 40}, {"api_token": "a " * 20}, {"endpoint": "127.0.0.1:51820"}, {"endpoint": "bad\nhost:51820"}, {"interface": "wg;echo"}, {"gateway_address": ipaddress.ip_address("10.66.1.1")}, {"public_interface": "wg-brawl"}):
        with pytest.raises(ValueError):
            replace(settings, **values)


def test_no_implicit_game_allowlist_or_auth_token():
    with pytest.raises(ValueError):
        Settings.from_env({})


def test_prepare_reserves_before_payment_without_granting_vpn(runtime):
    manager, runner, now = runtime
    assert manager.prepare(111) == {"ready": True}
    assert runner.generated == 0
    assert runner.peers == {}
    assert runner.leases == {}
    reservation = manager.connection.execute("SELECT * FROM reservations").fetchone()
    assert reservation["reserved_until"] == int(now[0]) + 3600
    manager.prepare(111, payment_pending=True)
    assert manager.connection.execute("SELECT reserved_until FROM reservations").fetchone()[0] is None


def test_idempotent_profiles_and_never_shortens_expiry(runtime):
    manager, runner, now = runtime
    manager.prepare(111, payment_pending=True)
    first = manager.access(111, expiry(now[0]))
    repeated = manager.access(111, expiry(now[0], 60))
    assert first == repeated
    assert runner.generated == 1
    assert manager.connection.execute("SELECT expires_at FROM peers").fetchone()[0] == now[0] + 30 * 86400
    assert "IncludedApplications = com.supercell.brawlstars" in first["android_config"]
    assert "IncludedApplications" not in first["ios_config"]
    assert "AllowedIPs = 8.8.8.8/32, 1.1.1.0/24" in first["ios_config"]
    assert "0.0.0.0/0" not in first["ios_config"]
    assert "DNS =" not in first["ios_config"]


def test_extended_subscriptions_can_exceed_a_year(runtime):
    manager, _, now = runtime
    manager.access(111, expiry(now[0], 730 * 86400))
    assert manager.connection.execute("SELECT expires_at FROM peers").fetchone()[0] == now[0] + 730 * 86400


def test_kernel_timeout_never_exceeds_paid_expiry(runtime):
    manager, runner, now = runtime
    manager.access(111, expiry(now[0], 90))
    assert list(runner.leases.values()) == [90]
    manager.access(222, expiry(now[0]))
    assert max(runner.leases.values()) <= 86400


def test_expiration_removes_lease_before_peer_even_if_wg_fails(runtime):
    manager, runner, now = runtime
    profile = manager.access(111, expiry(now[0], 60))
    now[0] += 61
    runner.fail_wg_set = True
    with pytest.raises(SystemCommandError):
        manager.expire_only()
    assert runner.leases == {}
    assert runner.peers  # Failed removal is still unable to forward through ipset.
    runner.fail_wg_set = False
    manager.expire_only()
    assert runner.peers == {}
    now[0] += 1
    manager.reconcile()
    renewed = manager.access(111, expiry(now[0], 60))
    assert renewed == profile


def test_rehydrates_database_after_restart(runtime):
    manager, runner, now = runtime
    expected = manager.access(111, expiry(now[0]))
    manager.close()
    runner.peers.clear()
    runner.leases.clear()
    restarted = AccessManager(manager.settings, runner, clock=lambda: now[0], monotonic=lambda: now[0])
    restarted.initialize()
    assert restarted.access(111, expiry(now[0])) == expected
    assert len(runner.peers) == 1
    assert runner.generated == 1
    # Fixture still owns a live manager for cleanup.
    manager.connection = restarted.connection
    manager.lock_fd = restarted.lock_fd


def test_startup_expires_stale_database_before_accepting_requests(runtime):
    manager, runner, now = runtime
    manager.access(111, expiry(now[0], 60))
    now[0] += 61
    manager.initialize()
    assert runner.peers == {}
    assert runner.leases == {}
    assert manager.health()


def test_readiness_fails_closed_for_unmanaged_peers(runtime):
    manager, runner, _ = runtime
    runner.peers[key(90)] = "10.66.0.40/32"
    assert not manager.health()
    assert runner.chains[("iptables", "filter")]["FORWARD"][0][-1] == Firewall.hold_chain


def test_readiness_fails_when_monitor_stops(runtime):
    manager, _, now = runtime
    now[0] += manager.settings.reconcile_seconds * 3 + 1
    assert not manager.health()
    with pytest.raises(GatewayUnavailable):
        manager.prepare(111)


def test_readiness_rejects_wrong_public_interface(runtime):
    manager, runner, _ = runtime
    runner.egress = "unrelated0"
    assert not manager.health()


def test_readiness_rejects_wrong_udp_endpoint_port(runtime):
    manager, runner, _ = runtime
    runner.listen_port = "51821"
    assert not manager.health()


def test_expired_or_non_utc_access_is_rejected(runtime):
    manager, _, now = runtime
    for expires in (expiry(now[0], -1), "2026-10-08T12:00:00", "2026-10-08T12:00:00+04:00", "garbage"):
        with pytest.raises(ValueError):
            manager.access(111, expires)


def test_paid_customer_addresses_stable_and_unpaid_holds_are_bounded(settings):
    small = replace(settings, client_subnet=ipaddress.ip_network("10.66.0.0/30"))
    now = [1_800_000_000.0]
    runner = FakeRunner(small)
    manager = AccessManager(small, runner, clock=lambda: now[0], monotonic=lambda: now[0])
    try:
        manager.initialize()
        manager.prepare(111)
        with pytest.raises(CapacityError):
            manager.prepare(222)
        assert manager.health()  # Existing reserved customers can still pay.
        now[0] += 3601
        manager.reconcile()
        manager.prepare(222, payment_pending=True)
        now[0] += 2 * 86400
        manager.reconcile()
        with pytest.raises(CapacityError):
            manager.prepare(111)
        manager.access(222, expiry(now[0], 60))
        now[0] += 61
        manager.reconcile()
        with pytest.raises(CapacityError):
            manager.prepare(333)
        assert manager.prepare(222) == {"ready": True}
    finally:
        manager.close()


def test_reservation_release_requires_verified_unpaid_and_rejects_paid(runtime):
    manager, _, now = runtime
    manager.prepare(111, payment_pending=True)
    with pytest.raises(ValueError):
        manager.release_reservation(111)
    assert manager.release_reservation(111, confirmed_unpaid=True)
    manager.access(222, expiry(now[0], 60))
    now[0] += 61
    manager.reconcile()
    with pytest.raises(ValueError):
        manager.release_reservation(222, confirmed_unpaid=True)


def test_secret_state_permissions(runtime):
    manager, _, _ = runtime
    assert manager.settings.database.stat().st_mode & 0o777 == 0o600
    assert manager.settings.database.parent.stat().st_mode & 0o777 == 0o700
    assert manager.settings.database.with_suffix(".lock").stat().st_mode & 0o777 == 0o600


def test_firewall_only_mutates_owned_chains_and_blocks_ipv6(runtime):
    manager, runner, _ = runtime
    for call in runner.calls:
        if call[0] in {"iptables", "ip6tables"} and call[5] == "-F":
            assert call[6].startswith("BRAWL_")
    assert runner.chains[("ip6tables", "filter")][Firewall.ipv6_chain] == [["-j", "DROP"]]
    assert runner.chains[("iptables", "filter")][Firewall.local_chain] == [["-j", "DROP"]]
    assert manager.health()


def test_quarantine_repairs_permissive_guard_atomically(runtime):
    manager, runner, _ = runtime
    runner.chains[("iptables", "filter")][Firewall.hold_chain] = [["-j", "ACCEPT"], ["-j", "DROP"]]
    runner.chains[("ip6tables", "filter")][Firewall.ipv6_chain] = [["-j", "ACCEPT"], ["-j", "DROP"]]
    manager.firewall.quarantine()
    assert runner.chains[("iptables", "filter")][Firewall.hold_chain] == [["-j", "DROP"]]
    assert runner.chains[("ip6tables", "filter")][Firewall.ipv6_chain] == [["-j", "DROP"]]
    assert not manager.health()


def test_firewall_detects_injected_accept_and_moved_hook(runtime):
    manager, runner, _ = runtime
    chain = runner.chains[("iptables", "filter")][Firewall.out_chain]
    chain.insert(0, ["-j", "ACCEPT"])
    with pytest.raises(SystemCommandError):
        manager.firewall.verify()
    chain.pop(0)
    runner.chains[("iptables", "filter")]["FORWARD"].insert(0, ["-j", "ACCEPT"])
    assert not manager.health()


def test_firewall_snapshot_understands_kernel_canonical_argument_order(runtime):
    manager, runner, _ = runtime
    for rule in runner.chains[("iptables", "filter")][Firewall.in_chain]:
        if "--ctstate" in rule:
            rule[rule.index("--ctstate") + 1] = "RELATED,ESTABLISHED"
    for rule in runner.chains[("iptables", "filter")][Firewall.out_chain]:
        if "-o" in rule:
            option = rule[:2]
            del rule[:2]
            rule.extend(option)
    manager.firewall.verify()


def test_gateway_http_requires_auth_and_reserves_capacity(settings):
    runner = FakeRunner(settings)
    manager = AccessManager(settings, runner)
    app = create_app(settings, manager)
    with TestClient(app) as client:
        assert client.get("/health").status_code == 401
        assert client.post("/prepare", json={"user_id": 111}).status_code == 401
        headers = {"Authorization": "Bearer " + settings.api_token}
        assert client.get("/health", headers=headers).json()["ready"] is True
        assert client.post("/prepare", headers=headers, json={"user_id": 111, "payment_pending": True}).json() == {"ready": True}
        response = client.post("/access", headers=headers, json={"user_id": 111, "expires_at": expiry(manager.clock())})
        assert response.status_code == 200
        assert "android_config" in response.json()
        assert client.post("/access", headers=headers, json={"user_id": True, "expires_at": expiry(manager.clock())}).status_code == 422
