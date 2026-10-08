from __future__ import annotations

import base64
import fcntl
import ipaddress
import os
import re
import sqlite3
import threading
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Iterator

from .firewall import Firewall
from .settings import Settings, valid_public_key
from .system import Runner


class CapacityError(RuntimeError):
    pass


class GatewayUnavailable(RuntimeError):
    pass


class AccessManager:
    def __init__(self, settings: Settings, runner: Runner | None = None, *, clock: Callable[[], float] = time.time, monotonic: Callable[[], float] = time.monotonic, firewall: Firewall | None = None):
        self.settings = settings
        self.runner = runner or Runner()
        self.firewall = firewall or Firewall(settings, self.runner)
        self.clock = clock
        self.monotonic = monotonic
        self.thread_lock = threading.RLock()
        self.heartbeat: float | None = None
        self.ready = False
        self.last_error = "Gateway has not started"
        self._prepare_secret_directory(settings.database.parent)
        self.lock_fd = self._secret_file(settings.database.with_suffix(".lock"))
        database_fd = self._secret_file(settings.database)
        os.close(database_fd)
        self.connection = sqlite3.connect(settings.database, check_same_thread=False, timeout=30)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute("PRAGMA journal_mode=WAL")
        self.connection.execute("PRAGMA busy_timeout=30000")
        with self.locked():
            self.connection.execute("""CREATE TABLE IF NOT EXISTS peers (
                user_id INTEGER PRIMARY KEY CHECK(user_id > 0),
                private_key TEXT NOT NULL,
                public_key TEXT NOT NULL UNIQUE,
                address TEXT UNIQUE,
                expires_at INTEGER NOT NULL,
                created_at INTEGER NOT NULL
            )""")
            self.connection.execute("""CREATE TABLE IF NOT EXISTS reservations (
                user_id INTEGER PRIMARY KEY CHECK(user_id > 0),
                address TEXT NOT NULL UNIQUE,
                reserved_until INTEGER,
                created_at INTEGER NOT NULL
            )""")
            self.connection.commit()

    @staticmethod
    def _prepare_secret_directory(directory: Path) -> None:
        if directory.is_symlink():
            raise ValueError("Gateway state directory must not be a symlink")
        directory.mkdir(parents=True, mode=0o700, exist_ok=True)
        stat = directory.stat()
        if stat.st_uid != os.geteuid() or stat.st_mode & 0o077:
            raise ValueError("Gateway state directory must belong to this process and have mode 0700")

    @staticmethod
    def _secret_file(path: Path) -> int:
        fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        stat = os.fstat(fd)
        if stat.st_uid != os.geteuid() or stat.st_mode & 0o077:
            os.close(fd)
            raise ValueError("Gateway state files must belong to this process and have mode 0600")
        return fd

    @contextmanager
    def locked(self) -> Iterator[None]:
        with self.thread_lock:
            fcntl.flock(self.lock_fd, fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(self.lock_fd, fcntl.LOCK_UN)

    def close(self) -> None:
        self.ready = False
        self.connection.close()
        os.close(self.lock_fd)

    def _rows(self) -> list[sqlite3.Row]:
        return self.connection.execute("SELECT * FROM peers ORDER BY user_id").fetchall()

    def _interface_peers(self) -> dict[str, str]:
        output = self.runner.run(["wg", "show", self.settings.interface, "allowed-ips"])
        peers: dict[str, str] = {}
        for line in output.splitlines():
            fields = line.split()
            if len(fields) != 2:
                raise GatewayUnavailable("WireGuard peer routing has an unsupported format")
            public_key, allowed = fields
            valid_public_key(public_key)
            if public_key in peers:
                raise GatewayUnavailable("WireGuard contains duplicate peer keys")
            peers[public_key] = allowed
        return peers

    def _check_interface(self) -> dict[str, str]:
        if self.runner.run(["wg", "show", self.settings.interface, "public-key"]) != self.settings.server_public_key:
            raise GatewayUnavailable("WireGuard server public key does not match configuration")
        if self.runner.run(["wg", "show", self.settings.interface, "listen-port"]) != str(int(self.settings.endpoint.rpartition(":")[2])):
            raise GatewayUnavailable("WireGuard listen port does not match the advertised endpoint")
        addresses = self.runner.run(["ip", "-4", "-o", "address", "show", "dev", self.settings.interface])
        expected_address = f"{self.settings.gateway_address}/{self.settings.client_subnet.prefixlen}"
        if re.findall(r"\binet\s+(\S+)", addresses) != [expected_address]:
            raise GatewayUnavailable("WireGuard interface IPv4 address does not match the dedicated client subnet")
        if self.runner.run(["sysctl", "-n", "net.ipv4.ip_forward"]) != "1":
            raise GatewayUnavailable("IPv4 forwarding is disabled")
        routes = self.runner.run(["ip", "-4", "route", "show", "default"])
        if not any(re.search(r"\bdev\s+" + re.escape(self.settings.public_interface) + r"(?:\s|$)", line) for line in routes.splitlines()):
            raise GatewayUnavailable("WG_PUBLIC_INTERFACE is not an IPv4 default-route interface")
        peers = self._interface_peers()
        known = {row["public_key"]: row for row in self._rows()}
        if set(peers) - set(known):
            raise GatewayUnavailable("WireGuard interface has unmanaged peers; use a dedicated interface")
        for key, allowed in peers.items():
            row = known[key]
            if row["address"] is None or allowed != f"{row['address']}/32":
                raise GatewayUnavailable("WireGuard managed peer route changed")
        return peers

    def _validate_records(self) -> None:
        ownership: dict[str, int] = {}
        for row in self._rows():
            valid_public_key(row["public_key"])
            try:
                key = base64.b64decode(row["private_key"], validate=True)
            except ValueError as error:
                raise GatewayUnavailable("Invalid private key in state database") from error
            if len(key) != 32:
                raise GatewayUnavailable("Invalid private key in state database")
            address = row["address"]
            if address is not None:
                try:
                    ip = ipaddress.ip_address(address)
                except ValueError as error:
                    raise GatewayUnavailable("Invalid client address in state database") from error
                if ip not in self.settings.client_subnet or ip in (self.settings.gateway_address, self.settings.client_subnet.network_address, self.settings.client_subnet.broadcast_address):
                    raise GatewayUnavailable("Client address in state database is outside the configured pool")
                ownership[address] = row["user_id"]
            if int(row["expires_at"] - self.clock()) >= 1 and address is None:
                raise GatewayUnavailable("An active record is missing a client address")
        for reservation in self.connection.execute("SELECT * FROM reservations").fetchall():
            ip = ipaddress.ip_address(reservation["address"])
            if ip not in self.settings.client_subnet or ip in (self.settings.gateway_address, self.settings.client_subnet.network_address, self.settings.client_subnet.broadcast_address):
                raise GatewayUnavailable("Reserved address is outside the configured pool")
            owner = ownership.get(reservation["address"])
            if owner is not None and owner != reservation["user_id"]:
                raise GatewayUnavailable("Reservation overlaps another customer's address")

    def _apply_records(self, *, only_expire: bool = False) -> None:
        peers = self._check_interface()
        now = self.clock()
        for row in self._rows():
            remaining = int(row["expires_at"] - now)
            address = row["address"]
            if remaining < 1:
                if address is not None:
                    # Kill kernel forwarding before attempting peer removal.
                    self.firewall.revoke(address)
                if row["public_key"] in peers:
                    self.runner.run(["wg", "set", self.settings.interface, "peer", row["public_key"], "remove"])
                # Paid customer addresses remain stable through expiry and renewal.
            elif not only_expire:
                if not address:
                    raise GatewayUnavailable("An active peer is missing its address")
                if row["public_key"] not in peers:
                    self.runner.run(["wg", "set", self.settings.interface, "peer", row["public_key"], "allowed-ips", f"{address}/32"])
                self.firewall.lease(address, remaining)

    def initialize(self) -> None:
        with self.locked():
            self.ready = False
            try:
                # Block existing traffic before checking stale state or changing rules.
                self.firewall.install()
                self._validate_records()
                self._apply_records()
                self.firewall.activate()
                self.firewall.verify()
                self.ready = True
                self.last_error = ""
                self.heartbeat = self.monotonic()
            except Exception:
                self.last_error = "Gateway startup checks failed; consult service logs and deployment settings"
                # Install already holds IPv4; attempt to keep it so on every error.
                try:
                    self.firewall.quarantine()
                except Exception:
                    pass
                raise

    def reconcile(self) -> None:
        with self.locked():
            try:
                self.firewall.verify()
                self._validate_records()
                self._apply_records()
                self.ready = True
                self.last_error = ""
                self.heartbeat = self.monotonic()
            except Exception:
                self.ready = False
                self.last_error = "Gateway runtime checks failed"
                try:
                    self.firewall.quarantine()
                except Exception:
                    pass
                raise

    def expire_only(self) -> None:
        """Independent systemd timer: never grants or extends a kernel lease."""
        with self.locked():
            self._validate_records()
            self._apply_records(only_expire=True)

    def health(self, *, check_runtime: bool = True) -> bool:
        with self.locked():
            fresh = self.heartbeat is not None and self.monotonic() - self.heartbeat <= self.settings.reconcile_seconds * 3
            if not self.ready or not fresh:
                return False
            if check_runtime:
                try:
                    self.firewall.verify()
                    peers = self._check_interface()
                    expected = {row["public_key"] for row in self._rows() if int(row["expires_at"] - self.clock()) >= 1}
                    if not expected.issubset(peers):
                        raise GatewayUnavailable("A paid WireGuard peer is unavailable")
                except Exception:
                    self.ready = False
                    self.last_error = "Gateway runtime checks failed"
                    try:
                        self.firewall.quarantine()
                    except Exception:
                        pass
                    return False
            return True

    def _allocate(self) -> str:
        self._purge_reservations()
        taken = {row["address"] for row in self._rows() if row["address"]}
        taken.update(row["address"] for row in self.connection.execute("SELECT address FROM reservations").fetchall())
        taken.add(str(self.settings.gateway_address))
        for address in self.settings.client_subnet.hosts():
            if str(address) not in taken:
                return str(address)
        raise CapacityError("The configured WireGuard client address pool is full")

    def _purge_reservations(self) -> None:
        self.connection.execute("DELETE FROM reservations WHERE reserved_until IS NOT NULL AND reserved_until <= ? AND user_id NOT IN (SELECT user_id FROM peers)", (int(self.clock()),))
        self.connection.commit()

    def _reserve(self, user_id: int, *, payment_pending: bool) -> str:
        self._purge_reservations()
        existing = self.connection.execute("SELECT * FROM reservations WHERE user_id=?", (user_id,)).fetchone()
        peer = self.connection.execute("SELECT * FROM peers WHERE user_id=?", (user_id,)).fetchone()
        if existing is not None:
            until = None if payment_pending or existing["reserved_until"] is None or peer is not None else int(self.clock()) + 3600
            self.connection.execute("UPDATE reservations SET reserved_until=? WHERE user_id=?", (until, user_id))
            address = existing["address"]
        else:
            address = peer["address"] if peer is not None and peer["address"] is not None else self._allocate()
            until = None if payment_pending or peer is not None else int(self.clock()) + 3600
            self.connection.execute("INSERT INTO reservations (user_id,address,reserved_until,created_at) VALUES (?,?,?,?)", (user_id, address, until, int(self.clock())))
        self.connection.commit()
        return address

    def prepare(self, user_id: int, *, payment_pending: bool = False) -> dict[str, bool]:
        if isinstance(user_id, bool) or not isinstance(user_id, int) or not 1 <= user_id <= 2**63 - 1:
            raise ValueError("user_id must be a positive Telegram identifier")
        with self.locked():
            fresh = self.heartbeat is not None and self.monotonic() - self.heartbeat <= self.settings.reconcile_seconds * 3
            if not self.ready or not fresh:
                raise GatewayUnavailable("Gateway is not ready")
            try:
                self.firewall.verify()
                self._apply_records()
                self._reserve(user_id, payment_pending=payment_pending)
            except (CapacityError, ValueError):
                self.connection.rollback()
                raise
            except Exception:
                self.connection.rollback()
                self.ready = False
                self.last_error = "Gateway reservation failed"
                try:
                    self.firewall.quarantine()
                except Exception:
                    pass
                raise
        return {"ready": True}

    def has_capacity(self) -> bool:
        with self.locked():
            try:
                self._allocate()
            except CapacityError:
                return False
            return True

    def release_reservation(self, user_id: int, *, confirmed_unpaid: bool = False) -> bool:
        if not confirmed_unpaid:
            raise ValueError("Explicit --confirmed-unpaid confirmation is required")
        if isinstance(user_id, bool) or not isinstance(user_id, int) or user_id < 1:
            raise ValueError("A positive Telegram user ID is required")
        with self.locked():
            # Any issued peer is payment history, even when it has since expired.
            if self.connection.execute("SELECT 1 FROM peers WHERE user_id=?", (user_id,)).fetchone():
                raise ValueError("Cannot release a reservation for a customer with issued VPN access")
            result = self.connection.execute("DELETE FROM reservations WHERE user_id=?", (user_id,))
            self.connection.commit()
            return result.rowcount > 0

    def _generate_keys(self) -> tuple[str, str]:
        private_key = self.runner.run(["wg", "genkey"])
        # wg pubkey receives a private key only through stdin, never argv.
        public_key = self.runner.run(["wg", "pubkey"], stdin=private_key + "\n")
        valid_public_key(public_key)
        return private_key, public_key

    @staticmethod
    def parse_expiry(value: str) -> int:
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except (ValueError, TypeError) as error:
            raise ValueError("expires_at must be an ISO 8601 UTC timestamp") from error
        if parsed.tzinfo is None or parsed.utcoffset() != timezone.utc.utcoffset(parsed):
            raise ValueError("expires_at must explicitly use UTC")
        return int(parsed.timestamp())

    def access(self, user_id: int, expires_at: str) -> dict[str, str]:
        if isinstance(user_id, bool) or not isinstance(user_id, int) or not 1 <= user_id <= 2**63 - 1:
            raise ValueError("user_id must be a positive Telegram identifier")
        expiry = self.parse_expiry(expires_at)
        if expiry - self.clock() < 2:
            raise ValueError("expires_at must be in the future")
        with self.locked():
            fresh = self.heartbeat is not None and self.monotonic() - self.heartbeat <= self.settings.reconcile_seconds * 3
            if not self.ready or not fresh:
                raise GatewayUnavailable("Gateway is not ready")
            try:
                self.firewall.verify()
                self._apply_records()
                row = self.connection.execute("SELECT * FROM peers WHERE user_id=?", (user_id,)).fetchone()
                reserved_address = self._reserve(user_id, payment_pending=True)
                if row is None:
                    address = reserved_address
                    private_key, public_key = self._generate_keys()
                    self.connection.execute("INSERT INTO peers (user_id, private_key, public_key, address, expires_at, created_at) VALUES (?, ?, ?, ?, ?, ?)", (user_id, private_key, public_key, address, expiry, int(self.clock())))
                else:
                    address = row["address"] or reserved_address
                    expiry = max(expiry, row["expires_at"])
                    self.connection.execute("UPDATE peers SET address=?, expires_at=? WHERE user_id=?", (address, expiry, user_id))
                # Persist before creating a peer: an interrupted request can be retried.
                self.connection.commit()
                self._apply_records()
                row = self.connection.execute("SELECT * FROM peers WHERE user_id=?", (user_id,)).fetchone()
            except (CapacityError, ValueError):
                self.connection.rollback()
                raise
            except Exception:
                self.connection.rollback()
                self.ready = False
                self.last_error = "Gateway provisioning failed"
                try:
                    self.firewall.quarantine()
                except Exception:
                    pass
                raise
            return {"android_config": self.render(row, android=True), "ios_config": self.render(row, android=False)}

    def render(self, row: sqlite3.Row, *, android: bool) -> str:
        lines = ["[Interface]", f"PrivateKey = {row['private_key']}", f"Address = {row['address']}/32"]
        if android:
            lines.append("IncludedApplications = com.supercell.brawlstars")
        lines.extend(["", "[Peer]", f"PublicKey = {self.settings.server_public_key}", f"Endpoint = {self.settings.endpoint}", "AllowedIPs = " + ", ".join(map(str, self.settings.game_cidrs)), "PersistentKeepalive = 25", ""])
        return "\n".join(lines)
