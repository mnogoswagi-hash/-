from __future__ import annotations

import base64
import fcntl
import hashlib
import hmac
import ipaddress
import json
import os
import selectors
import sqlite3
import stat
import subprocess
import sys
import threading
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Iterator
from urllib.parse import quote, urlencode
from uuid import UUID, uuid4

from vpn_shop.provider import INCY_PROXY_SITES as GAME_DOMAINS

from .settings import BLOCKED_NETWORKS, Settings, host_port, public_ipv4


class ProxyUnavailable(RuntimeError):
    pass


class CapacityError(RuntimeError):
    pass


def verify_key_pair(settings: Settings) -> None:
    private = bytes.fromhex("302e020100300506032b656e04220420") + base64.urlsafe_b64decode(settings.private_key + "=")
    expected = bytes.fromhex("302a300506032b656e032100") + base64.urlsafe_b64decode(settings.public_key + "=")
    try:
        result = subprocess.run(["openssl", "pkey", "-inform", "DER", "-pubout", "-outform", "DER"], input=private, capture_output=True, timeout=5)
        if result.returncode or not hmac.compare_digest(result.stdout, expected):
            raise ValueError
    except Exception:
        raise ProxyUnavailable("Reality private and public keys do not form a validated pair") from None


def write_heartbeat(process: subprocess.Popen, payload: str) -> None:
    if process.stdin is None:
        raise ProxyUnavailable("Proxy supervisor has no lease channel")
    fd = process.stdin.fileno()
    os.set_blocking(fd, False)
    writer = selectors.DefaultSelector()
    try:
        writer.register(fd, selectors.EVENT_WRITE)
        data = payload.encode("ascii")
        deadline = time.monotonic() + 1.0
        while data:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not writer.select(remaining):
                raise ProxyUnavailable("Proxy supervisor lease channel is unavailable")
            try:
                count = os.write(fd, data)
            except BlockingIOError:
                continue
            data = data[count:]
    except Exception:
        raise ProxyUnavailable("Proxy supervisor lease channel is unavailable") from None
    finally:
        writer.close()


def run_command(args: list[str]) -> str:
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.TimeoutExpired):
        raise ProxyUnavailable("Proxy prerequisite command failed") from None
    if result.returncode:
        # Never disclose stdout/stderr, config content, user UUIDs or keys.
        raise ProxyUnavailable("Proxy prerequisite command failed")
    return result.stdout.strip()


def wait_guardian_ready(process: subprocess.Popen) -> None:
    if process.stdout is None:
        raise ProxyUnavailable("Proxy supervisor has no readiness channel")
    reader = selectors.DefaultSelector()
    try:
        reader.register(process.stdout, selectors.EVENT_READ)
        deadline = time.monotonic() + 3.0
        data = b""
        while b"\n" not in data:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or process.poll() is not None or not reader.select(remaining):
                raise ProxyUnavailable("Proxy supervisor startup failed")
            chunk = os.read(process.stdout.fileno(), 512)
            if not chunk or len(data) + len(chunk) > 512:
                raise ProxyUnavailable("Proxy supervisor startup failed")
            data += chunk
        acknowledgement = json.loads(data.split(b"\n", 1)[0])
        if type(acknowledgement) is not dict or set(acknowledgement) != {"ready"} or acknowledgement["ready"] is not True or process.poll() is not None:
            raise ProxyUnavailable("Proxy supervisor startup failed")
    except ProxyUnavailable:
        raise
    except Exception:
        raise ProxyUnavailable("Proxy supervisor startup failed") from None
    finally:
        reader.close()


class AccessManager:
    def __init__(self, settings: Settings, *, command: Callable = run_command, process_factory: Callable = subprocess.Popen, ready_reader: Callable = wait_guardian_ready, heartbeat_writer: Callable = write_heartbeat, key_checker: Callable = verify_key_pair, clock: Callable[[], float] = time.time, monotonic: Callable[[], float] = time.monotonic):
        self.settings = settings
        self.command = command
        self.process_factory = process_factory
        self.ready_reader = ready_reader
        self.heartbeat_writer = heartbeat_writer
        self.key_checker = key_checker
        self.keys_verified = False
        self.clock = clock
        self.monotonic = monotonic
        self.thread_lock = threading.RLock()
        self.process: subprocess.Popen | None = None
        self.heartbeat: float | None = None
        self.ready = False
        self.last_error = "Proxy has not started"
        self.applied_digest: str | None = None
        self.applied_expirations: tuple[int, ...] = ()
        directory = settings.database.parent
        if directory.is_symlink():
            raise ValueError("Proxy state directory must not be a symlink")
        directory.mkdir(parents=True, mode=0o700, exist_ok=True)
        info = directory.stat()
        if info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise ValueError("Proxy state directory must be owned by this process with mode 0700")
        self.lock_fd = self._state_file(settings.database.with_suffix(".lock"))
        database_fd = self._state_file(settings.database)
        os.close(database_fd)
        self.connection = sqlite3.connect(settings.database, check_same_thread=False, timeout=30)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute("PRAGMA journal_mode=WAL")
        self.connection.execute("PRAGMA busy_timeout=30000")
        with self.locked():
            self.connection.execute("""CREATE TABLE IF NOT EXISTS users (
                user_id INTEGER PRIMARY KEY CHECK(user_id > 0),
                uuid TEXT NOT NULL UNIQUE,
                expires_at INTEGER NOT NULL DEFAULT 0,
                reserved_until INTEGER,
                created_at INTEGER NOT NULL
            )""")
            self.connection.commit()

    @staticmethod
    def _state_file(path: Path) -> int:
        fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
            os.close(fd)
            raise ValueError("Proxy database and lock must be private regular files")
        return fd

    @contextmanager
    def locked(self) -> Iterator[None]:
        with self.thread_lock:
            fcntl.flock(self.lock_fd, fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(self.lock_fd, fcntl.LOCK_UN)

    def _rows(self) -> list[sqlite3.Row]:
        return self.connection.execute("SELECT * FROM users ORDER BY user_id").fetchall()

    def _purge_reservations(self) -> None:
        # Issued customer identities and accepted checkouts never expire here.
        self.connection.execute("DELETE FROM users WHERE expires_at=0 AND reserved_until IS NOT NULL AND reserved_until <= ?", (int(self.clock()),))
        self.connection.commit()

    def _validate_records(self) -> None:
        for row in self._rows():
            try:
                parsed = UUID(row["uuid"])
                if parsed.version != 4 or str(parsed) != row["uuid"] or row["user_id"] < 1 or row["expires_at"] < 0:
                    raise ValueError
            except (ValueError, TypeError, AttributeError):
                raise ProxyUnavailable("Invalid proxy state record") from None

    def _endpoint_addresses(self) -> tuple[str, ...]:
        host, _ = host_port(self.settings.endpoint)
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            output = self.command(["getent", "ahostsv4", host])
            try:
                addresses = {ipaddress.ip_address(line.split()[0]) for line in output.splitlines() if line.split()}
            except ValueError:
                raise ProxyUnavailable("Cannot resolve the public proxy endpoint") from None
            if not addresses or not all(public_ipv4(address) for address in addresses):
                raise ProxyUnavailable("Proxy endpoint DNS is not publicly routable IPv4")
            return tuple(sorted(str(address) for address in addresses))
        if not public_ipv4(address):
            raise ProxyUnavailable("Proxy endpoint is not public IPv4")
        return (str(address),)

    def server_config(self, clients: list[dict[str, str]], endpoint_addresses: tuple[str, ...]) -> dict[str, object]:
        blocked = list(BLOCKED_NETWORKS) + [address + "/32" for address in endpoint_addresses]
        rules: list[dict[str, object]] = [
            {"type": "field", "ip": blocked, "outboundTag": "blocked"},
            {"type": "field", "ip": ["1.1.1.1/32"], "port": "53", "network": "tcp,udp", "outboundTag": "game"},
            # A reviewed broad game CIDR must not silently widen the DNS exception.
            {"type": "field", "ip": ["1.1.1.1/32"], "outboundTag": "blocked"},
            # AND with IPv4 requires DNS resolution to succeed; otherwise
            # unresolved names must never reach a system DNS fallback. This
            # IPv4 predicate is ANDed with the trusted domain predicate.
            {"type": "field", "domain": list(GAME_DOMAINS), "ip": ["0.0.0.0/0"], "outboundTag": "game"},
        ]
        if self.settings.game_cidrs:
            rules.append({"type": "field", "ip": list(map(str, self.settings.game_cidrs)), "outboundTag": "game"})
        rules.append({"type": "field", "network": "tcp,udp", "outboundTag": "blocked"})
        return {
            "log": {"loglevel": "none"},
            "dns": {"servers": [{"address": "1.1.1.1", "port": 53}], "queryStrategy": "UseIPv4", "disableFallback": True, "tag": "brawl-dns"},
            "inbounds": [{"tag": "brawl-in", "listen": "0.0.0.0", "port": 443, "protocol": "vless", "settings": {"clients": clients, "decryption": "none"}, "streamSettings": {"network": "tcp", "security": "reality", "realitySettings": {"show": False, "target": self.settings.target, "xver": 0, "serverNames": [self.settings.server_name], "privateKey": self.settings.private_key, "shortIds": [self.settings.short_id]}}, "sniffing": {"enabled": False}}],
            # Default outbound is a deny even if an unexpected request misses all rules.
            "outbounds": [{"tag": "blocked", "protocol": "blackhole", "settings": {}}, {"tag": "game", "protocol": "freedom", "settings": {"domainStrategy": "ForceIPv4"}}],
            "routing": {"domainStrategy": "IPOnDemand", "rules": rules},
        }

    def _desired(self) -> tuple[bytes, tuple[int, ...]]:
        self._purge_reservations()
        self._validate_records()
        active = [row for row in self._rows() if row["expires_at"] > self.clock()]
        clients = [{"id": row["uuid"], "flow": "xtls-rprx-vision", "email": "telegram-" + str(row["user_id"])} for row in active]
        data = json.dumps(self.server_config(clients, self._endpoint_addresses()), sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode() + b"\n"
        if len(data) > 1_048_576:
            raise ProxyUnavailable("Protected proxy configuration exceeds its supported size")
        return data, tuple(row["expires_at"] for row in active)

    def _stop_guardian(self) -> None:
        process, self.process = self.process, None
        self.ready = False
        if process is None:
            return
        try:
            if process.stdin is not None:
                try:
                    process.stdin.close()
                except OSError:
                    pass
            if process.poll() is None:
                process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)
        finally:
            if process.stdout is not None:
                process.stdout.close()

    def _fail(self) -> None:
        self.ready = False
        self.last_error = "Proxy reconciliation failed"
        self.applied_digest = None
        self.applied_expirations = ()
        try:
            self._stop_guardian()
        except Exception:
            pass

    def _ttl(self) -> float:
        remaining = min((expiry - self.clock() for expiry in self.applied_expirations), default=30.0)
        if remaining <= 0:
            raise ProxyUnavailable("An applied proxy client has expired")
        return min(30.0, remaining)

    def _send_heartbeat(self) -> None:
        if self.process is None or self.process.poll() is not None or self.process.stdin is None:
            raise ProxyUnavailable("Proxy supervisor is unavailable")
        self.heartbeat_writer(self.process, json.dumps({"ttl": self._ttl()}, separators=(",", ":")) + "\n")

    def _runtime_digest(self) -> str:
        try:
            fd = os.open(self.settings.runtime_config, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            with os.fdopen(fd, "rb") as file:
                info = os.fstat(file.fileno())
                if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o027 or info.st_size > 1_048_576:
                    raise ValueError
                return hashlib.sha256(file.read(1_048_577)).hexdigest()
        except Exception:
            raise ProxyUnavailable("Protected proxy runtime is unavailable") from None

    def _publish_runtime(self, data: bytes) -> None:
        if self.settings.runtime_config.exists() or self.settings.runtime_config.is_symlink():
            self._runtime_digest()  # Refuse symlinks and files with unsafe ownership/mode.
        # Xray infers the parser from the extension; a generic .tmp file fails
        # native validation even when its contents are valid JSON.
        temporary = self.settings.runtime_config.with_name(".runtime-" + uuid4().hex + ".json")
        owned_identity: tuple[int, int] | None = None
        try:
            fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o640)
            info = os.fstat(fd)
            owned_identity = info.st_dev, info.st_ino
            with os.fdopen(fd, "wb") as file:
                os.fchmod(file.fileno(), 0o640)
                file.write(data)
                file.flush()
                os.fsync(file.fileno())
            self.command([str(self.settings.xray_binary), "run", "-test", "-config", str(temporary)])
            os.replace(temporary, self.settings.runtime_config)
            directory_fd = os.open(self.settings.runtime_config.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        finally:
            if owned_identity is not None:
                try:
                    info = temporary.stat(follow_symlinks=False)
                    if stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid() and (info.st_dev, info.st_ino) == owned_identity:
                        temporary.unlink()
                except OSError:
                    pass

    def _reconcile_locked(self) -> None:
        try:
            data, expirations = self._desired()
            digest = hashlib.sha256(data).hexdigest()
            running = self.process is not None and self.process.poll() is None
            if digest != self.applied_digest or not running:
                # Close cached connections BEFORE changing membership or testing a
                # replacement configuration; a restart never leaves expired flows.
                self._stop_guardian()
                if not self.keys_verified:
                    self.key_checker(self.settings)
                    self.keys_verified = True
                self._publish_runtime(data)
                self.applied_expirations = expirations
                self.process = self.process_factory([sys.executable, "-m", "brawl_proxy.guardian", "--xray", str(self.settings.xray_binary), "--config", str(self.settings.runtime_config)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, bufsize=1)
                # Guardian consumes this lease before starting any Xray child.
                self._send_heartbeat()
                self.ready_reader(self.process)
                self.applied_digest = digest
            else:
                if self._runtime_digest() != self.applied_digest:
                    raise ProxyUnavailable("Proxy runtime changed outside the manager")
                self.applied_expirations = expirations
            self._send_heartbeat()
            self.heartbeat = self.monotonic()
            self.ready = True
            self.last_error = ""
        except Exception:
            self._fail()
            raise ProxyUnavailable("Proxy reconciliation failed") from None

    def initialize(self) -> None:
        with self.locked():
            self._reconcile_locked()

    def reconcile(self) -> None:
        with self.locked():
            self._reconcile_locked()

    def _require_live(self) -> None:
        fresh = self.heartbeat is not None and self.monotonic() - self.heartbeat <= self.settings.reconcile_seconds * 3
        if not self.ready or not fresh or self.process is None or self.process.poll() is not None:
            self._fail()
            raise ProxyUnavailable("Proxy is not ready")
        try:
            if self._runtime_digest() != self.applied_digest:
                raise ProxyUnavailable("Protected proxy runtime changed")
            self._ttl()
        except Exception:
            self._fail()
            raise ProxyUnavailable("Proxy is not ready") from None

    def health(self) -> bool:
        with self.locked():
            try:
                self._require_live()
            except ProxyUnavailable:
                return False
            return True

    def has_capacity(self) -> bool:
        with self.locked():
            self._purge_reservations()
            return self.connection.execute("SELECT COUNT(*) FROM users").fetchone()[0] < self.settings.max_users

    @staticmethod
    def _user_id(user_id: int) -> None:
        if isinstance(user_id, bool) or not isinstance(user_id, int) or not 1 <= user_id <= 2**63 - 1:
            raise ValueError("user_id must be a positive Telegram identifier")

    def _reserve(self, user_id: int, *, payment_pending: bool) -> sqlite3.Row:
        self._purge_reservations()
        row = self.connection.execute("SELECT * FROM users WHERE user_id=?", (user_id,)).fetchone()
        if row is None:
            if self.connection.execute("SELECT COUNT(*) FROM users").fetchone()[0] >= self.settings.max_users:
                raise CapacityError("Proxy user capacity is exhausted")
            self.connection.execute("INSERT INTO users(user_id,uuid,expires_at,reserved_until,created_at) VALUES(?,?,0,?,?)", (user_id, str(uuid4()), None if payment_pending else int(self.clock()) + 3600, int(self.clock())))
        else:
            until = None if payment_pending or row["reserved_until"] is None or row["expires_at"] > 0 else int(self.clock()) + 3600
            self.connection.execute("UPDATE users SET reserved_until=? WHERE user_id=?", (until, user_id))
        self.connection.commit()
        return self.connection.execute("SELECT * FROM users WHERE user_id=?", (user_id,)).fetchone()

    def prepare(self, user_id: int, *, payment_pending: bool = False) -> dict[str, bool]:
        self._user_id(user_id)
        with self.locked():
            self._require_live()
            self._reserve(user_id, payment_pending=payment_pending)
            self._reconcile_locked()
        return {"ready": True}

    @staticmethod
    def parse_expiry(value: str) -> int:
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            if parsed.tzinfo is None or parsed.utcoffset() != timezone.utc.utcoffset(parsed):
                raise ValueError
            return int(parsed.timestamp())
        except (ValueError, TypeError, AttributeError, OverflowError):
            raise ValueError("expires_at must be an explicit UTC ISO 8601 timestamp") from None

    def access(self, user_id: int, expires_at: str) -> dict[str, str]:
        self._user_id(user_id)
        expiry = self.parse_expiry(expires_at)
        if expiry - self.clock() < 2:
            raise ValueError("expires_at must be in the future")
        with self.locked():
            self._require_live()
            row = self._reserve(user_id, payment_pending=True)
            self.connection.execute("UPDATE users SET expires_at=?,reserved_until=NULL WHERE user_id=?", (max(expiry, row["expires_at"]), user_id))
            self.connection.commit()
            self._reconcile_locked()
            row = self.connection.execute("SELECT * FROM users WHERE user_id=?", (user_id,)).fetchone()
            return {"kind": "incy", "connection_uri": self.connection_uri(row["uuid"]), "routing_link": self.routing_link()}

    def connection_uri(self, identifier: str) -> str:
        host, port = host_port(self.settings.endpoint)
        query = urlencode({"encryption": "none", "security": "reality", "sni": self.settings.server_name, "fp": "chrome", "pbk": self.settings.public_key, "sid": self.settings.short_id, "spx": "/", "type": "tcp", "flow": "xtls-rprx-vision"})
        return f"vless://{identifier}@{host}:{port}?{query}#{quote('Brawl Stars', safe='')}"

    def routing_profile(self) -> dict[str, object]:
        return {"Name": "Brawl Stars", "GlobalProxy": "false", "DomainStrategy": "IPIfNonMatch", "FakeDNS": "true", "RemoteDNSType": "DoU", "RemoteDNSIP": "1.1.1.1", "DomesticDNSType": "DoU", "DomesticDNSIP": "1.1.1.1", "ProxySites": list(GAME_DOMAINS), "ProxyIp": list(map(str, self.settings.game_cidrs)), "DnsHosts": {}}

    def routing_link(self) -> str:
        encoded = base64.urlsafe_b64encode(json.dumps(self.routing_profile(), separators=(",", ":"), ensure_ascii=True).encode()).decode().rstrip("=")
        return "incy://routing/onadd/" + encoded

    def close(self) -> None:
        with self.locked():
            self._fail()
        self.connection.close()
        os.close(self.lock_fd)
