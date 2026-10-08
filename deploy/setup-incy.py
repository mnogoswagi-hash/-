#!/usr/bin/env python3
"""Migrate the local bot from WireGuard to an Incy VLESS/Reality gateway.

Run on the VDS as root. Secret values never enter command arguments or logs.
"""
from __future__ import annotations

import argparse
import base64
import fcntl
import hashlib
import io
import ipaddress
import json
import os
import platform
import pwd
import re
import secrets
import shlex
import shutil
import sqlite3
import stat
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
import zipfile
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator
from urllib.parse import urlsplit
from uuid import UUID, uuid4

PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT))
sys.dont_write_bytecode = True

XRAY_VERSION = "v26.3.27"
XRAY_SHA256 = "23cd9af937744d97776ee35ecad4972cf4b2109d1e0fe6be9930467608f7c8ae"
XRAY_RELEASE = f"https://github.com/XTLS/Xray-core/releases/download/{XRAY_VERSION}"
MAX_ARCHIVE_BYTES = 100 * 1024 * 1024
MAX_XRAY_BINARY_BYTES = 100 * 1024 * 1024
CONFIG_DIRECTORY = Path("/etc/brawl-vpn")
BINARY_PATH = Path("/usr/local/bin/brawl-xray")
STATE_DIRECTORY = Path("/var/lib/brawl-proxy")
SERVICE_DIRECTORY = Path("/etc/systemd/system")
SERVICE_NAME = "brawl-vpn-proxy.service"


class SetupError(RuntimeError):
    """A safe operator error; never contains raw configuration or tool output."""


def assert_owned_path(path: Path, *, owner_uids: set[int], directory: bool = False,
                      private: bool = False, allow_runtime_group_read: bool = False) -> None:
    try:
        info = path.lstat()
    except OSError:
        raise SetupError("Не удалось проверить существующий путь установки.") from None
    expected_type = stat.S_ISDIR if directory else stat.S_ISREG
    mode = stat.S_IMODE(info.st_mode)
    if (not expected_type(info.st_mode) or info.st_uid not in owner_uids or mode & 0o022):
        raise SetupError("Путь установки имеет небезопасный тип, владельца или права.")
    if private and not directory and mode not in ({0o600, 0o640} if allow_runtime_group_read else {0o600}):
        raise SetupError("Приватный файл установки имеет неподходящие права.")
    if directory and private and mode != 0o700:
        raise SetupError("Приватный каталог установки должен иметь режим 0700.")


def assert_trusted_tree(root: Path, *, owner_uid: int = 0, venv: Path | None = None) -> None:
    def inspect(path: Path) -> None:
        try:
            info = path.lstat()
        except OSError:
            raise SetupError("Не удалось проверить доверенность исходников или зависимостей.") from None
        if info.st_uid != owner_uid:
            raise SetupError("Исходники и зависимости должны принадлежать root.")
        if stat.S_ISLNK(info.st_mode):
            try:
                resolved = path.resolve(strict=True)
            except OSError:
                raise SetupError("Некорректный symlink в исходниках или зависимостях.") from None
            if venv is not None and path == venv / "lib64" and resolved == (venv / "lib").resolve():
                return
            if (venv is not None and path.parent == venv / "bin"
                    and re.fullmatch(r"python(?:3(?:\.\d+)?)?", path.name)):
                assert_owned_path(resolved, owner_uids={owner_uid})
                boundary = venv if resolved.is_relative_to(venv) else Path("/")
                for parent in resolved.parents:
                    assert_owned_path(parent, owner_uids={owner_uid}, directory=True)
                    if parent == boundary:
                        break
                return
            raise SetupError("Неподдерживаемый symlink в исполняемых исходниках или зависимостях.")
        if info.st_mode & 0o022 or not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)):
            raise SetupError("Исходники и зависимости доступны другим пользователям для записи.")
        if stat.S_ISDIR(info.st_mode):
            for child in path.iterdir():
                inspect(child)
    inspect(root)


def run(args: list[str], *, check: bool = True, timeout: int = 60) -> str:
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=timeout,
                                env={**os.environ, "LC_ALL": "C"})
    except (OSError, subprocess.TimeoutExpired):
        raise SetupError(f"Не удалось выполнить {Path(args[0]).name}.") from None
    if result.returncode and check:
        raise SetupError(f"Команда {Path(args[0]).name} завершилась ошибкой.")
    return result.stdout.strip() if result.returncode == 0 else ""


def private_bytes(path: Path) -> bytes:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as file:
            info = os.fstat(file.fileno())
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) != 0o600
                or info.st_size > 65536
            ):
                raise SetupError("Файл настроек должен принадлежать root и иметь режим 0600.")
            return file.read(65537)
    except OSError:
        raise SetupError("Не удалось безопасно прочитать приватный файл настроек.") from None


def load_private_env(path: Path) -> dict[str, str]:
    try:
        text = private_bytes(path).decode("utf-8")
        values: dict[str, str] = {}
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            name, separator, value = line.partition("=")
            if not separator or not re.fullmatch(r"[A-Z][A-Z0-9_]*", name) or name in values:
                raise ValueError
            if value.startswith(("'", '"')):
                tokens = shlex.split(value, comments=False)
                if len(tokens) != 1:
                    raise ValueError
                value = tokens[0]
            elif any(c.isspace() for c in value):
                raise ValueError
            if "\x00" in value:
                raise ValueError
            values[name] = value
        return values
    except (ValueError, UnicodeError):
        raise SetupError("Некорректный формат приватного env-файла; значения не выводятся.") from None


def render_env(values: dict[str, str]) -> bytes:
    lines: list[str] = []
    for name, value in values.items():
        if (
            not re.fullmatch(r"[A-Z][A-Z0-9_]*", name)
            or not isinstance(value, str)
            or any(c in value for c in "\x00\r\n")
        ):
            raise SetupError("Нельзя записать некорректные поля env-файла.")
        if re.fullmatch(r"[A-Za-z0-9_.:,/@+\-]*", value):
            encoded = value
        else:
            encoded = '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'
        lines.append(f"{name}={encoded}\n")
    return "".join(lines).encode("utf-8")


def atomic_private_env(path: Path, values: dict[str, str]) -> None:
    content = render_env(values)
    parent_fd = -1
    staged: str | None = None
    try:
        parent_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        info = os.fstat(parent_fd)
        if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) & 0o077:
            raise SetupError("Каталог настроек должен принадлежать root и иметь режим 0700.")
        existing: bytes | None = None
        try:
            os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            existing = private_bytes(path)
        if existing == content:
            return
        if existing is not None:
            backup = path.name + ".backup-" + secrets.token_hex(8)
            backup_fd = os.open(backup, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                0o600, dir_fd=parent_fd)
            with os.fdopen(backup_fd, "wb") as file:
                file.write(existing)
                file.flush()
                os.fsync(file.fileno())
        staged = ".incy-env-" + secrets.token_hex(12)
        fd = os.open(staged, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                     0o600, dir_fd=parent_fd)
        with os.fdopen(fd, "wb") as file:
            file.write(content)
            file.flush()
            os.fsync(file.fileno())
        os.replace(staged, path.name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
        staged = None
        os.fsync(parent_fd)
    except OSError:
        raise SetupError("Не удалось сохранить приватные настройки; проверьте права каталога.") from None
    finally:
        if staged is not None and parent_fd >= 0:
            os.unlink(staged, dir_fd=parent_fd)
        if parent_fd >= 0:
            os.close(parent_fd)


def parse_digest(text: str) -> str:
    digests = re.findall(r"^(?:SHA2-256|SHA256)\s*=\s*([a-fA-F0-9]{64})\s*$", text, re.M)
    if not digests or len({digest.lower() for digest in digests}) != 1:
        raise SetupError("Официальный файл .dgst не содержит однозначного SHA256.")
    return digests[0].lower()


def verified_xray_archive(archive: bytes, digest_text: str) -> bytes:
    if len(archive) > MAX_ARCHIVE_BYTES:
        raise SetupError("Архив Xray превышает допустимый размер.")
    if not secrets.compare_digest(hashlib.sha256(archive).hexdigest(), parse_digest(digest_text)):
        raise SetupError("SHA256 архива Xray не совпадает; установка прекращена.")
    try:
        with zipfile.ZipFile(io.BytesIO(archive)) as zipped:
            entries = [entry for entry in zipped.infolist() if entry.filename == "xray"]
            if len(entries) != 1:
                raise ValueError
            entry = entries[0]
            mode = entry.external_attr >> 16
            if (
                not stat.S_ISREG(mode)
                or not mode & 0o111
                or entry.file_size > MAX_XRAY_BINARY_BYTES
                or entry.file_size < 4
            ):
                raise ValueError
            binary = zipped.read(entry)
            if len(binary) != entry.file_size or not binary.startswith(b"\x7fELF"):
                raise ValueError
            return binary
    except (ValueError, OSError, zipfile.BadZipFile, RuntimeError, NotImplementedError):
        raise SetupError("Архив Xray не содержит безопасный Linux executable.") from None


class TrustedRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        url = urlsplit(newurl)
        if url.scheme != "https" or url.username or url.password or url.hostname not in {
            "github.com", "release-assets.githubusercontent.com", "objects.githubusercontent.com",
        }:
            raise SetupError("Неожиданный адрес перенаправления официального релиза.")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def download(url: str, limit: int) -> bytes:
    try:
        request = urllib.request.Request(url, headers={"User-Agent": "Brawl-VPN-Incy-Setup"})
        with urllib.request.build_opener(TrustedRedirect()).open(request, timeout=30) as response:
            result = response.read(limit + 1)
        if len(result) > limit:
            raise SetupError("Официальный артефакт превышает допустимый размер.")
        return result
    except (OSError, urllib.error.URLError):
        raise SetupError("Не удалось скачать официальный релиз Xray по HTTPS.") from None


def release_binary() -> bytes:
    digest = download(f"{XRAY_RELEASE}/Xray-linux-64.zip.dgst", 65536).decode("ascii")
    if parse_digest(digest) != XRAY_SHA256:
        raise SetupError("Официальный SHA256 отличается от закреплённого релиза; проверьте источник.")
    archive = download(f"{XRAY_RELEASE}/Xray-linux-64.zip", MAX_ARCHIVE_BYTES)
    return verified_xray_archive(archive, digest)


def parse_x25519(output: str) -> tuple[str, str]:
    private = public = None
    try:
        for line in output.splitlines():
            name, separator, value = line.partition(":")
            if not separator:
                continue
            normalized = name.strip().lower().replace(" ", "")
            if normalized == "privatekey":
                private = value.strip()
            elif normalized in {"publickey", "password(publickey)"}:
                public = value.strip()
        for value in (private, public):
            if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_-]{43}=?", value):
                raise ValueError
            decoded = base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
            if len(decoded) != 32 or decoded == bytes(32):
                raise ValueError
        return private, public
    except (ValueError, TypeError):
        raise SetupError("Не удалось безопасно получить ключи Reality из Xray.") from None


def update_bot_env(values: dict[str, str], admin_id: int) -> dict[str, str]:
    if isinstance(admin_id, bool) or not isinstance(admin_id, int) or admin_id <= 0:
        raise SetupError("Нужен положительный числовой Telegram admin-id.")
    try:
        admins = list(dict.fromkeys(int(value.strip()) for value in values.get("ADMIN_IDS", "").split(",") if value.strip()))
        if any(value <= 0 for value in admins):
            raise ValueError
    except ValueError:
        raise SetupError("ADMIN_IDS должен содержать положительные числовые ID.") from None
    if admin_id not in admins:
        admins.append(admin_id)
    updated = dict(values)
    updated.update(SALES_ENABLED="false", VPN_API_URL="http://127.0.0.1:8081",
                   ADMIN_IDS=",".join(map(str, admins)))
    return updated


def reset_active_deliveries(database: Path, *, now: float | None = None) -> int:
    if not database.exists():
        return 0
    if database.is_symlink() or not database.is_file():
        raise SetupError("База бота должна быть обычным файлом, не symlink.")
    connection = None
    backup_path = database.with_name(database.name + ".incy-backup-" + secrets.token_hex(8))
    try:
        connection = sqlite3.connect(database.as_uri() + "?mode=rw", uri=True, timeout=10)
        tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if "subscriptions" not in tables:
            return 0
        columns = {row[1] for row in connection.execute("PRAGMA table_info(subscriptions)")}
        if not {"user_id", "expires_at", "provisioned_until", "notified_until"} <= columns or "payments" not in tables:
            raise SetupError("Неожиданная схема базы оплат; автоматический перенос прекращён.")
        fd = os.open(backup_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        os.close(fd)
        with sqlite3.connect(backup_path) as backup:
            connection.backup(backup)
        connection.execute("PRAGMA synchronous=FULL")
        connection.execute("BEGIN IMMEDIATE")
        result = connection.execute(
            "UPDATE subscriptions SET provisioned_until=NULL,notified_until=NULL "
            "WHERE expires_at>? AND EXISTS "
            "(SELECT 1 FROM payments WHERE payments.user_id=subscriptions.user_id)",
            (time.time() if now is None else now,),
        )
        connection.commit()
        return result.rowcount
    except sqlite3.Error:
        raise SetupError("Не удалось сохранить очередь повторной выдачи; база оплат не изменена.") from None
    finally:
        if connection is not None:
            connection.close()


def account_uid(name: str, *, required: bool = False) -> int | None:
    try:
        account = pwd.getpwnam(name)
    except KeyError:
        if required:
            raise SetupError("Не найден системный пользователь уже установленного бота.") from None
        return None
    if account.pw_uid == 0 or account.pw_gid == 0 or account.pw_shell not in {
        "/usr/sbin/nologin", "/sbin/nologin", "/bin/false",
    }:
        raise SetupError("Службы должны использовать отдельные непривилегированные системные учётные записи.")
    return account.pw_uid


@contextmanager
def readonly_database(path: Path) -> Iterator[sqlite3.Connection]:
    connection = None
    original_uid = os.geteuid()
    original_gid = os.getegid()
    original_groups = os.getgroups()
    changed_identity = False
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode):
                raise SetupError("Существующая база должна быть обычным файлом.")
        finally:
            os.close(fd)
        if info.st_uid != original_uid:
            if original_uid != 0:
                raise SetupError("Нельзя прочитать базу от имени её владельца.")
            # SQLite may create WAL/SHM even for mode=ro. Keep the effective
            # owner through connect, every query and close, so sidecars belong
            # to the service rather than root. This installer is single-threaded.
            changed_identity = True
            os.setgroups([info.st_gid])
            os.setegid(info.st_gid)
            os.seteuid(info.st_uid)
        connection = sqlite3.connect(path.as_uri() + "?mode=ro", uri=True, timeout=5)
        connection.execute("PRAGMA query_only=ON")
        yield connection
    except (OSError, ValueError, sqlite3.Error):
        raise SetupError("Не удалось безопасно прочитать существующую базу.") from None
    finally:
        try:
            if connection is not None:
                connection.close()
        finally:
            if changed_identity:
                os.seteuid(original_uid)
                os.setegid(original_gid)
                os.setgroups(original_groups)


def paid_user_ids(database: Path, *, now: float | None = None) -> set[int]:
    if not database.exists():
        return set()
    with readonly_database(database) as connection:
        tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if not {"subscriptions", "payments", "orders"} <= tables:
            raise SetupError("Неожиданная схема базы оплат; исходная база сохранена.")
        subscription_columns = {row[1] for row in connection.execute("PRAGMA table_info(subscriptions)")}
        payment_columns = {row[1] for row in connection.execute("PRAGMA table_info(payments)")}
        if (not {"user_id", "expires_at", "provisioned_until", "notified_until"} <= subscription_columns
                or not {"user_id", "charge_id"} <= payment_columns):
            raise SetupError("Неожиданные столбцы базы оплат; исходная база сохранена.")
        users = {row[0] for row in connection.execute(
            "SELECT user_id FROM subscriptions WHERE expires_at>? AND EXISTS "
            "(SELECT 1 FROM payments WHERE payments.user_id=subscriptions.user_id)",
            (time.time() if now is None else now,),
        )}
        validate_user_ids(users)
        return users


def validate_user_ids(users: set[int]) -> None:
    if any(isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 2**63 - 1 for value in users):
        raise SetupError("База содержит некорректные Telegram ID; перенос остановлен.")


def legacy_reserved_user_ids(database: Path) -> set[int]:
    if not database.exists():
        return set()
    assert_owned_path(database.parent, owner_uids={os.geteuid()}, directory=True, private=True)
    assert_owned_path(database, owner_uids={os.geteuid()}, private=True)
    with readonly_database(database) as connection:
        tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if "reservations" not in tables:
            return set()
        columns = {row[1] for row in connection.execute("PRAGMA table_info(reservations)")}
        if not {"user_id", "reserved_until"} <= columns:
            raise SetupError("Неожиданная схема резервов старого шлюза.")
        users = {row[0] for row in connection.execute("SELECT user_id FROM reservations WHERE reserved_until IS NULL")}
        validate_user_ids(users)
        return users


def proxy_user_ids(database: Path) -> set[int]:
    if not database.exists():
        return set()
    with readonly_database(database) as connection:
        columns = {row[1] for row in connection.execute("PRAGMA table_info(users)")}
        if not {"user_id", "uuid", "expires_at", "reserved_until", "created_at"} <= columns:
            raise SetupError("Неожиданная схема существующей proxy-базы.")
        rows = connection.execute("SELECT user_id,uuid,expires_at,reserved_until,created_at FROM users").fetchall()
        users = {row[0] for row in rows}
        validate_user_ids(users)
        for _, identifier, expiry, reserved_until, created in rows:
            try:
                parsed = UUID(identifier)
                if str(parsed) != identifier or parsed.version != 4:
                    raise ValueError
                if (not isinstance(expiry, int) or not 0 <= expiry <= 2**63 - 1
                        or not isinstance(created, int) or not 0 <= created <= 2**63 - 1
                        or reserved_until is not None and
                        (not isinstance(reserved_until, int) or not 1 <= reserved_until <= 2**63 - 1)):
                    raise ValueError
            except (ValueError, TypeError, AttributeError):
                raise SetupError("Существующая proxy-база содержит некорректные учётные записи.") from None
        return users


def preflight_existing_install(bot: dict[str, str], gateway: dict[str, str],
                               proxy: dict[str, str] | None, database: Path,
                               *, owner_uid: int = 0) -> set[int]:
    assert_owned_path(CONFIG_DIRECTORY, owner_uids={owner_uid}, directory=True, private=True)
    assert_owned_path(SERVICE_DIRECTORY, owner_uids={owner_uid}, directory=True)
    if BINARY_PATH.exists() or BINARY_PATH.is_symlink():
        assert_owned_path(BINARY_PATH, owner_uids={owner_uid})
    assert_owned_path(BINARY_PATH.parent, owner_uids={owner_uid}, directory=True)
    target = SERVICE_DIRECTORY / SERVICE_NAME
    if target.exists() or target.is_symlink():
        assert_owned_path(target, owner_uids={owner_uid})
    proxy_uid = account_uid("brawl-proxy")
    proxy_owners = {owner_uid} | ({proxy_uid} if proxy_uid is not None else set())
    if STATE_DIRECTORY.exists() or STATE_DIRECTORY.is_symlink():
        assert_owned_path(STATE_DIRECTORY, owner_uids=proxy_owners, directory=True, private=True)
        for path in STATE_DIRECTORY.iterdir():
            assert_owned_path(path, owner_uids=proxy_owners, private=True,
                              allow_runtime_group_read=path.name == "runtime.json" or path.name.startswith(".runtime-"))
    assert_owned_path(STATE_DIRECTORY.parent, owner_uids={owner_uid}, directory=True)
    bot_uid = account_uid("brawl-vpn", required=True)
    bot_owners = {bot_uid}
    assert_owned_path(database.parent, owner_uids=bot_owners, directory=True, private=True)
    if os.statvfs(database.parent).f_flag & os.ST_RDONLY:
        raise SetupError("Каталог базы бота находится на read-only файловой системе.")
    for path in (database, database.with_name(database.name + "-wal"), database.with_name(database.name + "-shm")):
        if path.exists() or path.is_symlink():
            assert_owned_path(path, owner_uids=bot_owners, private=True)
    paid = paid_user_ids(database)
    raw_gateway_database = gateway.get("VPN_GATEWAY_DATABASE", "/var/lib/brawl-vpn/gateway.sqlite")
    gateway_database = Path(raw_gateway_database)
    if not gateway_database.is_absolute():
        raise SetupError("Путь базы прежнего шлюза должен быть абсолютным.")
    held = legacy_reserved_user_ids(gateway_database)
    existing = proxy_user_ids(STATE_DIRECTORY / "proxy.sqlite")
    maximum = int((proxy or {}).get("PROXY_MAX_USERS", "1000"))
    if len(existing | held | paid) > maximum:
        raise SetupError("Новый proxy не вместит оплаченных клиентов и подтверждённые резервы.")
    return held | paid


def transfer_reservations(database: Path, user_ids: set[int], *, max_users: int = 1000) -> int:
    validate_user_ids(user_ids)
    if not 1 <= max_users <= 1000:
        raise SetupError("Неподдерживаемая вместимость proxy.")
    if database.is_symlink():
        raise SetupError("Proxy-база не должна быть symlink.")
    if not database.exists():
        fd = os.open(database, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        os.close(fd)
    connection = sqlite3.connect(database, timeout=5)
    try:
        connection.execute("PRAGMA synchronous=FULL")
        connection.execute("BEGIN IMMEDIATE")
        connection.execute("CREATE TABLE IF NOT EXISTS users ("
                           "user_id INTEGER PRIMARY KEY CHECK(user_id>0),uuid TEXT NOT NULL UNIQUE,"
                           "expires_at INTEGER NOT NULL DEFAULT 0,reserved_until INTEGER,created_at INTEGER NOT NULL)")
        existing = {row[0] for row in connection.execute("SELECT user_id FROM users")}
        validate_user_ids(existing)
        if len(existing | user_ids) > max_users:
            raise SetupError("Недостаточно места для переноса подтверждённых резервов.")
        created = int(time.time())
        added = 0
        for user_id in sorted(user_ids & existing):
            connection.execute("UPDATE users SET reserved_until=NULL WHERE user_id=?", (user_id,))
        for user_id in sorted(user_ids - existing):
            connection.execute("INSERT INTO users VALUES(?,?,0,NULL,?)", (user_id, str(uuid4()), created))
            added += 1
        connection.commit()
        return added
    except sqlite3.Error:
        connection.rollback()
        raise SetupError("Не удалось сохранить перенос резервов; proxy-база не изменена.") from None
    finally:
        connection.close()


def assert_supported_host() -> None:
    if os.geteuid() != 0:
        raise SetupError("Запустите установщик через sudo в консоли VDS.")
    if sys.version_info < (3, 10) or platform.machine().lower() not in {"x86_64", "amd64"}:
        raise SetupError("Требуется Linux x86_64 и Python 3.10+.")
    values = dict(line.partition("=")[::2] for line in Path("/etc/os-release").read_text().splitlines() if "=" in line)
    if values.get("ID", "").strip('"') not in {"ubuntu", "debian"}:
        raise SetupError("Установщик поддерживает только Ubuntu / Debian.")
    for executable in ("systemctl", "ss", "useradd", "openssl", "getent"):
        if not shutil.which(executable):
            raise SetupError("Не хватает системных команд; сначала выполните подготовку VDS.")
    if PROJECT != Path("/opt/brawl-vpn"):
        raise SetupError("Разместите root-owned проект в /opt/brawl-vpn перед миграцией.")
    for path in (PROJECT, Path(__file__), PROJECT / "deploy" / SERVICE_NAME):
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise SetupError("Проект и службы должны принадлежать root без записи для других пользователей.")
    for parent in PROJECT.parents:
        assert_owned_path(parent, owner_uids={0}, directory=True)
    assert_owned_path(PROJECT / "deploy", owner_uids={0}, directory=True)
    for package in ("brawl_proxy", "vpn_shop", "vpn_gateway"):
        assert_trusted_tree(PROJECT / package)
    assert_trusted_tree(PROJECT / ".venv", venv=PROJECT / ".venv")


def assert_tcp443_available(*, rerun: bool) -> None:
    listeners = run(["ss", "-ltnpH", "sport = :443"])
    if not listeners:
        return
    if rerun:
        lines = listeners.splitlines()
        pids = re.findall(r"pid=(\d+)", listeners)
        if pids and all(re.search(r"pid=\d+", line) for line in lines):
            try:
                if all(process_belongs_to(pid, {SERVICE_NAME}) for pid in pids):
                    return
            except OSError:
                pass
    raise SetupError("TCP 443 занят другим процессом; освободите порт вручную, установщик ничего не остановил.")


def assert_api_port_available() -> None:
    listeners = run(["ss", "-ltnpH", "sport = :8081"])
    if not listeners:
        return
    pids = re.findall(r"pid=(\d+)", listeners)
    if pids and all(re.search(r"pid=\d+", line) for line in listeners.splitlines()):
        try:
            if all(process_belongs_to(pid, {"brawl-vpn-gateway.service", SERVICE_NAME}) for pid in pids):
                return
        except OSError:
            pass
    raise SetupError("API-порт 8081 занят посторонним процессом; существующие службы сохранены.")


def process_belongs_to(pid: str, services: set[str]) -> bool:
    for line in Path(f"/proc/{pid}/cgroup").read_text().splitlines():
        fields = line.split(":", 2)
        if len(fields) == 3:
            components = fields[2].strip("/").split("/")
            if len(components) >= 2 and components[0] == "system.slice" and components[1] in services:
                return True
    return False


def validated_proxy(values: dict[str, str]) -> None:
    try:
        expected_paths = {
            "XRAY_BINARY": str(BINARY_PATH),
            "PROXY_DATABASE": str(STATE_DIRECTORY / "proxy.sqlite"),
            "PROXY_RUNTIME_CONFIG": str(STATE_DIRECTORY / "runtime.json"),
        }
        if any(values.get(name) != value for name, value in expected_paths.items()):
            raise ValueError
        from brawl_proxy.manager import verify_key_pair
        from brawl_proxy.settings import Settings
        verify_key_pair(Settings.from_env(values))
    except Exception:
        raise SetupError("Настройки нового proxy не проходят проверку; значения не выводятся.") from None


def new_proxy_env(gateway: dict[str, str], keys: tuple[str, str]) -> dict[str, str]:
    endpoint = gateway.get("WG_ENDPOINT", "")
    host, separator, port = endpoint.rpartition(":")
    if not separator or not port.isdecimal() or not host:
        raise SetupError("Существующий WG_ENDPOINT не содержит публичный адрес VDS.")
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        if not re.fullmatch(r"[A-Za-z0-9.-]+", host) or "." not in host:
            raise SetupError("Не удалось определить публичный host существующего VDS.") from None
    else:
        if address.version != 4 or not address.is_global:
            raise SetupError("Для Reality требуется публичный IPv4 host VDS.")
    return {
        "VPN_API_TOKEN": gateway["VPN_API_TOKEN"],
        "XRAY_ENDPOINT": f"{host}:443",
        "XRAY_PRIVATE_KEY": keys[0],
        "XRAY_PUBLIC_KEY": keys[1],
        "XRAY_SHORT_ID": secrets.token_hex(8),
        "XRAY_SERVER_NAME": "www.microsoft.com",
        "XRAY_TARGET": "www.microsoft.com:443",
        "GAME_ALLOWED_CIDRS": gateway.get("GAME_ALLOWED_CIDRS", ""),
        "XRAY_BINARY": str(BINARY_PATH),
        "PROXY_DATABASE": str(STATE_DIRECTORY / "proxy.sqlite"),
        "PROXY_RUNTIME_CONFIG": str(STATE_DIRECTORY / "runtime.json"),
        "PROXY_MAX_USERS": "1000",
        "PROXY_RECONCILE_SECONDS": "5",
    }


def validate_xray_configuration(binary: Path, values: dict[str, str], directory: Path) -> None:
    try:
        from brawl_proxy.manager import AccessManager
        from brawl_proxy.settings import Settings
        manager = object.__new__(AccessManager)
        manager.settings = Settings.from_env(values)
        manager.command = run
        config = manager.server_config([], manager._endpoint_addresses())
        path = directory / "validate-reality.json"
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as file:
            json.dump(config, file)
        run([str(binary), "run", "-test", "-config", str(path)])
    except Exception:
        raise SetupError("Xray не подтвердил новую конфигурацию; существующие службы сохранены.") from None


def install_binary(binary: bytes) -> None:
    if BINARY_PATH.exists():
        info = BINARY_PATH.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise SetupError("Существующий brawl-xray имеет небезопасного владельца или права.")
        if BINARY_PATH.read_bytes() == binary:
            return
    with tempfile.NamedTemporaryFile(dir=BINARY_PATH.parent, prefix=".brawl-xray-", delete=False) as file:
        staged = Path(file.name)
        try:
            file.write(binary)
            file.flush()
            os.fsync(file.fileno())
            os.chmod(staged, 0o755)
            os.replace(staged, BINARY_PATH)
        finally:
            staged.unlink(missing_ok=True)


def prepare_state() -> None:
    try:
        account = pwd.getpwnam("brawl-proxy")
    except KeyError:
        run(["useradd", "--system", "--user-group", "--home-dir", "/nonexistent", "--shell", "/usr/sbin/nologin", "brawl-proxy"])
        account = pwd.getpwnam("brawl-proxy")
    if account.pw_uid == 0 or account.pw_gid == 0 or account.pw_shell not in {
        "/usr/sbin/nologin", "/sbin/nologin", "/bin/false",
    }:
        raise SetupError("brawl-proxy должен быть отдельным непривилегированным системным пользователем.")
    if STATE_DIRECTORY.exists():
        info = STATE_DIRECTORY.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid not in {0, account.pw_uid}:
            raise SetupError("Каталог proxy-состояния имеет неподходящего владельца.")
    else:
        STATE_DIRECTORY.mkdir(mode=0o700)
    os.chown(STATE_DIRECTORY, account.pw_uid, account.pw_gid)
    os.chmod(STATE_DIRECTORY, 0o700)
    for path in STATE_DIRECTORY.iterdir():
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid not in {0, account.pw_uid}:
            raise SetupError("Каталог proxy-состояния содержит неподдерживаемые файлы; проверьте их вручную.")
        os.chown(path, account.pw_uid, account.pw_gid, follow_symlinks=False)
        os.chmod(path, 0o600, follow_symlinks=False)


def validate_bot(values: dict[str, str]) -> Path:
    required = {"BOT_TOKEN", "STARS_PRICE", "VPN_API_URL", "VPN_API_TOKEN", "SUPPORT_USERNAME", "DATABASE_PATH"}
    if any(not values.get(name, "").strip() for name in required):
        raise SetupError("Существующий bot.env не содержит обязательные настройки.")
    names = set(values) | {"ADMIN_IDS", "SALES_ENABLED"}
    saved = {name: os.environ.get(name) for name in names}
    try:
        os.environ.update(values)
        from vpn_shop.config import Settings
        settings = Settings.from_env()
        if not settings.database_path.is_absolute():
            raise SetupError("DATABASE_PATH бота должен быть абсолютным путём.")
        return settings.database_path
    except ValueError:
        raise SetupError("Существующие настройки бота некорректны; значения сохранены и не выводятся.") from None
    finally:
        for name, value in saved.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value


def wait_ready(token: str, *, seconds: int = 30) -> None:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        try:
            request = urllib.request.Request("http://127.0.0.1:8081/health",
                                             headers={"Authorization": f"Bearer {token}"})
            # The private API is loopback only and must not use an HTTP proxy.
            with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(request, timeout=2) as response:
                result = json.loads(response.read(65536))
                if result.get("ready") is True and result.get("backend") == "vless-reality":
                    return
        except (OSError, ValueError, AttributeError):
            pass
        time.sleep(0.5)
    raise SetupError("Новый proxy не стал готовым; бот и продажи не возобновлены.")


def migrate(admin_id: int, *, dry_run: bool = False) -> None:
    assert_supported_host()
    bot_path = CONFIG_DIRECTORY / "bot.env"
    gateway_path = CONFIG_DIRECTORY / "gateway.env"
    proxy_path = CONFIG_DIRECTORY / "proxy.env"
    bot = load_private_env(bot_path)
    gateway = load_private_env(gateway_path)
    if not secrets.compare_digest(bot.get("VPN_API_TOKEN", ""), gateway.get("VPN_API_TOKEN", "")):
        raise SetupError("API-секреты существующего бота и шлюза не совпадают.")
    updated_bot = update_bot_env(bot, admin_id)
    database = validate_bot(updated_bot)
    rerun = proxy_path.exists() or proxy_path.is_symlink()
    proxy = load_private_env(proxy_path) if rerun else None
    if proxy is not None:
        if not secrets.compare_digest(proxy.get("VPN_API_TOKEN", ""), bot.get("VPN_API_TOKEN", "")):
            raise SetupError("Существующий proxy использует другой API-секрет.")
        validated_proxy(proxy)
    assert_tcp443_available(rerun=rerun)
    assert_api_port_available()
    preflight_existing_install(bot, gateway, proxy, database)
    if dry_run:
        print(f"Проверки VDS пройдены. План: Xray {XRAY_VERSION}, TCP 443. Настройки, службы и платежи не менялись; SQLite могла создать служебные WAL/SHM от имени владельца базы.")
        return
    binary = release_binary()
    # Verify and generate keys before stopping the working bot or gateway.
    with tempfile.TemporaryDirectory(prefix="brawl-xray-check-") as directory:
        verified = Path(directory) / "xray"
        verified.write_bytes(binary)
        verified.chmod(0o700)
        run([str(verified), "version"])
        if proxy is None:
            proxy = new_proxy_env(gateway, parse_x25519(run([str(verified), "x25519"])))
        validated_proxy(proxy)
        validate_xray_configuration(verified, proxy, Path(directory))
    run(["systemctl", "stop", "brawl-vpn-bot.service"])
    try:
        if (SERVICE_DIRECTORY / SERVICE_NAME).exists():
            run(["systemctl", "stop", SERVICE_NAME])
        # Re-read the durable holds after polling stopped, so checkouts accepted
        # while the release was downloading cannot disappear during migration.
        held_users = preflight_existing_install(bot, gateway, proxy, database)
        atomic_private_env(bot_path, updated_bot)
        atomic_private_env(proxy_path, proxy)
        install_binary(binary)
        prepare_state()
        transfer_reservations(STATE_DIRECTORY / "proxy.sqlite", held_users,
                              max_users=int(proxy["PROXY_MAX_USERS"]))
        prepare_state()  # Root created new SQLite files; return ownership to the service.
        run(["systemctl", "stop", "brawl-vpn-expire.service"])
        for old_service in ("brawl-vpn-gateway.service", "brawl-vpn-expire.timer", "wg-quick@wg-brawl.service"):
            run(["systemctl", "disable", "--now", old_service])
        reset_active_deliveries(database)
        target = SERVICE_DIRECTORY / SERVICE_NAME
        if target.is_symlink():
            raise SetupError("Существующая proxy-служба является symlink; сохранена без изменений.")
        shutil.copyfile(PROJECT / "deploy" / SERVICE_NAME, target)
        os.chmod(target, 0o644)
        run(["systemctl", "daemon-reload"])
        if shutil.which("ufw") and "Status: active" in run(["ufw", "status"], check=False):
            run(["ufw", "allow", "443/tcp"])
        run(["systemctl", "enable", "--now", SERVICE_NAME])
        run(["systemctl", "restart", SERVICE_NAME])
        wait_ready(proxy["VPN_API_TOKEN"])
        run(["systemctl", "restart", "brawl-vpn-bot.service"])
    except SetupError as error:
        raise SetupError(str(error) + " Перенос не завершён; бот не возобновлён.") from None
    except Exception:
        # Existing private settings/backups and payment history remain on disk.
        # Never turn sales on or silently resume the old backend after a failure.
        raise SetupError("Перенос не завершён. Бот не возобновлён; проверьте systemd status, приватные файлы и сохранённые резервные копии.") from None
    print("Incy backend запущен. Продажи выключены. Откройте TCP 443 в панели VDS и получите /testvpn android или /testvpn ios в боте.")


def main() -> int:
    parser = argparse.ArgumentParser(description="Перенос бота на Incy VLESS/Reality без вывода секретов")
    parser.add_argument("--admin-id", required=True, type=int, help="Числовой Telegram ID владельца")
    parser.add_argument("--dry-run", action="store_true", help="Без скачивания и изменения настроек/служб/платежей; возможны служебные SQLite WAL/SHM")
    args = parser.parse_args()
    try:
        if os.geteuid() != 0:
            raise SetupError("Запустите установщик через sudo в консоли VDS.")
        if args.admin_id <= 0:
            raise SetupError("admin-id должен быть положительным.")
        if args.dry_run:
            migrate(args.admin_id, dry_run=True)
        else:
            lock_fd = os.open("/run/brawl-vpn-incy-setup.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
            with os.fdopen(lock_fd, "w") as lock:
                info = os.fstat(lock.fileno())
                if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o600:
                    raise SetupError("Файл блокировки установщика имеет небезопасные права.")
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                migrate(args.admin_id)
        return 0
    except SetupError as error:
        print(str(error), file=sys.stderr)
        return 1
    except Exception:
        print("Не удалось завершить перенос. Секреты и вывод внешних команд скрыты; проверьте условия установки.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
