#!/usr/bin/env python3
"""Interactively create private VDS settings. Never starts any service.

Run from a real VDS console as root after prepare-vds.sh. Secrets are read only
through getpass or the existing private WireGuard file, never through argv.
"""
from __future__ import annotations

import base64
import configparser
import getpass
import ipaddress
import json
import os
import re
import secrets
import stat
import subprocess
import sys
import warnings
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

# Direct script execution works before installing the project as a package.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from vpn_gateway.settings import (  # noqa: E402
    Settings as GatewaySettings,
    interface_name,
    public_endpoint,
    valid_public_key,
)


class ConfigurationError(RuntimeError):
    """An operator-facing error whose text never contains secret values."""


@dataclass(frozen=True)
class WireGuardMetadata:
    public_key: str
    client_subnet: str
    gateway_address: str
    listen_port: int
    interface: str = "wg-brawl"


@dataclass(frozen=True)
class ConfigurationDraft:
    bot_env: dict[str, str] = field(repr=False)
    gateway_env: dict[str, str] = field(repr=False)
    game_cidrs_configured: bool


@dataclass(frozen=True)
class ConfigurationResult:
    bot_path: Path
    gateway_path: Path
    game_cidrs_configured: bool
    stars_price: int = 100
    plan_days: int = 30


def command_output(args: list[str], stdin: str | None = None) -> str:
    try:
        result = subprocess.run(args, input=stdin, text=True, capture_output=True, timeout=20)
    except (OSError, subprocess.TimeoutExpired):
        raise ConfigurationError("Не удалось выполнить wg/ip. Сначала запустите prepare-vds.sh.") from None
    if result.returncode:
        raise ConfigurationError("Команда wg/ip завершилась ошибкой. Проверьте подготовку VDS.")
    return result.stdout.strip()


def read_wireguard(path: Path, run: Callable = command_output) -> WireGuardMetadata:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, encoding="utf-8") as file:
            info = os.fstat(file.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077 or info.st_size > 65536:
                raise ConfigurationError("Конфиг WireGuard должен быть обычным приватным файлом владельца процесса, режим 0600.")
            text = file.read(65537)
        parser = configparser.ConfigParser(interpolation=None, strict=True)
        parser.read_string(text)
        if parser.sections() != ["Interface"]:
            raise ConfigurationError("Нужен отдельный конфиг wg-brawl, созданный prepare-vds.sh, без разделов Peer.")
        interface = parser["Interface"]
        if set(interface) - {"privatekey", "address", "listenport", "saveconfig"} or interface.get("SaveConfig", "false").strip().lower() != "false":
            raise ConfigurationError("Нужен конфиг prepare-vds.sh без дополнительных команд и с SaveConfig=false.")
        private_key = interface["PrivateKey"].strip()
        decoded = base64.b64decode(private_key, validate=True)
        if len(decoded) != 32 or decoded == bytes(32):
            raise ValueError
        address = ipaddress.ip_interface(interface["Address"].strip())
        ranges = [ipaddress.ip_network(value) for value in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]
        if address.version != 4 or not 16 <= address.network.prefixlen <= 30 or not any(address.network.subnet_of(value) for value in ranges):
            raise ValueError
        if address.ip in (address.network.network_address, address.network.broadcast_address):
            raise ValueError
        port = int(interface["ListenPort"])
        if not 1 <= port <= 65535 or path.stem != "wg-brawl":
            raise ValueError
        public_key = run(["wg", "pubkey"], private_key + "\n")
        valid_public_key(public_key)
        return WireGuardMetadata(public_key, str(address.network), str(address.ip), port)
    except ConfigurationError:
        raise
    except Exception:
        # ConfigParser errors can include the actual source line/private key.
        raise ConfigurationError("Не удалось прочитать корректный приватный /etc/wireguard/wg-brawl.conf.") from None


def detect_egress(run: Callable = command_output) -> str:
    try:
        routes = json.loads(run(["ip", "-4", "-j", "route", "show", "default"]))
        candidates = [(int(route.get("metric", 0)), interface_name(route["dev"])) for route in routes if route.get("dst", "default") == "default" and "dev" in route]
        if not candidates:
            raise ValueError
        best_metric = min(metric for metric, _ in candidates)
        best = {device for metric, device in candidates if metric == best_metric}
        if len(best) != 1:
            raise ValueError
        return best.pop()
    except ConfigurationError:
        raise
    except Exception:
        raise ConfigurationError("Не удалось однозначно определить внешний IPv4-интерфейс по маршруту default.") from None


def create_draft(*, bot_token: str, support_username: str, public_host: str, game_cidrs: str, wireguard: WireGuardMetadata, public_interface: str) -> ConfigurationDraft:
    try:
        valid_public_key(wireguard.public_key)
        if wireguard.interface != "wg-brawl" or not 1 <= wireguard.listen_port <= 65535:
            raise ValueError
        network = ipaddress.ip_network(wireguard.client_subnet, strict=True)
        address = ipaddress.ip_address(wireguard.gateway_address)
        private = [ipaddress.ip_network(value) for value in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]
        if network.version != 4 or not 16 <= network.prefixlen <= 30 or not any(network.subnet_of(value) for value in private):
            raise ValueError
        if address not in network or address in (network.network_address, network.broadcast_address):
            raise ValueError
    except (ValueError, TypeError):
        raise ConfigurationError("Некорректные параметры отдельного WireGuard-интерфейса.") from None
    bot_token = bot_token.strip()
    if not re.fullmatch(r"[0-9]+:[A-Za-z0-9_-]{20,}", bot_token):
        raise ConfigurationError("Некорректный формат BOT_TOKEN. Получите токен у BotFather; значение не выводится.")
    support_username = support_username.strip().removeprefix("@")
    if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{4,31}", support_username):
        raise ConfigurationError("Укажите Telegram username поддержки, например @my_support, без ссылки.")
    try:
        host = public_host.strip()
        endpoint = public_endpoint(host if ":" in host else f"{host}:{wireguard.listen_port}")
        if int(endpoint.rpartition(":")[2]) != wireguard.listen_port:
            raise ValueError
        interface_name(public_interface)
        if public_interface == wireguard.interface:
            raise ValueError
    except ValueError:
        raise ConfigurationError("Нужен публичный IPv4 или домен VDS; порт должен совпадать с ListenPort WireGuard.") from None
    configured = bool(game_cidrs.strip())
    api_token = secrets.token_urlsafe(32)
    gateway = {
        "VPN_API_TOKEN": api_token,
        "WG_EXCLUSIVE_INTERFACE": "true",
        "WG_INTERFACE": wireguard.interface,
        "WG_PUBLIC_INTERFACE": public_interface,
        "WG_CLIENT_SUBNET": wireguard.client_subnet,
        "WG_GATEWAY_ADDRESS": wireguard.gateway_address,
        "WG_SERVER_PUBLIC_KEY": wireguard.public_key,
        "WG_ENDPOINT": endpoint,
        "GAME_ALLOWED_CIDRS": "",
        "VPN_GATEWAY_DATABASE": "/var/lib/brawl-vpn/gateway.sqlite",
        "VPN_RECONCILE_SECONDS": "15",
    }
    if configured:
        try:
            networks = [ipaddress.ip_network(value.strip(), strict=True) for value in game_cidrs.split(",")]
            gateway["GAME_ALLOWED_CIDRS"] = ",".join(map(str, networks))
            # Share the gateway's full validation; no invented CIDR is supplied.
            GatewaySettings.from_env(gateway)
        except (ValueError, TypeError):
            raise ConfigurationError("GAME_ALLOWED_CIDRS: нужны проверенные публичные IPv4 CIDR /16 или уже, без пересечений и маршрута 0.0.0.0/0.") from None
    bot = {
        "BOT_TOKEN": bot_token,
        "STARS_PRICE": "100",
        "SALES_ENABLED": "false",
        "SUPPORT_USERNAME": support_username,
        "VPN_API_URL": "http://127.0.0.1:8081",
        "VPN_API_TOKEN": api_token,
        "DATABASE_PATH": "/var/lib/brawl-vpn-bot/shop.sqlite",
        "ADMIN_IDS": "",
    }
    return ConfigurationDraft(bot, gateway, configured)


def render_environment(values: dict[str, str]) -> str:
    # Fields have narrow validated alphabets. Reject line injection even if this
    # lower-level function is called directly with an unvalidated test draft.
    if any(not re.fullmatch(r"[A-Z][A-Z0-9_]*", name) or not value.isascii() or any(character.isspace() or character in "\x00\"'\\" for character in value) for name, value in values.items()):
        raise ConfigurationError("Нельзя сохранить некорректные поля конфигурации.")
    return "".join(f"{name}={value}\n" for name, value in values.items())


def open_private_directory(path: Path) -> int:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        info = os.fstat(fd)
        if info.st_uid != os.geteuid() or info.st_mode & 0o077:
            os.close(fd)
            raise ConfigurationError("Каталог /etc/brawl-vpn должен принадлежать владельцу процесса и иметь режим 0700.")
        return fd
    except OSError:
        raise ConfigurationError("Приватный каталог /etc/brawl-vpn недоступен. Сначала запустите prepare-vds.sh.") from None


def require_new_targets(directory_fd: int) -> None:
    for name in ("bot.env", "gateway.env"):
        try:
            os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        except FileNotFoundError:
            continue
        raise ConfigurationError("bot.env или gateway.env уже существует. Существующие настройки сохранены; отредактируйте их вручную.")


def write_configuration(directory: Path, draft: ConfigurationDraft) -> ConfigurationResult:
    # Validate both complete contents before opening any output file.
    contents = {"bot.env": render_environment(draft.bot_env), "gateway.env": render_environment(draft.gateway_env)}
    fd = open_private_directory(directory)
    owned: dict[str, tuple[int, int]] = {}
    staged: dict[str, str] = {}
    success = False
    try:
        require_new_targets(fd)
        for target, content in contents.items():
            name = f".configure-{secrets.token_hex(16)}.tmp"
            file_fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fd)
            info = os.fstat(file_fd)
            owned[name] = (info.st_dev, info.st_ino)
            with os.fdopen(file_fd, "w", encoding="ascii") as file:
                file.write(content)
                file.flush()
                os.fsync(file.fileno())
            staged[target] = name
        require_new_targets(fd)
        for target, name in staged.items():
            # Same-directory hard links atomically publish a complete mode-0600
            # file and fail if any target (including a symlink) already exists.
            os.link(name, target, src_dir_fd=fd, dst_dir_fd=fd, follow_symlinks=False)
            owned[target] = owned[name]
        os.fsync(fd)
        success = True
    except ConfigurationError:
        raise
    except Exception:
        raise ConfigurationError("Не удалось сохранить оба файла. Существующие настройки не перезаписаны.") from None
    finally:
        for name, identity in owned.items():
            if success and name in contents:
                continue
            try:
                info = os.stat(name, dir_fd=fd, follow_symlinks=False)
                if stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid() and (info.st_dev, info.st_ino) == identity:
                    os.unlink(name, dir_fd=fd)
            except OSError:
                pass
        os.close(fd)
    return ConfigurationResult(directory / "bot.env", directory / "gateway.env", draft.game_cidrs_configured)


def configure(*, wireguard_path: Path = Path("/etc/wireguard/wg-brawl.conf"), configuration_directory: Path = Path("/etc/brawl-vpn"), prompt: Callable[[str], str] = input, secret_prompt: Callable[[str], str] = getpass.getpass, run: Callable = command_output, is_tty: Callable[[], bool] | None = None, effective_uid: Callable[[], int] = os.geteuid, emit: Callable[[str], None] = print) -> ConfigurationResult:
    if not (is_tty() if is_tty is not None else sys.stdin.isatty() and sys.stderr.isatty()):
        raise ConfigurationError("Нужна интерактивная консоль VDS с TTY. Ввод токена через pipe запрещён.")
    if effective_uid() != 0:
        raise ConfigurationError("Запустите configure-vds.py через sudo в консоли VDS.")
    directory_fd = open_private_directory(configuration_directory)
    try:
        require_new_targets(directory_fd)
    finally:
        os.close(directory_fd)
    wireguard = read_wireguard(wireguard_path, run)
    public_interface = detect_egress(run)
    emit("Настройка: 100 Stars за 30 дней. Продажи отключены до проверки VPN. Секреты не выводятся; сервисы не запускаются.")
    support = prompt("Username поддержки в Telegram (@username): ")
    endpoint = prompt(f"Публичный IPv4 или домен VDS (UDP-порт {wireguard.listen_port}): ")
    cidrs = prompt("Проверенные GAME_ALLOWED_CIDRS через запятую; пусто = VPN и оплаты пока отключены: ")
    try:
        with warnings.catch_warnings():
            # getpass warns BEFORE falling back to visible input. Turning that
            # warning into an exception prevents accidental token disclosure.
            warnings.simplefilter("error", getpass.GetPassWarning)
            token = secret_prompt("BOT_TOKEN от BotFather (ввод скрыт): ")
    except (getpass.GetPassWarning, EOFError, KeyboardInterrupt):
        raise ConfigurationError("Скрытый ввод BOT_TOKEN недоступен или отменён. Файлы не созданы.") from None
    draft = create_draft(bot_token=token, support_username=support, public_host=endpoint, game_cidrs=cidrs, wireguard=wireguard, public_interface=public_interface)
    result = write_configuration(configuration_directory, draft)
    emit(f"Созданы приватные файлы: {result.bot_path} и {result.gateway_path} (0600).")
    if not result.game_cidrs_configured:
        emit("GAME_ALLOWED_CIDRS не задан. VPN-шлюз не готов; бот не принимает оплату до настройки реальных игровых сетей.")
    else:
        emit("GAME_ALLOWED_CIDRS сохранён. Перед продажей выполните проверку подключения к игре по инструкции README.")
    return result


def main() -> int:
    if len(sys.argv) != 1:
        print("Аргументы не принимаются. Запустите configure-vds.py без токенов в командной строке.", file=sys.stderr)
        return 2
    try:
        configure()
    except ConfigurationError as error:
        print(str(error), file=sys.stderr)
        return 1
    except (EOFError, KeyboardInterrupt):
        print("Настройка отменена. Сервисы не запускались.", file=sys.stderr)
        return 1
    except Exception:
        print("Настройка не завершена. Проверьте подготовку VDS; секреты не выводятся.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
