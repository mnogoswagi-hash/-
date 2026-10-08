"""Run the configured Telegram bot with ``python -m vpn_shop``."""

import asyncio
import logging

from .config import Settings
from .telegram import run_bot


def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    try:
        settings = Settings.from_env()
    except ValueError as exc:
        raise SystemExit(f"Ошибка настройки: {exc}") from None
    try:
        asyncio.run(run_bot(settings))
    except (KeyboardInterrupt, asyncio.CancelledError):
        pass


if __name__ == "__main__":
    main()
