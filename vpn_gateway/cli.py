from __future__ import annotations

import argparse
import sys

from .manager import AccessManager
from .settings import Settings


def main() -> int:
    parser = argparse.ArgumentParser(description="WireGuard gateway maintenance")
    parser.add_argument("command", choices=("expire", "quarantine", "check", "release-reservation"))
    parser.add_argument("user_id", type=int, nargs="?")
    parser.add_argument("--confirmed-unpaid", action="store_true", help="Only after canceling sales, synchronizing Telegram updates and checking Stars receipts")
    args = parser.parse_args()
    manager = None
    try:
        manager = AccessManager(Settings.from_env())
        if args.command == "expire":
            manager.expire_only()
        elif args.command == "quarantine":
            with manager.locked():
                manager.firewall.quarantine()
        elif args.command == "release-reservation":
            if args.user_id is None or not args.confirmed_unpaid:
                parser.error("release-reservation requires USER_ID --confirmed-unpaid")
            manager.release_reservation(args.user_id, confirmed_unpaid=args.confirmed_unpaid)
        else:
            with manager.locked():
                manager.firewall.verify()
                manager._check_interface()
        print(f"Gateway {args.command}: OK")
        return 0
    except Exception:
        print("Gateway maintenance failed; check configured interfaces, dependencies and state permissions", file=sys.stderr)
        return 1
    finally:
        if manager is not None:
            manager.close()


if __name__ == "__main__":
    raise SystemExit(main())
