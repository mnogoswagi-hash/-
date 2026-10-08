from __future__ import annotations

import os
import secrets
import sqlite3
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable, Iterator


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def timestamp(value: datetime) -> float:
    if value.tzinfo is None:
        raise ValueError("Timezone-aware datetime required")
    return value.timestamp()


def as_datetime(value: float | None) -> datetime | None:
    return None if value is None else datetime.fromtimestamp(value, timezone.utc)


@dataclass(frozen=True)
class Order:
    id: str
    user_id: int
    chat_id: int
    platform: str
    amount: int


@dataclass(frozen=True)
class Subscription:
    user_id: int
    chat_id: int
    platform: str
    expires_at: datetime
    provisioned_until: datetime | None
    notified_until: datetime | None


@dataclass(frozen=True)
class PaymentResult:
    is_new: bool
    expires_at: datetime


class Store:
    """Durable payment inbox and provisioning outbox. One connection per bot process."""

    def __init__(self, path: Path | str, *, clock: Callable[[], datetime] = utcnow,
                 plan_days: int = 30):
        self.clock = clock
        self.plan_days = plan_days
        if str(path) != ":memory:":
            path = Path(path)
            path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            fd = os.open(path, os.O_CREAT | os.O_RDWR, 0o600)
            os.close(fd)
            os.chmod(path, 0o600)
        self.connection = sqlite3.connect(str(path), isolation_level=None, timeout=5)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute("PRAGMA foreign_keys=ON")
        self.connection.execute("PRAGMA journal_mode=WAL")
        self.connection.execute("PRAGMA synchronous=FULL")
        self.connection.executescript("""
            CREATE TABLE IF NOT EXISTS orders (
                id TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                chat_id INTEGER NOT NULL,
                platform TEXT NOT NULL CHECK (platform IN ('android','ios')),
                amount INTEGER NOT NULL CHECK (amount > 0),
                created_at REAL NOT NULL,
                paid INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS subscriptions (
                user_id INTEGER PRIMARY KEY,
                chat_id INTEGER NOT NULL,
                platform TEXT NOT NULL,
                expires_at REAL NOT NULL,
                provisioned_until REAL,
                notified_until REAL
            );
            CREATE TABLE IF NOT EXISTS payments (
                charge_id TEXT PRIMARY KEY,
                order_id TEXT NOT NULL UNIQUE REFERENCES orders(id),
                user_id INTEGER NOT NULL,
                amount INTEGER NOT NULL,
                currency TEXT NOT NULL CHECK (currency = 'XTR'),
                paid_at REAL NOT NULL,
                expires_at REAL NOT NULL
            );
            CREATE TABLE IF NOT EXISTS payment_incidents (
                update_id INTEGER PRIMARY KEY,
                user_id INTEGER NOT NULL,
                invoice_payload TEXT NOT NULL,
                currency TEXT NOT NULL,
                amount INTEGER NOT NULL,
                charge_id TEXT NOT NULL,
                reason TEXT NOT NULL,
                recorded_at REAL NOT NULL
            );
        """)

    @contextmanager
    def transaction(self) -> Iterator[None]:
        self.connection.execute("BEGIN IMMEDIATE")
        try:
            yield
        except BaseException:
            self.connection.rollback()
            raise
        else:
            self.connection.commit()

    def create_order(self, user_id: int, chat_id: int, platform: str, amount: int) -> Order:
        if user_id <= 0 or chat_id != user_id or platform not in {"android", "ios"} or amount <= 0:
            raise ValueError("Invalid private-chat order")
        order = Order(secrets.token_urlsafe(18), user_id, chat_id, platform, amount)
        self.connection.execute(
            "INSERT INTO orders(id,user_id,chat_id,platform,amount,created_at) VALUES(?,?,?,?,?,?)",
            (order.id, user_id, chat_id, platform, amount, timestamp(self.clock())),
        )
        return order

    def _order_row(self, order_id: str, user_id: int, currency: str, amount: int) -> sqlite3.Row:
        row = self.connection.execute("SELECT * FROM orders WHERE id=?", (order_id,)).fetchone()
        if row is None or row["user_id"] != user_id:
            raise ValueError("Order does not belong to this user")
        if currency != "XTR" or amount != row["amount"]:
            raise ValueError("Payment currency or amount does not match the invoice")
        return row

    def validate_checkout(self, order_id: str, user_id: int, currency: str, amount: int) -> Order:
        row = self._order_row(order_id, user_id, currency, amount)
        if row["paid"]:
            raise ValueError("Order has already been paid")
        if timestamp(self.clock()) - row["created_at"] > 3600:
            raise ValueError("Invoice expired; create a new invoice")
        return Order(row["id"], row["user_id"], row["chat_id"], row["platform"], row["amount"])

    def accept_payment(self, order_id: str, user_id: int, currency: str,
                       amount: int, charge_id: str) -> PaymentResult:
        if not charge_id or len(charge_id) > 512:
            raise ValueError("Missing or invalid Telegram payment charge ID")
        with self.transaction():
            row = self._order_row(order_id, user_id, currency, amount)
            previous = self.connection.execute(
                "SELECT * FROM payments WHERE charge_id=?", (charge_id,)
            ).fetchone()
            if previous is not None:
                if previous["order_id"] != order_id or previous["user_id"] != user_id:
                    raise ValueError("Payment charge ID reused for another order")
                return PaymentResult(False, as_datetime(previous["expires_at"]))
            if row["paid"]:
                raise ValueError("Order already has a different successful payment")
            now = self.clock()
            subscription = self.get_subscription(user_id)
            start = max(now, subscription.expires_at) if subscription else now
            expiry = start + timedelta(days=self.plan_days)
            self.connection.execute(
                "INSERT INTO payments VALUES(?,?,?,?,?,?,?)",
                (charge_id, order_id, user_id, amount, currency, timestamp(now), timestamp(expiry)),
            )
            self.connection.execute("UPDATE orders SET paid=1 WHERE id=?", (order_id,))
            self.connection.execute("""
                INSERT INTO subscriptions(user_id,chat_id,platform,expires_at)
                VALUES(?,?,?,?)
                ON CONFLICT(user_id) DO UPDATE SET chat_id=excluded.chat_id,
                    platform=excluded.platform,expires_at=excluded.expires_at
                """, (user_id, row["chat_id"], row["platform"], timestamp(expiry)))
        return PaymentResult(True, expiry)

    @staticmethod
    def _subscription(row: sqlite3.Row) -> Subscription:
        return Subscription(row["user_id"], row["chat_id"], row["platform"],
                            as_datetime(row["expires_at"]),
                            as_datetime(row["provisioned_until"]),
                            as_datetime(row["notified_until"]))

    def get_subscription(self, user_id: int) -> Subscription | None:
        row = self.connection.execute(
            "SELECT * FROM subscriptions WHERE user_id=?", (user_id,)
        ).fetchone()
        return self._subscription(row) if row is not None else None

    def pending_subscriptions(self) -> list[Subscription]:
        rows = self.connection.execute("""
            SELECT * FROM subscriptions WHERE expires_at > ? AND
                (provisioned_until IS NULL OR provisioned_until < expires_at OR
                 notified_until IS NULL OR notified_until < expires_at)
            ORDER BY user_id
            """, (timestamp(self.clock()),)).fetchall()
        return [self._subscription(row) for row in rows]

    def _mark(self, column: str, user_id: int, expires_at: datetime) -> None:
        assert column in {"provisioned_until", "notified_until"}
        # A completion for an earlier extension must not complete a newer payment's job.
        self.connection.execute(
            f"UPDATE subscriptions SET {column}=MAX(COALESCE({column},0),?) "
            "WHERE user_id=? AND expires_at >= ?",
            (timestamp(expires_at), user_id, timestamp(expires_at)),
        )

    def mark_provisioned(self, user_id: int, expires_at: datetime) -> None:
        self._mark("provisioned_until", user_id, expires_at)

    def mark_notified(self, user_id: int, expires_at: datetime) -> None:
        self._mark("notified_until", user_id, expires_at)

    def record_payment_incident(self, update_id: int, user_id: int, invoice_payload: str,
                                currency: str, amount: int, charge_id: str,
                                reason: str) -> None:
        """Keep an unmatched real receipt before acknowledging its Telegram update."""
        self.connection.execute(
            "INSERT OR IGNORE INTO payment_incidents VALUES(?,?,?,?,?,?,?,?)",
            (update_id, user_id, invoice_payload, currency, amount, charge_id,
             reason, timestamp(self.clock())),
        )

    def close(self) -> None:
        self.connection.close()

