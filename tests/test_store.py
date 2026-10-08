from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
import sqlite3

import pytest

from vpn_shop.db import Store


NOW = datetime(2030, 1, 1, 12, tzinfo=timezone.utc)
PRICE = 140


class Clock:
    def __init__(self):
        self.now = NOW

    def __call__(self):
        return self.now


@pytest.fixture
def clock():
    return Clock()


@pytest.fixture
def store(tmp_path, clock):
    database = Store(tmp_path / "private" / "shop.sqlite", clock=clock)
    yield database
    database.close()


def order_for(store, user_id=11, platform="android", amount=PRICE):
    return store.create_order(user_id, user_id, platform, amount)


def pay(store, order, charge_id="tg-charge-1"):
    return store.accept_payment(order.id, order.user_id, "XTR", order.amount, charge_id)


@pytest.mark.parametrize(
    ("user_id", "currency", "amount"),
    [(12, "XTR", PRICE), (11, "RUB", PRICE), (11, "xtr", PRICE),
     (11, "XTR", PRICE - 1), (11, "XTR", PRICE + 1)],
)
def test_checkout_and_payment_reject_wrong_user_currency_or_invoice_amount(
    store, user_id, currency, amount
):
    order = order_for(store)
    with pytest.raises(ValueError):
        store.validate_checkout(order.id, user_id, currency, amount)
    with pytest.raises(ValueError):
        store.accept_payment(order.id, user_id, currency, amount, "tg-charge")
    assert store.pending_subscriptions() == []
    assert pay(store, order).expires_at == NOW + timedelta(days=30)


def test_price_is_snapshotted_for_each_invoice(store):
    old_order = order_for(store, amount=140)
    new_order = order_for(store, amount=160)
    assert store.validate_checkout(old_order.id, 11, "XTR", 140).amount == 140
    assert store.validate_checkout(new_order.id, 11, "XTR", 160).amount == 160
    with pytest.raises(ValueError):
        store.accept_payment(old_order.id, 11, "XTR", 160, "charge")
    assert pay(store, old_order).is_new is True


def test_unknown_invoice_cannot_grant_access(store):
    with pytest.raises(ValueError):
        store.validate_checkout("missing", 11, "XTR", PRICE)
    with pytest.raises(ValueError):
        store.accept_payment("missing", 11, "XTR", PRICE, "charge")
    assert store.get_subscription(11) is None


def test_duplicate_successful_payment_does_not_extend_access(store):
    order = order_for(store)
    first = pay(store, order)
    duplicate = pay(store, order)
    assert first.is_new is True
    assert duplicate.is_new is False
    assert duplicate.expires_at == first.expires_at == NOW + timedelta(days=30)
    assert store.get_subscription(11).expires_at == first.expires_at
    with pytest.raises(ValueError, match="already been paid"):
        store.validate_checkout(order.id, 11, "XTR", PRICE)


def test_replay_of_old_charge_after_renewal_keeps_current_subscription(store):
    first_order = order_for(store)
    first = pay(store, first_order, "first-charge")
    renewed = pay(store, order_for(store), "second-charge")
    replay = pay(store, first_order, "first-charge")
    assert replay.is_new is False
    assert replay.expires_at == first.expires_at
    assert store.get_subscription(11).expires_at == renewed.expires_at


@pytest.mark.parametrize("other_user", [11, 12])
def test_telegram_charge_cannot_be_reused_for_another_order(store, other_user):
    first = order_for(store)
    pay(store, first, "same-charge")
    second = order_for(store, user_id=other_user)
    with pytest.raises(ValueError, match="reused for another order"):
        pay(store, second, "same-charge")
    assert pay(store, second, "fresh-charge").is_new is True


def test_order_cannot_accept_a_second_distinct_charge(store):
    order = order_for(store)
    paid = pay(store, order, "first-charge")
    with pytest.raises(ValueError, match="different successful payment"):
        pay(store, order, "different-charge")
    assert store.get_subscription(11).expires_at == paid.expires_at


@pytest.mark.parametrize("elapsed_days", [5, 30, 45])
def test_renewal_stacks_active_access_or_starts_from_current_time(store, clock, elapsed_days):
    first = pay(store, order_for(store), "first-charge")
    clock.now += timedelta(days=elapsed_days)
    renewed = pay(store, order_for(store, platform="ios"), "renewal-charge")
    assert renewed.expires_at == max(first.expires_at, clock.now) + timedelta(days=30)
    current = store.get_subscription(11)
    assert current.platform == "ios"
    assert current.expires_at == renewed.expires_at


def test_paid_delivery_after_invoice_expiry_is_accepted_but_checkout_is_refused(store, clock):
    order = order_for(store)
    clock.now += timedelta(hours=1)
    assert store.validate_checkout(order.id, 11, "XTR", PRICE).id == order.id
    clock.now += timedelta(seconds=1)
    with pytest.raises(ValueError, match="Invoice expired"):
        store.validate_checkout(order.id, 11, "XTR", PRICE)
    assert pay(store, order).expires_at == clock.now + timedelta(days=30)


def test_paid_subscription_and_pending_delivery_survive_restart(tmp_path, clock):
    path = tmp_path / "database.sqlite"
    store = Store(path, clock=clock)
    order = order_for(store)
    paid = pay(store, order)
    store.mark_provisioned(11, paid.expires_at)
    store.close()

    reopened = Store(path, clock=clock)
    try:
        current = reopened.get_subscription(11)
        assert current.expires_at == paid.expires_at
        assert current.provisioned_until == paid.expires_at
        assert current.notified_until is None
        assert reopened.pending_subscriptions() == [current]
        assert pay(reopened, order).is_new is False
        reopened.mark_notified(11, paid.expires_at)
        assert reopened.pending_subscriptions() == []
    finally:
        reopened.close()
    assert path.stat().st_mode & 0o777 == 0o600


def test_pending_access_job_survives_restart_before_provisioning(tmp_path, clock):
    path = tmp_path / "database.sqlite"
    store = Store(path, clock=clock)
    paid = pay(store, order_for(store))
    store.close()
    reopened = Store(path, clock=clock)
    try:
        jobs = reopened.pending_subscriptions()
        assert len(jobs) == 1
        assert jobs[0].expires_at == paid.expires_at
        assert jobs[0].provisioned_until is None
        assert jobs[0].notified_until is None
    finally:
        reopened.close()


def test_older_provision_completion_cannot_complete_newer_paid_extension(store):
    first = pay(store, order_for(store), "first")
    renewed = pay(store, order_for(store), "renewed")
    store.mark_provisioned(11, first.expires_at)
    store.mark_notified(11, first.expires_at)
    pending = store.pending_subscriptions()
    assert len(pending) == 1
    assert pending[0].expires_at == renewed.expires_at
    assert pending[0].provisioned_until == first.expires_at
    store.mark_provisioned(11, renewed.expires_at)
    store.mark_notified(11, renewed.expires_at)
    assert store.pending_subscriptions() == []
    store.mark_provisioned(11, first.expires_at)
    store.mark_notified(11, first.expires_at)
    assert store.pending_subscriptions() == []
    assert store.get_subscription(11).provisioned_until == renewed.expires_at


def test_unsold_future_completion_does_not_hide_pending_access(store):
    paid = pay(store, order_for(store))
    store.mark_provisioned(11, paid.expires_at + timedelta(days=30))
    store.mark_notified(11, paid.expires_at + timedelta(days=30))
    assert len(store.pending_subscriptions()) == 1
    assert store.get_subscription(11).provisioned_until is None


def test_expired_subscriptions_are_not_provisioned_or_notified(store, clock):
    paid = pay(store, order_for(store))
    clock.now = paid.expires_at
    assert store.pending_subscriptions() == []


def test_database_failure_rolls_back_charge_order_and_subscription_together(store):
    order = order_for(store)
    store.connection.execute("""
        CREATE TRIGGER reject_subscription BEFORE INSERT ON subscriptions
        BEGIN SELECT RAISE(ABORT, 'simulated storage failure'); END
    """)
    with pytest.raises(sqlite3.IntegrityError, match="simulated storage failure"):
        pay(store, order)
    assert store.get_subscription(11) is None
    assert store.validate_checkout(order.id, 11, "XTR", PRICE).id == order.id
    store.connection.execute("DROP TRIGGER reject_subscription")
    assert pay(store, order).is_new is True
    assert store.get_subscription(11).expires_at == NOW + timedelta(days=30)


def test_unmatched_real_payment_receipt_survives_restart_without_granting_access(tmp_path, clock):
    path = tmp_path / "incident.sqlite"
    store = Store(path, clock=clock)
    store.record_payment_incident(
        update_id=7001,
        user_id=11,
        invoice_payload="unknown-invoice-payload",
        currency="XTR",
        amount=PRICE,
        charge_id="telegram-actual-receipt-id",
        reason="Order does not belong to this user",
    )
    assert store.get_subscription(11) is None
    assert store.pending_subscriptions() == []
    store.close()

    reopened = Store(path, clock=clock)
    try:
        incidents = reopened.connection.execute("SELECT * FROM payment_incidents").fetchall()
        assert len(incidents) == 1
        assert dict(incidents[0]) == {
            "update_id": 7001,
            "user_id": 11,
            "invoice_payload": "unknown-invoice-payload",
            "currency": "XTR",
            "amount": PRICE,
            "charge_id": "telegram-actual-receipt-id",
            "reason": "Order does not belong to this user",
            "recorded_at": NOW.timestamp(),
        }
        assert reopened.get_subscription(11) is None
    finally:
        reopened.close()


def test_payment_incident_redelivery_is_idempotent_and_preserves_original_receipt(store, clock):
    store.record_payment_incident(7001, 11, "unknown-order", "XTR", PRICE, "charge", "missing")
    clock.now += timedelta(minutes=5)
    store.record_payment_incident(
        7001, 99, "changed-order", "RUB", 999, "changed-charge", "changed reason"
    )
    rows = store.connection.execute("SELECT * FROM payment_incidents").fetchall()
    assert len(rows) == 1
    assert dict(rows[0]) == {
        "update_id": 7001, "user_id": 11, "invoice_payload": "unknown-order",
        "currency": "XTR", "amount": PRICE, "charge_id": "charge", "reason": "missing",
        "recorded_at": NOW.timestamp(),
    }


def test_incident_preserves_mismatched_currency_and_amount_for_refund_review(store):
    order = order_for(store)
    with pytest.raises(ValueError) as rejected:
        store.accept_payment(order.id, 11, "RUB", 999, "wrong-currency-charge")
    store.record_payment_incident(
        7002, 11, order.id, "RUB", 999, "wrong-currency-charge", str(rejected.value)
    )
    row = store.connection.execute("SELECT * FROM payment_incidents").fetchone()
    assert row["currency"] == "RUB"
    assert row["amount"] == 999
    assert row["invoice_payload"] == order.id
    assert row["charge_id"] == "wrong-currency-charge"
    assert store.get_subscription(11) is None
    assert store.validate_checkout(order.id, 11, "XTR", PRICE).id == order.id


def test_concurrent_payment_delivery_from_separate_connections_extends_once(tmp_path):
    path = tmp_path / "shared.sqlite"
    initial = Store(path, clock=lambda: NOW)
    order = order_for(initial)
    initial.close()

    def deliver(_):
        worker = Store(path, clock=lambda: NOW)
        try:
            return pay(worker, order)
        finally:
            worker.close()

    with ThreadPoolExecutor(max_workers=4) as executor:
        results = list(executor.map(deliver, range(8)))
    assert sum(result.is_new for result in results) == 1
    assert {result.expires_at for result in results} == {NOW + timedelta(days=30)}
    final = Store(path, clock=lambda: NOW)
    try:
        assert final.get_subscription(11).expires_at == NOW + timedelta(days=30)
    finally:
        final.close()


@pytest.mark.parametrize("charge", ["", "x" * 513])
def test_invalid_charge_id_cannot_grant_access(store, charge):
    with pytest.raises(ValueError, match="charge ID"):
        pay(store, order_for(store), charge)
    assert store.pending_subscriptions() == []


@pytest.mark.parametrize(
    ("user_id", "chat_id", "platform", "amount"),
    [(0, 0, "android", PRICE), (11, -42, "android", PRICE),
     (11, 12, "android", PRICE), (11, 11, "windows", PRICE), (11, 11, "ios", 0)],
)
def test_orders_require_private_chat_supported_platform_and_positive_price(
    store, user_id, chat_id, platform, amount
):
    with pytest.raises(ValueError, match="private-chat order"):
        store.create_order(user_id, chat_id, platform, amount)
