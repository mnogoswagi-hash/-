from __future__ import annotations

import asyncio
import sqlite3
from contextlib import suppress
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock

import pytest
from aiogram import Bot, Dispatcher
from aiogram.client.session.base import BaseSession
from aiogram.exceptions import TelegramNetworkError
from aiogram.methods import AnswerPreCheckoutQuery, SendDocument, SendInvoice, SendMessage
from aiogram.types import (
    CallbackQuery,
    Chat,
    Message,
    PreCheckoutQuery,
    SuccessfulPayment,
    Update,
    User,
)

from vpn_shop.config import Settings
from vpn_shop.db import Store
from vpn_shop.provider import VPNAccess, VPNUnavailable
from vpn_shop.telegram import (
    DeliveryService,
    create_router,
    handle_pre_checkout,
    persist_paid_update,
    poll_updates,
)


class RecordingSession(BaseSession):
    def __init__(self):
        super().__init__()
        self.requests = []
        self.fail_document_once = False

    async def close(self):
        pass

    async def stream_content(self, *args, **kwargs):
        yield b""

    async def make_request(self, bot, method, timeout=None):
        self.requests.append(method)
        if isinstance(method, SendDocument) and self.fail_document_once:
            self.fail_document_once = False
            raise TelegramNetworkError(method=method, message="Test transport failure")
        if isinstance(method, (SendMessage, SendInvoice, SendDocument)):
            return Message(
                message_id=len(self.requests),
                date=datetime.now(timezone.utc),
                chat=Chat(id=method.chat_id, type="private"),
            )
        return True


def private_message(user_id=1, **extra):
    return Message(
        message_id=1,
        date=datetime.now(timezone.utc),
        chat=Chat(id=user_id, type="private"),
        from_user=User(id=user_id, is_bot=False, first_name="Test"),
        **extra,
    )


def paid_update(order, *, update_id=10, charge_id="charge-1", **overrides):
    payment_data = {
        "currency": "XTR",
        "total_amount": order.amount,
        "invoice_payload": f"vpn30:{order.id}",
        "telegram_payment_charge_id": charge_id,
        "provider_payment_charge_id": "",
    }
    payment_data.update(overrides)
    return Update(
        update_id=update_id,
        message=private_message(
            order.user_id, successful_payment=SuccessfulPayment(**payment_data)
        ),
    )


@pytest.fixture
def app(tmp_path):
    settings = Settings(
        bot_token="123456:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        stars_price=80,
        vpn_api_url="http://127.0.0.1:8080",
        vpn_api_token="A" * 32,
        support_username="support_test",
        database_path=tmp_path / "shop.sqlite",
        sales_enabled=True,
    )
    store = Store(settings.database_path)
    vpn = AsyncMock()
    vpn.health.return_value = True
    vpn.prepare_access.return_value = True
    vpn.ensure_access.return_value = VPNAccess("android-profile", "ios-profile")
    session = RecordingSession()
    bot = Bot(settings.bot_token, session=session)
    delivery = DeliveryService(bot, store, vpn)
    dispatcher = Dispatcher()
    dispatcher.include_router(create_router(settings, store, vpn, delivery))
    yield settings, store, vpn, session, bot, delivery, dispatcher
    store.close()


def configured_app(app, **settings_changes):
    settings, store, vpn, session, bot, delivery, _ = app
    settings = replace(settings, **settings_changes)
    dispatcher = Dispatcher()
    dispatcher.include_router(create_router(settings, store, vpn, delivery))
    return settings, store, vpn, session, bot, delivery, dispatcher


async def feed_callback(app, data, *, user_id=1, owner_id=1):
    _, _, _, _, bot, _, dispatcher = app
    await dispatcher.feed_update(
        bot,
        Update(
            update_id=1,
            callback_query=CallbackQuery(
                id="callback",
                from_user=User(id=user_id, is_bot=False, first_name="Test"),
                chat_instance="test-chat",
                message=private_message(owner_id),
                data=data,
            ),
        ),
    )


async def test_invoice_requires_callback_owner_and_a_ready_gateway(app):
    settings, store, vpn, session, *_ = app
    await feed_callback(app, "accept:2:android")
    vpn.health.assert_not_called()
    assert not any(isinstance(item, SendInvoice) for item in session.requests)

    vpn.health.return_value = False
    await feed_callback(app, "accept:1:android")
    assert not any(isinstance(item, SendInvoice) for item in session.requests)

    vpn.health.return_value = True
    await feed_callback(app, "accept:1:android")
    invoice = next(item for item in session.requests if isinstance(item, SendInvoice))
    assert invoice.currency == "XTR"
    assert invoice.provider_token == ""
    assert len(invoice.prices) == 1
    assert invoice.prices[0].amount == settings.stars_price
    assert invoice.model_dump().get("subscription_period") is None
    order = store.validate_checkout(invoice.payload.removeprefix("vpn30:"), 1, "XTR", 80)
    assert order.platform == "android"


async def test_ios_limitations_are_shown_before_payment(app):
    _, _, _, session, *_ = app
    await feed_callback(app, "buy:1:ios")
    terms = next(item for item in session.requests if isinstance(item, SendMessage))
    assert "не гарантирует" in terms.text
    assert "iOS" in terms.text
    assert "Принимаю условия" in terms.reply_markup.inline_keyboard[0][0].text
    assert not any(isinstance(item, SendInvoice) for item in session.requests)


@pytest.mark.parametrize(
    "currency,amount,user_id,ready,allowed",
    [
        ("XTR", 80, 1, True, True),
        ("RUB", 80, 1, True, False),
        ("XTR", 79, 1, True, False),
        ("XTR", 80, 2, True, False),
        ("XTR", 80, 1, False, False),
    ],
)
async def test_precheckout_verifies_ownership_amount_currency_and_health(
    app, currency, amount, user_id, ready, allowed
):
    _, store, vpn, session, bot, *_ = app
    order = store.create_order(1, 1, "android", 80)
    vpn.health.return_value = ready
    query = PreCheckoutQuery(
        id="checkout",
        from_user=User(id=user_id, is_bot=False, first_name="Test"),
        currency=currency,
        total_amount=amount,
        invoice_payload=f"vpn30:{order.id}",
    ).as_(bot)
    await handle_pre_checkout(query, store, vpn)
    answer = session.requests[-1]
    assert isinstance(answer, AnswerPreCheckoutQuery)
    assert answer.ok is allowed
    if currency != "XTR" or amount != 80 or user_id != 1:
        vpn.health.assert_not_called()


async def test_paid_access_survives_provisioning_failure_without_double_extension(app):
    _, store, vpn, session, bot, delivery, dispatcher = app
    order = store.create_order(1, 1, "android", 80)
    update = paid_update(order)
    vpn.ensure_access.side_effect = VPNUnavailable("Test gateway outage")
    await dispatcher.feed_update(bot, update)
    expiry = store.get_subscription(1).expires_at
    assert len(store.pending_subscriptions()) == 1
    assert not any(isinstance(item, SendDocument) for item in session.requests)

    vpn.ensure_access.side_effect = None
    assert await delivery.deliver(1)
    assert not store.pending_subscriptions()
    document = next(item for item in session.requests if isinstance(item, SendDocument))
    assert document.document.data == b"android-profile"
    assert document.protect_content is False
    assert "Не передавайте" in document.caption

    await dispatcher.feed_update(bot, paid_update(order, update_id=11))
    assert store.get_subscription(1).expires_at == expiry
    assert sum(isinstance(item, SendDocument) for item in session.requests) == 1


async def test_telegram_delivery_failure_is_retried_and_myvpn_can_resend(app):
    _, store, _, session, bot, delivery, dispatcher = app
    order = store.create_order(1, 1, "ios", 80)
    store.accept_payment(order.id, 1, "XTR", 80, "charge")
    session.fail_document_once = True
    with pytest.raises(TelegramNetworkError):
        await delivery.deliver(1)
    subscription = store.get_subscription(1)
    assert subscription.provisioned_until == subscription.expires_at
    assert subscription.notified_until is None
    assert len(store.pending_subscriptions()) == 1

    await delivery.deliver(1)
    assert not store.pending_subscriptions()
    await dispatcher.feed_update(bot, Update(update_id=20, message=private_message(text="/myvpn")))
    documents = [item for item in session.requests if isinstance(item, SendDocument)]
    assert len(documents) == 3  # Failed attempt, successful retry, manual resend.
    assert documents[-1].document.data == b"ios-profile"
    assert "выбрать только приложение" in documents[-1].caption


async def test_group_chat_cannot_buy(app):
    _, _, vpn, session, bot, _, dispatcher = app
    message = Message(
        message_id=1,
        date=datetime.now(timezone.utc),
        chat=Chat(id=-100, type="supergroup"),
        from_user=User(id=1, is_bot=False, first_name="Test"),
        text="/buy",
    )
    await dispatcher.feed_update(bot, Update(update_id=1, message=message))
    assert not session.requests
    vpn.health.assert_not_called()


async def test_polling_does_not_acknowledge_payment_while_sqlite_commit_fails(app, monkeypatch):
    _, store, _, _, bot, _, dispatcher = app
    order = store.create_order(1, 1, "android", 80)
    update = paid_update(order)
    failure_seen = asyncio.Event()

    def failing_commit(*args, **kwargs):
        failure_seen.set()
        raise sqlite3.OperationalError("Test disk failure")

    monkeypatch.setattr(store, "accept_payment", failing_commit)
    get_updates = AsyncMock(return_value=[update])
    monkeypatch.setattr(bot, "get_updates", get_updates)
    task = asyncio.create_task(poll_updates(bot, dispatcher, store, retry_interval=60))
    await asyncio.wait_for(failure_seen.wait(), timeout=1)
    task.cancel()
    with suppress(asyncio.CancelledError):
        await task
    assert get_updates.await_count == 1
    assert get_updates.await_args.kwargs["offset"] is None
    assert store.get_subscription(1) is None


async def test_payment_is_durable_if_process_stops_before_handler_runs(app, monkeypatch):
    settings, store, _, _, bot, _, dispatcher = app
    order = store.create_order(1, 1, "android", 80)
    update = paid_update(order)
    handler_entered = asyncio.Event()

    async def blocked_handler(*args, **kwargs):
        handler_entered.set()
        await asyncio.Future()

    async def fetch_updates(**kwargs):
        if kwargs["offset"] is None:
            return [update]
        await asyncio.Future()

    get_updates = AsyncMock(side_effect=fetch_updates)
    monkeypatch.setattr(bot, "get_updates", get_updates)
    monkeypatch.setattr(dispatcher, "feed_update", blocked_handler)
    task = asyncio.create_task(poll_updates(bot, dispatcher, store))
    await asyncio.wait_for(handler_entered.wait(), timeout=1)
    task.cancel()
    with suppress(asyncio.CancelledError):
        await task

    recovered = Store(settings.database_path)
    try:
        assert len(recovered.pending_subscriptions()) == 1
        assert recovered.get_subscription(1).notified_until is None
    finally:
        recovered.close()
    assert get_updates.await_args_list[0].kwargs["offset"] is None


async def test_slow_delivery_does_not_block_precheckout_deadline(app, monkeypatch):
    _, store, vpn, session, bot, _, dispatcher = app
    old_order = store.create_order(1, 1, "android", 80)
    store.accept_payment(old_order.id, 1, "XTR", 80, "old-charge")
    new_order = store.create_order(2, 2, "ios", 80)
    slow_update = Update(update_id=10, message=private_message(text="/myvpn"))
    checkout_update = Update(
        update_id=11,
        pre_checkout_query=PreCheckoutQuery(
            id="fast-checkout",
            from_user=User(id=2, is_bot=False, first_name="Test"),
            currency="XTR",
            total_amount=80,
            invoice_payload=f"vpn30:{new_order.id}",
        ),
    )
    slow_started = asyncio.Event()

    async def slow_access(*args, **kwargs):
        slow_started.set()
        await asyncio.Future()

    vpn.ensure_access.side_effect = slow_access

    async def fetch_updates(**kwargs):
        if kwargs["offset"] is None:
            return [slow_update, checkout_update]
        await asyncio.Future()

    monkeypatch.setattr(bot, "get_updates", AsyncMock(side_effect=fetch_updates))
    task = asyncio.create_task(poll_updates(bot, dispatcher, store))
    try:
        await asyncio.wait_for(slow_started.wait(), timeout=1)
        async def wait_for_checkout_reply():
            while not any(isinstance(item, AnswerPreCheckoutQuery) for item in session.requests):
                await asyncio.sleep(0)
        await asyncio.wait_for(wait_for_checkout_reply(), timeout=1)
        answer = next(item for item in session.requests if isinstance(item, AnswerPreCheckoutQuery))
        assert answer.ok is True
        vpn.prepare_access.assert_awaited_once_with(2, payment_pending=True)
    finally:
        task.cancel()
        with suppress(asyncio.CancelledError):
            await task


async def test_malformed_successful_payment_is_durably_recorded(app):
    _, store, *_ = app
    order = store.create_order(1, 1, "android", 80)
    update = paid_update(order, total_amount=79)
    result, incident = await persist_paid_update(update, store)
    assert result is None and incident
    assert store.get_subscription(1) is None
    rows = store.connection.execute("SELECT * FROM payment_incidents").fetchall()
    assert len(rows) == 1
    assert rows[0]["update_id"] == update.update_id
    await persist_paid_update(update, store)
    assert store.connection.execute("SELECT count(*) FROM payment_incidents").fetchone()[0] == 1


@pytest.mark.parametrize("command", ["/start", "/buy"])
async def test_disabled_sales_show_testing_message_without_purchase_keyboard(app, command):
    app = configured_app(app, sales_enabled=False)
    _, _, vpn, session, bot, _, dispatcher = app
    await dispatcher.feed_update(bot, Update(update_id=1, message=private_message(text=command)))
    reply = next(item for item in session.requests if isinstance(item, SendMessage))
    assert "проходит проверку" in reply.text
    assert reply.reply_markup is None
    assert "⭐" not in reply.text
    vpn.health.assert_not_called()
    vpn.ensure_access.assert_not_called()


async def test_disabled_sales_prevent_new_invoices_even_from_old_acceptance_buttons(app):
    app = configured_app(app, sales_enabled=False)
    _, store, vpn, session, *_ = app
    await feed_callback(app, "accept:1:android")
    assert not any(isinstance(item, SendInvoice) for item in session.requests)
    assert store.connection.execute("SELECT count(*) FROM orders").fetchone()[0] == 0
    vpn.health.assert_not_called()
    vpn.prepare_access.assert_not_called()


async def test_disabled_sales_reject_checkout_of_an_existing_valid_invoice(app):
    app = configured_app(app, sales_enabled=False)
    _, store, vpn, session, bot, _, dispatcher = app
    order = store.create_order(1, 1, "android", 80)
    await dispatcher.feed_update(
        bot,
        Update(
            update_id=1,
            pre_checkout_query=PreCheckoutQuery(
                id="old-checkout",
                from_user=User(id=1, is_bot=False, first_name="Test"),
                currency="XTR",
                total_amount=80,
                invoice_payload=f"vpn30:{order.id}",
            ),
        ),
    )
    answer = next(item for item in session.requests if isinstance(item, AnswerPreCheckoutQuery))
    assert answer.ok is False
    assert "проверку" in answer.error_message
    assert store.get_subscription(1) is None
    vpn.health.assert_not_called()
    vpn.prepare_access.assert_not_called()


async def test_disabled_sales_still_credit_paid_receipts_and_retry_delivery(app):
    app = configured_app(app, sales_enabled=False)
    _, store, vpn, session, bot, delivery, dispatcher = app
    order = store.create_order(1, 1, "android", 80)
    vpn.ensure_access.side_effect = VPNUnavailable("Test gateway outage")
    await dispatcher.feed_update(bot, paid_update(order))
    assert store.get_subscription(1) is not None
    assert len(store.pending_subscriptions()) == 1
    vpn.ensure_access.side_effect = None
    await delivery.deliver(1)
    assert not store.pending_subscriptions()
    assert any(isinstance(item, SendDocument) for item in session.requests)


async def test_testvpn_requires_admin_id_and_does_not_authorize_support_username(app):
    app = configured_app(app, sales_enabled=False, admin_ids=(2,))
    settings, store, vpn, session, bot, _, dispatcher = app
    message = private_message(text="/testvpn android").model_copy(
        update={
            "from_user": User(
                id=1,
                is_bot=False,
                first_name="Test",
                username=settings.support_username,
            )
        }
    )
    await dispatcher.feed_update(bot, Update(update_id=1, message=message))
    vpn.ensure_access.assert_not_called()
    assert not any(isinstance(item, SendDocument) for item in session.requests)
    assert store.get_subscription(1) is None
    assert "администратору" in session.requests[-1].text


@pytest.mark.parametrize(
    "command,platform",
    [("/testvpn", "android"), ("/testvpn android", "android"), ("/testvpn ios", "ios")],
)
async def test_admin_gets_one_hour_profile_without_purchase_or_charge(app, command, platform):
    app = configured_app(app, sales_enabled=False, admin_ids=(1,))
    _, store, vpn, session, bot, _, dispatcher = app
    before = datetime.now(timezone.utc)
    await dispatcher.feed_update(bot, Update(update_id=1, message=private_message(text=command)))
    vpn.ensure_access.assert_awaited_once()
    user_id, expiry = vpn.ensure_access.await_args.args
    assert user_id == 1
    assert before + timedelta(hours=1) <= expiry <= datetime.now(timezone.utc) + timedelta(hours=1)
    document = next(item for item in session.requests if isinstance(item, SendDocument))
    assert document.document.data == f"{platform}-profile".encode()
    assert document.document.filename == f"brawl-stars-{platform}.conf"
    assert document.protect_content is False
    assert "Профиль для проверки" in document.caption
    assert "WireGuard" in document.caption
    assert "Не передавайте" in document.caption
    assert store.get_subscription(1) is None
    assert store.connection.execute("SELECT count(*) FROM orders").fetchone()[0] == 0
    assert store.connection.execute("SELECT count(*) FROM payments").fetchone()[0] == 0
    assert not any(isinstance(item, SendInvoice) for item in session.requests)


async def test_admin_test_does_not_shorten_or_modify_existing_paid_subscription(app):
    app = configured_app(app, sales_enabled=False, admin_ids=(1,))
    _, store, vpn, _, bot, _, dispatcher = app
    order = store.create_order(1, 1, "android", 80)
    store.accept_payment(order.id, 1, "XTR", 80, "paid-charge")
    subscription = store.get_subscription(1)
    await dispatcher.feed_update(
        bot, Update(update_id=1, message=private_message(text="/testvpn ios"))
    )
    vpn.ensure_access.assert_awaited_once_with(1, subscription.expires_at)
    assert store.get_subscription(1) == subscription
    assert store.connection.execute("SELECT count(*) FROM orders").fetchone()[0] == 1
    assert store.connection.execute("SELECT count(*) FROM payments").fetchone()[0] == 1


async def test_admin_test_failure_is_friendly_and_does_not_disclose_gateway_error(app, caplog):
    app = configured_app(app, sales_enabled=False, admin_ids=(1,))
    _, store, vpn, session, bot, _, dispatcher = app
    vpn.ensure_access.side_effect = VPNUnavailable("private-error-detail")
    await dispatcher.feed_update(
        bot, Update(update_id=1, message=private_message(text="/testvpn android"))
    )
    assert not any(isinstance(item, SendDocument) for item in session.requests)
    assert "Тестовый профиль временно недоступен" in session.requests[-1].text
    assert "private-error-detail" not in session.requests[-1].text
    assert "private-error-detail" not in caplog.text
    assert store.get_subscription(1) is None


@pytest.mark.parametrize("command", ["/testvpn windows", "/testvpn android extra"])
async def test_admin_test_invalid_platform_does_not_request_access(app, command):
    app = configured_app(app, admin_ids=(1,))
    _, _, vpn, session, bot, _, dispatcher = app
    await dispatcher.feed_update(bot, Update(update_id=1, message=private_message(text=command)))
    vpn.ensure_access.assert_not_called()
    assert "Для проверки" in session.requests[-1].text


@pytest.mark.parametrize("chat_id,chat_type", [(-100, "supergroup"), (2, "private")])
async def test_admin_test_cannot_deliver_profiles_outside_admins_own_private_chat(
    app, chat_id, chat_type
):
    app = configured_app(app, admin_ids=(1,))
    _, _, vpn, session, bot, _, dispatcher = app
    message = private_message(text="/testvpn").model_copy(
        update={"chat": Chat(id=chat_id, type=chat_type)}
    )
    await dispatcher.feed_update(bot, Update(update_id=1, message=message))
    vpn.ensure_access.assert_not_called()
    assert not any(isinstance(item, SendDocument) for item in session.requests)
