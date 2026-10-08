"""Telegram checkout and recoverable delivery of paid VPN access."""

from __future__ import annotations

import asyncio
import logging
import signal
import sqlite3
from contextlib import suppress
from datetime import datetime, timedelta, timezone

from aiogram import Bot, Dispatcher, F, Router
from aiogram.enums import ChatType
from aiogram.exceptions import (
    TelegramAPIError,
    TelegramConflictError,
    TelegramRetryAfter,
    TelegramUnauthorizedError,
)
from aiogram.filters import Command, CommandStart
from aiogram.types import (
    BotCommand,
    BufferedInputFile,
    CallbackQuery,
    InlineKeyboardButton,
    InlineKeyboardMarkup,
    LabeledPrice,
    Message,
    PreCheckoutQuery,
    Update,
)

from .config import Settings
from .db import PaymentResult, Store
from .provider import VPNAccess, VPNClient


log = logging.getLogger(__name__)
PLATFORMS = {"android": "Android", "ios": "iPhone / iPad"}
INVOICE_PREFIX = "vpn30:"


def _support(settings: Settings) -> str:
    return f"Поддержка: @{settings.support_username.lstrip('@')}"


def _price(settings: Settings) -> str:
    return (
        f"Доступ на {settings.plan_days} дней — {settings.stars_price} ⭐.\n"
        f"Стоимость в рублях: ориентир {settings.rub_price} ₽. "
        "Списывается указанное число Stars; стоимость покупки Stars зависит от Telegram."
    )


def _sales_paused(settings: Settings) -> str:
    return (
        "Магазин проходит проверку. Покупка временно недоступна.\n"
        "Оплаченный доступ можно получить через /myvpn.\n"
        f"{_support(settings)}"
    )


def terms_text(settings: Settings) -> str:
    return (
        f"Условия покупки\n\n{_price(settings)}\n\n"
        "Срок начинается после успешной оплаты. Повторная покупка добавляет "
        f"{settings.plan_days} дней к действующему сроку. Автопродления нет.\n\n"
        "На Android требуется VPN-клиент с выбором приложений: в профиле должен "
        "быть выбран Brawl Stars. На iOS обычный VPN не умеет выбирать одно "
        "приложение: профиль направляет через VPN адреса игры. Такое ограничение "
        "не гарантирует, что через VPN пройдёт только Brawl Stars.\n\n"
        "Если выдача после оплаты задержится, бот сохранит платёж и повторит "
        "выдачу. Повторно платить из-за сбоя не нужно. Доступ не гарантирует "
        "работу самой игры во время её собственных сбоев.\n\n"
        f"По оплате и возвратам: /paysupport. {_support(settings)}"
    )


def platform_keyboard(user_id: int) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        inline_keyboard=[
            [
                InlineKeyboardButton(
                    text=label, callback_data=f"buy:{user_id}:{platform}"
                )
            ]
            for platform, label in PLATFORMS.items()
        ]
    )


def _callback_selection(query: CallbackQuery, action: str) -> str | None:
    """Bind every checkout callback to the user who received its keyboard."""
    if not query.data or not query.message:
        return None
    if query.message.chat.type != ChatType.PRIVATE:
        return None
    parts = query.data.split(":")
    if len(parts) != 3 or parts[0] != action:
        return None
    if parts[1] != str(query.from_user.id):
        return None
    if query.message.chat.id != query.from_user.id:
        return None
    return parts[2] if parts[2] in PLATFORMS else None


def _order_id(payload: str) -> str:
    if not payload.startswith(INVOICE_PREFIX):
        raise ValueError("Unknown invoice payload")
    order_id = payload[len(INVOICE_PREFIX) :]
    if not order_id or len(order_id) > 100:
        raise ValueError("Invalid invoice payload")
    return order_id


async def gateway_ready(
    vpn: VPNClient,
    user_id: int | None = None,
    *,
    payment_pending: bool = False,
) -> bool:
    async def check() -> bool:
        if not await vpn.health():
            return False
        if user_id is not None:
            return await vpn.prepare_access(user_id, payment_pending=payment_pending)
        return True

    try:
        return bool(await asyncio.wait_for(check(), timeout=3.0))
    except Exception as exc:
        log.warning("VPN health check failed (%s)", type(exc).__name__)
        return False


async def handle_pre_checkout(
    query: PreCheckoutQuery,
    store: Store,
    vpn: VPNClient,
    *,
    sales_enabled: bool = True,
) -> None:
    """Answer checkout within Telegram's ten-second deadline."""
    if not sales_enabled:
        await query.answer(
            ok=False,
            error_message="Магазин проходит проверку. Оплата временно недоступна.",
        )
        return
    try:
        store.validate_checkout(
            _order_id(query.invoice_payload),
            query.from_user.id,
            query.currency,
            query.total_amount,
        )
    except ValueError:
        await query.answer(
            ok=False,
            error_message="Счёт недействителен. Создайте новый через /buy.",
        )
        return
    except Exception as exc:
        log.error("Checkout validation unavailable (%s)", type(exc).__name__)
        await query.answer(
            ok=False, error_message="Оплата временно недоступна. Попробуйте позже."
        )
        return

    if not await gateway_ready(vpn, query.from_user.id, payment_pending=True):
        await query.answer(
            ok=False,
            error_message="VPN-сервер временно недоступен. Деньги не будут списаны.",
        )
        return
    await query.answer(ok=True)


class DeliveryService:
    """Retry paid provisioning and Telegram delivery without another charge."""

    def __init__(self, bot: Bot, store: Store, vpn: VPNClient) -> None:
        self.bot = bot
        self.store = store
        self.vpn = vpn
        self._locks: dict[int, asyncio.Lock] = {}

    async def _send_profile(
        self,
        chat_id: int,
        platform: str,
        access: VPNAccess,
        expires_at: datetime,
        *,
        testing: bool = False,
    ) -> None:
        if platform == "android":
            profile = access.android_config
            instructions = (
                "Импортируйте профиль в приложение WireGuard. "
                "Профиль ограничивает VPN приложением Brawl Stars "
                "(com.supercell.brawlstars)."
            )
            filename = "brawl-stars-android.conf"
        elif platform == "ios":
            profile = access.ios_config
            instructions = (
                "Импортируйте профиль в приложение WireGuard. "
                "На iOS маршрутизация ограничивается адресами игры; "
                "выбрать только приложение Brawl Stars невозможно."
            )
            filename = "brawl-stars-ios.conf"
        else:
            raise ValueError("Unsupported subscription platform")
        if not profile:
            raise ValueError("VPN gateway returned an empty profile")
        expiry = expires_at.astimezone(timezone.utc).strftime("%d.%m.%Y %H:%M UTC")
        label = "Профиль для проверки" if testing else "Ваш VPN-доступ"
        await self.bot.send_document(
            chat_id=chat_id,
            document=BufferedInputFile(profile.encode("utf-8"), filename=filename),
            caption=(
                f"{label} действует до {expiry}.\n\n{instructions}\n\n"
                "Не передавайте профиль другим людям."
            ),
            protect_content=False,
        )

    async def test_access(self, user_id: int, platform: str) -> None:
        """Issue an admin's short test without creating a purchase or editing payments."""
        lock = self._locks.setdefault(user_id, asyncio.Lock())
        async with lock:
            expiry = datetime.now(timezone.utc) + timedelta(hours=1)
            subscription = self.store.get_subscription(user_id)
            if subscription is not None:
                expiry = max(expiry, subscription.expires_at)
            access = await self.vpn.ensure_access(user_id, expiry)
            await self._send_profile(user_id, platform, access, expiry, testing=True)

    async def deliver(self, user_id: int, *, resend: bool = False) -> bool:
        lock = self._locks.setdefault(user_id, asyncio.Lock())
        async with lock:
            subscription = self.store.get_subscription(user_id)
            if subscription is None:
                return False
            if subscription.expires_at <= datetime.now(timezone.utc):
                return False
            if not resend and (
                subscription.provisioned_until is not None
                and subscription.provisioned_until >= subscription.expires_at
                and subscription.notified_until is not None
                and subscription.notified_until >= subscription.expires_at
            ):
                return True

            access = await self.vpn.ensure_access(user_id, subscription.expires_at)
            self.store.mark_provisioned(user_id, subscription.expires_at)
            await self._send_profile(
                subscription.chat_id,
                subscription.platform,
                access,
                subscription.expires_at,
            )
            self.store.mark_notified(user_id, subscription.expires_at)
            return True

    async def run(self, *, interval: float = 30.0) -> None:
        while True:
            try:
                subscriptions = self.store.pending_subscriptions()
            except Exception as exc:
                log.error("Cannot load pending deliveries (%s)", type(exc).__name__)
                subscriptions = []
            for subscription in subscriptions:
                try:
                    await self.deliver(subscription.user_id)
                except Exception as exc:
                    log.warning(
                        "Paid access delivery pending for user %s (%s)",
                        subscription.user_id,
                        type(exc).__name__,
                    )
            await asyncio.sleep(interval)


def create_router(
    settings: Settings, store: Store, vpn: VPNClient, delivery: DeliveryService
) -> Router:
    router = Router(name="vpn_shop")
    router.message.filter(F.chat.type == ChatType.PRIVATE)
    router.callback_query.filter(F.message.chat.type == ChatType.PRIVATE)

    @router.message(CommandStart())
    @router.message(Command("buy"))
    async def buy(message: Message) -> None:
        if message.from_user is None:
            return
        if not settings.sales_enabled:
            admin_help = (
                "\nПроверка администратора: /testvpn android или /testvpn ios."
                if message.from_user.id in settings.admin_ids
                else ""
            )
            await message.answer(_sales_paused(settings) + admin_help)
            return
        await message.answer(
            "VPN для Brawl Stars\n\n"
            f"{_price(settings)}\n\n"
            "Выберите устройство. Перед оплатой покажу ограничения и условия.\n"
            "Ваш доступ и повторная выдача профиля: /myvpn.",
            reply_markup=platform_keyboard(message.from_user.id),
        )

    @router.callback_query(F.data.startswith("buy:"))
    async def select_platform(query: CallbackQuery) -> None:
        platform = _callback_selection(query, "buy")
        if platform is None:
            await query.answer("Откройте /buy в личном чате с ботом.", show_alert=True)
            return
        await query.answer()
        if not settings.sales_enabled:
            await query.message.answer(_sales_paused(settings))
            return
        await query.message.answer(
            f"Устройство: {PLATFORMS[platform]}\n\n{terms_text(settings)}",
            reply_markup=InlineKeyboardMarkup(
                inline_keyboard=[
                    [
                        InlineKeyboardButton(
                            text=f"Принимаю условия · {settings.stars_price} ⭐",
                            callback_data=f"accept:{query.from_user.id}:{platform}",
                        )
                    ]
                ]
            ),
        )

    @router.callback_query(F.data.startswith("accept:"))
    async def accept_terms(query: CallbackQuery) -> None:
        platform = _callback_selection(query, "accept")
        if platform is None:
            await query.answer("Откройте /buy в личном чате с ботом.", show_alert=True)
            return
        await query.answer()
        if not settings.sales_enabled:
            await query.message.answer(_sales_paused(settings))
            return
        if not await gateway_ready(vpn, query.from_user.id):
            await query.message.answer(
                "VPN-сервер пока не готов к выдаче. Оплата временно недоступна.\n"
                f"{_support(settings)}"
            )
            return
        order = store.create_order(
            query.from_user.id,
            query.message.chat.id,
            platform,
            settings.stars_price,
        )
        await query.message.answer_invoice(
            title=f"Brawl Stars VPN · {settings.plan_days} дней",
            description=(
                f"Доступ для {PLATFORMS[platform]} на {settings.plan_days} дней. "
                "Условия приняты. Автопродления нет."
            ),
            payload=f"{INVOICE_PREFIX}{order.id}",
            currency="XTR",
            prices=[LabeledPrice(label="VPN-доступ", amount=settings.stars_price)],
            provider_token="",
        )

    @router.pre_checkout_query()
    async def pre_checkout(query: PreCheckoutQuery) -> None:
        await handle_pre_checkout(query, store, vpn, sales_enabled=settings.sales_enabled)

    @router.message(F.successful_payment)
    async def successful_payment(
        message: Message,
        payment_result: PaymentResult | None = None,
        payment_incident: bool = False,
    ) -> None:
        if message.from_user is None or message.successful_payment is None:
            return
        payment = message.successful_payment
        try:
            if payment_incident:
                raise ValueError("Payment was saved for administrative review")
            result = payment_result or store.accept_payment(
                _order_id(payment.invoice_payload),
                message.from_user.id,
                payment.currency,
                payment.total_amount,
                payment.telegram_payment_charge_id,
            )
        except Exception as exc:
            log.error(
                "Successful payment requires review for user %s (%s)",
                message.from_user.id,
                type(exc).__name__,
            )
            await message.answer(
                "Telegram сообщил об оплате, но требуется проверка платежа. "
                "Не оплачивайте повторно. Обратитесь в /paysupport.\n"
                f"{_support(settings)}"
            )
            for admin_id in settings.admin_ids:
                with suppress(TelegramAPIError):
                    await delivery.bot.send_message(
                        admin_id,
                        "Требуется проверка платежа. "
                        f"Пользователь: {message.from_user.id}. "
                        f"Telegram charge ID: {payment.telegram_payment_charge_id}",
                    )
            return
        notice = (
            "Оплата получена. Готовлю ваш VPN-профиль."
            if result.is_new
            else "Этот платёж уже учтён. Проверяю выдачу доступа."
        )
        with suppress(TelegramAPIError):
            await message.answer(notice)
        try:
            await delivery.deliver(message.from_user.id)
        except Exception as exc:
            log.warning(
                "Paid delivery will retry for user %s (%s)",
                message.from_user.id,
                type(exc).__name__,
            )
            with suppress(TelegramAPIError):
                await message.answer(
                    "Платёж сохранён. Выдача задерживается: бот повторит её "
                    "автоматически. Профиль можно запросить через /myvpn. "
                    "Повторно платить не нужно."
                )

    @router.message(Command("myvpn"))
    async def my_vpn(message: Message) -> None:
        if message.from_user is None:
            return
        subscription = store.get_subscription(message.from_user.id)
        if subscription is None or subscription.expires_at <= datetime.now(timezone.utc):
            await message.answer("Активного доступа нет. Купить на 30 дней: /buy.")
            return
        try:
            await delivery.deliver(message.from_user.id, resend=True)
        except Exception as exc:
            log.warning(
                "Profile resend failed for user %s (%s)",
                message.from_user.id,
                type(exc).__name__,
            )
            await message.answer(
                "Ваш оплаченный доступ сохранён. Профиль временно недоступен; "
                "повторите /myvpn позже. Повторная оплата не нужна.\n"
                f"{_support(settings)}"
            )

    @router.message(Command("terms"))
    async def terms(message: Message) -> None:
        await message.answer(terms_text(settings))

    @router.message(Command("testvpn"))
    async def test_vpn(message: Message) -> None:
        if (
            message.from_user is None
            or message.from_user.id not in settings.admin_ids
            or message.chat.id != message.from_user.id
        ):
            await message.answer("Команда доступна только администратору в личном чате.")
            return
        arguments = (message.text or "").split()
        platform = arguments[1].lower() if len(arguments) == 2 else "android"
        if len(arguments) > 2 or platform not in PLATFORMS:
            await message.answer("Для проверки: /testvpn android или /testvpn ios.")
            return
        try:
            await delivery.test_access(message.from_user.id, platform)
        except Exception as exc:
            log.warning(
                "Admin test profile unavailable for user %s (%s)",
                message.from_user.id,
                type(exc).__name__,
            )
            await message.answer(
                "Тестовый профиль временно недоступен. Попробуйте позже.\n"
                f"{_support(settings)}"
            )

    @router.message(Command("help"))
    async def help_command(message: Message) -> None:
        admin_help = (
            "\n/testvpn android|ios — проверить VPN без оплаты (1 час)\n"
            if message.from_user and message.from_user.id in settings.admin_ids
            else ""
        )
        await message.answer(
            "/buy — купить доступ\n"
            "/myvpn — получить свой профиль\n"
            "/terms — условия и ограничения Android / iOS\n"
            "/paysupport — помощь с оплатой и возвратами\n"
            f"{admin_help}\n"
            f"{_support(settings)}"
        )

    @router.message(Command("paysupport"))
    async def pay_support(message: Message) -> None:
        await message.answer(
            "По оплате, задержке выдачи или возврату обратитесь в поддержку. "
            "Укажите свой Telegram ID и дату покупки. "
            "Токены бота и VPN-профили отправлять не нужно.\n"
            f"Ваш Telegram ID: {message.from_user.id if message.from_user else message.chat.id}\n"
            f"{_support(settings)}",
            reply_markup=InlineKeyboardMarkup(
                inline_keyboard=[
                    [
                        InlineKeyboardButton(
                            text="Поддержка",
                            url=f"https://t.me/{settings.support_username.lstrip('@')}",
                        )
                    ]
                ]
            ),
        )

    return router


async def persist_paid_update(
    update: Update, store: Store, *, retry_interval: float = 3.0
) -> tuple[PaymentResult | None, bool]:
    """Commit money-related updates before Telegram can acknowledge their offset."""
    message = update.message
    if message is None or message.successful_payment is None:
        return None, False
    payment = message.successful_payment
    user_id = message.from_user.id if message.from_user else 0
    while True:
        try:
            try:
                if message.chat.type != ChatType.PRIVATE or not user_id:
                    raise ValueError("Invalid payment chat")
                result = store.accept_payment(
                    _order_id(payment.invoice_payload),
                    user_id,
                    payment.currency,
                    payment.total_amount,
                    payment.telegram_payment_charge_id,
                )
            except ValueError:
                store.record_payment_incident(
                    update_id=update.update_id,
                    user_id=user_id,
                    invoice_payload=payment.invoice_payload,
                    currency=payment.currency,
                    amount=payment.total_amount,
                    charge_id=payment.telegram_payment_charge_id,
                    reason="Successful payment failed invoice validation",
                )
                return None, True
            return result, False
        except (sqlite3.Error, OSError) as exc:
            log.error(
                "Cannot persist paid update %s; offset retained (%s)",
                update.update_id,
                type(exc).__name__,
            )
            await asyncio.sleep(retry_interval)


async def poll_updates(
    bot: Bot,
    dispatcher: Dispatcher,
    store: Store,
    *,
    retry_interval: float = 3.0,
    max_handlers: int = 128,
    max_checkouts: int = 32,
) -> None:
    """Persist paid receipts before acknowledgment and dispatch replies concurrently."""
    offset: int | None = None
    allowed_updates = dispatcher.resolve_used_update_types()
    handlers: set[asyncio.Task[None]] = set()
    checkouts: set[asyncio.Task[None]] = set()

    async def dispatch(update: Update, result: PaymentResult | None, incident: bool) -> None:
        try:
            await dispatcher.feed_update(
                bot,
                update,
                payment_result=result,
                payment_incident=incident,
            )
        except Exception as exc:
            log.warning("Update %s reply failed (%s)", update.update_id, type(exc).__name__)

    try:
        while True:
            try:
                updates = await bot.get_updates(
                    offset=offset, timeout=30, allowed_updates=allowed_updates
                )
            except (TelegramConflictError, TelegramUnauthorizedError):
                raise
            except TelegramRetryAfter as exc:
                await asyncio.sleep(exc.retry_after)
                continue
            except TelegramAPIError as exc:
                log.warning("Telegram polling will retry (%s)", type(exc).__name__)
                await asyncio.sleep(retry_interval)
                continue

            for update in updates:
                result, incident = await persist_paid_update(
                    update, store, retry_interval=retry_interval
                )
                if update.pre_checkout_query is not None:
                    if len(checkouts) >= max_checkouts:
                        await bot.answer_pre_checkout_query(
                            pre_checkout_query_id=update.pre_checkout_query.id,
                            ok=False,
                            error_message="Оплата временно перегружена. Попробуйте позже.",
                        )
                    else:
                        task = asyncio.create_task(dispatch(update, result, incident))
                        checkouts.add(task)
                        task.add_done_callback(checkouts.discard)
                elif len(handlers) < max_handlers:
                    task = asyncio.create_task(dispatch(update, result, incident))
                    handlers.add(task)
                    task.add_done_callback(handlers.discard)
                else:
                    # Payment receipts already committed remain in the delivery outbox.
                    log.warning("Non-checkout update %s skipped at capacity", update.update_id)
                offset = update.update_id + 1
            await asyncio.sleep(0)
    finally:
        tasks = handlers | checkouts
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)


async def run_bot(settings: Settings) -> None:
    store = Store(settings.database_path, plan_days=settings.plan_days)
    vpn = VPNClient(settings.vpn_api_url, settings.vpn_api_token)
    bot = Bot(settings.bot_token)
    dispatcher = Dispatcher()
    delivery = DeliveryService(bot, store, vpn)
    dispatcher.include_router(create_router(settings, store, vpn, delivery))
    worker: asyncio.Task[None] | None = None
    loop = asyncio.get_running_loop()
    main_task = asyncio.current_task()
    if main_task is not None:
        loop.add_signal_handler(signal.SIGTERM, main_task.cancel)
    try:
        await bot.set_my_commands(
            [
                BotCommand(command="buy", description="Купить VPN для Brawl Stars"),
                BotCommand(command="myvpn", description="Получить свой VPN-профиль"),
                BotCommand(command="terms", description="Условия и ограничения"),
                BotCommand(command="help", description="Помощь"),
                BotCommand(command="paysupport", description="Оплата и возвраты"),
            ]
        )
        worker = asyncio.create_task(delivery.run(), name="paid-vpn-delivery")
        await poll_updates(bot, dispatcher, store)
    finally:
        loop.remove_signal_handler(signal.SIGTERM)
        if worker is not None:
            worker.cancel()
            with suppress(asyncio.CancelledError):
                await worker
        await vpn.close()
        await bot.session.close()
        store.close()
