"""Primary HWID admission stays authoritative; secondary never adds capacity."""

from __future__ import annotations

import re
from contextlib import asynccontextmanager

from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, create_async_engine
from sqlalchemy.orm import selectinload
from sqlalchemy.pool import NullPool

from app.database.models import Subscription, SubscriptionBsAccount
from app.services.bs_account_identity import verify_bs_identity
from app.services.bs_subscription_composer import SubscriptionDocument
from app.services.bs_traffic_policy import BsAccountIdentityError
from app.services.panel_sync.identity import find_foreign_panel_owner
from app.services.panel_sync.writer import sync_bs_device_limit


_LOCK_NAMESPACE = 0x42534456  # BSDV, distinct from grace/account merge locks.
_HWID = re.compile(r'[a-zA-Z0-9=-]{10,64}')


class BsDevicePolicyError(ValueError):
    """Shared device policy could not be confirmed; no BS configs may be sent."""


@asynccontextmanager
async def _independent_session(db):
    bind = getattr(db, 'bind', None)
    if not isinstance(bind, AsyncEngine) or bind.dialect.name != 'postgresql':
        raise BsDevicePolicyError('Shared devices require an independent PostgreSQL session')
    # Do not borrow a second connection from the caller's pool. Under load all
    # pool slots could be held by callers waiting for their own guard sessions.
    # The connection uses the same configured URL/TLS settings, bounded driver
    # timeouts, and closes when the scope exits (no retained extra pool).
    independent = create_async_engine(
        bind.url,
        poolclass=NullPool,
        connect_args={
            'timeout': 10,
            'command_timeout': 30,
            'server_settings': {
                'application_name': 'remnawave_bs_devices',
                'statement_timeout': '30000',
                'idle_in_transaction_session_timeout': '300000',
            },
        },
    )
    try:
        async with AsyncSession(independent, expire_on_commit=False) as session:
            yield session
    finally:
        await independent.dispose()


def is_split_subscription(subscription) -> bool:
    return getattr(subscription, 'traffic_mode', 'shared') == 'split' and not getattr(subscription, 'is_trial', True)


@asynccontextmanager
async def bs_device_lock(db, subscription_id: int):
    """Own a dedicated transaction; never commit/autoflush the caller's work.

    All split delivery/removal/reset paths use this PostgreSQL lock. It is
    automatically released on success, exceptions, cancellation and disconnect.
    An AsyncConnection-bound session cannot guarantee independent ownership.
    """
    async with _independent_session(db) as locked_db, locked_db.begin():
        await locked_db.execute(text("SET LOCAL lock_timeout = '5s'"))
        await locked_db.execute(
            text('SELECT pg_advisory_xact_lock(:namespace, :subscription_id)'),
            {'namespace': _LOCK_NAMESPACE, 'subscription_id': subscription_id},
        )
        yield locked_db


async def device_hwids(api, panel_id: int) -> set[str]:
    """Require the complete per-user contract; a malformed list is not empty."""
    data = await api.get_user_devices(panel_id)
    if not isinstance(data, dict) or not isinstance(data.get('devices'), list):
        raise BsDevicePolicyError('Invalid panel device list')
    total, devices = data.get('total'), data['devices']
    if type(total) is not int or total < 0 or total != len(devices):
        raise BsDevicePolicyError('Incomplete panel device list')
    result = set()
    for device in devices:
        if (
            not isinstance(device, dict)
            or type(device.get('userId')) is not int
            or device['userId'] != panel_id
            or not isinstance(device.get('hwid'), str)
            or _HWID.fullmatch(device['hwid']) is None
            or device['hwid'] in result
        ):
            raise BsDevicePolicyError('Invalid device ownership or HWID')
        result.add(device['hwid'])
    return result


def _finite_admission(document: SubscriptionDocument, hwid: str | None, limit: int) -> None:
    if document.hwid_denied or document.status != 200:
        raise BsDevicePolicyError('Public device admission was denied')
    if limit == 0:
        return  # Explicit unlimited; no new bypass is introduced by the bot.
    headers = {key.lower(): value for key, value in document.headers.items()}
    if (
        not hwid
        or _HWID.fullmatch(hwid) is None
        or headers.get('x-hwid-active', '').strip().lower() != 'true'
        or document.hwid_denied
        or document.status != 200
    ):
        raise BsDevicePolicyError('Finite HWID admission was not confirmed')


async def prepare_secondary_devices(api, primary, secondary, account, document, headers) -> int:
    """Prune stale secondary registrations, then mirror the actual primary limit.

    Called only while bs_device_lock is held, after the primary public gate.
    No device is administratively added and the secondary public gate remains on.
    """
    limit = primary.hwid_device_limit
    if type(limit) is not int or limit < 0:
        raise BsDevicePolicyError('Primary device limit must be explicit')
    hwid = headers.get('x-hwid')
    _finite_admission(document, hwid, limit)
    primary_hwids = await device_hwids(api, primary.id)
    if limit > 0 and hwid not in primary_hwids:
        raise BsDevicePolicyError('Device was not admitted by the primary account')
    secondary_hwids = await device_hwids(api, secondary.id)
    for stale in sorted(secondary_hwids - primary_hwids):
        if not await api.remove_device(secondary.id, stale):
            raise BsDevicePolicyError('Secondary device cleanup failed')
    # Do not trust a bare success acknowledgement from a panel/proxy.
    if not (await device_hwids(api, secondary.id)).issubset(primary_hwids):
        raise BsDevicePolicyError('Secondary device cleanup was not confirmed')
    if type(secondary.hwid_device_limit) is not int or secondary.hwid_device_limit != limit:
        await sync_bs_device_limit(api, account=account, primary=primary, secondary=secondary, limit=limit)
    return limit


async def confirm_secondary_devices(api, primary, secondary, document, headers, limit: int) -> None:
    """Check the public gate and registry again before sending any BS keys."""
    hwid = headers.get('x-hwid')
    _finite_admission(document, hwid, limit)
    primary_hwids = await device_hwids(api, primary.id)
    secondary_hwids = await device_hwids(api, secondary.id)
    if not secondary_hwids.issubset(primary_hwids):
        raise BsDevicePolicyError('Secondary registry exceeds primary admission')
    if limit > 0 and (hwid not in primary_hwids or hwid not in secondary_hwids):
        raise BsDevicePolicyError('Device admission changed during delivery')


async def _mutate_split_devices(db, api, subscription_id, primary_id, hwid):
    async with bs_device_lock(db, subscription_id) as locked_db:
        subscription = await locked_db.scalar(
            select(Subscription).where(Subscription.id == subscription_id).options(selectinload(Subscription.user))
        )
        if subscription is None:
            raise BsDevicePolicyError('Subscription disappeared')
        if not is_split_subscription(subscription):
            return (
                await api.reset_user_devices(primary_id) if hwid is None else await api.remove_device(primary_id, hwid)
            )
        if (
            subscription.remnawave_id != primary_id
            or not subscription.remnawave_short_uuid
            or subscription.user is None
        ):
            raise BsDevicePolicyError('Split subscription changed')
        if hwid is not None and (not isinstance(hwid, str) or _HWID.fullmatch(hwid) is None):
            raise BsDevicePolicyError('Invalid device HWID')
        foreign = await find_foreign_panel_owner(
            locked_db, subscription.user, subscription, primary_id, multi_tariff=False
        )
        primary = await api.get_user_by_id(primary_id) if foreign is None else None
        if primary is None or primary.id != primary_id or primary.short_uuid != subscription.remnawave_short_uuid:
            raise BsAccountIdentityError('Primary device owner could not be confirmed')
        account = await locked_db.scalar(
            select(SubscriptionBsAccount).where(SubscriptionBsAccount.subscription_id == subscription_id)
        )
        if account is None or account.migration_state != 'active':
            raise BsDevicePolicyError('Secondary is not active')
        secondary = await verify_bs_identity(locked_db, api, account, primary)
        # Read BOTH lists before touching either account. A partial or foreign
        # list is a failed operation, never an excuse to reset the other one.
        await device_hwids(api, primary.id)
        await device_hwids(api, secondary.id)
        # Secondary first: a failure cannot delete the authoritative primary
        # registration and leave an independently admitted secondary behind.
        for panel_id in (secondary.id, primary.id):
            success = (
                await api.reset_user_devices(panel_id) if hwid is None else await api.remove_device(panel_id, hwid)
            )
            if not success:
                return False
            remaining = await device_hwids(api, panel_id)
            if (hwid is None and remaining) or (hwid is not None and hwid in remaining):
                return False
        return True


async def _device_subscription_id(db, subscription, primary_id):
    """Real ORM callers recheck mode under lock, including stale shared objects."""
    if is_split_subscription(subscription):
        return subscription.id
    bind = getattr(db, 'bind', None)
    if not isinstance(bind, AsyncEngine) or bind.dialect.name != 'postgresql':
        return None
    if isinstance(subscription, Subscription):
        # A newly flushed shared subscription may still belong to the caller's
        # uncommitted purchase transaction. Preserve that legacy reset path;
        # do not wait on its row lock or commit it from another session.
        async with _independent_session(db) as lookup_db:
            return await lookup_db.scalar(select(Subscription.id).where(Subscription.id == subscription.id))
    if subscription is None:
        # Legacy surfaces may only know users.remnawave_id. Resolve the exact
        # subscription rather than silently skipping the secondary account.
        async with _independent_session(db) as lookup_db:
            return await lookup_db.scalar(select(Subscription.id).where(Subscription.remnawave_id == primary_id))
    return None


async def remove_subscription_device(api, db, subscription, primary_id: int, hwid: str) -> bool:
    """Shared subscriptions retain their existing single-account behavior."""
    subscription_id = await _device_subscription_id(db, subscription, primary_id)
    if subscription_id is None:
        return await api.remove_device(primary_id, hwid)
    return await _mutate_split_devices(db, api, subscription_id, primary_id, hwid)


async def reset_subscription_devices(api, db, subscription, primary_id: int) -> bool:
    subscription_id = await _device_subscription_id(db, subscription, primary_id)
    if subscription_id is None:
        return await api.reset_user_devices(primary_id)
    return await _mutate_split_devices(db, api, subscription_id, primary_id, None)
