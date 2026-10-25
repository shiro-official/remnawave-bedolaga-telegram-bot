"""Internal delivery engine; no public route or cutover is enabled here.

The future public route must resolve/authenticate its token before calling this
service. It must not expose a subscription database id as a bearer credential.
Shared device removal and lifecycle coordination remain cutover prerequisites.
"""

from __future__ import annotations

from datetime import UTC, datetime

import aiohttp
from sqlalchemy import select
from sqlalchemy.orm import selectinload

from app.config import settings
from app.database.models import Subscription, SubscriptionBsAccount, SubscriptionPublicLink
from app.external.remnawave_api import RemnaWaveAPIError, UserStatus
from app.services.bs_account_identity import verify_bs_identity
from app.services.bs_device_policy import (
    BsDevicePolicyError,
    bs_device_lock,
    bs_device_session,
    confirm_secondary_devices,
    is_split_subscription,
    prepare_secondary_devices,
)
from app.services.bs_public_link_tokens import CLIENT_TYPES, hash_public_token
from app.services.bs_subscription_composer import (
    CompositionResult,
    SubscriptionDocument,
    compose_subscriptions,
    contains_account_credentials,
    forwarded_device_headers,
)
from app.services.bs_traffic_policy import BsAccountIdentityError
from app.services.panel_sync.identity import find_foreign_panel_owner


class SubscriptionUnavailable(ValueError):
    """No locally authorized subscription identity can be delivered."""


def _future(value: datetime | None) -> bool:
    return value is not None and value.tzinfo is not None and value > datetime.now(UTC)


def _panel_active(user) -> bool:
    return (
        user is not None
        and user.status == UserStatus.ACTIVE
        and _future(user.expire_at)
        and (user.traffic_limit_bytes == 0 or user.used_traffic_bytes < user.traffic_limit_bytes)
    )


async def deliver_subscription(db, api, subscription_id: int, *, request_headers: dict[str, str]) -> CompositionResult:
    """Fetch primary first and preserve ordinary access on a secondary failure.

    Split delivery synchronizes stale secondary devices and the explicit primary
    device limit under the same lock used for device deletion/reset. It never
    bypasses HWID admission, alters primary limits, or caches configurations.
    """
    if db.new or db.dirty or db.deleted:
        raise SubscriptionUnavailable('Delivery requires a clean unit of work')
    subscription = await db.scalar(
        select(Subscription).where(Subscription.id == subscription_id).options(selectinload(Subscription.user))
    )
    if subscription is not None and is_split_subscription(subscription):
        async with bs_device_lock(db, subscription_id) as locked_db:
            # Use a fresh snapshot after acquiring the shared device lock.
            subscription = await locked_db.scalar(
                select(Subscription).where(Subscription.id == subscription_id).options(selectinload(Subscription.user))
            )
            return await _deliver_subscription(locked_db, api, subscription, request_headers)
    return await _deliver_subscription(db, api, subscription, request_headers)


async def deliver_public_subscription(
    db, api, token: str, *, request_headers: dict[str, str], client_type=None, api_factory=None
):
    """Authenticate an opaque capability again UNDER the shared delivery/revoke lock."""
    digest = hash_public_token(token)
    if digest is None or (client_type is not None and client_type not in CLIENT_TYPES):
        raise SubscriptionUnavailable('Subscription is unavailable')
    if db.new or db.dirty or db.deleted:
        raise SubscriptionUnavailable('Delivery requires a clean unit of work')
    async with bs_device_session(db) as lookup_db:
        subscription_id = await lookup_db.scalar(
            select(SubscriptionPublicLink.subscription_id).where(
                SubscriptionPublicLink.token_hash == digest, SubscriptionPublicLink.enabled.is_(True)
            )
        )
    if subscription_id is None:
        raise SubscriptionUnavailable('Subscription is unavailable')
    async with bs_device_lock(db, subscription_id) as locked_db:
        link = await locked_db.scalar(
            select(SubscriptionPublicLink).where(SubscriptionPublicLink.subscription_id == subscription_id)
        )
        subscription = await locked_db.scalar(
            select(Subscription).where(Subscription.id == subscription_id).options(selectinload(Subscription.user))
        )
        account = await locked_db.scalar(
            select(SubscriptionBsAccount).where(SubscriptionBsAccount.subscription_id == subscription_id)
        )
        if (
            link is None
            or not link.enabled
            or link.rotation_pending
            or link.token_hash != digest
            or subscription is None
            or not is_split_subscription(subscription)
            or account is None
            or account.migration_state != 'active'
            or subscription.remnawave_id != link.primary_id
            or subscription.remnawave_short_uuid != link.primary_short_uuid
            or account.remnawave_id != link.secondary_id
            or account.remnawave_short_uuid != link.secondary_short_uuid
        ):
            raise SubscriptionUnavailable('Subscription is unavailable')
        _require_local_subscription(subscription)
        if api_factory is not None:
            async with api_factory() as client:
                return await _deliver_subscription(
                    locked_db, client, subscription, request_headers, client_type=client_type
                )
        return await _deliver_subscription(locked_db, api, subscription, request_headers, client_type=client_type)


def _require_local_subscription(subscription) -> None:
    if (
        subscription is None
        or subscription.user is None
        or subscription.user.status != 'active'
        or subscription.status not in ('active', 'trial')
        or not _future(subscription.end_date)
        or not subscription.remnawave_id
        or not subscription.remnawave_short_uuid
    ):
        raise SubscriptionUnavailable('Subscription is unavailable')


async def _deliver_subscription(db, api, subscription, request_headers, *, client_type=None) -> CompositionResult:
    _require_local_subscription(subscription)
    if is_split_subscription(subscription) and await db.scalar(
        select(SubscriptionPublicLink.rotation_pending).where(SubscriptionPublicLink.subscription_id == subscription.id)
    ):
        raise SubscriptionUnavailable('Subscription is unavailable')
    foreign = await find_foreign_panel_owner(
        db,
        subscription.user,
        subscription,
        subscription.remnawave_id,
        multi_tariff=settings.is_multi_tariff_enabled(),
    )
    if foreign is not None:
        raise SubscriptionUnavailable('Primary identity is unavailable')
    # Do not follow email/Telegram fallbacks: only these recorded identities may
    # receive client HWID data or provide credentials for this subscription.
    primary_user = await api.get_user_identity(subscription.remnawave_id)
    if (
        primary_user is None
        or primary_user.id != subscription.remnawave_id
        or primary_user.short_uuid != subscription.remnawave_short_uuid
    ):
        raise SubscriptionUnavailable('Primary identity is unavailable')
    headers = forwarded_device_headers(request_headers)
    format_kwargs = {'client_type': client_type} if client_type is not None else {}
    status, body, response_headers = await api.get_public_subscription_response(
        primary_user.short_uuid, headers=headers, **format_kwargs
    )
    primary = SubscriptionDocument(body, response_headers, status)

    def ordinary(reason: str) -> CompositionResult:
        return CompositionResult(primary.for_client(), False, reason)

    if primary.status != 200 or primary.hwid_denied:
        return ordinary('primary_denied')
    if not _panel_active(primary_user):
        # A status response may itself contain custom remarks. Preserve it, but
        # never append BS configurations to it even if it looks like valid JSON.
        return ordinary('primary_inactive')
    if subscription.is_trial or subscription.traffic_mode != 'split':
        return ordinary('shared')
    if not contains_account_credentials(primary, primary_user):
        return ordinary('primary_not_configuration')
    account = await db.scalar(
        select(SubscriptionBsAccount).where(SubscriptionBsAccount.subscription_id == subscription.id)
    )
    if (
        account is None
        or account.migration_state != 'active'
        or not account.remnawave_id
        or not account.remnawave_short_uuid
    ):
        return ordinary('secondary_unprepared')
    try:
        secondary_user = await verify_bs_identity(db, api, account, primary_user)
        if not _panel_active(secondary_user):
            return ordinary('secondary_inactive')
        limit = await prepare_secondary_devices(api, primary_user, secondary_user, account, primary, headers)
        status, body, response_headers = await api.get_public_subscription_response(
            secondary_user.short_uuid, headers=headers, **format_kwargs
        )
    except BsAccountIdentityError:
        return ordinary('secondary_identity_mismatch')
    except BsDevicePolicyError:
        return ordinary('device_policy_unconfirmed')
    except (RemnaWaveAPIError, aiohttp.ClientError, TimeoutError):
        return ordinary('secondary_unavailable')
    secondary = SubscriptionDocument(body, response_headers, status)
    if not contains_account_credentials(secondary, secondary_user):
        return ordinary('secondary_not_configuration')
    # Preserve the original HTTP/HWID refusal before checking device metadata.
    if secondary.status != 200 or secondary.hwid_denied:
        return ordinary('secondary_denied')
    try:
        await confirm_secondary_devices(api, primary_user, secondary_user, secondary, headers, limit)
    except (BsDevicePolicyError, RemnaWaveAPIError, aiohttp.ClientError, TimeoutError):
        return ordinary('device_policy_unconfirmed')
    # asyncio cancellation intentionally propagates; do not turn request shutdown
    # into a successful response with partially fetched configuration material.
    return compose_subscriptions(primary, secondary)
