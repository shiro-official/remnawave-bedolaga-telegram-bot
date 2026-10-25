"""Read-only delivery engine; no public route or cutover is enabled here.

The future public route must resolve/authenticate its token before calling this
service. It must not expose a subscription database id as a bearer credential.
Shared device removal and lifecycle coordination remain cutover prerequisites.
"""

from __future__ import annotations

from datetime import UTC, datetime

import aiohttp
from sqlalchemy import or_, select
from sqlalchemy.orm import selectinload

from app.config import settings
from app.database.models import Subscription, SubscriptionBsAccount, User
from app.external.remnawave_api import RemnaWaveAPIError, UserStatus
from app.services.bs_subscription_composer import (
    CompositionResult,
    SubscriptionDocument,
    compose_subscriptions,
    contains_account_credentials,
    forwarded_device_headers,
)
from app.services.bs_traffic_policy import bs_ownership_marker
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

    This service never bypasses either account's HWID gate, modifies panel
    accounts, changes device limits or caches a subscription response.
    """
    if db.new or db.dirty or db.deleted:
        raise SubscriptionUnavailable('Delivery requires a clean unit of work')
    subscription = await db.scalar(
        select(Subscription).where(Subscription.id == subscription_id).options(selectinload(Subscription.user))
    )
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
    primary_user = await api.get_user_by_id(subscription.remnawave_id)
    if (
        primary_user is None
        or primary_user.id != subscription.remnawave_id
        or primary_user.short_uuid != subscription.remnawave_short_uuid
    ):
        raise SubscriptionUnavailable('Primary identity is unavailable')
    headers = forwarded_device_headers(request_headers)
    status, body, response_headers = await api.get_public_subscription_response(
        primary_user.short_uuid, headers=headers
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
    if account.remnawave_id == primary_user.id or account.remnawave_short_uuid == primary_user.short_uuid:
        return ordinary('secondary_identity_mismatch')
    if await db.scalar(select(User.id).where(User.remnawave_id == account.remnawave_id).limit(1)) is not None:
        return ordinary('secondary_identity_mismatch')
    if (
        await db.scalar(
            select(Subscription.id)
            .where(
                or_(
                    Subscription.remnawave_id == account.remnawave_id,
                    Subscription.remnawave_short_uuid == account.remnawave_short_uuid,
                )
            )
            .limit(1)
        )
        is not None
    ):
        return ordinary('secondary_identity_mismatch')
    try:
        secondary_user = await api.get_user_by_id(account.remnawave_id)
        if (
            secondary_user is None
            or secondary_user.id != account.remnawave_id
            or secondary_user.short_uuid != account.remnawave_short_uuid
            or secondary_user.username != account.panel_username
            or secondary_user.description != bs_ownership_marker(account)
        ):
            return ordinary('secondary_identity_mismatch')
        if not _panel_active(secondary_user):
            return ordinary('secondary_inactive')
        status, body, response_headers = await api.get_public_subscription_response(
            secondary_user.short_uuid, headers=headers
        )
    except (RemnaWaveAPIError, aiohttp.ClientError, TimeoutError):
        return ordinary('secondary_unavailable')
    secondary = SubscriptionDocument(body, response_headers, status)
    if not contains_account_credentials(secondary, secondary_user):
        return ordinary('secondary_not_configuration')
    # asyncio cancellation intentionally propagates; do not turn request shutdown
    # into a successful response with partially fetched configuration material.
    return compose_subscriptions(primary, secondary)
