"""Recoverable preparation of BS accounts; production cutover is deliberately separate."""

from __future__ import annotations

from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.config import settings
from app.database.models import Subscription, SubscriptionBsAccount, User
from app.services.bs_traffic_policy import (
    BsAccountIdentityError,
    BsTrafficConfigurationError,
    bs_ownership_marker,
    build_split_payloads,
    resolve_bs_plan,
    validate_bs_inbounds,
)
from app.services.panel_sync.writer import prepare_bs_panel_account


async def prepare_bs_account(db: AsyncSession, api, subscription_id: int) -> SubscriptionBsAccount | None:
    """Persist an intent, prepare a disabled panel identity, then persist its id.

    This is an explicit preparation job with its own transaction boundaries,
    not a helper to call inside a payment transaction. It commits the intent
    before panel I/O; errors leave that intent available for a later retry.
    It never changes primary squads, keys, limits, dates, or traffic mode.
    """
    if db.new or db.dirty or db.deleted:
        raise BsTrafficConfigurationError('BS preparation requires a clean unit of work')
    if not settings.is_tariffs_mode():
        raise BsTrafficConfigurationError('BS preparation requires tariff sales mode')
    try:
        return await _prepare_bs_account(db, api, subscription_id)
    except BaseException:
        # Release the primary row lock on preflight errors as well as write
        # errors. The committed intent, if any, remains available for retry.
        await db.rollback()
        raise


async def _prepare_bs_account(db: AsyncSession, api, subscription_id: int) -> SubscriptionBsAccount | None:
    subscription = await db.scalar(
        select(Subscription)
        .where(Subscription.id == subscription_id)
        .options(selectinload(Subscription.tariff), selectinload(Subscription.user))
        .with_for_update()
    )
    if subscription is None:
        raise BsTrafficConfigurationError('Subscription not found')
    plan = resolve_bs_plan(
        subscription.tariff,
        is_trial=subscription.is_trial,
        multi_tariff=settings.is_multi_tariff_enabled(),
    )
    if plan is None:
        await db.commit()
        return None
    user = subscription.user
    if user is None:
        raise BsTrafficConfigurationError('Subscription owner not found')
    account = await db.scalar(
        select(SubscriptionBsAccount).where(SubscriptionBsAccount.subscription_id == subscription_id).with_for_update()
    )
    if account is not None and account.migration_state == 'active':
        await db.commit()
        return account
    await validate_bs_inbounds(api, plan)
    if account is None:
        account = SubscriptionBsAccount(
            subscription_id=subscription_id,
            panel_username=settings.build_remnawave_subscription_username(
                full_name=user.full_name,
                username=user.username,
                telegram_id=user.telegram_id,
                email=user.email,
                user_id=user.id,
                suffix=f'_bs{subscription_id}',
            ),
            provisioning_key=uuid4().hex,
            base_traffic_limit_gb=plan.base_limit_gb,
            purchased_traffic_gb=0,
        )
        db.add(account)
        await db.flush()
    account.migration_state = 'pending'
    _, payload = build_split_payloads(user, subscription, account, plan)
    account_id = account.id
    known_id = account.remnawave_id
    marker = bs_ownership_marker(account)
    await db.commit()

    async def check_owner(panel_id: int) -> None:
        # Cross-table uniqueness matters: secondary ids must never be adopted
        # by a primary, even if the corresponding panel description was edited.
        for model in (User, Subscription):
            if await db.scalar(select(model.id).where(model.remnawave_id == panel_id).limit(1)) is not None:
                raise BsAccountIdentityError('BS panel id is already assigned to a primary account')
        other = await db.scalar(
            select(SubscriptionBsAccount.id).where(
                SubscriptionBsAccount.remnawave_id == panel_id,
                SubscriptionBsAccount.id != account_id,
            )
        )
        if other is not None:
            raise BsAccountIdentityError('BS panel id is already assigned to another subscription')

    try:
        panel_user = await prepare_bs_panel_account(
            api,
            payload=payload,
            known_id=known_id,
            ownership_marker=marker,
            check_owner=check_owner,
        )
        account = await db.scalar(
            select(SubscriptionBsAccount)
            .where(SubscriptionBsAccount.id == account_id)
            .with_for_update()
            .execution_options(populate_existing=True)
        )
        if account is None or account.remnawave_id not in (None, known_id, panel_user.id):
            raise BsAccountIdentityError('BS identity changed during preparation')
        account.remnawave_id = panel_user.id
        account.remnawave_short_uuid = panel_user.short_uuid
        account.panel_status = 'DISABLED'
        account.migration_state = 'prepared'
        account.traffic_used_bytes = panel_user.used_traffic_bytes
        await db.commit()
        return account
    except Exception:
        await db.rollback()
        raise
