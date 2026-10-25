"""Recoverable paired key rotation. Disabled capability is committed before I/O."""

from __future__ import annotations

import hashlib
import re
import secrets
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import selectinload

from app.config import settings
from app.database.models import Subscription, SubscriptionBsAccount, SubscriptionPublicLink
from app.services.bs_account_identity import verify_bs_identity
from app.services.bs_device_policy import BsDevicePolicyError, bs_device_lock, bs_device_session, is_split_subscription
from app.services.bs_public_link_tokens import (
    hash_public_token,
    new_public_token,
    public_subscription_base_url,
    public_subscription_url,
    public_token_from_url,
)
from app.services.bs_traffic_policy import BsAccountIdentityError
from app.services.panel_sync.identity import find_foreign_panel_owner


_KEY_FIELDS = ('vless_uuid', 'trojan_password', 'ss_password')


def _panel_target(excluded: set[str]) -> str:
    for _ in range(16):
        candidate = secrets.token_urlsafe(12)
        if candidate not in excluded:
            return candidate
    raise BsDevicePolicyError('Could not create distinct panel rotation targets')


def _valid_intent(intent, subscription, account, link) -> bool:
    if (
        not isinstance(intent, dict)
        or intent.get('version') != 1
        or intent.get('primary_id') != subscription.remnawave_id
        or intent.get('secondary_id') != account.remnawave_id
        or not isinstance(intent.get('primary_username'), str)
    ):
        return False
    for name in ('primary_target', 'secondary_target'):
        if not isinstance(intent.get(name), str) or re.fullmatch(r'[A-Za-z0-9_-]{16}', intent[name]) is None:
            return False
    for name in ('primary_old_hashes', 'secondary_old_hashes'):
        hashes = intent.get(name)
        if not isinstance(hashes, dict) or not hashes or set(hashes) - set(_KEY_FIELDS):
            return False
        if any(not isinstance(value, str) or re.fullmatch('[0-9a-f]{64}', value) is None for value in hashes.values()):
            return False
    old = {link.primary_short_uuid, link.secondary_short_uuid}
    return (
        intent['primary_target'] != intent['secondary_target']
        and intent['primary_target'] not in old
        and intent['secondary_target'] not in old
    )


def _key_hashes(user) -> dict[str, str]:
    return {
        name: hashlib.sha256(value.encode()).hexdigest()
        for name in _KEY_FIELDS
        if isinstance(value := getattr(user, name, None), str) and value
    }


def _rotated(user, target, old_hashes) -> bool:
    hashes = _key_hashes(user)
    return (
        user.short_uuid == target
        and bool(old_hashes)
        and all(name in hashes and hashes[name] != value for name, value in old_hashes.items())
    )


async def _primary(db, api, subscription, intent=None):
    foreign = await find_foreign_panel_owner(
        db, subscription.user, subscription, subscription.remnawave_id, multi_tariff=False
    )
    user = await api.get_user_identity(subscription.remnawave_id) if foreign is None else None
    allowed = {subscription.remnawave_short_uuid}
    if intent:
        allowed.add(intent['primary_target'])
    if (
        user is None
        or user.id != subscription.remnawave_id
        or user.short_uuid not in allowed
        or (intent and user.username != intent['primary_username'])
    ):
        raise BsAccountIdentityError('Primary identity changed during key rotation')
    return user


async def _secondary(db, api, account, primary, intent=None):
    allowed = {account.remnawave_short_uuid}
    if intent:
        allowed.add(intent['secondary_target'])
    return await verify_bs_identity(db, api, account, primary, allowed_short_uuids=allowed)


async def revoke_split_public_link(db, api, subscription_id: int) -> str:
    """No successful result until BOTH accounts and the new capability are saved.

    Only a previously enabled split link can start a rotation. Pending attempts
    resume with the same planned panel short UUIDs; readback proves a lost reply
    already changed the keys, so it does not rotate them again unnecessarily.
    """
    if not settings.BS_SUBSCRIPTION_DELIVERY_ENABLED:
        raise BsDevicePolicyError('Public BS delivery is disabled')
    public_subscription_base_url()
    if db.new or db.dirty or db.deleted:
        raise BsDevicePolicyError('Key rotation requires a clean caller transaction')
    async with bs_device_lock(db, subscription_id):
        # The guard transaction stays open while the independent work session
        # durably commits each step. Committing an intent cannot release the lock.
        async with bs_device_session(db) as work:
            subscription = await work.scalar(
                select(Subscription).where(Subscription.id == subscription_id).options(selectinload(Subscription.user))
            )
            account = await work.scalar(
                select(SubscriptionBsAccount).where(SubscriptionBsAccount.subscription_id == subscription_id)
            )
            link = await work.scalar(
                select(SubscriptionPublicLink).where(SubscriptionPublicLink.subscription_id == subscription_id)
            )
            if (
                subscription is None
                or not is_split_subscription(subscription)
                or subscription.user is None
                or account is None
                or account.migration_state != 'active'
                or link is None
                or link.primary_id != subscription.remnawave_id
                or link.secondary_id != account.remnawave_id
            ):
                raise BsDevicePolicyError('Split key rotation is unavailable')
            if not link.rotation_pending:
                if (
                    not link.enabled
                    or link.primary_short_uuid != subscription.remnawave_short_uuid
                    or link.secondary_short_uuid != account.remnawave_short_uuid
                ):
                    raise BsDevicePolicyError('Public capability is not active or its binding changed')
                last = subscription.last_revoke_at
                if (
                    last is not None
                    and (datetime.now(UTC) - last).total_seconds() < settings.SUBSCRIPTION_REVOKE_COOLDOWN_SECONDS
                ):
                    current_token = public_token_from_url(subscription.subscription_url)
                    if current_token and hash_public_token(current_token) == link.token_hash:
                        return subscription.subscription_url
                    raise BsDevicePolicyError('Recent key rotation has no confirmed public URL')
                primary = await _primary(work, api, subscription)
                secondary = await _secondary(work, api, account, primary)
                primary_hashes, secondary_hashes = _key_hashes(primary), _key_hashes(secondary)
                if not primary_hashes or not secondary_hashes:
                    raise BsDevicePolicyError('Cannot confirm account key rotation')
                primary_target = _panel_target({primary.short_uuid, secondary.short_uuid})
                secondary_target = _panel_target({primary.short_uuid, secondary.short_uuid, primary_target})
                link.rotation_intent = {
                    'version': 1,
                    'primary_id': primary.id,
                    'secondary_id': secondary.id,
                    'primary_username': primary.username,
                    'primary_target': primary_target,
                    'secondary_target': secondary_target,
                    'primary_old_hashes': primary_hashes,
                    'secondary_old_hashes': secondary_hashes,
                }
                link.enabled = False
                link.rotation_pending = True
                await work.commit()
            intent = link.rotation_intent
            if not _valid_intent(intent, subscription, account, link):
                raise BsDevicePolicyError('Invalid persisted key rotation intent')
            primary = await _primary(work, api, subscription, intent)
            secondary = await _secondary(work, api, account, primary, intent)
            if not _rotated(secondary, intent['secondary_target'], intent['secondary_old_hashes']):
                result = await api.revoke_user_subscription(
                    secondary.id, new_short_uuid=intent['secondary_target'], enrich_happ=False
                )
                if not _rotated(result, intent['secondary_target'], intent['secondary_old_hashes']):
                    raise BsAccountIdentityError('Secondary key rotation response is unconfirmed')
                secondary = await _secondary(work, api, account, primary, intent)
                if not _rotated(secondary, intent['secondary_target'], intent['secondary_old_hashes']):
                    raise BsAccountIdentityError('Secondary key rotation readback is unconfirmed')
            account.remnawave_short_uuid = secondary.short_uuid
            await work.commit()
            if not _rotated(primary, intent['primary_target'], intent['primary_old_hashes']):
                result = await api.revoke_user_subscription(
                    primary.id, new_short_uuid=intent['primary_target'], enrich_happ=False
                )
                if not _rotated(result, intent['primary_target'], intent['primary_old_hashes']):
                    raise BsAccountIdentityError('Primary key rotation response is unconfirmed')
                primary = await _primary(work, api, subscription, intent)
                if not _rotated(primary, intent['primary_target'], intent['primary_old_hashes']):
                    raise BsAccountIdentityError('Primary key rotation readback is unconfirmed')
            subscription.remnawave_short_uuid = primary.short_uuid
            await work.commit()
            # Publish only after both planned rotations are independently confirmed.
            token = new_public_token()
            url = public_subscription_url(token)
            crypto_link = None
            if settings.is_happ_cryptolink_mode():
                try:
                    # Only the combined, user-facing URL may be encrypted.
                    crypto_link = await api.encrypt_happ_crypto_link(url)
                except Exception:
                    # Keep the existing product fallback to the ordinary URL;
                    # never retain a cryptolink to a raw primary/BS account.
                    crypto_link = None
            subscription.subscription_url = url
            subscription.subscription_crypto_link = crypto_link
            subscription.last_revoke_at = datetime.now(UTC)
            link.token_hash = hash_public_token(token)
            link.primary_short_uuid = primary.short_uuid
            link.secondary_short_uuid = secondary.short_uuid
            link.rotation_pending = False
            link.rotation_intent = None
            link.enabled = True
            await work.commit()
            return url
