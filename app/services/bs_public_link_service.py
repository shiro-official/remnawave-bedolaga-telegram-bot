"""Prepare/revoke capabilities without switching existing subscription links."""

from dataclasses import dataclass, field

from sqlalchemy import select

from app.database.models import Subscription, SubscriptionBsAccount, SubscriptionPublicLink
from app.services.bs_device_policy import BsDevicePolicyError, bs_device_lock
from app.services.bs_public_link_tokens import hash_public_token, new_public_token, public_subscription_url


@dataclass(frozen=True)
class PreparedPublicLink:
    subscription_id: int
    url: str = field(repr=False)


async def prepare_public_link(db, subscription_id: int) -> PreparedPublicLink:
    """Mint a disabled candidate. Does not publish it, activate users or edit their URL.

    A lost reply may be retried: a fresh disabled capability replaces the lost
    candidate. An active link or pending panel-key rotation is never overwritten.
    """
    token = new_public_token()
    url = public_subscription_url(token)  # Validate configuration BEFORE any changes.
    async with bs_device_lock(db, subscription_id) as locked_db:
        subscription = await locked_db.scalar(select(Subscription).where(Subscription.id == subscription_id))
        account = await locked_db.scalar(
            select(SubscriptionBsAccount).where(SubscriptionBsAccount.subscription_id == subscription_id)
        )
        link = await locked_db.scalar(
            select(SubscriptionPublicLink).where(SubscriptionPublicLink.subscription_id == subscription_id)
        )
        if (
            subscription is None
            or subscription.is_trial
            or account is None
            or account.migration_state not in ('prepared', 'active')
            or not subscription.remnawave_id
            or not subscription.remnawave_short_uuid
            or not account.remnawave_id
            or not account.remnawave_short_uuid
            or account.remnawave_id == subscription.remnawave_id
            or account.remnawave_short_uuid == subscription.remnawave_short_uuid
        ):
            raise BsDevicePolicyError('Public link preparation requires both account identities')
        if link is not None and (link.enabled or link.rotation_pending):
            raise BsDevicePolicyError('An active public link or key rotation cannot be replaced by preparation')
        if link is None:
            link = SubscriptionPublicLink(subscription_id=subscription_id)
            locked_db.add(link)
        link.token_hash = hash_public_token(token)
        link.enabled = False
        link.primary_id = subscription.remnawave_id
        link.primary_short_uuid = subscription.remnawave_short_uuid
        link.secondary_id = account.remnawave_id
        link.secondary_short_uuid = account.remnawave_short_uuid
    return PreparedPublicLink(subscription_id, url)


async def disable_public_link(db, subscription_id: int) -> None:
    """Immediately stop future merged downloads; never resets traffic or VPN keys."""
    async with bs_device_lock(db, subscription_id) as locked_db:
        link = await locked_db.scalar(
            select(SubscriptionPublicLink).where(SubscriptionPublicLink.subscription_id == subscription_id)
        )
        if link is not None:
            link.enabled = False
