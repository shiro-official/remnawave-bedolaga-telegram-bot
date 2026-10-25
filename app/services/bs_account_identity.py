"""Exact secondary ownership checks shared by delivery and device mutations."""

from sqlalchemy import or_, select

from app.database.models import Subscription, User
from app.services.bs_traffic_policy import BsAccountIdentityError, bs_ownership_marker


async def verify_bs_identity(db, api, account, primary):
    """Never resolve a secondary through Telegram/email or a primary reservation."""
    if (
        not account.remnawave_id
        or not account.remnawave_short_uuid
        or account.remnawave_id == primary.id
        or account.remnawave_short_uuid == primary.short_uuid
    ):
        raise BsAccountIdentityError('Invalid secondary identity')
    if await db.scalar(select(User.id).where(User.remnawave_id == account.remnawave_id).limit(1)) is not None:
        raise BsAccountIdentityError('Secondary reserved as a user primary')
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
        raise BsAccountIdentityError('Secondary reserved as a subscription primary')
    secondary = await api.get_user_by_id(account.remnawave_id)
    if (
        secondary is None
        or secondary.id != account.remnawave_id
        or secondary.short_uuid != account.remnawave_short_uuid
        or secondary.username != account.panel_username
        or secondary.description != bs_ownership_marker(account)
    ):
        raise BsAccountIdentityError('Secondary ownership could not be confirmed')
    return secondary
