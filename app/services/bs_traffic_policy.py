"""Validate separate traffic pools without changing the primary subscription."""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime
from uuid import UUID

from app.external.remnawave_api import TrafficLimitStrategy, UserStatus
from app.services.panel_sync.payload import PanelPayload, build_panel_payload


class BsTrafficConfigurationError(ValueError):
    """The proposed pools cannot safely be separated."""


class BsAccountIdentityError(ValueError):
    """A candidate panel account does not belong to this BS identity."""


@dataclass(frozen=True)
class BsTrafficPlan:
    primary_squads: tuple[str, ...]
    bs_squads: tuple[str, ...]
    base_limit_gb: int


def _squad_ids(values) -> tuple[str, ...]:
    try:
        return tuple(dict.fromkeys(str(UUID(str(value))) for value in (values or ())))
    except (ValueError, TypeError, AttributeError) as exc:
        raise BsTrafficConfigurationError('Squads must be selected by UUID') from exc


def resolve_bs_plan(tariff, *, is_trial: bool, multi_tariff: bool = False) -> BsTrafficPlan | None:
    """Trial and disabled tariffs retain the original single-account behavior."""
    if is_trial or tariff is None or not getattr(tariff, 'bs_traffic_enabled', False):
        return None
    if multi_tariff or getattr(tariff, 'is_daily', False) or getattr(tariff, 'custom_traffic_enabled', False):
        raise BsTrafficConfigurationError('Separate BS traffic requires a single period-based tariff')
    if getattr(tariff, 'traffic_limit_gb', None) != 0:
        raise BsTrafficConfigurationError('Ordinary traffic must be unlimited for separate BS traffic')
    limit = getattr(tariff, 'bs_traffic_limit_gb', 0) or 0
    if not isinstance(limit, int) or isinstance(limit, bool) or limit <= 0:
        raise BsTrafficConfigurationError('BS traffic requires a positive limit')
    allowed = _squad_ids(getattr(tariff, 'allowed_squads', None))
    bs_squads = _squad_ids(getattr(tariff, 'bs_squad_uuids', None))
    if not bs_squads or not set(bs_squads).issubset(allowed):
        raise BsTrafficConfigurationError('Select BS squads from the tariff squads')
    primary = tuple(squad for squad in allowed if squad not in bs_squads)
    if not primary:
        raise BsTrafficConfigurationError('At least one ordinary squad is required')
    return BsTrafficPlan(primary, bs_squads, limit)


async def validate_bs_inbounds(api, plan: BsTrafficPlan) -> None:
    """Reject hidden overlap through Trial/Default before any panel write."""
    groups: list[set[str]] = []
    for selected in (plan.primary_squads, plan.bs_squads):
        inbounds: set[str] = set()
        for squad_id in selected:
            squad = await api.get_internal_squad_by_uuid(squad_id)
            if squad is None or not squad.inbounds:
                raise BsTrafficConfigurationError(f'Squad {squad_id} is missing or has no inbounds')
            for inbound in squad.inbounds:
                try:
                    inbound_id = str(UUID(str(inbound.uuid)))
                except (ValueError, TypeError, AttributeError) as exc:
                    raise BsTrafficConfigurationError(f'Squad {squad_id} has an unidentified inbound') from exc
                inbounds.add(inbound_id)
        groups.append(inbounds)
    if groups[0] & groups[1]:
        raise BsTrafficConfigurationError('Ordinary and BS squads share inbounds')


def bs_ownership_marker(account) -> str:
    return f'eBunny BS; subscription={account.subscription_id}; key={account.provisioning_key}'


def build_split_payloads(
    user, subscription, account, plan: BsTrafficPlan, *, now: datetime | None = None
) -> tuple[PanelPayload, PanelPayload]:
    """Build both pool payloads; the secondary is deliberately prepared DISABLED.

    Returning a primary payload is not authorization to send it: cutover needs
    a working merged link and a shared device-admission policy first.
    """
    common = build_panel_payload(user, subscription, multi_tariff=False, now=now)
    if account.panel_username == common.username:
        raise BsAccountIdentityError('BS and primary usernames must differ')
    base_limit = account.traffic_limit_override_gb
    if base_limit is None:
        base_limit = account.base_traffic_limit_gb
    if base_limit <= 0 or (account.purchased_traffic_gb or 0) < 0:
        raise BsTrafficConfigurationError('BS account limits must remain positive')
    primary = replace(
        common,
        traffic_limit_bytes=0,
        traffic_limit_strategy=TrafficLimitStrategy.NO_RESET,
        active_internal_squads=plan.primary_squads,
    )
    bs = replace(
        common,
        username=account.panel_username,
        status=UserStatus.DISABLED,
        traffic_limit_bytes=(base_limit + (account.purchased_traffic_gb or 0)) * 1024**3,
        active_internal_squads=plan.bs_squads,
        telegram_id=None,
        email=None,
        description=bs_ownership_marker(account),
        is_live=False,
    )
    return primary, bs
