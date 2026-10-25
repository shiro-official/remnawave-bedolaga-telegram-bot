from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from app.external.remnawave_api import TrafficLimitStrategy, UserStatus
from app.services.bs_traffic_policy import (
    BsAccountIdentityError,
    BsTrafficConfigurationError,
    build_split_payloads,
    resolve_bs_plan,
    validate_bs_inbounds,
)


ORDINARY = '00000000-0000-0000-0000-000000000001'
BS = '00000000-0000-0000-0000-000000000002'
TRIAL = '00000000-0000-0000-0000-000000000003'


def _tariff(**changes):
    data = dict(
        bs_traffic_enabled=True,
        traffic_limit_gb=0,
        bs_traffic_limit_gb=100,
        allowed_squads=[ORDINARY, BS],
        bs_squad_uuids=[BS],
        is_daily=False,
        traffic_reset_mode='WEEK',
        external_squad_uuid=None,
    )
    return SimpleNamespace(**(data | changes))


@pytest.mark.parametrize('trial,enabled', [(True, True), (True, False), (False, False)])
def test_trial_and_disabled_tariffs_keep_shared_account(trial, enabled):
    assert resolve_bs_plan(_tariff(bs_traffic_enabled=enabled), is_trial=trial) is None


@pytest.mark.parametrize(
    'changes',
    [
        {'traffic_limit_gb': 50},
        {'bs_traffic_limit_gb': 0},
        {'bs_traffic_limit_gb': -1},
        {'bs_traffic_limit_gb': True},
        {'bs_squad_uuids': []},
        {'allowed_squads': [ORDINARY]},
        {'allowed_squads': [BS]},
        {'bs_squad_uuids': ['CDN White']},
        {'is_daily': True},
        {'custom_traffic_enabled': True},
    ],
)
def test_invalid_split_configuration_is_rejected(changes):
    with pytest.raises(BsTrafficConfigurationError):
        resolve_bs_plan(_tariff(**changes), is_trial=False)


def test_multi_tariff_is_not_silently_enabled():
    with pytest.raises(BsTrafficConfigurationError):
        resolve_bs_plan(_tariff(), is_trial=False, multi_tariff=True)


def test_squads_are_partitioned_by_identity_not_name():
    plan = resolve_bs_plan(_tariff(allowed_squads=[ORDINARY, BS, ORDINARY]), is_trial=False)
    assert plan.primary_squads == (ORDINARY,)
    assert plan.bs_squads == (BS,)
    assert plan.base_limit_gb == 100


@pytest.mark.asyncio
async def test_trial_squad_overlap_is_rejected_before_writing():
    plan = resolve_bs_plan(_tariff(allowed_squads=[ORDINARY, BS, TRIAL]), is_trial=False)
    squads = {
        ORDINARY: SimpleNamespace(inbounds=[SimpleNamespace(uuid=ORDINARY)]),
        BS: SimpleNamespace(inbounds=[SimpleNamespace(uuid=BS)]),
        TRIAL: SimpleNamespace(inbounds=[SimpleNamespace(uuid=ORDINARY), SimpleNamespace(uuid=BS)]),
    }
    api = SimpleNamespace(get_internal_squad_by_uuid=AsyncMock(side_effect=lambda key: squads[key]))
    with pytest.raises(BsTrafficConfigurationError, match='share inbounds'):
        await validate_bs_inbounds(api, plan)


@pytest.mark.asyncio
@pytest.mark.parametrize('squad', [None, SimpleNamespace(inbounds=[])])
async def test_missing_or_empty_squad_does_not_pass_preflight(squad):
    api = SimpleNamespace(get_internal_squad_by_uuid=AsyncMock(return_value=squad))
    with pytest.raises(BsTrafficConfigurationError):
        await validate_bs_inbounds(api, resolve_bs_plan(_tariff(), is_trial=False))


def _payloads(override=None):
    now = datetime.now(UTC)
    tariff = _tariff()
    user = SimpleNamespace(id=4, telegram_id=12345, email=None, username='owner', full_name='Owner', status='active')
    subscription = SimpleNamespace(
        id=8,
        tariff=tariff,
        is_trial=False,
        status='active',
        end_date=now + timedelta(days=30),
        traffic_limit_gb=0,
        connected_squads=[ORDINARY, BS],
        device_limit=3,
    )
    account = SimpleNamespace(
        panel_username='owner_bs8',
        subscription_id=8,
        provisioning_key='persisted-intent',
        base_traffic_limit_gb=100,
        traffic_limit_override_gb=override,
        purchased_traffic_gb=50,
    )
    return build_split_payloads(
        user, subscription, account, resolve_bs_plan(tariff, is_trial=False), now=now
    ), subscription


def test_prepared_bs_is_disabled_and_shares_expiry_without_primary_credentials():
    (primary, bs), subscription = _payloads()
    assert primary.traffic_limit_bytes == 0
    assert primary.active_internal_squads == (ORDINARY,)
    assert primary.status is UserStatus.ACTIVE
    assert bs.traffic_limit_bytes == 150 * 1024**3
    assert bs.active_internal_squads == (BS,)
    assert bs.traffic_limit_strategy is TrafficLimitStrategy.WEEK
    assert bs.status is UserStatus.DISABLED
    assert bs.telegram_id is None and bs.email is None
    assert primary.username != bs.username
    assert bs.create_kwargs()['expire_at'] == subscription.end_date
    assert subscription.connected_squads == [ORDINARY, BS], 'building a plan must not perform cutover'


def test_personal_limit_override_is_not_replaced_by_tariff_limit():
    (_, bs), _ = _payloads(override=200)
    assert bs.traffic_limit_bytes == 250 * 1024**3


def test_secondary_username_cannot_equal_primary():
    (primary, _), _ = _payloads()
    # The storage identity is validated when building, not inferred from a suffix.
    with pytest.raises(BsAccountIdentityError):
        build_split_payloads(
            SimpleNamespace(id=4, telegram_id=12345, email=None, username='owner', full_name='Owner', status='active'),
            SimpleNamespace(
                id=8, tariff=_tariff(), status='active', end_date=primary.end_date, traffic_limit_gb=0, device_limit=3
            ),
            SimpleNamespace(panel_username=primary.username),
            resolve_bs_plan(_tariff(), is_trial=False),
        )
