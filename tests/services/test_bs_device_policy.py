"""Malformed/partial device lists never stand in for an empty device registry."""

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from app.services.bs_device_policy import (
    BsDevicePolicyError,
    device_hwids,
    remove_subscription_device,
    reset_subscription_devices,
)


HWID = 'device-123456'


@pytest.mark.parametrize(
    'payload',
    [
        None,
        {},
        {'devices': [], 'total': True},
        {'devices': [], 'total': '0'},
        {'devices': [], 'total': 1},
        {'devices': [], 'total': -1},
        {'devices': None, 'total': 0},
        {'devices': [{}], 'total': 1},
        {'devices': [{'userId': 2, 'hwid': HWID}], 'total': 1},
        {'devices': [{'userId': '1', 'hwid': HWID}], 'total': 1},
        {'devices': [{'userId': True, 'hwid': HWID}], 'total': 1},
        {'devices': [{'userId': 1, 'hwid': '../bad'}], 'total': 1},
        {'devices': [{'userId': 1, 'hwid': HWID}] * 2, 'total': 2},
    ],
)
@pytest.mark.asyncio
async def test_malformed_device_registry_is_rejected(payload):
    api = SimpleNamespace(get_user_devices=AsyncMock(return_value=payload))
    with pytest.raises(BsDevicePolicyError):
        await device_hwids(api, 1)


@pytest.mark.asyncio
async def test_empty_and_complete_registry_are_accepted():
    api = SimpleNamespace(get_user_devices=AsyncMock(return_value={'devices': [], 'total': 0}))
    assert await device_hwids(api, 1) == set()
    api.get_user_devices.return_value = {'devices': [{'userId': 1, 'hwid': HWID}], 'total': 1}
    assert await device_hwids(api, 1) == {HWID}


@pytest.mark.parametrize(
    'subscription', [None, SimpleNamespace(traffic_mode='shared'), SimpleNamespace(traffic_mode='split', is_trial=True)]
)
@pytest.mark.asyncio
async def test_shared_and_trial_operations_keep_single_account_behavior(subscription):
    api = SimpleNamespace(remove_device=AsyncMock(return_value=True), reset_user_devices=AsyncMock(return_value=False))
    assert await remove_subscription_device(api, None, subscription, 1, 'legacy-device')
    assert not await reset_subscription_devices(api, None, subscription, 1)
    api.remove_device.assert_awaited_once_with(1, 'legacy-device')
    api.reset_user_devices.assert_awaited_once_with(1)
