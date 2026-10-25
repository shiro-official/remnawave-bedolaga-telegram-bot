from datetime import UTC, datetime
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest

from app.external.remnawave_api import RemnaWaveAPI


@pytest.mark.parametrize('operation', ['id', 'username', 'create', 'update', 'revoke'])
@pytest.mark.asyncio
async def test_technical_identity_operations_never_generate_a_direct_happ_link(operation):
    api = RemnaWaveAPI('https://panel.example', 'test-key')
    user = SimpleNamespace(id=2000, hwid_device_limit=2)
    api._make_request = AsyncMock(return_value={'response': {}})
    api._parse_user = Mock(return_value=user)
    api.enrich_user_with_happ_link = AsyncMock(side_effect=AssertionError('Direct technical URL must not be exported'))
    if operation == 'id':
        result = await api.get_user_identity(2000)
    elif operation == 'username':
        result = await api.get_user_identity_by_username('test_bs')
    elif operation == 'create':
        result = await api.create_user('test_bs', datetime.now(UTC), enrich_happ=False)
    elif operation == 'update':
        result = await api.update_user(2000, hwid_device_limit=2, enrich_happ=False)
    else:
        result = await api.revoke_user_subscription(2000, new_short_uuid='new-short', enrich_happ=False)
    assert result is user
    api.enrich_user_with_happ_link.assert_not_awaited()


@pytest.mark.asyncio
async def test_legacy_primary_read_keeps_its_existing_enrichment():
    api = RemnaWaveAPI('https://panel.example', 'test-key')
    user = SimpleNamespace(id=1000)
    api._make_request = AsyncMock(return_value={'response': {}})
    api._parse_user = Mock(return_value=user)
    api.enrich_user_with_happ_link = AsyncMock(return_value=user)
    assert await api.get_user_by_id(1000) is user
    api.enrich_user_with_happ_link.assert_awaited_once_with(user)
