"""Two account registries share primary admission and real PostgreSQL serialization."""

import asyncio
import copy
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi import HTTPException
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine

from app.database.models import Subscription
from app.external.remnawave_api import RemnaWaveAPIError
from app.services.bs_device_policy import (
    BsDevicePolicyError,
    bs_device_lock,
    remove_subscription_device,
    reset_subscription_devices,
)
from app.services.bs_subscription_delivery import deliver_subscription
from app.services.bs_traffic_policy import BsAccountIdentityError
from tests.database.test_bs_subscription_delivery_postgres import DEVICE_HEADERS, MAIN, TABLES, seed
from tests.fixtures.postgres_db import postgres_session


pytestmark = pytest.mark.postgres
HWID = 'device-123456'
STALE = 'stale-device-123456'


@pytest.mark.asyncio
async def test_stale_secondary_is_pruned_before_its_atomic_public_admission(postgres_database):
    async with postgres_session(postgres_database, TABLES) as db:
        _, sub, _, api = await seed(db)
        api.devices[2000] = {STALE}
        api.users[1000].hwid_device_limit = api.users[2000].hwid_device_limit = 1
        result = await deliver_subscription(db, api, sub.id, request_headers=DEVICE_HEADERS)
        assert result.bs_included
        assert api.removed == [(2000, STALE)]
        assert api.devices == {1000: {HWID}, 2000: {HWID}}
        assert api.updates == []


@pytest.mark.parametrize('limit', [1, 3, 7, 0])
@pytest.mark.asyncio
async def test_primary_actual_device_limit_is_mirrored_without_changing_other_fields(postgres_database, limit):
    async with postgres_session(postgres_database, TABLES) as db:
        _, sub, _, api = await seed(db)
        api.users[1000].hwid_device_limit = limit
        previous = vars(api.users[2000]).copy()
        result = await deliver_subscription(db, api, sub.id, request_headers=DEVICE_HEADERS)
        assert result.bs_included
        assert api.updates == [{'user_id': 2000, 'hwid_device_limit': limit}]
        assert vars(api.users[2000]) == {**previous, 'hwid_device_limit': limit}


@pytest.mark.parametrize(
    'problem', ['null-limit', 'missing-hwid', 'invalid-hwid', 'missing-gate', 'unregistered', 'stale-noop']
)
@pytest.mark.asyncio
async def test_unconfirmed_primary_or_cleanup_never_issues_bs(postgres_database, problem):
    async with postgres_session(postgres_database, TABLES) as db:
        _, sub, _, api = await seed(db)
        headers = dict(DEVICE_HEADERS)
        if problem == 'null-limit':
            api.users[1000].hwid_device_limit = None
        elif problem == 'missing-hwid':
            headers.pop('X-HWID')
        elif problem == 'invalid-hwid':
            headers['X-HWID'] = 'invalid'
        elif problem == 'missing-gate':
            api.responses['primary-short'][2].pop('x-hwid-active')
        elif problem == 'unregistered':
            api.devices[1000].clear()
            api.auto_register = False
        else:
            api.devices[2000].add(STALE)
            api.ack_without_delete.add(2000)
        result = await deliver_subscription(db, api, sub.id, request_headers=headers)
        assert not result.bs_included and result.reason == 'device_policy_unconfirmed'
        assert result.document.body == MAIN
        assert len(api.requests) == 1


@pytest.mark.asyncio
async def test_explicit_unlimited_supports_clients_without_hwid(postgres_database):
    async with postgres_session(postgres_database, TABLES) as db:
        _, sub, _, api = await seed(db)
        api.users[1000].hwid_device_limit = api.users[2000].hwid_device_limit = 0
        result = await deliver_subscription(db, api, sub.id, request_headers={'User-Agent': 'Clash'})
        assert result.bs_included and api.updates == []


@pytest.mark.asyncio
async def test_secondary_public_gate_is_not_bypassed_when_it_refuses_a_device(postgres_database):
    async with postgres_session(postgres_database, TABLES) as db:
        _, sub, _, api = await seed(db)
        api.responses['secondary-short'] = (200, '', {'x-hwid-limit': 'true'})
        result = await deliver_subscription(db, api, sub.id, request_headers=DEVICE_HEADERS)
        assert not result.bs_included and result.document.body == MAIN
        assert len(api.requests) == 2


@pytest.mark.parametrize('reset', [False, True])
@pytest.mark.asyncio
async def test_device_mutations_affect_both_accounts_secondary_first(postgres_database, reset):
    async with postgres_session(postgres_database, TABLES) as db:
        _, sub, _, api = await seed(db)
        if reset:
            assert await reset_subscription_devices(api, db, sub, 1000)
            assert api.resets == [2000, 1000]
        else:
            assert await remove_subscription_device(api, db, sub, 1000, HWID)
            assert api.removed == [(2000, HWID), (1000, HWID)]
        assert api.devices == {1000: set(), 2000: set()}
        assert not db.dirty


@pytest.mark.parametrize('reset', [False, True])
@pytest.mark.parametrize('problem', ['failed', 'false-ack'])
@pytest.mark.asyncio
async def test_secondary_failure_preserves_primary_registration(postgres_database, reset, problem):
    async with postgres_session(postgres_database, TABLES) as db:
        _, sub, _, api = await seed(db)
        if problem == 'false-ack':
            api.ack_without_delete.add(2000)
        elif reset:
            api.fail_reset.add(2000)
        else:
            api.fail_remove.add(2000)
        if reset:
            assert not await reset_subscription_devices(api, db, sub, 1000)
            assert api.resets == [2000]
        else:
            assert not await remove_subscription_device(api, db, sub, 1000, HWID)
            assert api.removed == [(2000, HWID)]
        assert api.devices[1000] == {HWID}


@pytest.mark.asyncio
async def test_reset_cleans_stale_secondary_even_when_primary_is_empty(postgres_database):
    async with postgres_session(postgres_database, TABLES) as db:
        _, sub, _, api = await seed(db)
        api.devices[1000].clear()
        assert await reset_subscription_devices(api, db, sub, 1000)
        assert api.devices == {1000: set(), 2000: set()}


@pytest.mark.asyncio
async def test_partial_delete_can_be_retried_without_claiming_success(postgres_database):
    async with postgres_session(postgres_database, TABLES) as db:
        _, sub, _, api = await seed(db)
        api.fail_remove.add(1000)
        assert not await remove_subscription_device(api, db, sub, 1000, HWID)
        assert api.devices == {1000: {HWID}, 2000: set()}
        api.fail_remove.clear()
        assert await remove_subscription_device(api, db, sub, 1000, HWID)
        assert api.devices == {1000: set(), 2000: set()}


@pytest.mark.asyncio
async def test_foreign_secondary_cannot_be_reset(postgres_database):
    async with postgres_session(postgres_database, TABLES) as db:
        _, sub, _, api = await seed(db)
        api.users[2000].description = 'foreign-account'
        with pytest.raises(BsAccountIdentityError):
            await reset_subscription_devices(api, db, sub, 1000)
        assert api.removed == api.resets == []


@pytest.mark.asyncio
async def test_dirty_caller_is_neither_committed_nor_autoflushed_by_device_mutation(postgres_database):
    async with postgres_session(postgres_database, TABLES) as db:
        user, sub, _, api = await seed(db)
        user.balance_kopeks = 99999
        assert await remove_subscription_device(api, db, sub, 1000, HWID)
        assert user in db.dirty
        await db.rollback()


@pytest.mark.asyncio
async def test_concurrent_new_devices_cannot_double_the_primary_slot_count(postgres_database):
    async with postgres_session(postgres_database, TABLES) as db:
        _, sub, _, api = await seed(db)
        api.devices = {1000: set(), 2000: set()}
        api.users[1000].hwid_device_limit = api.users[2000].hwid_device_limit = 1

        async def request(hwid):
            # Each request owns a distinct session/connection, as in ASGI.
            async with type(db)(db.bind, expire_on_commit=False) as request_db:
                return await deliver_subscription(request_db, api, sub.id, request_headers={'x-hwid': hwid})

        results = await asyncio.gather(request('concurrent-device-A'), request('concurrent-device-B'))
        assert sum(result.bs_included for result in results) == 1
        assert {result.reason for result in results} == {'combined', 'primary_denied'}
        assert len(api.devices[1000]) == 1 and api.devices[1000] == api.devices[2000]


@pytest.mark.asyncio
async def test_reset_waits_for_inflight_delivery_and_finishes_with_empty_registries(postgres_database):
    async with postgres_session(postgres_database, TABLES) as db:
        _, sub, _, api = await seed(db)
        admitted, release = asyncio.Event(), asyncio.Event()
        public_fetch = api.get_public_subscription_response

        async def paused_fetch(short_uuid, *, headers):
            result = await public_fetch(short_uuid, headers=headers)
            if short_uuid == 'primary-short':
                admitted.set()
                await release.wait()
            return result

        api.get_public_subscription_response = paused_fetch
        delivery = asyncio.create_task(deliver_subscription(db, api, sub.id, request_headers=DEVICE_HEADERS))
        await asyncio.wait_for(admitted.wait(), 2)
        reset = asyncio.create_task(reset_subscription_devices(api, db, sub, 1000))
        try:
            with pytest.raises(TimeoutError):
                await asyncio.wait_for(asyncio.shield(reset), 0.05)
            assert api.resets == []
        finally:
            release.set()
        assert (await asyncio.wait_for(delivery, 2)).bs_included
        assert await asyncio.wait_for(reset, 2)
        assert api.devices == {1000: set(), 2000: set()}


@pytest.mark.asyncio
async def test_cancelled_lock_holder_releases_lock_and_other_subscriptions_do_not_block(postgres_database):
    async with postgres_session(postgres_database, TABLES) as db:
        entered, release = asyncio.Event(), asyncio.Event()

        async def holder():
            async with bs_device_lock(db, 1):
                entered.set()
                await release.wait()

        task = asyncio.create_task(holder())
        await asyncio.wait_for(entered.wait(), 2)
        async with asyncio.timeout(1), bs_device_lock(db, 2):
            pass
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        async with asyncio.timeout(1), bs_device_lock(db, 1):
            pass


@pytest.mark.asyncio
async def test_split_operations_require_a_real_independent_database_session():
    with pytest.raises(BsDevicePolicyError):
        async with bs_device_lock(None, 1):
            pytest.fail('Missing PostgreSQL session must not yield a fake lock')


@pytest.mark.parametrize('context', ['stale-shared', 'missing-subscription'])
@pytest.mark.asyncio
async def test_legacy_context_cannot_skip_persisted_secondary(postgres_database, context):
    async with postgres_session(postgres_database, TABLES) as db:
        _, sub, _, api = await seed(db)
        if context == 'stale-shared':
            sub.traffic_mode = 'shared'  # Caller state is deliberately uncommitted.
        assert await reset_subscription_devices(api, db, sub if context == 'stale-shared' else None, 1000)
        assert api.resets == [2000, 1000]
        if context == 'stale-shared':
            assert sub in db.dirty


@pytest.mark.parametrize('failure', ['no-op', 'lost-reply'])
@pytest.mark.asyncio
async def test_unconfirmed_limit_update_preserves_ordinary_and_recovers_on_retry(postgres_database, failure):
    async with postgres_session(postgres_database, TABLES) as db:
        _, sub, _, api = await seed(db)
        api.users[1000].hwid_device_limit = 3
        update = api.update_user

        async def failed_update(**kwargs):
            if failure == 'no-op':
                return copy.copy(api.users[2000])
            await update(**kwargs)
            raise RemnaWaveAPIError('reply lost after applying update')

        api.update_user = failed_update
        result = await deliver_subscription(db, api, sub.id, request_headers=DEVICE_HEADERS)
        assert not result.bs_included and result.document.body == MAIN
        assert len(api.requests) == 1
        api.update_user = update
        assert (await deliver_subscription(db, api, sub.id, request_headers=DEVICE_HEADERS)).bs_included
        assert api.users[2000].hwid_device_limit == 3


@pytest.mark.asyncio
async def test_unregistered_secondary_appearing_during_fetch_is_not_delivered(postgres_database):
    async with postgres_session(postgres_database, TABLES) as db:
        _, sub, _, api = await seed(db)
        fetch = api.get_public_subscription_response

        async def fetch_with_external_registration(short_uuid, *, headers):
            response = await fetch(short_uuid, headers=headers)
            if short_uuid == 'secondary-short':
                api.devices[2000].add(STALE)
            return response

        api.get_public_subscription_response = fetch_with_external_registration
        result = await deliver_subscription(db, api, sub.id, request_headers=DEVICE_HEADERS)
        assert not result.bs_included and result.reason == 'device_policy_unconfirmed'


@pytest.mark.parametrize('surface', ['cabinet', 'bot'])
@pytest.mark.parametrize('failure', [False, True])
@pytest.mark.asyncio
async def test_empty_primary_ui_reset_still_cleans_secondary_and_reports_failure(
    postgres_database, monkeypatch, surface, failure
):
    import app.cabinet.routes.subscription_modules.devices as cabinet
    import app.handlers.subscription.devices as bot_devices
    import app.services.remnawave_service as remnawave

    async with postgres_session(postgres_database, TABLES) as db:
        user, sub, _, api = await seed(db)
        api.devices[1000].clear()
        if failure:
            api.fail_reset.add(2000)

        @asynccontextmanager
        async def api_context():
            yield api

        service = SimpleNamespace(get_api_client=api_context)
        monkeypatch.setattr(remnawave, 'RemnaWaveService', lambda: service)
        if surface == 'cabinet':
            monkeypatch.setattr(cabinet, 'resolve_subscription', AsyncMock(return_value=sub))
            if failure:
                with pytest.raises(HTTPException) as error:
                    await cabinet.delete_all_devices(subscription_id=sub.id, user=user, db=db)
                assert error.value.status_code == 502
            else:
                result = await cabinet.delete_all_devices(subscription_id=sub.id, user=user, db=db)
                assert result['success'] and result['deleted_count'] == 0
        else:
            monkeypatch.setattr(bot_devices, '_resolve_subscription', AsyncMock(return_value=(sub, sub.id)))
            callback = MagicMock()
            callback.answer = AsyncMock()
            callback.message.edit_text = AsyncMock()
            await bot_devices.handle_all_devices_reset_from_management(callback, user, db)
            if failure:
                assert not any('успешно' in str(call).lower() for call in callback.message.edit_text.await_args_list)
            else:
                assert any('успешно' in str(call).lower() for call in callback.message.edit_text.await_args_list)
        assert api.resets == ([2000] if failure else [2000, 1000])
        assert bool(api.devices[2000]) == failure


@pytest.mark.asyncio
async def test_busy_one_connection_caller_pool_cannot_deadlock_device_guard(postgres_database):
    async with postgres_session(postgres_database, TABLES) as db:
        _, sub, _, api = await seed(db)
        limited_engine = create_async_engine(postgres_database, pool_size=1, max_overflow=0, pool_timeout=0.15)
        try:
            async with AsyncSession(limited_engine) as caller_db:
                await caller_db.execute(text('SELECT 1'))  # Occupy its ONLY pool slot.
                async with asyncio.timeout(2):
                    assert await reset_subscription_devices(api, caller_db, sub, 1000)
                assert caller_db.in_transaction()
                assert await caller_db.scalar(text('SELECT 1')) == 1
        finally:
            await limited_engine.dispose()


@pytest.mark.asyncio
async def test_uncommitted_new_shared_subscription_keeps_legacy_reset_without_commit(postgres_database):
    async with postgres_session(postgres_database, TABLES) as db:
        user, _, _, api = await seed(db)
        pending = Subscription(
            user_id=user.id,
            status='active',
            is_trial=False,
            traffic_mode='shared',
            remnawave_id=3000,
            remnawave_short_id='pending-test',
            end_date=datetime.now(UTC) + timedelta(days=1),
        )
        db.add(pending)
        await db.flush()
        api.devices[3000] = {HWID}
        assert await reset_subscription_devices(api, db, pending, 3000)
        assert api.resets == [3000]
        async with AsyncSession(db.bind) as observer:
            assert await observer.scalar(select(Subscription.id).where(Subscription.id == pending.id)) is None
        await db.rollback()
