"""Read-only delivery with actual ownership rows and a controlled panel boundary."""

import asyncio
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest

from app.database.models import Base, Subscription, SubscriptionBsAccount, User
from app.external.remnawave_api import RemnaWaveAPIError, UserStatus
from app.services.bs_subscription_delivery import SubscriptionUnavailable, deliver_subscription
from app.services.bs_traffic_policy import bs_ownership_marker
from tests.fixtures.postgres_db import postgres_session


pytestmark = pytest.mark.postgres
TABLES = list(Base.metadata.sorted_tables)
MAIN = 'vless://main-key@ordinary.example:443#Ordinary'
BS = 'vless://bs-key@bs.example:443#BS'
DEVICE_HEADERS = {'User-Agent': 'Happ/4.2.1', 'X-HWID': 'device-123456', 'Authorization': 'never-forward'}


class FakePanel:
    def __init__(self, subscription, account):
        future = datetime.now(UTC) + timedelta(days=7)
        self.users = {
            1000: SimpleNamespace(
                id=1000,
                short_uuid='primary-short',
                status=UserStatus.ACTIVE,
                expire_at=future,
                traffic_limit_bytes=0,
                used_traffic_bytes=42,
                vless_uuid='main-key',
            ),
            2000: SimpleNamespace(
                id=2000,
                short_uuid='secondary-short',
                username=account.panel_username,
                description=bs_ownership_marker(account),
                status=UserStatus.ACTIVE,
                expire_at=future,
                traffic_limit_bytes=1000,
                used_traffic_bytes=42,
                vless_uuid='bs-key',
            ),
        }
        self.responses = {
            'primary-short': (200, MAIN, {'subscription-userinfo': 'download=42; total=0'}),
            'secondary-short': (200, BS, {'subscription-userinfo': 'download=42; total=1000'}),
        }
        self.read_ids = []
        self.requests = []
        self.error_on_secondary = None

    async def get_user_by_id(self, panel_id):
        self.read_ids.append(panel_id)
        if panel_id == 2000 and self.error_on_secondary:
            raise self.error_on_secondary
        return self.users.get(panel_id)

    async def get_public_subscription_response(self, short_uuid, *, headers):
        self.requests.append((short_uuid, headers))
        return self.responses[short_uuid]


async def seed(db):
    user = User(telegram_id=12345, first_name='Test', status='active', balance_kopeks=12345, remnawave_id=1000)
    db.add(user)
    await db.flush()
    subscription = Subscription(
        user_id=user.id,
        status='active',
        is_trial=False,
        traffic_mode='split',
        end_date=datetime.now(UTC) + timedelta(days=7),
        remnawave_id=1000,
        remnawave_short_uuid='primary-short',
        remnawave_short_id='main-test-id',
        subscription_url='https://example.test/existing-link',
    )
    db.add(subscription)
    await db.flush()
    account = SubscriptionBsAccount(
        subscription_id=subscription.id,
        panel_username='test_bs',
        provisioning_key='a' * 32,
        remnawave_id=2000,
        remnawave_short_uuid='secondary-short',
        base_traffic_limit_gb=100,
        migration_state='active',
        panel_status='ACTIVE',
    )
    db.add(account)
    await db.commit()
    return user, subscription, account, FakePanel(subscription, account)


@pytest.mark.asyncio
async def test_active_split_delivers_both_without_changing_database(postgres_database):
    async with postgres_session(postgres_database, TABLES) as db:
        user, sub, account, api = await seed(db)
        result = await deliver_subscription(db, api, sub.id, request_headers=DEVICE_HEADERS)
        assert result.bs_included and result.document.body.splitlines() == [MAIN, BS]
        assert [request[0] for request in api.requests] == ['primary-short', 'secondary-short']
        assert all(headers == {'user-agent': 'Happ/4.2.1', 'x-hwid': 'device-123456'} for _, headers in api.requests)
        assert result.document.headers['subscription-userinfo'] == 'download=42; total=0'
        assert not db.dirty and not db.new and not db.deleted
        assert user.balance_kopeks == 12345 and sub.traffic_mode == 'split'
        assert sub.subscription_url == 'https://example.test/existing-link'
        assert account.panel_status == 'ACTIVE'


@pytest.mark.parametrize('flag', ['x-hwid-limit', 'x-hwid-not-supported', 'x-hwid-max-devices-reached'])
@pytest.mark.asyncio
async def test_primary_hwid_refusal_never_contacts_bs(postgres_database, flag):
    async with postgres_session(postgres_database, TABLES) as db:
        _, sub, _, api = await seed(db)
        api.responses['primary-short'] = (200, MAIN, {flag: 'true', 'x-hwid-active': 'true'})
        result = await deliver_subscription(db, api, sub.id, request_headers=DEVICE_HEADERS)
        assert not result.bs_included and result.reason == 'primary_denied'
        assert api.read_ids == [1000] and len(api.requests) == 1
        assert result.document.body == MAIN


@pytest.mark.parametrize('state', ['LIMITED', 'DISABLED', 'EXPIRED', 'past-date', 'used-quota'])
@pytest.mark.parametrize('primary', [False, True])
@pytest.mark.asyncio
async def test_inactive_panel_identity_cannot_add_bs(postgres_database, state, primary):
    async with postgres_session(postgres_database, TABLES) as db:
        _, sub, _, api = await seed(db)
        target = api.users[1000 if primary else 2000]
        if state == 'past-date':
            target.expire_at = datetime.now(UTC) - timedelta(seconds=1)
        elif state == 'used-quota':
            target.traffic_limit_bytes = target.used_traffic_bytes
        else:
            target.status = UserStatus(state)
        result = await deliver_subscription(db, api, sub.id, request_headers=DEVICE_HEADERS)
        assert result.reason == ('primary_inactive' if primary else 'secondary_inactive')
        assert result.document.body == MAIN and len(api.requests) == 1


@pytest.mark.parametrize('mode', ['trial', 'shared', 'pending', 'prepared', 'missing-bs'])
@pytest.mark.asyncio
async def test_trial_shared_and_unprepared_subscriptions_fetch_primary_only(postgres_database, mode):
    async with postgres_session(postgres_database, TABLES) as db:
        _, sub, account, api = await seed(db)
        if mode == 'trial':
            sub.is_trial, sub.status = True, 'trial'
        elif mode == 'shared':
            sub.traffic_mode = 'shared'
        elif mode == 'missing-bs':
            await db.delete(account)
        else:
            account.migration_state = mode
        await db.commit()
        result = await deliver_subscription(db, api, sub.id, request_headers=DEVICE_HEADERS)
        assert not result.bs_included and len(api.requests) == 1
        assert api.read_ids == [1000]


@pytest.mark.parametrize(
    'change', ['blocked', 'deleted', 'expired', 'disabled', 'past-date', 'missing-id', 'missing-key']
)
@pytest.mark.asyncio
async def test_local_denial_makes_no_panel_request(postgres_database, change):
    async with postgres_session(postgres_database, TABLES) as db:
        user, sub, _, api = await seed(db)
        if change in ('blocked', 'deleted'):
            user.status = change
        elif change == 'past-date':
            sub.end_date = datetime.now(UTC) - timedelta(seconds=1)
        elif change == 'missing-id':
            sub.remnawave_id = None
        elif change == 'missing-key':
            sub.remnawave_short_uuid = None
        else:
            sub.status = change
        await db.commit()
        with pytest.raises(SubscriptionUnavailable):
            await deliver_subscription(db, api, sub.id, request_headers=DEVICE_HEADERS)
        assert api.read_ids == [] and api.requests == []


@pytest.mark.parametrize('field', ['id', 'short_uuid'])
@pytest.mark.asyncio
async def test_wrong_primary_panel_identity_never_receives_hwid(postgres_database, field):
    async with postgres_session(postgres_database, TABLES) as db:
        _, sub, _, api = await seed(db)
        setattr(api.users[1000], field, 3333 if field == 'id' else 'someone-else')
        with pytest.raises(SubscriptionUnavailable):
            await deliver_subscription(db, api, sub.id, request_headers=DEVICE_HEADERS)
        assert api.requests == []


@pytest.mark.parametrize('field', ['id', 'short_uuid', 'username', 'description'])
@pytest.mark.asyncio
async def test_wrong_secondary_panel_identity_never_receives_hwid(postgres_database, field):
    async with postgres_session(postgres_database, TABLES) as db:
        _, sub, _, api = await seed(db)
        setattr(api.users[2000], field, 3333 if field == 'id' else 'someone-else')
        result = await deliver_subscription(db, api, sub.id, request_headers=DEVICE_HEADERS)
        assert not result.bs_included and result.reason == 'secondary_identity_mismatch'
        assert len(api.requests) == 1


@pytest.mark.parametrize('holder', ['user', 'subscription-id', 'subscription-short'])
@pytest.mark.asyncio
async def test_secondary_reserved_as_another_primary_cannot_be_delivered(postgres_database, holder):
    async with postgres_session(postgres_database, TABLES) as db:
        _, sub, _, api = await seed(db)
        other = User(telegram_id=54321, first_name='Other', status='active')
        if holder == 'user':
            other.remnawave_id = 2000
        db.add(other)
        await db.flush()
        if holder != 'user':
            db.add(
                Subscription(
                    user_id=other.id,
                    end_date=datetime.now(UTC) + timedelta(days=1),
                    remnawave_id=2000 if holder == 'subscription-id' else 3000,
                    remnawave_short_uuid='secondary-short' if holder == 'subscription-short' else 'other-short',
                    remnawave_short_id='other-test-id',
                )
            )
        await db.commit()
        result = await deliver_subscription(db, api, sub.id, request_headers=DEVICE_HEADERS)
        assert result.reason == 'secondary_identity_mismatch' and len(api.requests) == 1


@pytest.mark.parametrize('error', [TimeoutError(), RemnaWaveAPIError('unavailable')])
@pytest.mark.asyncio
async def test_secondary_failure_preserves_ordinary_access(postgres_database, error):
    async with postgres_session(postgres_database, TABLES) as db:
        _, sub, _, api = await seed(db)
        api.error_on_secondary = error
        result = await deliver_subscription(db, api, sub.id, request_headers=DEVICE_HEADERS)
        assert result.reason == 'secondary_unavailable' and result.document.body == MAIN


@pytest.mark.asyncio
async def test_cancellation_is_propagated(postgres_database):
    async with postgres_session(postgres_database, TABLES) as db:
        _, sub, _, api = await seed(db)
        api.error_on_secondary = asyncio.CancelledError()
        with pytest.raises(asyncio.CancelledError):
            await deliver_subscription(db, api, sub.id, request_headers=DEVICE_HEADERS)


@pytest.mark.parametrize('primary', [False, True])
@pytest.mark.asyncio
async def test_http_200_error_remark_without_denial_header_cannot_add_bs(postgres_database, primary):
    async with postgres_session(postgres_database, TABLES) as db:
        _, sub, _, api = await seed(db)
        key = 'primary-short' if primary else 'secondary-short'
        api.responses[key] = (200, 'vless://00000000-0000-0000-0000-000000000000@0.0.0.0:443#Denied', {})
        result = await deliver_subscription(db, api, sub.id, request_headers=DEVICE_HEADERS)
        assert not result.bs_included
        assert result.reason == ('primary_not_configuration' if primary else 'secondary_not_configuration')
        if primary:
            assert len(api.requests) == 1 and api.read_ids == [1000]
        else:
            assert result.document.body == MAIN


@pytest.mark.asyncio
async def test_primary_reserved_as_bs_fails_before_panel_access(postgres_database):
    async with postgres_session(postgres_database, TABLES) as db:
        _, sub, account, api = await seed(db)
        account.remnawave_id = 1000
        await db.commit()
        with pytest.raises(SubscriptionUnavailable):
            await deliver_subscription(db, api, sub.id, request_headers=DEVICE_HEADERS)
        assert api.read_ids == [] and api.requests == []


@pytest.mark.asyncio
async def test_dirty_caller_transaction_cannot_be_autoflushed_by_delivery(postgres_database):
    async with postgres_session(postgres_database, TABLES) as db:
        user, sub, _, api = await seed(db)
        user.balance_kopeks = 99999
        with pytest.raises(SubscriptionUnavailable, match='clean unit of work'):
            await deliver_subscription(db, api, sub.id, request_headers=DEVICE_HEADERS)
        assert user in db.dirty and api.read_ids == []


@pytest.mark.asyncio
async def test_missing_secondary_short_uuid_keeps_ordinary_access(postgres_database):
    async with postgres_session(postgres_database, TABLES) as db:
        _, sub, account, api = await seed(db)
        account.remnawave_short_uuid = None
        await db.commit()
        result = await deliver_subscription(db, api, sub.id, request_headers=DEVICE_HEADERS)
        assert result.reason == 'secondary_unprepared' and api.read_ids == [1000]
