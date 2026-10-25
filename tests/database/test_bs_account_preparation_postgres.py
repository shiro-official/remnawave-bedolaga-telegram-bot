"""BS preparation uses real PostgreSQL, durable intent, and a fake panel boundary."""

import asyncio
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
from sqlalchemy import func, select, text

from app.config import settings
from app.database.models import Base, Subscription, SubscriptionBsAccount, Tariff, User
from app.external.remnawave_api import UserStatus
from app.services.backup_service import backup_service
from app.services.bs_subscription_service import prepare_bs_account
from app.services.bs_traffic_policy import BsAccountIdentityError, BsTrafficConfigurationError
from app.services.panel_sync import push_subscription
from app.services.panel_sync.identity import (
    PanelAccountOwnedByAnotherUser,
    PanelIdentity,
    find_foreign_panel_owner,
    link_subscription_panel_identity,
    panel_id_is_free_for,
    user_panel_id_is_free_for,
)
from tests.fixtures.postgres_db import postgres_session, postgres_sessions


pytestmark = pytest.mark.postgres
TABLES = list(Base.metadata.sorted_tables)
ORDINARY = '00000000-0000-0000-0000-000000000001'
BS = '00000000-0000-0000-0000-000000000002'


class FakePanel:
    def __init__(self):
        self.users = {}
        self.created = []
        self.updated = []
        self.overlap = False
        self.lose_create_reply = False
        self.read_error = False
        self.ignore_update = False

    async def get_internal_squad_by_uuid(self, squad_id):
        inbound = ORDINARY if self.overlap else squad_id
        return SimpleNamespace(inbounds=[SimpleNamespace(uuid=inbound)])

    async def get_user_identity(self, panel_id):
        return await self.get_user_by_id(panel_id)

    async def get_user_identity_by_username(self, username):
        return await self.get_user_by_username(username)

    async def get_user_by_id(self, panel_id):
        if self.read_error:
            raise TimeoutError('panel unavailable')
        return self.users.get(panel_id)

    async def get_user_by_username(self, username):
        if self.read_error:
            raise TimeoutError('panel unavailable')
        return next((u for u in self.users.values() if u.username == username), None)

    async def create_user(self, *, enrich_happ=True, **data):
        assert not any(u.username == data['username'] for u in self.users.values())
        self.created.append(data)
        result = SimpleNamespace(
            id=2000,
            short_uuid='secondary-short',
            used_traffic_bytes=0,
            expire_at=data['expire_at'],
            **{k: v for k, v in data.items() if k != 'expire_at'},
        )
        self.users[result.id] = result
        if self.lose_create_reply:
            self.lose_create_reply = False
            raise TimeoutError('response lost after successful create')
        return result

    async def update_user(self, *, enrich_happ=True, **data):
        self.updated.append(data)
        user = self.users[data['user_id']]
        if self.ignore_update:
            return user
        for key, value in data.items():
            if key != 'user_id':
                setattr(user, key, value)
        return user


async def _seed(db, *, trial=False, enabled=True):
    tariff = Tariff(
        name='BS plan',
        traffic_limit_gb=0,
        bs_traffic_enabled=enabled,
        bs_traffic_limit_gb=100,
        bs_squad_uuids=[BS],
        allowed_squads=[ORDINARY, BS],
        period_prices={'30': 44900},
    )
    user = User(
        telegram_id=12345, first_name='Test', language='ru', status='active', remnawave_id=1000, balance_kopeks=12345
    )
    db.add_all([tariff, user])
    await db.flush()
    subscription = Subscription(
        user_id=user.id,
        tariff_id=tariff.id,
        is_trial=trial,
        status='trial' if trial else 'active',
        remnawave_id=1000,
        remnawave_short_id='primary-key',
        subscription_url='https://example.test/primary',
        traffic_limit_gb=50 if trial else 0,
        traffic_used_gb=37.5,
        connected_squads=[ORDINARY, BS],
        end_date=datetime.now(UTC) + timedelta(days=30),
    )
    db.add(subscription)
    await db.commit()
    return user, subscription


@pytest.fixture(autouse=True)
def single_period_tariffs(monkeypatch):
    monkeypatch.setattr(settings, 'SALES_MODE', 'tariffs')
    monkeypatch.setattr(settings, 'MULTI_TARIFF_ENABLED', False)


@pytest.mark.asyncio
async def test_preparation_is_repeatable_and_never_changes_primary(postgres_database):
    async with postgres_session(postgres_database, TABLES) as db:
        user, subscription = await _seed(db)
        original_expiry = subscription.end_date
        panel = FakePanel()
        first = await prepare_bs_account(db, panel, subscription.id)
        second = await prepare_bs_account(db, panel, subscription.id)
        assert first.id == second.id
        assert len(panel.created) == 1
        assert second.remnawave_id == 2000 and second.migration_state == 'prepared'
        assert second.panel_status == 'DISABLED'
        assert panel.created[0]['traffic_limit_bytes'] == 100 * 1024**3
        assert panel.created[0]['active_internal_squads'] == [BS]
        assert panel.created[0]['status'] is UserStatus.DISABLED
        assert panel.created[0]['telegram_id'] is None and panel.created[0]['email'] is None
        assert all(update['user_id'] == 2000 for update in panel.updated)
        await db.refresh(subscription)
        await db.refresh(user)
        assert subscription.traffic_mode == 'shared'
        assert subscription.remnawave_id == user.remnawave_id == 1000
        assert subscription.traffic_limit_gb == 0 and subscription.traffic_used_gb == 37.5
        assert subscription.connected_squads == [ORDINARY, BS]
        assert subscription.subscription_url == 'https://example.test/primary'
        assert subscription.end_date == original_expiry
        assert user.balance_kopeks == 12345


@pytest.mark.asyncio
async def test_lost_create_response_recovers_persisted_intent_without_duplicate(postgres_database):
    async with postgres_session(postgres_database, TABLES) as db:
        _, sub = await _seed(db)
        sub_id = sub.id
        panel = FakePanel()
        panel.lose_create_reply = True
        with pytest.raises(TimeoutError):
            await prepare_bs_account(db, panel, sub_id)
        intent = await db.scalar(select(SubscriptionBsAccount))
        assert intent is not None and intent.remnawave_id is None and intent.migration_state == 'pending'
        key = intent.provisioning_key
        await db.commit()
        recovered = await prepare_bs_account(db, panel, sub_id)
        assert recovered.provisioning_key == key and recovered.remnawave_id == 2000
        assert len(panel.created) == 1 and len(panel.users) == 1


@pytest.mark.asyncio
async def test_inbound_overlap_blocks_writes_and_intent_creation(postgres_database):
    async with postgres_session(postgres_database, TABLES) as db:
        _, sub = await _seed(db)
        panel = FakePanel()
        panel.overlap = True
        with pytest.raises(BsTrafficConfigurationError, match='share inbounds'):
            await prepare_bs_account(db, panel, sub.id)
        assert not panel.created and not panel.updated
        assert await db.scalar(select(func.count()).select_from(SubscriptionBsAccount)) == 0


@pytest.mark.asyncio
@pytest.mark.parametrize('trial,enabled', [(True, True), (False, False)])
async def test_trial_and_disabled_tariff_do_not_get_secondary(postgres_database, trial, enabled):
    async with postgres_session(postgres_database, TABLES) as db:
        _, sub = await _seed(db, trial=trial, enabled=enabled)
        panel = FakePanel()
        assert await prepare_bs_account(db, panel, sub.id) is None
        assert not panel.created
        assert await db.scalar(select(func.count()).select_from(SubscriptionBsAccount)) == 0


@pytest.mark.asyncio
async def test_conflicting_username_is_never_adopted_or_modified(postgres_database):
    async with postgres_session(postgres_database, TABLES) as db:
        _, sub = await _seed(db)
        panel = FakePanel()
        panel.read_error = True
        sub_id = sub.id
        with pytest.raises(TimeoutError):
            await prepare_bs_account(db, panel, sub_id)
        intent = await db.scalar(select(SubscriptionBsAccount))
        panel.users[1000] = SimpleNamespace(
            id=1000,
            username=intent.panel_username,
            description='Unrelated primary',
            status=UserStatus.ACTIVE,
        )
        await db.commit()
        panel.read_error = False
        with pytest.raises(BsAccountIdentityError):
            await prepare_bs_account(db, panel, sub_id)
        assert not panel.created and not panel.updated


@pytest.mark.asyncio
async def test_primary_id_collision_blocks_write_even_with_matching_marker(postgres_database):
    async with postgres_session(postgres_database, TABLES) as db:
        _, sub = await _seed(db)
        panel = FakePanel()
        panel.read_error = True
        sub_id = sub.id
        with pytest.raises(TimeoutError):
            await prepare_bs_account(db, panel, sub_id)
        intent = await db.scalar(select(SubscriptionBsAccount))
        from app.services.bs_traffic_policy import bs_ownership_marker

        panel.users[1000] = SimpleNamespace(
            id=1000,
            username=intent.panel_username,
            description=bs_ownership_marker(intent),
            status=UserStatus.DISABLED,
        )
        await db.commit()
        panel.read_error = False
        with pytest.raises(BsAccountIdentityError, match='primary account'):
            await prepare_bs_account(db, panel, sub_id)
        assert not panel.created and not panel.updated


def test_bs_account_is_in_backup_after_parent_subscription():
    models = backup_service._get_models_for_backup(True)
    assert SubscriptionBsAccount in models
    assert models.index(Subscription) < models.index(SubscriptionBsAccount)


@pytest.mark.asyncio
async def test_secondary_cannot_be_written_or_adopted_as_primary(postgres_database):
    async with postgres_session(postgres_database, TABLES) as db:
        user, sub = await _seed(db)
        panel = FakePanel()
        account = await prepare_bs_account(db, panel, sub.id)
        bs_id = account.remnawave_id
        owner = await find_foreign_panel_owner(db, user, sub, bs_id, multi_tariff=False)
        assert owner is not None and owner.account_role == 'bs'
        assert owner.subscription_id == sub.id
        assert not await panel_id_is_free_for(db, sub, bs_id)
        assert not await user_panel_id_is_free_for(db, user, bs_id)
        sub.remnawave_id = None
        assert not await link_subscription_panel_identity(db, sub, bs_id)
        # Even an explicitly supplied, stale primary identity must be rejected.
        with pytest.raises(PanelAccountOwnedByAnotherUser) as error:
            await push_subscription(panel, user, sub, db=db, multi_tariff=False, identity=PanelIdentity(known_id=bs_id))
        assert error.value.owner_account_role == 'bs'
        assert not panel.updated


@pytest.mark.asyncio
async def test_secondary_reservation_beats_corrupt_stored_primary_pointer(postgres_database):
    async with postgres_session(postgres_database, TABLES) as db:
        user, sub = await _seed(db)
        panel = FakePanel()
        account = await prepare_bs_account(db, panel, sub.id)
        sub.remnawave_id = account.remnawave_id
        owner = await find_foreign_panel_owner(db, user, sub, account.remnawave_id, multi_tariff=False)
        assert owner is not None and owner.account_role == 'bs'


@pytest.mark.asyncio
async def test_preparation_refuses_enabled_candidate_without_disabling_it(postgres_database):
    async with postgres_session(postgres_database, TABLES) as db:
        _, sub = await _seed(db)
        sub_id = sub.id
        panel = FakePanel()
        account = await prepare_bs_account(db, panel, sub_id)
        panel.users[account.remnawave_id].status = UserStatus.ACTIVE
        with pytest.raises(BsAccountIdentityError, match='already enabled'):
            await prepare_bs_account(db, panel, sub_id)
        assert panel.users[2000].status is UserStatus.ACTIVE
        assert not panel.updated


@pytest.mark.asyncio
async def test_preparation_keeps_personal_bs_limit(postgres_database):
    async with postgres_session(postgres_database, TABLES) as db:
        _, sub = await _seed(db)
        panel = FakePanel()
        account = await prepare_bs_account(db, panel, sub.id)
        account.traffic_limit_override_gb = 200
        await db.commit()
        await prepare_bs_account(db, panel, sub.id)
        assert panel.updated[-1]['traffic_limit_bytes'] == 200 * 1024**3


@pytest.mark.asyncio
async def test_concurrent_preparation_keeps_one_persisted_identity(postgres_database):
    async with postgres_sessions(postgres_database, TABLES) as (first, second):
        _, sub = await _seed(first)
        panel = FakePanel()
        accounts = await asyncio.gather(
            prepare_bs_account(first, panel, sub.id), prepare_bs_account(second, panel, sub.id)
        )
        assert accounts[0].id == accounts[1].id
        assert accounts[0].remnawave_id == accounts[1].remnawave_id == 2000
        assert len(panel.created) == 1
        assert await first.scalar(select(func.count()).select_from(SubscriptionBsAccount)) == 1


@pytest.mark.asyncio
async def test_preflight_error_releases_primary_lock(postgres_database):
    async with postgres_sessions(postgres_database, TABLES) as (first, second):
        _, sub = await _seed(first)
        sub_id = sub.id
        panel = FakePanel()
        panel.overlap = True
        with pytest.raises(BsTrafficConfigurationError):
            await prepare_bs_account(first, panel, sub_id)
        await second.execute(text("SET LOCAL lock_timeout = '100ms'"))
        assert await second.scalar(select(Subscription.id).where(Subscription.id == sub_id).with_for_update()) == sub_id


@pytest.mark.asyncio
async def test_unconfirmed_panel_quota_leaves_a_retryable_intent(postgres_database):
    async with postgres_session(postgres_database, TABLES) as db:
        _, sub = await _seed(db)
        sub_id = sub.id
        panel = FakePanel()
        account = await prepare_bs_account(db, panel, sub_id)
        account.traffic_limit_override_gb = 200
        await db.commit()
        panel.ignore_update = True
        with pytest.raises(BsAccountIdentityError, match='quota'):
            await prepare_bs_account(db, panel, sub_id)
        account = await db.scalar(select(SubscriptionBsAccount))
        assert account.migration_state == 'pending'
        assert account.remnawave_id == 2000 and account.traffic_limit_override_gb == 200
        await db.commit()
        panel.ignore_update = False
        recovered = await prepare_bs_account(db, panel, sub_id)
        assert recovered.migration_state == 'prepared'
        assert len(panel.created) == 1
