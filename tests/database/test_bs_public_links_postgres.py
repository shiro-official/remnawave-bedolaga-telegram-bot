import asyncio
import json
from contextlib import asynccontextmanager

import httpx
import pytest
from fastapi import FastAPI
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.database.models import Subscription, SubscriptionPublicLink
from app.external.remnawave_api import RemnaWaveAPIError
from app.services.backup_service import backup_service
from app.services.bs_device_policy import BsDevicePolicyError, bs_device_lock, bs_device_session
from app.services.bs_public_link_revoke import revoke_split_public_link
from app.services.bs_public_link_service import disable_public_link, prepare_public_link
from app.services.bs_public_link_tokens import hash_public_token, new_public_token, public_token_from_url
from app.services.bs_subscription_delivery import SubscriptionUnavailable, deliver_public_subscription
from app.services.bs_traffic_policy import BsAccountIdentityError
from app.webserver.bs_subscription import create_public_subscription_router
from tests.database.test_bs_subscription_delivery_postgres import DEVICE_HEADERS, TABLES, seed
from tests.fixtures.bs_public_subscription import seed_public
from tests.fixtures.postgres_db import postgres_session


pytestmark = pytest.mark.postgres


@pytest.fixture(autouse=True)
def configured_public_delivery(monkeypatch):
    monkeypatch.setattr(settings, 'BS_SUBSCRIPTION_DELIVERY_ENABLED', True)
    monkeypatch.setattr(settings, 'BS_SUBSCRIPTION_PUBLIC_BASE_URL', 'https://vpn.example')


@pytest.mark.asyncio
async def test_preparation_only_creates_a_disabled_hashed_candidate(postgres_database):
    async with postgres_session(postgres_database, TABLES) as db:
        _, sub, _, _ = await seed(db)
        original = sub.subscription_url
        prepared = await prepare_public_link(db, sub.id)
        async with AsyncSession(db.bind) as observer:
            link = await observer.scalar(select(SubscriptionPublicLink))
            stored = await observer.get(Subscription, sub.id)
            assert not link.enabled and not link.rotation_pending
            assert link.token_hash == hash_public_token(public_token_from_url(prepared.url))
            assert stored.subscription_url == original and stored.traffic_mode == 'split'
            assert prepared.url not in repr(prepared)
        second = await prepare_public_link(db, sub.id)
        assert second.url != prepared.url


@pytest.mark.asyncio
async def test_active_capability_fetches_the_pair_and_can_be_disabled(postgres_database):
    async with postgres_session(postgres_database, TABLES) as db:
        _, sub, _, _, token, api = await seed_public(db)
        result = await deliver_public_subscription(db, api, token, request_headers=DEVICE_HEADERS)
        assert result.bs_included and 'main-key' in result.document.body and 'bs-key' in result.document.body
        with pytest.raises(BsDevicePolicyError):
            await prepare_public_link(db, sub.id)
        await disable_public_link(db, sub.id)
        reads = len(api.read_ids)
        with pytest.raises(SubscriptionUnavailable):
            await deliver_public_subscription(db, api, token, request_headers=DEVICE_HEADERS)
        assert len(api.read_ids) == reads


@pytest.mark.parametrize(
    'change', ['disabled', 'pending', 'primary-binding', 'secondary-binding', 'trial', 'shared', 'owner-blocked']
)
@pytest.mark.asyncio
async def test_invalid_binding_or_access_never_fetches_panel_credentials(postgres_database, change):
    async with postgres_session(postgres_database, TABLES) as db:
        user, sub, _, link, token, api = await seed_public(db)
        if change == 'disabled':
            link.enabled = False
        elif change == 'pending':
            link.rotation_pending = True
        elif change == 'primary-binding':
            link.primary_short_uuid = 'not-primary'
        elif change == 'secondary-binding':
            link.secondary_short_uuid = 'not-secondary'
        elif change == 'trial':
            sub.is_trial = True
        elif change == 'shared':
            sub.traffic_mode = 'shared'
        else:
            user.status = 'blocked'
        await db.commit()
        with pytest.raises(SubscriptionUnavailable):
            await deliver_public_subscription(db, api, token, request_headers=DEVICE_HEADERS)
        assert api.read_ids == [] and api.requests == []


@pytest.mark.parametrize('bad', ['database-id', 'panel-short', 'unknown-valid'])
@pytest.mark.asyncio
async def test_only_the_opaque_token_is_a_public_credential(postgres_database, bad):
    async with postgres_session(postgres_database, TABLES) as db:
        _, sub, _, _, _, api = await seed_public(db)
        token = {
            'database-id': str(sub.id),
            'panel-short': sub.remnawave_short_uuid,
            'unknown-valid': new_public_token(),
        }[bad]
        with pytest.raises(SubscriptionUnavailable):
            await deliver_public_subscription(db, api, token, request_headers=DEVICE_HEADERS)
        assert api.read_ids == []


@pytest.mark.asyncio
async def test_paired_revoke_changes_both_keys_and_public_url_without_touching_payment_or_quota(postgres_database):
    async with postgres_session(postgres_database, TABLES) as db:
        user, sub, account, _, old_token, api = await seed_public(db)
        original = (user.balance_kopeks, sub.end_date, account.base_traffic_limit_gb, account.traffic_used_bytes)
        url = await revoke_split_public_link(db, api, sub.id)
        assert [item[0] for item in api.revoked] == [2000, 1000]
        new_token = public_token_from_url(url)
        assert new_token != old_token
        with pytest.raises(SubscriptionUnavailable):
            await deliver_public_subscription(db, api, old_token, request_headers=DEVICE_HEADERS)
        result = await deliver_public_subscription(db, api, new_token, request_headers=DEVICE_HEADERS)
        assert result.bs_included and 'main-key' not in result.document.body and 'bs-key' not in result.document.body
        await db.refresh(sub)
        await db.refresh(account)
        assert (
            user.balance_kopeks,
            sub.end_date,
            account.base_traffic_limit_gb,
            account.traffic_used_bytes,
        ) == original
        assert sub.subscription_url == url and sub.subscription_crypto_link is None
        assert await revoke_split_public_link(db, api, sub.id) == url  # duplicate inside cooldown
        assert len(api.revoked) == 2


@pytest.mark.parametrize('panel_id', [2000, 1000])
@pytest.mark.parametrize('failure', ['before', 'lost-reply', 'no-op', 'false-ack'])
@pytest.mark.asyncio
async def test_partial_or_lost_revoke_stays_closed_and_recovers_the_same_intent(postgres_database, panel_id, failure):
    async with postgres_session(postgres_database, TABLES) as db:
        _, sub, _, _, token, api = await seed_public(db)
        target = {
            'before': api.fail_before,
            'lost-reply': api.lose_reply,
            'no-op': api.no_op,
            'false-ack': api.fake_ack,
        }[failure]
        target.add(panel_id)
        with pytest.raises((RemnaWaveAPIError, BsAccountIdentityError)):
            await revoke_split_public_link(db, api, sub.id)
        async with AsyncSession(db.bind) as observer:
            link = await observer.scalar(select(SubscriptionPublicLink))
            assert link.rotation_pending and not link.enabled
            assert link.rotation_intent and 'main-key' not in json.dumps(link.rotation_intent)
            intent = dict(link.rotation_intent)
        with pytest.raises(SubscriptionUnavailable):
            await deliver_public_subscription(db, api, token, request_headers=DEVICE_HEADERS)
        target.clear()
        count = len([item for item in api.revoked if item[0] == panel_id])
        url = await revoke_split_public_link(db, api, sub.id)
        assert (
            await deliver_public_subscription(db, api, public_token_from_url(url), request_headers=DEVICE_HEADERS)
        ).bs_included
        assert api.users[1000].short_uuid == intent['primary_target']
        assert api.users[2000].short_uuid == intent['secondary_target']
        if failure == 'lost-reply':
            assert len([item for item in api.revoked if item[0] == panel_id]) == count


@pytest.mark.asyncio
async def test_public_link_is_in_backup_and_removed_with_its_parent(postgres_database):
    async with postgres_session(postgres_database, TABLES) as db:
        _, sub, _, _, _, _ = await seed_public(db)
        order = backup_service._base_backup_models
        assert order.index(Subscription) < order.index(SubscriptionPublicLink)
        await db.delete(sub)
        await db.commit()
        assert await db.scalar(select(SubscriptionPublicLink.id)) is None


@asynccontextmanager
async def public_client(db, api, monkeypatch):
    from unittest.mock import AsyncMock

    from app.utils.cache import RateLimitCache

    monkeypatch.setattr(RateLimitCache, 'is_ip_rate_limited', AsyncMock(return_value=False))
    monkeypatch.setattr(RateLimitCache, 'is_subject_rate_limited', AsyncMock(return_value=False))

    @asynccontextmanager
    async def panel():
        yield api

    app = FastAPI()
    app.include_router(
        create_public_subscription_router(
            session_factory=lambda: AsyncSession(db.bind, expire_on_commit=False),
            api_factory=panel,
        )
    )
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app), base_url='https://vpn.example') as client:
        yield client, app


@pytest.mark.parametrize('client_type', [None, 'json', 'v2ray-json'])
@pytest.mark.asyncio
async def test_actual_http_route_serves_both_accounts_with_private_headers(postgres_database, monkeypatch, client_type):
    async with postgres_session(postgres_database, TABLES) as db:
        _, _, _, _, token, api = await seed_public(db)
        async with public_client(db, api, monkeypatch) as (client, app):
            suffix = '' if client_type is None else '/' + client_type
            response = await client.get(f'/s/{token}{suffix}', headers=DEVICE_HEADERS)
            assert response.status_code == 200 and 'main-key' in response.text and 'bs-key' in response.text
            assert response.headers['cache-control'] == 'no-store, private'
            assert response.headers['referrer-policy'] == 'no-referrer'
            assert api.formats == [client_type, client_type]
            assert not any('/s/' in path for path in app.openapi()['paths'])
            assert all('authorization' not in headers for _, headers in api.requests)


@pytest.mark.parametrize('failure', ['disabled', 'rate', 'unknown-format', 'query', 'html', 'upstream'])
@pytest.mark.asyncio
async def test_http_failures_do_not_echo_the_secret_or_redirect_to_raw_panel_links(
    postgres_database, monkeypatch, failure
):
    from unittest.mock import AsyncMock

    from app.utils.cache import RateLimitCache

    async with postgres_session(postgres_database, TABLES) as db:
        _, _, _, _, token, api = await seed_public(db)
        async with public_client(db, api, monkeypatch) as (client, _):
            suffix = ''
            if failure == 'disabled':
                monkeypatch.setattr(settings, 'BS_SUBSCRIPTION_DELIVERY_ENABLED', False)
            elif failure == 'rate':
                monkeypatch.setattr(RateLimitCache, 'is_ip_rate_limited', AsyncMock(return_value=True))
            elif failure == 'unknown-format':
                suffix = '/evil-format'
            elif failure == 'query':
                suffix = '?override=raw'
            elif failure == 'html':
                api.html = True
            else:

                async def bad_read(panel_id):
                    raise RuntimeError(f'upstream failure contains secret {token}')

                api.get_user_by_id = bad_read
            response = await client.get(f'/s/{token}{suffix}', headers=DEVICE_HEADERS)
            expected = {
                'disabled': 404,
                'rate': 429,
                'unknown-format': 404,
                'query': 404,
                'html': 406,
                'upstream': 503,
            }[failure]
            assert response.status_code == expected
            assert token not in response.text and 'location' not in response.headers
            assert response.headers['cache-control'] == 'no-store, private'
            if failure in ('disabled', 'rate', 'unknown-format', 'query'):
                assert api.read_ids == []


@pytest.mark.asyncio
async def test_public_capability_is_rechecked_after_waiting_for_the_mutation_lock(postgres_database, monkeypatch):
    import app.services.bs_subscription_delivery as delivery

    async with postgres_session(postgres_database, TABLES) as db:
        _, sub, _, _, token, api = await seed_public(db)
        resolved = asyncio.Event()

        @asynccontextmanager
        async def observed_lock(session, subscription_id):
            resolved.set()  # The preliminary token lookup has completed.
            async with bs_device_lock(session, subscription_id) as locked:
                yield locked

        monkeypatch.setattr(delivery, 'bs_device_lock', observed_lock)
        async with bs_device_lock(db, sub.id):
            request = asyncio.create_task(deliver_public_subscription(db, api, token, request_headers=DEVICE_HEADERS))
            await asyncio.wait_for(resolved.wait(), 2)
            async with bs_device_session(db) as writer:
                link = await writer.scalar(select(SubscriptionPublicLink))
                link.enabled = False
                await writer.commit()
        with pytest.raises(SubscriptionUnavailable):
            await asyncio.wait_for(request, 2)
        assert api.read_ids == []


@pytest.mark.asyncio
async def test_revoke_entry_used_by_bot_and_cabinet_dispatches_the_pair_and_refreshes_url(
    postgres_database, monkeypatch
):
    from app.services.subscription_service import SubscriptionService

    async with postgres_session(postgres_database, TABLES) as db:
        _, sub, _, _, token, api = await seed_public(db)

        @asynccontextmanager
        async def panel():
            yield api

        service = SubscriptionService()
        monkeypatch.setattr(service, 'get_api_client', panel)
        url = await service.revoke_subscription(db, sub)
        assert url and sub.subscription_url == url and public_token_from_url(url) != token
        assert [item[0] for item in api.revoked] == [2000, 1000]


@pytest.mark.parametrize('problem', ['foreign-secondary', 'feature-off', 'dirty-caller'])
@pytest.mark.asyncio
async def test_unapproved_pair_state_cannot_start_key_rotation(postgres_database, monkeypatch, problem):
    async with postgres_session(postgres_database, TABLES) as db:
        user, sub, _, _, _, api = await seed_public(db)
        if problem == 'foreign-secondary':
            api.users[2000].description = 'a different account'
        elif problem == 'feature-off':
            monkeypatch.setattr(settings, 'BS_SUBSCRIPTION_DELIVERY_ENABLED', False)
        else:
            user.balance_kopeks = 99999
        with pytest.raises((BsDevicePolicyError, BsAccountIdentityError)):
            await revoke_split_public_link(db, api, sub.id)
        assert api.revoked == []
        async with bs_device_session(db) as observer:
            link = await observer.scalar(select(SubscriptionPublicLink))
            assert link.enabled and not link.rotation_pending


@pytest.mark.asyncio
async def test_happ_mode_encrypts_only_the_new_combined_link(postgres_database, monkeypatch):
    monkeypatch.setattr(settings, 'CONNECT_BUTTON_MODE', 'happ_cryptolink')
    async with postgres_session(postgres_database, TABLES) as db:
        _, sub, _, _, _, api = await seed_public(db)
        url = await revoke_split_public_link(db, api, sub.id)
        await db.refresh(sub)
        assert api.encrypted == [url]
        assert sub.subscription_crypto_link == 'happ://crypt4/combined-new'


@pytest.mark.parametrize('reason', ['unknown', 'disabled', 'blocked'])
@pytest.mark.asyncio
async def test_capability_authentication_precedes_even_api_client_initialization(postgres_database, reason):
    async with postgres_session(postgres_database, TABLES) as db:
        user, _, _, link, token, _ = await seed_public(db)
        if reason == 'unknown':
            token = new_public_token()
        elif reason == 'disabled':
            link.enabled = False
        else:
            user.status = 'blocked'
        await db.commit()
        opened = []

        @asynccontextmanager
        async def unavailable_api():
            opened.append(True)
            raise RuntimeError('Panel client configuration missing')
            yield  # pragma: no cover - shape of an async context manager

        with pytest.raises(SubscriptionUnavailable):
            await deliver_public_subscription(
                db, None, token, request_headers=DEVICE_HEADERS, api_factory=unavailable_api
            )
        assert opened == []
