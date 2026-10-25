import hashlib
from types import SimpleNamespace

import pytest

from app.config import settings
from app.services.bs_public_link_tokens import (
    apply_panel_subscription_links,
    hash_public_token,
    new_public_token,
    public_subscription_base_url,
    public_subscription_url,
    public_token_from_url,
    redact_public_subscription_path,
)


@pytest.mark.parametrize('token', ['', '1', 'x' * 42, 'x' * 44, 'x' * 42 + '/', 'x' * 42 + '☃', '../secret'])
def test_invalid_capability_is_not_an_identifier(token):
    assert hash_public_token(token) is None


def test_generated_capabilities_are_random_and_only_their_digests_are_lookup_keys(monkeypatch):
    monkeypatch.setattr(settings, 'BS_SUBSCRIPTION_PUBLIC_BASE_URL', 'https://vpn.example/')
    first, second = new_public_token(), new_public_token()
    assert first != second and len(first) == len(second) == 43
    assert hash_public_token(first) == hashlib.sha256(first.encode()).hexdigest()
    assert public_subscription_url(first) == f'https://vpn.example/s/{first}'
    assert public_token_from_url(public_subscription_url(first)) == first


@pytest.mark.parametrize(
    'origin',
    [
        '',
        'http://vpn.example',
        'https://user:pass@vpn.example',
        'https://vpn.example/s',
        'https://vpn.example?token=bad',
        'https://vpn.example#bad',
        'https://vpn.example?',
        'https://vpn.example#',
        'https://vpn.example\x00evil',
        'https://vpn.example:99999',
        'https://vpn.example\\evil',
    ],
)
def test_public_origin_must_be_explicit_and_valid(monkeypatch, origin):
    monkeypatch.setattr(settings, 'BS_SUBSCRIPTION_PUBLIC_BASE_URL', origin)
    with pytest.raises(ValueError):
        public_subscription_base_url()


@pytest.mark.parametrize('path', ['/s', '/s/abc', '/s/' + 's' * 43, '/s/abc/format/other-secret'])
def test_public_secret_path_is_redacted_even_if_no_route_matches(path):
    assert redact_public_subscription_path(path) == '/s/[redacted]'
    assert redact_public_subscription_path('/subscriptions/1') == '/subscriptions/1'


@pytest.mark.parametrize('mode', ['shared', 'split'])
def test_panel_updates_preserve_only_the_combined_url_and_its_cryptolink(mode):
    token = new_public_token()
    original = f'https://vpn.example/s/{token}'
    subscription = SimpleNamespace(traffic_mode=mode, subscription_url=original, subscription_crypto_link='old-crypto')
    apply_panel_subscription_links(subscription, 'https://panel.example/raw', 'panel-crypto')
    assert subscription.subscription_url == (original if mode == 'split' else 'https://panel.example/raw')
    assert subscription.subscription_crypto_link == ('old-crypto' if mode == 'split' else 'panel-crypto')


def test_panel_projection_can_update_identity_without_replacing_combined_link():
    from app.services.panel_sync import ADMIN_PULL, PanelSnapshot, project_onto_subscription
    from tests.services.panel_sync.test_projection import _sub

    url = f'https://vpn.example/s/{new_public_token()}'
    subscription = _sub(traffic_mode='split', subscription_url=url, subscription_crypto_link='combined-crypto')
    changed = project_onto_subscription(
        subscription,
        PanelSnapshot(
            short_uuid='rotated-panel-short',
            subscription_url='https://panel.example/raw',
            crypto_link='direct-panel-crypto',
        ),
        policy=ADMIN_PULL,
    )
    assert subscription.remnawave_short_uuid == 'rotated-panel-short'
    assert subscription.subscription_url == url and subscription.subscription_crypto_link == 'combined-crypto'
    assert 'subscription_url' not in changed and 'subscription_crypto_link' not in changed


@pytest.mark.asyncio
async def test_regular_panel_push_does_not_publish_a_direct_primary_url():
    from app.services.panel_sync import push_subscription
    from tests.services.panel_sync.test_writer import _api, _db, _panel_user, _sub, _user

    url = f'https://vpn.example/s/{new_public_token()}'
    subscription = _sub(
        traffic_mode='split', remnawave_id=42, subscription_url=url, subscription_crypto_link='combined-crypto'
    )
    api = _api(get_user_by_id=_panel_user())
    result = await push_subscription(
        api, _user(remnawave_id=42), subscription, db=_db(), multi_tariff=False, reset_devices=False
    )
    assert result.action == 'updated'
    assert subscription.subscription_url == url and subscription.subscription_crypto_link == 'combined-crypto'
