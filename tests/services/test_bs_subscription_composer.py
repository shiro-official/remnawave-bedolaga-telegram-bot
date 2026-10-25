"""Generated subscription documents retain credentials, routing, and admission."""

import base64
import copy
import json
from types import SimpleNamespace

import pytest
import yaml

from app.services.bs_subscription_composer import (
    MAX_SUBSCRIPTION_BYTES,
    SubscriptionDocument,
    compose_subscriptions,
    contains_account_credentials,
    forwarded_device_headers,
)


MAIN_LINK = 'vless://ordinary-key@ordinary.example:443?security=reality&pbk=main#Обычный'
BS_LINK = 'vless://bs-key@bs.example:443?security=reality&pbk=bs#БС'


def document(body=MAIN_LINK, **headers):
    return SubscriptionDocument(
        body, {'subscription-userinfo': 'upload=0; download=12; total=0; expire=4102444800', **headers}
    )


def profile(key='primary', address='ordinary.example'):
    return {
        'remarks': 'Server',
        'dns': {'servers': ['1.1.1.1']},
        'inbounds': [{'tag': 'socks', 'protocol': 'socks', 'port': 10808}],
        'outbounds': [
            {
                'tag': 'proxy',
                'protocol': 'vless',
                'settings': {'vnext': [{'address': address, 'users': [{'id': key}]}]},
                'streamSettings': {'security': 'reality', 'realitySettings': {'publicKey': key}},
            },
            {'tag': 'direct', 'protocol': 'freedom'},
        ],
        'routing': {'rules': [{'type': 'field', 'domain': ['example.com'], 'outboundTag': 'proxy'}]},
    }


def clash(name='Server', credential='primary'):
    return {
        'mixed-port': 7890,
        'dns': {'enable': True, 'nameserver': ['1.1.1.1']},
        'proxies': [{'name': name, 'type': 'trojan', 'server': 'server.example', 'port': 443, 'password': credential}],
        'proxy-groups': [
            {'name': 'Select', 'type': 'select', 'proxies': ['Auto', name, 'DIRECT']},
            {'name': 'Auto', 'type': 'url-test', 'url': 'https://example.com/test', 'proxies': [name]},
        ],
        'rules': ['MATCH,Select'],
    }


@pytest.mark.parametrize('primary_encoded', [False, True])
@pytest.mark.parametrize('secondary_encoded', [False, True])
def test_uri_and_base64_preserve_keys_and_primary_encoding(primary_encoded, secondary_encoded):
    first = base64.b64encode(MAIN_LINK.encode()).decode() if primary_encoded else MAIN_LINK
    second = base64.b64encode(BS_LINK.encode()).decode().rstrip('=') if secondary_encoded else BS_LINK
    result = compose_subscriptions(document(first), document(second))
    assert result.bs_included and result.reason == 'combined'
    body = base64.b64decode(result.document.body).decode() if primary_encoded else result.document.body
    assert body.splitlines() == [MAIN_LINK, BS_LINK]
    assert result.document.headers['subscription-userinfo'] == document().headers['subscription-userinfo']


def test_duplicate_identical_links_are_not_repeated():
    result = compose_subscriptions(document(MAIN_LINK), document(f'{MAIN_LINK}\n{BS_LINK}'))
    assert result.document.body.splitlines() == [MAIN_LINK, BS_LINK]


@pytest.mark.parametrize('array', [False, True])
def test_xray_full_profiles_keep_private_keys_and_internal_tags(array):
    first, second = profile(), profile('bs', 'bs.example')
    body = json.dumps([first] if array else first)
    result = compose_subscriptions(document(body), document(json.dumps([second])))
    assert result.bs_included
    assert json.loads(result.document.body) == [first, second]
    assert result.document.headers['content-type'] == 'application/json; charset=utf-8'


def test_clash_groups_and_colliding_names_are_rewritten_without_touching_keys():
    first, second = clash(), clash(credential='bs')
    original = copy.deepcopy((first, second))
    result = compose_subscriptions(document(yaml.safe_dump(first)), document(yaml.safe_dump(second)))
    assert result.bs_included
    merged = yaml.safe_load(result.document.body)
    assert [proxy['name'] for proxy in merged['proxies']] == ['Server', 'Server [БС]']
    assert [proxy['password'] for proxy in merged['proxies']] == ['primary', 'bs']
    assert merged['proxy-groups'][0]['proxies'] == ['Auto', 'Server', 'DIRECT', 'Server [БС]']
    assert merged['proxy-groups'][1]['proxies'] == ['Server', 'Server [БС]']
    assert merged['dns'] == first['dns'] and merged['rules'] == first['rules']
    assert (first, second) == original


def test_clash_generated_suffix_cannot_collide_with_existing_secondary_name():
    second = clash(credential='bs')
    second['proxies'].append({**second['proxies'][0], 'name': 'Server [БС]'})
    for group in second['proxy-groups']:
        group['proxies'].append('Server [БС]')
    result = compose_subscriptions(document(json.dumps(clash())), document(json.dumps(second)))
    merged = yaml.safe_load(result.document.body)
    assert result.bs_included
    assert [proxy['name'] for proxy in merged['proxies']] == ['Server', 'Server [БС 2]', 'Server [БС]']
    assert result.document.headers['content-type'] == 'application/yaml; charset=utf-8'


@pytest.mark.parametrize('flag', ['X-Hwid-Limit', 'x-hwid-not-supported', 'x-hwid-max-devices-reached'])
@pytest.mark.parametrize('value', ['true', '1', '', 'unexpected'])
def test_primary_http_200_hwid_refusal_is_preserved_even_with_valid_config(flag, value):
    primary = document(json.dumps([profile()]), **{flag: value, 'x-hwid-active': 'true'})
    result = compose_subscriptions(primary, document(json.dumps([profile('bs')])))
    assert not result.bs_included and result.reason == 'primary_denied'
    assert result.document.body == primary.body
    assert result.document.headers[flag.lower()] == value


@pytest.mark.parametrize('status', [204, 302, 401, 403, 404, 500])
@pytest.mark.parametrize('primary', [False, True])
def test_non_200_from_either_account_cannot_append_bs(status, primary):
    first, second = document(), document(BS_LINK)
    if primary:
        first = SubscriptionDocument(first.body, first.headers, status)
    else:
        second = SubscriptionDocument(second.body, second.headers, status)
    result = compose_subscriptions(first, second)
    assert not result.bs_included and result.document.body == first.body
    assert result.document.status == first.status


def test_secondary_hwid_denial_does_not_remove_ordinary_access_or_leak_its_headers():
    result = compose_subscriptions(document(), document(BS_LINK, **{'x-hwid-limit': 'true'}))
    assert result.reason == 'secondary_denied'
    assert result.document.body == MAIN_LINK
    assert 'x-hwid-limit' not in result.document.headers


@pytest.mark.parametrize(
    'body',
    [
        '',
        '<html>Subscription page</html>',
        'denied',
        '[1,2]',
        '{"outbounds":[]}',
        '{"outbounds":[{"type":"vless","server":"example.com"}]}',
        'https://attacker.example/sub',
        'vless://x\nhttps://attacker.example',
        '&recursive {proxies: [*recursive]}',
        '{bad json',
        '☃',
    ],
)
def test_unsupported_or_empty_documents_preserve_primary(body):
    primary = document(body)
    result = compose_subscriptions(primary, document(BS_LINK))
    assert not result.bs_included and result.document.body == body
    assert result.reason == 'unsupported_format'


def test_different_valid_formats_cannot_be_appended():
    result = compose_subscriptions(document(json.dumps([profile()])), document(BS_LINK))
    assert not result.bs_included


def test_oversized_and_oversized_combined_documents_preserve_primary():
    first = document('vless://' + 'x' * (MAX_SUBSCRIPTION_BYTES // 2))
    second = document('vless://' + 'y' * (MAX_SUBSCRIPTION_BYTES // 2))
    assert not compose_subscriptions(first, second).bs_included
    assert not compose_subscriptions(document(), document('x' * (MAX_SUBSCRIPTION_BYTES + 1))).bs_included


@pytest.mark.parametrize('change', ['dns', 'rules', 'dialer', 'group', 'unreachable', 'duplicate', 'direct-rule'])
def test_incompatible_clash_templates_keep_ordinary_document(change):
    first, second = clash(), clash(credential='bs')
    if change == 'dns':
        second['dns']['nameserver'] = ['8.8.8.8']
    elif change == 'rules':
        second['rules'] = ['MATCH,DIRECT']
    elif change == 'dialer':
        second['proxies'][0]['dialer-proxy'] = 'Server'
    elif change == 'group':
        second['proxy-groups'][0]['type'] = 'fallback'
    elif change == 'unreachable':
        second['proxies'].append({**second['proxies'][0], 'name': 'Unreachable'})
    elif change == 'duplicate':
        second['proxies'].append(second['proxies'][0])
    else:
        first['rules'] = second['rules'] = ['MATCH,Server']
    primary = document(yaml.safe_dump(first))
    result = compose_subscriptions(primary, document(yaml.safe_dump(second)))
    assert not result.bs_included and result.document.body == primary.body


def test_headers_preserve_primary_quota_but_strip_cache_identifiers_and_private_data():
    primary = document(
        **{
            'Set-Cookie': 'secret',
            'ETag': 'old',
            'Content-Length': '123',
            'Content-Encoding': 'gzip',
            'Authorization': 'private',
            'profile-title': 'eBunny',
            'X-Hwid-Active': 'true',
        }
    )
    result = compose_subscriptions(primary, document(BS_LINK, **{'profile-title': 'WL private account'}))
    assert result.bs_included
    assert result.document.headers == {
        **document().headers,
        'profile-title': 'eBunny',
        'x-hwid-active': 'true',
        'cache-control': 'no-store, private',
        'pragma': 'no-cache',
        'x-content-type-options': 'nosniff',
        'content-type': 'text/plain; charset=utf-8',
    }


def test_only_device_metadata_is_forwarded_to_panel():
    assert forwarded_device_headers(
        {
            'User-Agent': 'Happ/4.2.1',
            'X-HWID': 'device-123456',
            'x-device-os': 'iOS',
            'x-ver-os': '26',
            'x-device-model': 'iPhone',
            'Authorization': 'client-secret',
            'X-Api-Key': 'bad',
            'Cookie': 'bad',
            'Host': 'bad',
            'X-Forwarded-For': 'bad',
            'X-Remnawave-Disable-Hwid': 'true',
        }
    ) == {
        'user-agent': 'Happ/4.2.1',
        'x-hwid': 'device-123456',
        'x-device-os': 'iOS',
        'x-ver-os': '26',
        'x-device-model': 'iPhone',
    }


@pytest.mark.parametrize('kind', ['uri', 'base64', 'vmess', 'xray', 'clash', 'trojan', 'ss'])
def test_account_credential_proof_supports_real_panel_formats(kind):
    user = SimpleNamespace(vless_uuid='ordinary-key', trojan_password='trojan-key', ss_password='ss-key')
    if kind == 'uri':
        body = MAIN_LINK
    elif kind == 'base64':
        body = base64.b64encode(MAIN_LINK.encode()).decode()
    elif kind == 'vmess':
        body = 'vmess://' + base64.b64encode(json.dumps({'id': 'ordinary-key'}).encode()).decode()
    elif kind == 'xray':
        body = json.dumps([profile('ordinary-key')])
    elif kind == 'clash':
        body = yaml.safe_dump(clash(credential='trojan-key'))
    elif kind == 'trojan':
        body = 'trojan://trojan-key@ordinary.example:443'
    else:
        body = 'ss://' + base64.b64encode(b'aes-256-gcm:ss-key').decode() + '@ordinary.example:443'
    assert contains_account_credentials(document(body), user)


@pytest.mark.parametrize(
    'body',
    [
        'vless://00000000-0000-0000-0000-000000000000@0.0.0.0:443#Denied',
        json.dumps([profile('00000000-0000-0000-0000-000000000000', '0.0.0.0')]),
        'trojan://foreign-key@ordinary.example:443',
        'vmess://bad-base64',
        'ss://bad-base64@ordinary.example:443',
        '{"outbounds":[{"protocol":"vless","settings":null}]}',
        '<html>No access</html>',
    ],
)
def test_valid_looking_error_remarks_do_not_prove_account_access(body):
    user = SimpleNamespace(vless_uuid='ordinary-key', trojan_password='trojan-key', ss_password='ss-key')
    assert not contains_account_credentials(document(body), user)


def test_accounts_without_credentials_cannot_prove_a_real_config():
    assert not contains_account_credentials(document(MAIN_LINK), SimpleNamespace())


@pytest.mark.parametrize('field', ['filter', 'exclude-filter', 'use', 'include-all-proxies'])
def test_dynamic_clash_selectors_are_preserved_without_merging(field):
    first, second = clash(), clash(credential='bs')
    first['proxy-groups'][0][field] = second['proxy-groups'][0][field] = 'Server'
    result = compose_subscriptions(document(yaml.safe_dump(first)), document(yaml.safe_dump(second)))
    assert not result.bs_included
