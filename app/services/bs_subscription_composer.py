"""Combine panel subscription documents without changing credentials or admission.

This module does not authorize requests or create accounts. A caller must first
verify local ownership and both panel identities. Unsupported documents preserve
the primary response; configuration bodies must never be written to logs.
"""

from __future__ import annotations

import base64
import binascii
import copy
import json
from dataclasses import dataclass
from urllib.parse import unquote, urlsplit

import yaml


MAX_SUBSCRIPTION_BYTES = 4 * 1024 * 1024
MAX_CONFIGURATIONS = 5000
HWID_DENIAL_HEADERS = ('x-hwid-limit', 'x-hwid-not-supported', 'x-hwid-max-devices-reached')
REQUEST_HEADERS = frozenset({'user-agent', 'x-hwid', 'x-device-os', 'x-ver-os', 'x-device-model'})
RESPONSE_HEADERS = frozenset(
    {
        'content-type',
        'content-disposition',
        'subscription-userinfo',
        'subscription-refill-date',
        'profile-title',
        'profile-update-interval',
        'support-url',
        'announce',
        'announce-url',
        'x-hwid-active',
        *HWID_DENIAL_HEADERS,
    }
)
URI_SCHEMES = frozenset(
    {'vless', 'vmess', 'trojan', 'ss', 'ssr', 'hysteria', 'hysteria2', 'hy2', 'tuic', 'wireguard', 'socks', 'socks5'}
)


class UnsupportedSubscription(ValueError):
    """A document cannot be combined without interpreting or changing its template."""


@dataclass(frozen=True)
class SubscriptionDocument:
    body: str
    headers: dict[str, str]
    status: int = 200

    @property
    def hwid_denied(self) -> bool:
        headers = {key.lower(): value for key, value in self.headers.items()}
        # Only explicit false values are non-denials. Unknown flag values fail closed.
        return any(key in headers and headers[key].strip().lower() not in ('false', '0') for key in HWID_DENIAL_HEADERS)

    def for_client(self) -> SubscriptionDocument:
        headers = {key.lower(): value for key, value in self.headers.items() if key.lower() in RESPONSE_HEADERS}
        headers.update(
            {'cache-control': 'no-store, private', 'pragma': 'no-cache', 'x-content-type-options': 'nosniff'}
        )
        return SubscriptionDocument(self.body, headers, self.status)


@dataclass(frozen=True)
class CompositionResult:
    document: SubscriptionDocument
    bs_included: bool
    reason: str


def forwarded_device_headers(headers: dict[str, str]) -> dict[str, str]:
    """Never accept client authorization, host, proxy, cookie or format override headers."""
    return {key.lower(): value for key, value in headers.items() if key.lower() in REQUEST_HEADERS}


def _uri_lines(text: str) -> list[str]:
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if not lines or len(lines) > MAX_CONFIGURATIONS:
        raise UnsupportedSubscription('Invalid URI list size')
    for line in lines:
        scheme, separator, value = line.partition('://')
        if scheme.lower() not in URI_SCHEMES or not separator or not value or any(c.isspace() for c in line):
            raise UnsupportedSubscription('Not a URI subscription')
    return lines


def _xray_profiles(data: object) -> list[dict]:
    profiles = data if isinstance(data, list) else [data]
    if not profiles or len(profiles) > MAX_CONFIGURATIONS:
        raise UnsupportedSubscription('Invalid profile count')
    for profile in profiles:
        if not isinstance(profile, dict) or not isinstance(profile.get('outbounds'), list):
            raise UnsupportedSubscription('Not an Xray profile')
        if not profile['outbounds'] or not all(
            isinstance(outbound, dict) and isinstance(outbound.get('protocol'), str)
            for outbound in profile['outbounds']
        ):
            raise UnsupportedSubscription('Not an Xray outbound list')
    return profiles


def _parse(body: str) -> tuple[str, object]:
    if len(body.encode()) > MAX_SUBSCRIPTION_BYTES:
        raise UnsupportedSubscription('Subscription is too large')
    text = body.strip()
    if text.startswith(('[', '{')):
        data = json.loads(text)
        if isinstance(data, dict) and 'proxies' in data:
            return 'clash', data
        return 'xray', _xray_profiles(data)
    if '://' in text.split('\n', 1)[0]:
        return 'uri', _uri_lines(text)
    try:
        decoded = base64.b64decode(''.join(text.split()) + '=' * (-len(''.join(text.split())) % 4), validate=True)
        return 'base64', _uri_lines(decoded.decode('utf-8'))
    except (binascii.Error, UnicodeError, UnsupportedSubscription):
        pass
    # YAML aliases are unnecessary for generated documents and permit recursive
    # objects. Reject them before constructing data or comparing templates.
    if any(isinstance(token, (yaml.AliasToken, yaml.AnchorToken)) for token in yaml.scan(text)):
        raise UnsupportedSubscription('YAML aliases are unsupported')
    data = yaml.safe_load(text)
    if isinstance(data, dict) and 'proxies' in data:
        return 'clash', data
    raise UnsupportedSubscription('Unsupported subscription format')


def contains_account_credentials(document: SubscriptionDocument, user) -> bool:
    """Reject panel error remarks that happen to be valid configurations.

    Remnawave can generate HTTP 200 fallback profiles before the HWID check,
    including response-rule remarks. They normally contain a zero UUID. This
    check is additional evidence of a real account configuration, not a way to
    replace the panel's device admission gate or attest arbitrary custom rules.
    """
    vless = getattr(user, 'vless_uuid', None)
    trojan = getattr(user, 'trojan_password', None)
    shadowsocks = getattr(user, 'ss_password', None)

    def matches(protocol: str, credential: object) -> bool:
        expected = {'vless': vless, 'vmess': vless, 'trojan': trojan, 'ss': shadowsocks}.get(protocol)
        return bool(expected) and credential == expected

    try:
        kind, data = _parse(document.body)
        if kind in ('uri', 'base64'):
            for line in data:
                parsed = urlsplit(line)
                protocol = parsed.scheme.lower()
                if protocol in ('vless', 'trojan') and matches(protocol, unquote(parsed.username or '')):
                    return True
                if protocol == 'vmess':
                    encoded = line.split('://', 1)[1].split('#', 1)[0]
                    config = json.loads(base64.b64decode(encoded + '=' * (-len(encoded) % 4), validate=True))
                    if isinstance(config, dict) and matches(protocol, config.get('id')):
                        return True
                if protocol == 'ss' and parsed.username:
                    encoded = unquote(parsed.username)
                    credentials = (
                        f'{encoded}:{unquote(parsed.password)}'
                        if parsed.password is not None
                        else base64.b64decode(encoded + '=' * (-len(encoded) % 4), validate=True).decode()
                    )
                    if matches(protocol, credentials.partition(':')[2]):
                        return True
        elif kind == 'xray':
            for profile in data:
                for outbound in profile['outbounds']:
                    protocol = outbound['protocol']
                    settings = outbound.get('settings', {})
                    for server in settings.get('vnext', []):
                        if any(matches(protocol, item.get('id')) for item in server.get('users', [])):
                            return True
                    if any(
                        matches('ss' if protocol == 'shadowsocks' else protocol, item.get('password'))
                        for item in settings.get('servers', [])
                    ):
                        return True
        elif kind == 'clash':
            _, proxies, _, _ = _clash_parts(data)
            return any(matches(proxy['type'], proxy.get('uuid') or proxy.get('password')) for proxy in proxies)
    except (ValueError, TypeError, AttributeError, KeyError, yaml.YAMLError, RecursionError):
        return False
    return False


def _clash_parts(data: dict) -> tuple[dict, list[dict], list[dict], set[str]]:
    proxies, groups = data.get('proxies'), data.get('proxy-groups')
    if not isinstance(proxies, list) or not proxies or len(proxies) > MAX_CONFIGURATIONS:
        raise UnsupportedSubscription('Invalid Clash proxies')
    if not isinstance(groups, list) or not groups:
        raise UnsupportedSubscription('Explicit Clash groups required')
    names = set()
    for proxy in proxies:
        if not isinstance(proxy, dict) or not isinstance(proxy.get('name'), str) or not proxy.get('type'):
            raise UnsupportedSubscription('Invalid Clash proxy')
        name = proxy['name']
        if not name or name in names or name in ('DIRECT', 'REJECT', 'PASS', 'COMPATIBLE') or 'dialer-proxy' in proxy:
            raise UnsupportedSubscription('Ambiguous Clash proxy reference')
        names.add(name)
    group_names = set()
    for group in groups:
        if not isinstance(group, dict) or not isinstance(group.get('name'), str):
            raise UnsupportedSubscription('Invalid Clash group')
        name = group['name']
        if name in names or name in group_names or not isinstance(group.get('proxies'), list):
            raise UnsupportedSubscription('Ambiguous Clash group')
        if not all(isinstance(member, str) for member in group['proxies']):
            raise UnsupportedSubscription('Invalid Clash group members')
        if any(
            key in group
            for key in (
                'filter',
                'exclude-filter',
                'use',
                'include-all',
                'include-all-proxies',
                'include-all-providers',
            )
        ):
            raise UnsupportedSubscription('Dynamic Clash group selection is unsupported')
        group_names.add(name)
    envelope = {key: value for key, value in data.items() if key not in ('proxies', 'proxy-groups')}

    # Direct references to proxy names outside group membership cannot be
    # renamed reliably across arbitrary Clash/Mihomo template extensions.
    def references_proxy(value: object) -> bool:
        if isinstance(value, str):
            return value in names or any(part.strip() in names for part in value.split(','))
        if isinstance(value, list):
            return any(references_proxy(item) for item in value)
        if isinstance(value, dict):
            return any(references_proxy(item) for item in value.values())
        return False

    if references_proxy(envelope):
        raise UnsupportedSubscription('Proxy references outside groups are unsupported')
    return envelope, proxies, groups, names


def _merge_clash(primary: dict, secondary: dict) -> str:
    envelope, proxies, groups, names = _clash_parts(primary)
    bs_envelope, bs_proxies, bs_groups, bs_names = _clash_parts(secondary)
    if envelope != bs_envelope or len(groups) != len(bs_groups):
        raise UnsupportedSubscription('Incompatible Clash templates')
    # Reserve ALL original names before allocating suffixes, including other
    # secondary names and group names, so generated names stay deterministic.
    reserved = names | bs_names | {group['name'] for group in groups}
    renamed = {}
    for name in sorted(bs_names):
        if name not in names:
            renamed[name] = name
            continue
        candidate = f'{name} [БС]'
        index = 2
        while candidate in reserved:
            candidate = f'{name} [БС {index}]'
            index += 1
        renamed[name] = candidate
        reserved.add(candidate)
    merged = copy.deepcopy(primary)
    reached = set()
    for target, group, bs_group in zip(merged['proxy-groups'], groups, bs_groups, strict=True):
        base = {key: value for key, value in group.items() if key != 'proxies'}
        bs_base = {key: value for key, value in bs_group.items() if key != 'proxies'}
        static = [member for member in group['proxies'] if member not in names]
        bs_static = [member for member in bs_group['proxies'] if member not in bs_names]
        if base != bs_base or static != bs_static:
            raise UnsupportedSubscription('Incompatible Clash group templates')
        members = [member for member in bs_group['proxies'] if member in bs_names]
        reached.update(members)
        target['proxies'].extend(renamed[member] for member in members)
    if reached != bs_names:
        raise UnsupportedSubscription('Some BS proxies are unreachable through explicit groups')
    merged['proxies'].extend({**proxy, 'name': renamed[proxy['name']]} for proxy in bs_proxies)
    if len(proxies) + len(bs_proxies) > MAX_CONFIGURATIONS:
        raise UnsupportedSubscription('Too many Clash proxies')
    return yaml.safe_dump(merged, allow_unicode=True, sort_keys=False)


def compose_subscriptions(primary: SubscriptionDocument, secondary: SubscriptionDocument) -> CompositionResult:
    """Keep the primary admission result, profile headers and whole configurations."""
    fallback = primary.for_client()
    if primary.status != 200 or primary.hwid_denied:
        return CompositionResult(fallback, False, 'primary_denied')
    if secondary.status != 200 or secondary.hwid_denied:
        return CompositionResult(fallback, False, 'secondary_denied')
    try:
        kind, first = _parse(primary.body)
        bs_kind, second = _parse(secondary.body)
        if kind in ('uri', 'base64') and bs_kind in ('uri', 'base64'):
            lines = list(dict.fromkeys([*first, *second]))
            if len(lines) > MAX_CONFIGURATIONS:
                raise UnsupportedSubscription('Too many URI configurations')
            body = '\n'.join(lines) + '\n'
            if kind == 'base64':
                body = base64.b64encode(body.encode()).decode()
        elif kind == bs_kind == 'xray':
            if len(first) + len(second) > MAX_CONFIGURATIONS:
                raise UnsupportedSubscription('Too many Xray configurations')
            body = json.dumps([*first, *second], ensure_ascii=False, separators=(',', ':'))
        elif kind == bs_kind == 'clash':
            body = _merge_clash(first, second)
        else:
            raise UnsupportedSubscription('Different subscription formats')
        if len(body.encode()) > MAX_SUBSCRIPTION_BYTES:
            raise UnsupportedSubscription('Combined subscription is too large')
    except (UnsupportedSubscription, ValueError, TypeError, yaml.YAMLError, RecursionError):
        return CompositionResult(fallback, False, 'unsupported_format')
    headers = {**fallback.headers, 'content-type': 'text/plain; charset=utf-8'}
    if kind == 'xray':
        headers['content-type'] = 'application/json; charset=utf-8'
    elif kind == 'clash':
        headers['content-type'] = 'application/yaml; charset=utf-8'
    return CompositionResult(SubscriptionDocument(body, headers, 200), True, 'combined')
