"""Opaque subscription capabilities and redaction; no credentials in diagnostics."""

from __future__ import annotations

import hashlib
import re
import secrets
from urllib.parse import urlsplit

from app.config import settings


PUBLIC_SUBSCRIPTION_PREFIX = '/s'
CLIENT_TYPES = frozenset({'json', 'v2ray-json', 'clash', 'mihomo', 'stash', 'singbox'})
_TOKEN = re.compile(r'[A-Za-z0-9_-]{43}')


def hash_public_token(token: str) -> str | None:
    if not isinstance(token, str) or _TOKEN.fullmatch(token) is None:
        return None
    return hashlib.sha256(token.encode('ascii')).hexdigest()


def new_public_token() -> str:
    return secrets.token_urlsafe(32)


def public_subscription_base_url() -> str:
    value = settings.BS_SUBSCRIPTION_PUBLIC_BASE_URL.strip().rstrip('/')
    parsed = urlsplit(value)
    if (
        parsed.scheme != 'https'
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or '?' in value
        or '#' in value
        or parsed.path not in ('', '/')
        or any(character.isspace() or ord(character) < 32 or ord(character) == 127 for character in value)
        or '\\' in value
    ):
        raise ValueError('BS_SUBSCRIPTION_PUBLIC_BASE_URL must be an HTTPS origin without credentials or path')
    # Accessing port validates malformed and out-of-range ports without an HTTP request.
    _ = parsed.port
    return value


def public_subscription_url(token: str) -> str:
    if hash_public_token(token) is None:
        raise ValueError('Invalid public subscription capability')
    return f'{public_subscription_base_url()}{PUBLIC_SUBSCRIPTION_PREFIX}/{token}'


def public_token_from_url(url: str | None) -> str | None:
    if not isinstance(url, str):
        return None
    try:
        parsed = urlsplit(url)
        prefix = f'{PUBLIC_SUBSCRIPTION_PREFIX}/'
        token = parsed.path[len(prefix) :] if parsed.path.startswith(prefix) else ''
        if (
            parsed.scheme == 'https'
            and parsed.hostname
            and parsed.username is None
            and parsed.password is None
            and not parsed.query
            and not parsed.fragment
            and hash_public_token(token) is not None
        ):
            return token
    except ValueError:
        pass
    return None


def has_combined_public_link(subscription) -> bool:
    return (
        getattr(subscription, 'traffic_mode', None) == 'split'
        and public_token_from_url(getattr(subscription, 'subscription_url', None)) is not None
    )


def apply_panel_subscription_links(
    subscription, panel_url, crypto_link, *, replace_url=True, replace_crypto=True
) -> None:
    """Panel synchronization must not replace a combined URL or its cryptolink."""
    if has_combined_public_link(subscription):
        return
    if replace_url:
        subscription.subscription_url = panel_url
    if replace_crypto:
        subscription.subscription_crypto_link = crypto_link


def redact_public_subscription_path(path: str) -> str:
    # Redact even malformed/unknown /s paths. Never echo their trailing text,
    # since an attacker can insert a secret into an unsupported format segment.
    marker = f'{PUBLIC_SUBSCRIPTION_PREFIX}/'
    if marker in path:
        return path.split(marker, 1)[0] + marker + '[redacted]'
    if path.endswith(PUBLIC_SUBSCRIPTION_PREFIX):
        return path + '/[redacted]'
    return path
