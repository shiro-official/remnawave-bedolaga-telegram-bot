"""Opt-in opaque public subscription route. Enabling it never migrates accounts."""

from __future__ import annotations

import asyncio

import structlog
from fastapi import APIRouter, Request, Response

from app.config import settings
from app.services.bs_public_link_tokens import CLIENT_TYPES, hash_public_token, public_subscription_base_url
from app.services.bs_subscription_delivery import SubscriptionUnavailable, deliver_public_subscription
from app.utils.cache import RateLimitCache


logger = structlog.get_logger(__name__)
_PRIVATE_HEADERS = {
    'cache-control': 'no-store, private',
    'pragma': 'no-cache',
    'referrer-policy': 'no-referrer',
    'x-content-type-options': 'nosniff',
    'x-robots-tag': 'noindex, nofollow',
}


def _unavailable(status: int = 404) -> Response:
    headers = dict(_PRIVATE_HEADERS)
    if status == 429:
        headers['retry-after'] = '60'
    body = {
        404: 'Subscription unavailable',
        406: 'Откройте ссылку в VPN-приложении.',
        429: 'Too many requests',
        503: 'Service temporarily unavailable',
    }[status]
    return Response(body, status_code=status, headers=headers, media_type='text/plain')


def create_public_subscription_router(*, session_factory=None, api_factory=None) -> APIRouter:
    router = APIRouter(include_in_schema=False)
    if not settings.BS_SUBSCRIPTION_DELIVERY_ENABLED:
        return router
    public_subscription_base_url()  # Fail startup on an invalid explicitly enabled configuration.
    slots = asyncio.Semaphore(settings.BS_SUBSCRIPTION_MAX_CONCURRENT)

    async def download(request: Request, token: str, client_type: str | None = None) -> Response:
        if not settings.BS_SUBSCRIPTION_DELIVERY_ENABLED:
            return _unavailable()
        digest = hash_public_token(token)
        if digest is None or request.query_params or (client_type is not None and client_type not in CLIENT_TYPES):
            return _unavailable()
        peer = request.client.host if request.client else 'unknown'
        # Proxy headers are resolved only by the configured trusted ASGI server,
        # never trusted directly from a caller here. Redis keys contain a digest.
        if await RateLimitCache.is_ip_rate_limited(
            peer, 'bs_subscription', limit=settings.BS_SUBSCRIPTION_IP_RATE_LIMIT, window=60, fail_closed=True
        ) or await RateLimitCache.is_subject_rate_limited(
            digest, 'bs_subscription', limit=settings.BS_SUBSCRIPTION_TOKEN_RATE_LIMIT, window=60, fail_closed=True
        ):
            return _unavailable(429)
        try:
            async with asyncio.timeout(1):
                await slots.acquire()
        except TimeoutError:
            return _unavailable(503)
        try:
            from app.database.database import AsyncSessionLocal
            from app.services.remnawave_service import RemnaWaveService

            sessions = session_factory or AsyncSessionLocal

            def configured_api():
                return RemnaWaveService().get_api_client()

            clients = api_factory or configured_api
            async with sessions() as db:
                result = await deliver_public_subscription(
                    db, None, token, request_headers=dict(request.headers), client_type=client_type, api_factory=clients
                )
            document = result.document.for_client()
            if 'text/html' in document.headers.get(
                'content-type', ''
            ).lower() or document.body.lstrip().lower().startswith(('<!doctype html', '<html')):
                # Do not return a panel page whose import links point directly
                # at the primary-only subscription. The separate branded page
                # needs its own integration and is not replaced by this route.
                return _unavailable(406)
            return Response(
                document.body, status_code=document.status, headers={**document.headers, **_PRIVATE_HEADERS}
            )
        except SubscriptionUnavailable:
            return _unavailable()
        except Exception as error:
            # No token, URL, upstream text, SQL parameters or exception traceback.
            logger.warning('Public subscription request unavailable', error_type=type(error).__name__)
            return _unavailable(503)
        finally:
            slots.release()

    router.add_api_route('/s/{token}', download, methods=['GET'])
    router.add_api_route('/s/{token}/{client_type}', download, methods=['GET'])
    return router
