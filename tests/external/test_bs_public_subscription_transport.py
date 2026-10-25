"""Actual aiohttp transport: bounded responses and no credential-bearing redirects."""

from contextlib import asynccontextmanager

import aiohttp
import pytest
from aiohttp import web

from app.external.remnawave_api import RemnaWaveAPI, RemnaWaveAPIError


@asynccontextmanager
async def panel_server(handler):
    app = web.Application()
    app.router.add_get('/api/sub/{short_uuid}', handler)
    app.router.add_get('/api/sub/{short_uuid}/{client_type}', handler)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, '127.0.0.1', 0)
    await site.start()
    port = runner.addresses[0][1]
    try:
        async with aiohttp.ClientSession(headers={'Authorization': 'Bearer test-panel-key'}) as session:
            api = RemnaWaveAPI(f'http://127.0.0.1:{port}', api_key='test-panel-key')
            api.session = session
            yield api
    finally:
        await runner.cleanup()


@pytest.mark.asyncio
async def test_public_fetch_preserves_hwid_refusal_body_headers_and_http_status():
    requests = []

    async def handle(request):
        requests.append(dict(request.headers))
        return web.Response(text='denied', status=403, headers={'x-hwid-limit': 'true'})

    async with panel_server(handle) as api:
        status, body, headers = await api.get_public_subscription_response(
            'primary-short', headers={'user-agent': 'Happ/4.2.1', 'x-hwid': 'device-123456'}
        )
    assert status == 403 and body == 'denied' and headers['x-hwid-limit'] == 'true'
    assert {key.lower(): value for key, value in requests[0].items()}['x-hwid'] == 'device-123456'


@pytest.mark.asyncio
async def test_redirect_is_not_followed_with_panel_credentials():
    requests = []

    async def handle(request):
        requests.append(request.match_info['short_uuid'])
        return web.Response(status=302, headers={'location': '/api/sub/redirect-target'})

    async with panel_server(handle) as api:
        with pytest.raises(RemnaWaveAPIError, match='redirect refused'):
            await api.get_public_subscription_response('primary-short')
    assert requests == ['primary-short']


@pytest.mark.asyncio
async def test_chunked_response_without_content_length_is_still_bounded():
    async def handle(request):
        response = web.StreamResponse()
        await response.prepare(request)
        try:
            for _ in range(65):
                await response.write(b'x' * 65536)
            await response.write_eof()
        except (ConnectionResetError, aiohttp.ClientConnectionError):
            pass  # The bounded reader closes the response before EOF.
        return response

    async with panel_server(handle) as api:
        with pytest.raises(RemnaWaveAPIError, match='size limit'):
            await api.get_public_subscription_response('primary-short')


@pytest.mark.asyncio
async def test_invalid_utf8_is_not_replaced_with_damaged_credentials():
    async def handle(request):
        return web.Response(body=b'vless://\xff')

    async with panel_server(handle) as api:
        with pytest.raises(RemnaWaveAPIError, match='not UTF-8'):
            await api.get_public_subscription_response('primary-short')


@pytest.mark.parametrize('short_uuid', ['../system', 'short?x=1', 'https://evil.example', 'x', 'x' * 65])
@pytest.mark.asyncio
async def test_invalid_short_uuid_never_makes_a_request(short_uuid):
    requests = []

    async def handle(request):
        requests.append(request)
        return web.Response(text='unexpected')

    async with panel_server(handle) as api:
        with pytest.raises(RemnaWaveAPIError, match='identifier'):
            await api.get_public_subscription_response(short_uuid)
    assert requests == []


@pytest.mark.parametrize('client_type', ['json', 'v2ray-json', 'clash', 'mihomo', 'stash', 'singbox'])
@pytest.mark.asyncio
async def test_client_type_is_forwarded_as_a_validated_path_segment(client_type):
    requests = []

    async def handle(request):
        requests.append(dict(request.match_info))
        return web.Response(text='configuration')

    async with panel_server(handle) as api:
        status, body, _ = await api.get_public_subscription_response('primary-short', client_type=client_type)
    assert status == 200 and body == 'configuration'
    assert requests == [{'short_uuid': 'primary-short', 'client_type': client_type}]


@pytest.mark.asyncio
async def test_client_type_cannot_inject_a_path_or_query():
    requests = []

    async def handle(request):
        requests.append(request.path)
        return web.Response(text='unexpected')

    async with panel_server(handle) as api:
        with pytest.raises(RemnaWaveAPIError, match='client type'):
            await api.get_public_subscription_response('primary-short', client_type='../../users?secret=x')
    assert requests == []
