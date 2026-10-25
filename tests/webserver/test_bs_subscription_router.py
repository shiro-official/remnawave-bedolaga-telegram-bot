import json

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from structlog.testing import capture_logs

from app.config import settings
from app.services.bs_public_link_tokens import new_public_token, redact_public_subscription_path
from app.services.user_action_log_service import current_request_path
from app.webapi.middleware import RequestLoggingMiddleware, RequestPathContextMiddleware
from app.webserver.bs_subscription import create_public_subscription_router


def test_public_router_is_absent_by_default(monkeypatch):
    monkeypatch.setattr(settings, 'BS_SUBSCRIPTION_DELIVERY_ENABLED', False)
    assert create_public_subscription_router().routes == []


def test_explicitly_enabled_router_requires_valid_origin(monkeypatch):
    monkeypatch.setattr(settings, 'BS_SUBSCRIPTION_DELIVERY_ENABLED', True)
    monkeypatch.setattr(settings, 'BS_SUBSCRIPTION_PUBLIC_BASE_URL', '')
    with pytest.raises(ValueError):
        create_public_subscription_router()


@pytest.mark.parametrize('enabled', [False, True])
def test_public_routes_are_independent_of_admin_api_mode(monkeypatch, enabled):
    from app.webserver.unified_app import _create_base_app

    monkeypatch.setattr(settings, 'WEB_API_ENABLED', enabled)
    monkeypatch.setattr(settings, 'CABINET_ENABLED', False)
    monkeypatch.setattr(settings, 'BS_SUBSCRIPTION_DELIVERY_ENABLED', True)
    monkeypatch.setattr(settings, 'BS_SUBSCRIPTION_PUBLIC_BASE_URL', 'https://vpn.example')
    app = _create_base_app()
    # FastAPI may retain included routers lazily; exercise the HTTP route rather
    # than assuming app.routes contains only flattened APIRoute objects.
    response = TestClient(app).get('/s/not-a-capability')
    assert response.status_code == 404 and response.text == 'Subscription unavailable'
    assert response.headers['cache-control'] == 'no-store, private'
    assert not any('/s/' in path for path in app.openapi()['paths'])


def test_logging_and_action_context_redact_public_tokens_and_upstream_exception_messages():
    app = FastAPI()
    app.add_middleware(RequestLoggingMiddleware)
    app.add_middleware(RequestPathContextMiddleware)
    captured_paths = []
    token = new_public_token()

    @app.get('/s/{secret}')
    async def failing(secret: str):
        captured_paths.append(current_request_path())
        raise TimeoutError('a URL-bearing error ' + secret)

    with capture_logs() as logs:
        response = TestClient(app).get(f'/s/{token}')
    assert response.status_code == 503
    assert captured_paths == ['/s/[redacted]']
    assert token not in json.dumps(logs)
    assert token not in response.text
    assert response.headers['cache-control'] == 'no-store, private'
    assert redact_public_subscription_path(f'/edge/s/{token}/extra') == '/edge/s/[redacted]'
