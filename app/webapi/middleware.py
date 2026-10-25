from __future__ import annotations

from time import monotonic

import structlog
from sqlalchemy.exc import InterfaceError, OperationalError
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from structlog.contextvars import bound_contextvars

from app.services.bs_public_link_tokens import redact_public_subscription_path


logger = structlog.get_logger('web_api')


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """Логирование входящих запросов в административный API."""

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        path = redact_public_subscription_path(request.url.path)
        with bound_contextvars(http_method=request.method, http_path=path):
            start = monotonic()
            response: Response | None = None
            try:
                response = await call_next(request)
                return response
            except (TimeoutError, ConnectionRefusedError, OSError, OperationalError, InterfaceError) as e:
                logger.error(
                    'Database connection error while handling request',
                    method=request.method,
                    path=path,
                    e=type(e).__name__ if path != request.url.path else str(e)[:200],
                )
                response = JSONResponse(
                    status_code=503,
                    content={'detail': 'Service temporarily unavailable. Please try again later.'},
                    headers={'Cache-Control': 'no-store, private'} if path != request.url.path else None,
                )
                return response
            finally:
                duration_ms = (monotonic() - start) * 1000
                status = response.status_code if response else 'error'
                logger.debug(
                    'Request handled',
                    method=request.method,
                    path=path,
                    status=status,
                    duration_ms=duration_ms,
                )


class RequestPathContextMiddleware(BaseHTTPMiddleware):
    """Кладёт путь запроса в контекст на время его обработки.

    Нужен логу действий пользователя: авторизация Mini App знает пользователя,
    но не путь — ``init_data`` приходит телом, поэтому единой зависимости с
    ``Request`` там нет. Включается всегда, в отличие от логирования запросов
    (``WEB_API_REQUEST_LOGGING``), иначе таймлайн активности зависел бы от
    настройки отладочных логов.
    """

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        from app.services.user_action_log_service import bind_request_path, reset_request_path

        token = bind_request_path(redact_public_subscription_path(request.url.path))
        try:
            return await call_next(request)
        finally:
            reset_request_path(token)
