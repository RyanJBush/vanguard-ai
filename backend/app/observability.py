import logging
import time
import uuid
from contextvars import ContextVar

from fastapi import Request

request_id_ctx: ContextVar[str] = ContextVar("request_id", default="-")


def configure_logging() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s request_id=%(request_id)s %(message)s",
    )


class RequestContextFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        record.request_id = request_id_ctx.get("-")
        return True


def attach_request_context_filter() -> None:
    root_logger = logging.getLogger()
    existing = [flt for flt in root_logger.filters if isinstance(flt, RequestContextFilter)]
    if not existing:
        root_logger.addFilter(RequestContextFilter())


async def request_tracing_middleware(request: Request, call_next):
    request_id = request.headers.get("x-request-id") or str(uuid.uuid4())
    token = request_id_ctx.set(request_id)
    start = time.perf_counter()
    try:
        response = await call_next(request)
    finally:
        duration_ms = round((time.perf_counter() - start) * 1000, 2)
        logging.getLogger("vanguard.request").info(
            "method=%s path=%s duration_ms=%s",
            request.method,
            request.url.path,
            duration_ms,
        )
        request_id_ctx.reset(token)

    response.headers["x-request-id"] = request_id
    return response
