from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.db import Base, SessionLocal, engine
from app.observability import (
    attach_request_context_filter,
    configure_logging,
    request_tracing_middleware,
)
from app.routers.alerts import router as alerts_router
from app.routers.auth import router as auth_router
from app.routers.detections import router as detections_router
from app.routers.events import router as events_router
from app.routers.health import router as health_router
from app.routers.incidents import router as incidents_router
from app.routers.jobs import router as jobs_router
from app.routers.metrics import router as metrics_router
from app.routers.platform import router as platform_router
from app.services.seed import seed_demo_data


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        seed_demo_data(db)
    finally:
        db.close()
    yield


app = FastAPI(title="Vanguard AI API", version="0.1.0", lifespan=lifespan)
configure_logging()
attach_request_context_filter()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.middleware("http")(request_tracing_middleware)

app.include_router(health_router)
app.include_router(auth_router)
app.include_router(events_router)
app.include_router(alerts_router)
app.include_router(detections_router)
app.include_router(incidents_router)
app.include_router(jobs_router)
app.include_router(platform_router)
app.include_router(metrics_router)
