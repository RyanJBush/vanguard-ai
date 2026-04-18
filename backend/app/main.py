from fastapi import FastAPI

from app.core.config import settings
from app.core.logging import setup_logging
from app.db.base import Base
from app.db.session import SessionLocal, engine
from app.routers import alerts, auth, detections, events, health, metrics
from app.services.auth_service import seed_demo_users

setup_logging()
app = FastAPI(title=settings.app_name, debug=settings.app_debug)


@app.on_event("startup")
def on_startup() -> None:
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        seed_demo_users(db)
    finally:
        db.close()


app.include_router(health.router, tags=["health"])
app.include_router(auth.router, prefix=settings.api_v1_prefix, tags=["auth"])
app.include_router(events.router, prefix=settings.api_v1_prefix, tags=["events"])
app.include_router(alerts.router, prefix=settings.api_v1_prefix, tags=["alerts"])
app.include_router(detections.router, prefix=settings.api_v1_prefix, tags=["detections"])
app.include_router(metrics.router, prefix=settings.api_v1_prefix, tags=["metrics"])
