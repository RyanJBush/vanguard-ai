from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.db import Base, SessionLocal, engine
from app.routers.alerts import router as alerts_router
from app.routers.auth import router as auth_router
from app.routers.detections import router as detections_router
from app.routers.events import router as events_router
from app.routers.health import router as health_router
from app.routers.metrics import router as metrics_router
from app.services.seed import seed_demo_data

app = FastAPI(title="Vanguard AI API", version="0.1.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(health_router)
app.include_router(auth_router)
app.include_router(events_router)
app.include_router(alerts_router)
app.include_router(detections_router)
app.include_router(metrics_router)


@app.on_event("startup")
def on_startup() -> None:
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        seed_demo_data(db)
    finally:
        db.close()
