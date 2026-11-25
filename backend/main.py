import sys
from pathlib import Path
from contextlib import asynccontextmanager

# Ensure backend directory is in Python path
sys.path.append(str(Path(__file__).resolve().parent))

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from database import engine, Base
import models
from routers import (
    auth_routes,
    monitor_routes,
    event_routes,
    incident_routes,
    dashboard_routes,
    admin_routes,
    report_routes
)


# ── Lifespan: startup / shutdown events ──────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    FastAPI lifespan handler.

    On startup:
    - Create all SQLite tables (idempotent; safe to call repeatedly).
    - Load detection rule thresholds from the Configuration table into the
      shared RuleEngine so the pipeline always starts with DB-driven values.

    On shutdown (implicit): Python GC cleans up threads; MonitorManager.stop()
    is called explicitly by the /monitor/stop routes when the user stops a
    folder monitor through the UI or API.
    """
    # Ensure tables exist before any route handler runs
    Base.metadata.create_all(bind=engine)

    # Pre-load DB thresholds into the shared RuleEngine
    try:
        from database import SessionLocal
        from security.rules import load_thresholds_from_db
        from security.pipeline import monitor_manager

        db = SessionLocal()
        try:
            load_thresholds_from_db(db)
        finally:
            db.close()
    except Exception as exc:
        import logging
        logging.getLogger("ransomwatch.startup").warning(
            "Could not pre-load thresholds from DB (may be first run): %s", exc
        )

    yield  # App runs here

    # Graceful shutdown: stop any still-running monitors
    try:
        from security.pipeline import monitor_manager
        for folder_id in list(monitor_manager._monitors.keys()):
            monitor_manager.stop_monitoring(folder_id)
    except Exception:
        pass


# ── Application ───────────────────────────────────────────────────────────────
app = FastAPI(
    title="RansomWatch API",
    description="File Activity Early Warning System — Full API",
    version="2.0.0",
    lifespan=lifespan,
)

# ── CORS — allow Member C's frontend dev servers ──────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",   # Vite (most common React / Vue setup)
        "http://localhost:3000",   # Create React App / Next.js
        "http://localhost:8080",   # Vue CLI / generic
        "http://127.0.0.1:5173",
        "http://127.0.0.1:3000",
        "http://127.0.0.1:8080",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Register all routers ──────────────────────────────────────────────────────
app.include_router(auth_routes.router)       # /auth/...
app.include_router(monitor_routes.router)    # /monitor/...
app.include_router(event_routes.router)      # /events/...
app.include_router(incident_routes.router)   # /incidents/...
app.include_router(dashboard_routes.router)  # /dashboard/...
app.include_router(admin_routes.router)      # /admin/...
app.include_router(report_routes.router)     # /reports/...


@app.get("/", tags=["Health"])
def home():
    return {"message": "Welcome to RansomWatch", "status": "running", "version": "2.0.0"}


@app.get("/health", tags=["Health"])
def health():
    return {"status": "healthy"}
