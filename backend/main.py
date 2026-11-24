import sys
from pathlib import Path

# Ensure backend directory is in Python path
sys.path.append(str(Path(__file__).resolve().parent))

from fastapi import FastAPI
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

# Create all database tables
Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="RansomWatch API",
    description="File Activity Early Warning System — Full API",
    version="2.0.0"
)

# ── Register all routers ──────────────────────────────────────────
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
