import sys
from pathlib import Path

# Ensure backend directory is in Python path for clean imports
sys.path.append(str(Path(__file__).resolve().parent))

from fastapi import FastAPI
from database import engine, Base
import models
from routers import auth_routes

# Create database tables if they don't already exist
Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="RansomWatch API",
    description="File Activity Early Warning System",
    version="1.0.0"
)

# Register routers
app.include_router(auth_routes.router)

@app.get("/")
def home():
    return {
        "message": "Welcome to RansomWatch",
        "status": "running"
    }

@app.get("/health")
def health():
    return {
        "status": "healthy"
    }