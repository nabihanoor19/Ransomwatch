from fastapi import FastAPI
from database import engine, Base
import models

# Create database tables
Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="RansomWatch API",
    description="File Activity Early Warning System",
    version="1.0.0"
)

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