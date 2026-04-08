"""
FinGuard API - Main Application
Security scanning and compliance checking service
"""

import os
import logging
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
import uvicorn

from api.routes import scan, dashboard, feedback, ws
from api.database import init_db


# -------------------------
# LOGGING
# -------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s"
)

logger = logging.getLogger("finguard")


# -------------------------
# LIFESPAN HANDLER
# -------------------------
@asynccontextmanager
async def lifespan(app: FastAPI):
    try:
        logger.info("Initializing database...")
        await init_db()
        logger.info("Database initialized successfully")
    except Exception as e:
        logger.error(f"Database init failed: {e}")
    yield
    logger.info("FinGuard shutting down...")


# -------------------------
# APP INIT
# -------------------------
app = FastAPI(
    title="FinGuard API",
    description="Security scanning and compliance checking for financial applications",
    version="1.0.0",
    lifespan=lifespan
)


# -------------------------
# CORS (ENV BASED)
# -------------------------
origins = os.environ.get("CORS_ORIGINS", "*").split(",")

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# -------------------------
# ROUTES
# -------------------------
app.include_router(scan.router, prefix="/api/scan", tags=["Scanning"])
app.include_router(dashboard.router, prefix="/api/dashboard", tags=["Dashboard"])
app.include_router(feedback.router, prefix="/api/feedback", tags=["Feedback"])
app.include_router(ws.router, prefix="/api/ws", tags=["WebSocket"])


# -------------------------
# HEALTH + ROOT
# -------------------------
@app.get("/")
async def root():
    return {
        "message": "FinGuard API is running",
        "version": "1.0.0"
    }


@app.get("/health")
async def health_check():
    return {
        "status": "healthy"
    }


# -------------------------
# ENTRY POINT
# -------------------------
if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 8000)),
        reload=True
    )