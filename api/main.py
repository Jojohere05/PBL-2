"""
FinGuard API - Main Application
Security scanning and compliance checking service
"""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
import uvicorn

from routes import scan, dashboard, feedback, ws
from database import init_db


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan handler"""
    # Startup
    await init_db()
    yield
    # Shutdown
    pass


app = FastAPI(
    title="FinGuard API",
    description="Security scanning and compliance checking for financial applications",
    version="1.0.0",
    lifespan=lifespan
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(scan.router, prefix="/api/scan", tags=["Scanning"])
app.include_router(dashboard.router, prefix="/api/dashboard", tags=["Dashboard"])
app.include_router(feedback.router, prefix="/api/feedback", tags=["Feedback"])
app.include_router(ws.router, prefix="/api/ws", tags=["WebSocket"])


@app.get("/")
async def root():
    return {"message": "FinGuard API is running", "version": "1.0.0"}


@app.get("/health")
async def health_check():
    return {"status": "healthy"}


if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
