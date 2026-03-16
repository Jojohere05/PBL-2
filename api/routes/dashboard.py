from fastapi import APIRouter
from api.database import get_recent_scans, get_dashboard_stats

router = APIRouter()

@router.get("/api/dashboard/summary")
async def dashboard_summary():
    scans = await get_recent_scans(20)
    stats = await get_dashboard_stats()
    return {"recent_scans": scans, "decision_stats": stats}

@router.get("/api/scans/recent")
async def recent_scans():
    return await get_recent_scans(20)