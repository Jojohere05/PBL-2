"""
Dashboard Routes - API endpoints for dashboard data
"""
from fastapi import APIRouter
from typing import Optional
from datetime import datetime, timedelta

router = APIRouter()


@router.get("/summary")
async def get_dashboard_summary():
    """Get overall security summary"""
    return {
        "total_scans": 0,
        "critical_findings": 0,
        "high_findings": 0,
        "medium_findings": 0,
        "low_findings": 0,
        "avg_risk_score": 0.0,
        "last_scan": None
    }


@router.get("/trends")
async def get_security_trends(days: Optional[int] = 30):
    """Get security trends over time"""
    return {
        "period_days": days,
        "findings_trend": [],
        "risk_score_trend": []
    }


@router.get("/top-vulnerabilities")
async def get_top_vulnerabilities(limit: Optional[int] = 10):
    """Get top vulnerabilities across all scans"""
    return {
        "vulnerabilities": []
    }


@router.get("/compliance-status")
async def get_compliance_status():
    """Get compliance status overview"""
    return {
        "frameworks": [],
        "overall_compliance": 0.0
    }


@router.get("/recent-scans")
async def get_recent_scans(limit: Optional[int] = 5):
    """Get recent scan history"""
    return {
        "scans": []
    }
