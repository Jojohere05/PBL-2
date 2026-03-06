"""
Database - SQLite/PostgreSQL database for storing scan results
"""
from typing import Optional, List, Dict, Any
import os
from datetime import datetime

# Use SQLite for development, PostgreSQL for production
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./finguard.db")

# Simple in-memory storage for development
_scans_db: Dict[str, Dict] = {}
_findings_db: Dict[str, List[Dict]] = {}
_feedback_db: List[Dict] = []


async def init_db():
    """Initialize database connection"""
    # For production, initialize SQLAlchemy or another ORM
    print("Database initialized")


async def create_scan(
    scan_id: str,
    repo_url: str,
    branch: str,
    trigger: str,
    status: str = "pending"
) -> Dict:
    """Create a new scan record"""
    scan = {
        "id": scan_id,
        "repo_url": repo_url,
        "branch": branch,
        "trigger": trigger,
        "status": status,
        "created_at": datetime.utcnow().isoformat(),
        "updated_at": datetime.utcnow().isoformat(),
        "completed_at": None,
        "summary": None
    }
    _scans_db[scan_id] = scan
    return scan


async def update_scan(scan_id: str, **kwargs) -> Optional[Dict]:
    """Update scan record"""
    if scan_id not in _scans_db:
        return None
    
    _scans_db[scan_id].update(kwargs)
    _scans_db[scan_id]["updated_at"] = datetime.utcnow().isoformat()
    return _scans_db[scan_id]


async def get_scan(scan_id: str) -> Optional[Dict]:
    """Get scan by ID"""
    return _scans_db.get(scan_id)


async def get_scans(
    limit: int = 10,
    offset: int = 0,
    repo_url: Optional[str] = None
) -> List[Dict]:
    """Get list of scans"""
    scans = list(_scans_db.values())
    
    if repo_url:
        scans = [s for s in scans if s["repo_url"] == repo_url]
    
    scans.sort(key=lambda x: x["created_at"], reverse=True)
    return scans[offset:offset + limit]


async def create_findings(scan_id: str, findings: List[Dict]) -> int:
    """Store findings for a scan"""
    _findings_db[scan_id] = findings
    return len(findings)


async def get_findings(
    scan_id: str,
    severity: Optional[str] = None,
    finding_type: Optional[str] = None
) -> List[Dict]:
    """Get findings for a scan"""
    findings = _findings_db.get(scan_id, [])
    
    if severity:
        findings = [f for f in findings if f.get("severity") == severity]
    
    if finding_type:
        findings = [f for f in findings if f.get("type") == finding_type]
    
    return findings


async def create_feedback(
    finding_id: str,
    rule_id: str,
    feedback_type: str,
    comment: Optional[str] = None
) -> Dict:
    """Store feedback for a finding"""
    feedback = {
        "id": len(_feedback_db) + 1,
        "finding_id": finding_id,
        "rule_id": rule_id,
        "feedback_type": feedback_type,
        "comment": comment,
        "created_at": datetime.utcnow().isoformat()
    }
    _feedback_db.append(feedback)
    return feedback


async def get_feedback_for_rule(rule_id: str) -> List[Dict]:
    """Get all feedback for a rule"""
    return [f for f in _feedback_db if f["rule_id"] == rule_id]


async def get_scan_statistics() -> Dict:
    """Get overall scan statistics"""
    total_scans = len(_scans_db)
    completed_scans = len([s for s in _scans_db.values() if s["status"] == "completed"])
    
    all_findings = []
    for findings in _findings_db.values():
        all_findings.extend(findings)
    
    severity_counts = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0
    }
    
    for finding in all_findings:
        severity = finding.get("severity", "medium")
        severity_counts[severity] = severity_counts.get(severity, 0) + 1
    
    return {
        "total_scans": total_scans,
        "completed_scans": completed_scans,
        "total_findings": len(all_findings),
        "by_severity": severity_counts
    }


def get_db():
    """Get database session (for dependency injection)"""
    # Return session for SQLAlchemy in production
    return None
