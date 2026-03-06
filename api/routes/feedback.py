"""
Feedback Routes - API endpoints for user feedback on findings
"""
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional
from enum import Enum
import json
from pathlib import Path

router = APIRouter()

WEIGHTS_FILE = Path(__file__).parent.parent.parent / "data" / "feedback" / "rule_weights.json"


class FeedbackType(str, Enum):
    FALSE_POSITIVE = "false_positive"
    TRUE_POSITIVE = "true_positive"
    NEEDS_REVIEW = "needs_review"


class FeedbackRequest(BaseModel):
    finding_id: str
    rule_id: str
    feedback_type: FeedbackType
    comment: Optional[str] = None


@router.post("/submit")
async def submit_feedback(request: FeedbackRequest):
    """Submit feedback for a finding"""
    # Load current weights
    weights = _load_weights()
    
    # Update weight based on feedback
    if request.rule_id not in weights["weights"]:
        weights["weights"][request.rule_id] = {"score": 1.0, "feedback_count": 0}
    
    rule_weight = weights["weights"][request.rule_id]
    
    if request.feedback_type == FeedbackType.FALSE_POSITIVE:
        rule_weight["score"] = max(0.1, rule_weight["score"] - 0.1)
    elif request.feedback_type == FeedbackType.TRUE_POSITIVE:
        rule_weight["score"] = min(2.0, rule_weight["score"] + 0.05)
    
    rule_weight["feedback_count"] += 1
    weights["feedback_count"] += 1
    
    _save_weights(weights)
    
    return {"status": "success", "message": "Feedback recorded"}


@router.get("/weights")
async def get_rule_weights():
    """Get current rule weights"""
    return _load_weights()


@router.get("/stats")
async def get_feedback_stats():
    """Get feedback statistics"""
    weights = _load_weights()
    return {
        "total_feedback": weights["feedback_count"],
        "rules_with_feedback": len(weights["weights"])
    }


def _load_weights():
    try:
        with open(WEIGHTS_FILE, "r") as f:
            return json.load(f)
    except FileNotFoundError:
        return {"weights": {}, "feedback_count": 0, "last_updated": None}


def _save_weights(weights):
    from datetime import datetime
    weights["last_updated"] = datetime.now().isoformat()
    with open(WEIGHTS_FILE, "w") as f:
        json.dump(weights, f, indent=2)
