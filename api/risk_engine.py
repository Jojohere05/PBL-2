"""
Risk Engine - Calculates risk scores for findings
"""
from typing import List, Dict, Any
import json
from pathlib import Path


WEIGHTS_FILE = Path(__file__).parent.parent / "data" / "feedback" / "rule_weights.json"

# Base severity weights
SEVERITY_WEIGHTS = {
    "critical": 10.0,
    "high": 7.0,
    "medium": 4.0,
    "low": 1.0
}

# Finding type weights
TYPE_WEIGHTS = {
    "secret": 1.5,  # Secrets are high priority
    "dependency": 1.2,
    "terraform": 1.0
}


def calculate_risk_score(findings: List[Dict[str, Any]]) -> int:
    """
    Calculate overall risk score (0-100) based on findings
    
    Factors:
    - Number and severity of findings
    - Type of findings
    - Feedback-adjusted rule weights
    """
    if not findings:
        return 0
    
    # Load feedback weights
    rule_weights = _load_rule_weights()
    
    total_score = 0
    max_possible_score = 0
    
    for finding in findings:
        severity = finding.get("severity", "medium")
        finding_type = finding.get("type", "unknown")
        rule_id = finding.get("rule_id", "")
        
        # Base score from severity
        base_score = SEVERITY_WEIGHTS.get(severity, 4.0)
        
        # Adjust by type
        type_multiplier = TYPE_WEIGHTS.get(finding_type, 1.0)
        
        # Adjust by feedback weight
        feedback_multiplier = rule_weights.get(rule_id, {}).get("score", 1.0)
        
        # Calculate finding score
        finding_score = base_score * type_multiplier * feedback_multiplier
        total_score += finding_score
        
        # Track max possible (for normalization)
        max_possible_score += 10.0 * 1.5  # Critical + secret type
    
    # Normalize to 0-100 scale
    if max_possible_score == 0:
        return 0
    
    # Use logarithmic scaling for better distribution
    import math
    normalized_score = (total_score / max_possible_score) * 100
    
    # Apply logarithmic curve for more meaningful scores
    if normalized_score > 0:
        # Scale so that a few critical findings quickly raise score
        risk_score = min(100, int(30 * math.log10(1 + normalized_score)))
    else:
        risk_score = 0
    
    # Ensure minimum scores based on critical/high findings
    critical_count = len([f for f in findings if f.get("severity") == "critical"])
    high_count = len([f for f in findings if f.get("severity") == "high"])
    
    if critical_count > 0:
        risk_score = max(risk_score, min(100, 50 + critical_count * 10))
    elif high_count > 0:
        risk_score = max(risk_score, min(80, 30 + high_count * 5))
    
    return min(100, risk_score)


def get_risk_level(score: int) -> str:
    """Get risk level label from score"""
    if score >= 80:
        return "critical"
    elif score >= 60:
        return "high"
    elif score >= 40:
        return "medium"
    elif score >= 20:
        return "low"
    else:
        return "minimal"


def get_risk_breakdown(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Get detailed risk breakdown"""
    breakdown = {
        "by_severity": {},
        "by_type": {},
        "top_rules": [],
        "recommendations": []
    }
    
    # Count by severity
    for severity in ["critical", "high", "medium", "low"]:
        count = len([f for f in findings if f.get("severity") == severity])
        breakdown["by_severity"][severity] = {
            "count": count,
            "contribution": count * SEVERITY_WEIGHTS.get(severity, 1.0)
        }
    
    # Count by type
    type_counts = {}
    for finding in findings:
        finding_type = finding.get("type", "unknown")
        type_counts[finding_type] = type_counts.get(finding_type, 0) + 1
    
    for finding_type, count in type_counts.items():
        breakdown["by_type"][finding_type] = {
            "count": count,
            "contribution": count * TYPE_WEIGHTS.get(finding_type, 1.0)
        }
    
    # Top rules by occurrence
    rule_counts = {}
    for finding in findings:
        rule_id = finding.get("rule_id", "unknown")
        rule_counts[rule_id] = rule_counts.get(rule_id, 0) + 1
    
    top_rules = sorted(rule_counts.items(), key=lambda x: x[1], reverse=True)[:5]
    breakdown["top_rules"] = [{"rule_id": r[0], "count": r[1]} for r in top_rules]
    
    # Recommendations
    if breakdown["by_severity"].get("critical", {}).get("count", 0) > 0:
        breakdown["recommendations"].append({
            "priority": "immediate",
            "message": "Address critical findings immediately - they pose immediate security risk"
        })
    
    if breakdown["by_type"].get("secret", {}).get("count", 0) > 0:
        breakdown["recommendations"].append({
            "priority": "high",
            "message": "Rotate exposed secrets and implement secrets management"
        })
    
    if breakdown["by_type"].get("dependency", {}).get("count", 0) > 0:
        breakdown["recommendations"].append({
            "priority": "medium",
            "message": "Update vulnerable dependencies to patched versions"
        })
    
    return breakdown


def _load_rule_weights() -> Dict[str, Dict]:
    """Load feedback-adjusted rule weights"""
    try:
        with open(WEIGHTS_FILE, "r") as f:
            data = json.load(f)
            return data.get("weights", {})
    except (FileNotFoundError, json.JSONDecodeError):
        return {}
