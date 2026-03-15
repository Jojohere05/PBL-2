import json
import os

SEVERITY_SCORES = {
    "CRITICAL": 25,
    "HIGH":     15,
    "MEDIUM":   8,
    "LOW":      3
}

# Must match Settings page display
THRESHOLDS = [
    (76, "BLOCK"),
    (56, "REVIEW"),
    (31, "WARN"),
    (0,  "ALLOW")
]

FB_PATH = "data/feedback/rule_weights.json"


def _load_weights() -> dict:
    try:
        with open(FB_PATH) as f:
            return json.load(f)
    except Exception:
        return {}


def _get_confidence(rule_id: str, weights: dict) -> float:
    """
    Returns 0.5–1.0 based on past false positive rate.
    Falls back to 1.0 if not enough data.
    """
    rule = weights.get(rule_id, {})
    fired = rule.get("fired", 0)
    if fired < 10:
        return 1.0
    fp_rate = rule.get("false_positive", 0) / fired
    return max(0.5, 1.0 - fp_rate)


def compute_risk(violations: list, context: dict) -> dict:
    weights   = _load_weights()
    raw_score = 0

    for v in violations:
        sev    = v.get("severity", "LOW").upper()
        base   = SEVERITY_SCORES.get(sev, 3)
        conf   = _get_confidence(v.get("rule_id", ""), weights)
        raw_score += int(base * conf)

    # Fintech amplification
    has_payment = context.get("is_fintech", False)
    has_secret  = any(
        v.get("dimension") == "data_sensitivity_risk"
        for v in violations
    )
    amplified = has_payment and has_secret
    if amplified:
        raw_score = int(raw_score * 1.3)

    score = min(raw_score, 100)

    decision = "ALLOW"
    for threshold, label in THRESHOLDS:
        if score >= threshold:
            decision = label
            break

    return {
        "score":    score,
        "decision": decision,
        "amplified": amplified
    }