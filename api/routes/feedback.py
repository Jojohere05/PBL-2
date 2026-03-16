import json
import os
from fastapi import APIRouter

router  = APIRouter()
FB_PATH = "data/feedback/rule_weights.json"

def _load():
    try:
        with open(FB_PATH) as f:
            return json.load(f)
    except:
        return {}

def _save(d):
    os.makedirs(os.path.dirname(FB_PATH), exist_ok=True)
    with open(FB_PATH, "w") as f:
        json.dump(d, f, indent=2)

@router.post("/api/feedback")
def submit_feedback(rule_id: str, is_false_positive: bool):
    w = _load()
    if rule_id not in w:
        w[rule_id] = {"fired": 0, "confirmed": 0, "false_positive": 0}
    w[rule_id]["fired"] += 1
    if is_false_positive:
        w[rule_id]["false_positive"] += 1
    else:
        w[rule_id]["confirmed"] += 1
    _save(w)
    return {"status": "ok", "rule_id": rule_id, "weights": w[rule_id]}