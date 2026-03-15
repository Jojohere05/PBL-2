import os
import re
import json

RULES_PATH  = "data/gitleaks/gitleaks_rules.json"
SKIP_EXT    = {".png",".jpg",".jpeg",".gif",".svg",".ico",
               ".zip",".tar",".gz",".woff",".ttf",".eot",
               ".mp4",".mp3",".bin",".exe",".dll"}
SKIP_DIRS   = {".git","node_modules","__pycache__",".venv","venv"}
MAX_FILE_SIZE = 1_000_000


def scan_files_for_secrets(repo_path: str) -> dict:
    """
    Scans all text files for secret leaks using gitleaks regex rules.
    Returns raw violations — no LLM, no decisions.
    """
    try:
        with open(RULES_PATH) as f:
            rules = json.load(f)
    except Exception as e:
        return {"violations": [], "count": 0,
                "error": f"Cannot load gitleaks rules: {e}"}

    compiled = []
    for rule in rules:
        pattern = rule.get("regex", "")
        if not pattern:
            continue
        try:
            compiled.append({
                "id":       rule.get("id", "unknown"),
                "pattern":  re.compile(pattern),
                "severity": rule.get("severity", "HIGH")
            })
        except re.error:
            continue

    violations = []
    for root, dirs, files in os.walk(repo_path):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for fname in files:
            ext = os.path.splitext(fname)[1].lower()
            if ext in SKIP_EXT:
                continue
            fpath = os.path.join(root, fname)
            try:
                if os.path.getsize(fpath) > MAX_FILE_SIZE:
                    continue
                with open(fpath, "r", errors="ignore") as f:
                    lines = f.readlines()
            except Exception:
                continue

            for rule in compiled:
                for lineno, line in enumerate(lines, 1):
                    if rule["pattern"].search(line):
                        violations.append({
                            "rule_id":   rule["id"],
                            "file":      os.path.relpath(fpath, repo_path),
                            "line":      lineno,
                            "severity":  rule["severity"],
                            "dimension": "data_sensitivity_risk",
                            "message":   f"Pattern '{rule['id']}' matched",
                            "line_content": line.strip()[:120]
                        })
                        break  # one match per rule per file
    return {"violations": violations, "count": len(violations)}