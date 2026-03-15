import json
import os
import re

errors = []

print("=" * 60)
print("FINGUARD DATASET VALIDATION")
print("=" * 60)

# ── 1. Compliance Rules ───────────────────────────────────────────
print("\n[1] Compliance Rules")
try:
    with open("data/rules/compliance_rules.json") as f:
        rules = json.load(f)
    assert len(rules) > 0, "Empty rules list"
    frameworks = set(r.get("framework", "") for r in rules)
    sevs = {s: sum(1 for r in rules if r.get("severity") == s)
            for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]}
    print(f"  ✅ {len(rules)} rules loaded")
    print(f"     Frameworks : {sorted(frameworks)}")
    print(f"     Severities : {sevs}")
    missing_fields = [r for r in rules if not r.get("id") or not r.get("title")]
    if missing_fields:
        print(f"  ⚠ {len(missing_fields)} rules missing id or title")
except Exception as e:
    print(f"  ❌ FAILED: {e}")
    errors.append("compliance_rules")

# ── 2. Gitleaks Rules ─────────────────────────────────────────────
print("\n[2] Gitleaks Rules")
try:
    with open("data/gitleaks/gitleaks_rules.json") as f:
        gl_rules = json.load(f)
    assert len(gl_rules) > 0, "Empty rules list"
    bad_regex = 0
    for r in gl_rules:
        try:
            re.compile(r.get("regex", ""))
        except re.error:
            bad_regex += 1
    sevs = {s: sum(1 for r in gl_rules if r.get("severity") == s)
            for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]}
    print(f"  ✅ {len(gl_rules)} rules loaded")
    print(f"     Bad regex  : {bad_regex}")
    print(f"     Severities : {sevs}")
    if bad_regex > 0:
        print(f"  ⚠ {bad_regex} rules have invalid regex — will be skipped")
except Exception as e:
    print(f"  ❌ FAILED: {e}")
    errors.append("gitleaks_rules")

# ── 3. OSV Database ───────────────────────────────────────────────
print("\n[3] OSV Database")
try:
    osv_dir = "data/osv"
    assert os.path.exists(osv_dir), f"{osv_dir} does not exist"
    files = [f for f in os.listdir(osv_dir) if f.endswith(".json")]
    assert len(files) > 0, "No JSON files in data/osv/"

    ecosystems = {}
    bad_files  = 0
    sample_pkgs = []

    for fname in files[:300]:  # sample 300
        try:
            with open(os.path.join(osv_dir, fname)) as f:
                d = json.load(f)
            for aff in d.get("affected", []):
                pkg = aff.get("package", {})
                eco = pkg.get("ecosystem", "unknown")
                ecosystems[eco] = ecosystems.get(eco, 0) + 1
                if len(sample_pkgs) < 5:
                    sample_pkgs.append(
                        f"{pkg.get('name')} ({eco})"
                    )
        except Exception:
            bad_files += 1

    top_eco = sorted(ecosystems.items(), key=lambda x: -x[1])[:5]
    print(f"  ✅ {len(files)} OSV files found")
    print(f"     Bad files (sample) : {bad_files}")
    print(f"     Top ecosystems     : {top_eco}")
    print(f"     Sample packages    : {sample_pkgs}")
except Exception as e:
    print(f"  ❌ FAILED: {e}")
    errors.append("osv_database")

# ── 4. Feedback file (auto-create if missing) ─────────────────────
print("\n[4] Feedback Weights")
fb_path = "data/feedback/rule_weights.json"
try:
    os.makedirs("data/feedback", exist_ok=True)
    if not os.path.exists(fb_path):
        with open(fb_path, "w") as f:
            json.dump({}, f)
        print(f"  ✅ Created empty {fb_path}")
    else:
        with open(fb_path) as f:
            fb = json.load(f)
        print(f"  ✅ {len(fb)} rule weights loaded")
except Exception as e:
    print(f"  ❌ FAILED: {e}")
    errors.append("feedback")

# ── Summary ───────────────────────────────────────────────────────
print("\n" + "=" * 60)
if errors:
    print(f"❌ FAILED: Fix these before running — {errors}")
else:
    print("✅ ALL DATASETS VALID — ready to run pipeline")
    print("\nNext step:")
    print("  uvicorn api.main:app --reload --port 8000")
print("=" * 60)