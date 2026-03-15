import json, os, sys, re

try:
    import tomllib
except ImportError:
    try:
        import tomli as tomllib
    except ImportError:
        print("Run: pip install tomli")
        sys.exit(1)

FINTECH_CRITICAL = [
    "stripe","razorpay","aws","gcp","github","private_key",
    "jwt","twilio","sendgrid","plaid","upi","payment"
]

def convert():
    with open("data/raw/gitleaks.toml", "rb") as f:
        data = tomllib.load(f)

    rules = []
    skipped = 0

    for rule in data.get("rules", []):
        regex = rule.get("regex","") or rule.get("pattern","")
        if not regex:
            continue

        # ── Fix \z (Ruby end-of-string) → \Z (Python equivalent) ──
        regex = regex.replace("\\z", "\\Z")

        # ── Validate regex is compilable in Python ──
        try:
            re.compile(regex)
        except re.error:
            skipped += 1
            continue

        tags     = [t.lower() for t in rule.get("tags", [])]
        severity = "HIGH"
        if any(t in tags for t in ["critical","high"]):
            severity = "CRITICAL"
        elif "medium" in tags:
            severity = "MEDIUM"
        elif "low" in tags:
            severity = "LOW"

        rule_id = rule.get("id", rule.get("description","UNKNOWN"))
        if any(kw in rule_id.lower() for kw in FINTECH_CRITICAL):
            severity = "CRITICAL"

        rules.append({
            "id":          rule_id,
            "regex":       regex,
            "severity":    severity,
            "description": rule.get("description",""),
            "tags":        tags
        })

    os.makedirs("data/gitleaks", exist_ok=True)
    with open("data/gitleaks/gitleaks_rules.json","w") as f:
        json.dump(rules, f, indent=2)

    from collections import Counter
    counts = Counter(r["severity"] for r in rules)
    print(f"✅ {len(rules)} gitleaks rules saved (skipped {skipped} bad regex)")
    print(f"   CRITICAL:{counts['CRITICAL']} HIGH:{counts['HIGH']} "
          f"MEDIUM:{counts['MEDIUM']} LOW:{counts['LOW']}")

if __name__ == "__main__":
    convert()
