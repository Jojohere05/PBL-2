import pandas as pd
import json
import os

# ── Correct column names matching YOUR dataset ────────────────────────────────
COL_MAP = {
    "Rule ID":               "id",
    "Regulation":            "framework",      # was "Framework" — WRONG
    "Section":               "section",
    "Requirement Text":      "title",          # was "Title" — WRONG
    "Infra Interpretation":  "description",    # was "Description" — WRONG
    "Violation Example":     "check",          # was "Check" — WRONG
    "Keywords":              "keywords",
    # NOTE: your dataset has no Severity or Remediation columns
}

# Severity override: no Severity column in your dataset, assign by framework
FRAMEWORK_SEVERITY = {
    "RBI-PA-PG-2020":       "CRITICAL",
    "PCI-DSS v4":           "HIGH",
    "DPDP Rules 2025":      "HIGH",
    "SEBI Cybersecurity":   "HIGH",
}

def convert():
    df = pd.read_excel("data/raw/compliance.xlsx")
    df.columns = [c.strip() for c in df.columns]
    df = df.rename(columns=COL_MAP)

    # Remove duplicates (SEBI rows are duplicated in your dataset)
    df = df.drop_duplicates(subset=["id"]).reset_index(drop=True)
    print(f"Total rules after dedup: {len(df)}")

    rules = []
    for _, row in df.iterrows():
        kw_raw = str(row.get("keywords", ""))
        framework = str(row.get("framework", "")).strip()

        # Build richer description for RAG keyword matching
        title = str(row.get("title", "")).strip()
        desc  = str(row.get("description", "")).strip()
        full_desc = title
        if desc and desc != "nan":
            full_desc += f" Infra: {desc}."

        # Assign severity: no column in dataset so use framework default
        severity = FRAMEWORK_SEVERITY.get(framework, "HIGH")

        rules.append({
            "id":          str(row.get("id", f"RULE-{_}")).strip(),
            "framework":   framework,
            "section":     str(row.get("section",   "")).strip(),
            "title":       title,
            "description": full_desc,
            "severity":    severity,
            "check":       str(row.get("check", "")).strip(),
            "fix":         str(row.get("description", "")).strip(),  # infra interpretation = best fix hint
            "keywords":    [k.strip().lower() for k in kw_raw.split(",") if k.strip() and k.strip() != "nan"]
        })

    os.makedirs("data/rules", exist_ok=True)
    with open("data/rules/compliance_rules.json", "w") as f:
        json.dump(rules, f, indent=2)

    from collections import Counter
    fw_counts  = Counter(r["framework"] for r in rules)
    sev_counts = Counter(r["severity"]  for r in rules)

    print(f"✅ Saved {len(rules)} rules → data/rules/compliance_rules.json")
    print(f"\nBy framework: {dict(fw_counts)}")
    print(f"By severity:  {dict(sev_counts)}")
    print("\nSample:")
    print(json.dumps(rules[0], indent=2))

if __name__ == "__main__":
    convert()
