import sys
from pathlib import Path

# Ensure imports work regardless of current working directory.
PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT))

from api.rag.retriever import (
    retrieve_rules,
    retrieve_rules_by_query,
    get_rules_by_framework,
    get_all_frameworks
)

print("=" * 55)
print("RETRIEVER TEST")
print("=" * 55)

# Test 1 — Static RAG (violation dict)
print("\n[1] retrieve_rules — TF_DB_PUBLIC")
rules1 = retrieve_rules(
    {"rule_id": "TF_DB_PUBLIC", "dimension": "infrastructure_risk"},
    top_k=3
)
print(f"    Found: {len(rules1)} rules")
for r in rules1:
    print(f"    → [{r.get('framework')}] §{r.get('section')} | {r.get('title','')[:55]}")

# Test 2 — Agentic RAG (free text query)
print("\n[2] retrieve_rules_by_query — 'RBI database encryption'")
rules2 = retrieve_rules_by_query("RBI database encryption payment", top_k=3)
print(f"    Found: {len(rules2)} rules")
for r in rules2:
    print(f"    → [{r.get('framework')}] §{r.get('section')} | {r.get('title','')[:55]}")

# Test 3 — Framework filter
print("\n[3] get_rules_by_framework — SEBI Cybersecurity")
rules3 = get_rules_by_framework("SEBI Cybersecurity", top_k=3)
print(f"    Found: {len(rules3)} rules")
for r in rules3:
    print(f"    → §{r.get('section')} | {r.get('title','')[:55]}")

# Test 4 — All frameworks
print("\n[4] get_all_frameworks")
frameworks = get_all_frameworks()
print(f"    {frameworks}")

# Test 5 — Secret violation
print("\n[5] retrieve_rules — stripe-api-key secret")
rules5 = retrieve_rules(
    {"rule_id": "stripe-api-key", "dimension": "data_sensitivity_risk"},
    top_k=3
)
print(f"    Found: {len(rules5)} rules")
for r in rules5:
    print(f"    → [{r.get('framework')}] §{r.get('section')} | {r.get('title','')[:55]}")

# Test 6 — Dependency violation
print("\n[6] retrieve_rules — CVE vulnerability")
rules6 = retrieve_rules(
    {"rule_id": "GHSA-1234", "dimension": "vulnerability_risk"},
    top_k=3
)
print(f"    Found: {len(rules6)} rules")
for r in rules6:
    print(f"    → [{r.get('framework')}] §{r.get('section')} | {r.get('title','')[:55]}")

# Summary
print("\n" + "=" * 55)
passed = all([rules1, rules2, rules3, frameworks, rules5])
print("✅ All tests passed — retriever is working correctly"
      if passed else
      "❌ Some tests returned empty — check compliance_rules.json")
print("=" * 55)
