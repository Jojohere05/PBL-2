"""
RAG Retriever — retrieves compliance rules relevant to violations.

Standalone version for CLI usage. Resolves compliance_rules.json
relative to project root.
"""

import json
import os
from pathlib import Path
from typing import List, Dict

# Resolve relative to monorepo root (PBL-2/)
# __file__ = <repo>/finguard/rag/retriever.py → go three levels up
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
RULES_PATH = os.path.join(_PROJECT_ROOT, "data", "rules", "compliance_rules.json")

KEYWORD_MAP = {
    "TF_DB_PUBLIC":                ["database","public","network",
                                    "rbi","customer data","accessible"],
    "TF_S3_PUBLIC_ACL":            ["storage","s3","public","dpdp"],
    "TF_S3_PUBLIC_BLOCK_DISABLED": ["s3","public","access control"],
    "TF_SG_OPEN_INGRESS":          ["network","firewall","ingress","sebi"],
    "TF_RDS_ENCRYPTION_MISSING":   ["encryption","rds","rbi","pci"],
    "TF_EBS_NOT_ENCRYPTED":        ["encryption","ebs","pci","dpdp"],
    "TF_STORAGE_UNENCRYPTED":      ["encryption","storage","pci","rbi"],
    "TF_ENCRYPT_AT_REST_DISABLED": ["encryption","at rest","pci","rbi"],
    "TF_SNS_SQS_NO_KMS":           ["kms","sns","sqs","encryption"],
    "data_sensitivity_risk":       ["secret","credential","api key",
                                    "pci","dpdp","sensitive","token"],
    "vulnerability_risk":          ["vulnerability","cve","patch",
                                    "sebi","dependency","outdated"],
    "infrastructure_risk":         ["infrastructure","cloud","rbi",
                                    "network","aws","terraform"],
}

_rules_cache: List[Dict] = None


def _load_rules() -> List[Dict]:
    global _rules_cache
    if _rules_cache is None:
        try:
            with open(RULES_PATH) as f:
                _rules_cache = json.load(f)
        except Exception as e:
            print(f"[RAG] Warning: could not load rules: {e}")
            _rules_cache = []
    return _rules_cache


def retrieve_rules(violation: Dict, top_k: int = 3) -> List[Dict]:
    rules     = _load_rules()
    rule_id   = violation.get("rule_id", "")
    dimension = violation.get("dimension", "")

    keywords = set()
    for key, kws in KEYWORD_MAP.items():
        if key in rule_id or key in dimension:
            keywords.update(kws)
    for part in rule_id.lower().replace("_", " ").split():
        if len(part) > 2:
            keywords.add(part)

    if not keywords or not rules:
        return []

    scored = []
    for rule in rules:
        text = " ".join([
            rule.get("title", ""),
            rule.get("description", ""),
            rule.get("section", ""),
            rule.get("check", ""),
            " ".join(rule.get("keywords", []))
        ]).lower()
        score = sum(1 for kw in keywords if kw in text)
        if score > 0:
            scored.append((score, rule))

    scored.sort(key=lambda x: -x[0])
    return [r for _, r in scored[:top_k]]


class RuleRetriever:
    """Compatibility wrapper for class-based callers."""

    def retrieve_rules(self, violation: Dict, top_k: int = 3) -> List[Dict]:
        return retrieve_rules(violation, top_k=top_k)
