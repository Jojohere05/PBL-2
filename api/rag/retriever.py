import json
import os
from pathlib import Path
from typing import List, Dict

RULES_PATH = Path(__file__).resolve().parents[2] / "data" / "rules" / "compliance_rules.json"

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
    """
    Standard RAG: retrieve top_k rules for a violation dict.
    Used for static context injection before LLM reasoning.
    """
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


def retrieve_rules_by_query(query: str, top_k: int = 3) -> List[Dict]:
    """
    Agentic RAG: retrieve rules using a free-text query.
    Called BY the orchestrator agent when it wants more specific context.
    The agent decides what to search for — not pre-mapped.
    """
    rules = _load_rules()
    if not rules or not query:
        return []

    query_words = set(
        w.lower() for w in query.replace(",", " ").split()
        if len(w) > 2
    )

    scored = []
    for rule in rules:
        text = " ".join([
            rule.get("title", ""),
            rule.get("description", ""),
            rule.get("framework", ""),
            rule.get("section", ""),
            rule.get("check", ""),
            rule.get("fix", ""),
            " ".join(rule.get("keywords", []))
        ]).lower()
        score = sum(1 for w in query_words if w in text)
        if score > 0:
            scored.append((score, rule))

    scored.sort(key=lambda x: -x[0])
    return [r for _, r in scored[:top_k]]


def get_all_frameworks() -> List[str]:
    """Returns list of unique frameworks in the compliance DB."""
    rules = _load_rules()
    return list(set(r.get("framework", "") for r in rules if r.get("framework")))


def get_rules_by_framework(framework: str, top_k: int = 5) -> List[Dict]:
    """Get rules filtered by specific framework (RBI, PCI, DPDP, SEBI)."""
    rules = _load_rules()
    matched = [r for r in rules
               if r.get("framework", "").upper() == framework.upper()]
    return matched[:top_k]


class RuleRetriever:
    """Compatibility wrapper for class-based callers (e.g., explainer)."""

    def retrieve_rules(self, violation: Dict, top_k: int = 3) -> List[Dict]:
        return retrieve_rules(violation, top_k=top_k)

    def retrieve_rules_by_query(self, query: str, top_k: int = 3) -> List[Dict]:
        return retrieve_rules_by_query(query, top_k=top_k)

    def get_all_frameworks(self) -> List[str]:
        return get_all_frameworks()

    def get_rules_by_framework(self, framework: str, top_k: int = 5) -> List[Dict]:
        return get_rules_by_framework(framework, top_k=top_k)

    def get_rule_context(self, rule_id: str) -> Dict:
        """Return context dict expected by explainer for a rule id."""
        if not rule_id:
            return {}
        rid = rule_id.lower()
        for rule in _load_rules():
            candidate = str(rule.get("id", "")).lower()
            if candidate == rid:
                return {
                    "rule": rule,
                    "remediation": rule.get("fix", ""),
                    "references": rule.get("references", []),
                }
        return {}

    def get_vulnerability_context(self, vuln_id: str) -> Dict:
        """Fallback vulnerability context using compliance rule match."""
        return self.get_rule_context(vuln_id)


def create_retriever() -> RuleRetriever:
    """Factory for class-based retriever usage."""
    return RuleRetriever()