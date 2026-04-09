"""
RAG Explainer — generates explanations for violations.

Standalone version for CLI usage. Falls back to deterministic
explanations when no API key is present (no external API calls
in GitHub Actions).
"""

import asyncio
import os
import random
from typing import Any

from .retriever import RuleRetriever


# ── Helpers ──────────────────────────────────────────────

def _sanitize(value: Any, fallback: str) -> str:
    val = str(value or "").strip()
    return val if val else fallback


def _rule_summary(rules):
    if not rules:
        return "Applicable compliance standards"
    return " | ".join([
        f"{r.get('framework')} §{r.get('section')}"
        for r in rules[:2]
    ])


# ── Contextual Engine (Rule-Based, Deterministic) ───────

_SECRETS_WHAT = [
    "The value at line {line} of {file} matches the {rule_id} pattern with high entropy, indicating a real credential is hardcoded.",
    "{file} contains a hardcoded {rule_id} — the matched value at line {line} has structural characteristics of an active key.",
    "A live {rule_id} credential is embedded directly in {context} ({file}), detectable via pattern match and entropy analysis.",
    "Source code in {file} exposes a {rule_id} value at line {line} that passes entropy thresholds for real secrets.",
]

_SECRETS_FIX = [
    "Remove `{preview}` from {file}, rotate the credential immediately in your provider dashboard, then inject via environment variable.",
    "Delete the hardcoded value at line {line} of {file}, revoke and reissue the credential, and reference it via `os.environ['KEY']` or AWS Secrets Manager.",
    "Rotate this {rule_id} credential immediately (assume it is compromised), remove line {line} from {file}, and use a secrets manager going forward.",
    "Replace the literal value in {file} line {line} with an environment variable reference. Rotate the credential — treat it as already leaked.",
]

_INFRA_WHAT = [
    "{file} defines a resource with `{rule_id}` set in a way that exposes it to public network access.",
    "Terraform configuration in {file} has a misconfiguration flagged by {rule_id} — this weakens the network security boundary.",
    "The {rule_id} check failed on {file}: a resource is configured without the required security control.",
    "{file} contains an infrastructure resource that violates {rule_id} — the configuration allows unintended public exposure.",
]

_INFRA_FIX = [
    "In {file}, locate the flagged resource block and set the appropriate attribute to enforce private access or encryption.",
    "Update {file} to correct the {rule_id} misconfiguration — enforce private subnets, restrict CIDRs, or enable encryption as required.",
    "Fix the resource in {file} that triggered {rule_id}: apply the least-privilege network or encryption setting and re-run terraform plan.",
    "Add the missing security attribute to the resource in {file}. For {rule_id}, consult the matched regulation's infrastructure requirement.",
]

_DEP_FIX = [
    "Upgrade {pkg} from {version} to a patched release listed in OSV advisory {rule_id}.",
    "Pin {pkg} to a non-vulnerable version in your dependency file. Advisory {rule_id} lists the safe version range.",
    "Run `pip install --upgrade {pkg}` (or npm equivalent) and verify the installed version is outside the {rule_id} affected range.",
]


def _contextual_explanation(v: dict, rules: list[dict]) -> dict:
    rule_id = str(v.get("rule_id", "unknown"))
    file = str(v.get("file", "unknown"))
    preview = str(v.get("line_preview", "")).strip()[:40]
    dimension = str(v.get("dimension", ""))
    severity = str(v.get("adjusted_severity", v.get("severity", "")))
    line = v.get("line") or "N/A"
    rule_text = _rule_summary(rules)

    context = "application code"
    if "controller" in file: context = "API controller"
    elif "model" in file: context = "data model"
    elif "config" in file: context = "configuration file"
    elif ".tf" in file: context = "Terraform infrastructure"

    if dimension == "data_sensitivity_risk":
        impact = "credential exposure and unauthorized system access"
        if any(k in file for k in ("payment", "transaction", "upi", "card")):
            impact = "direct financial fraud and RBI penalty exposure up to ₹5 crore"
        elif any(k in rule_id.lower() for k in ("aws", "gcp", "azure")):
            impact = "full cloud account compromise — all hosted data and services at risk"
        elif any(k in rule_id.lower() for k in ("stripe", "razorpay")):
            impact = "payment processor abuse — unauthorized charges and PCI-DSS violation"

        return {
            "what_it_means": random.choice(_SECRETS_WHAT).format(
                rule_id=rule_id, file=file, line=line, context=context
            ),
            "regulation_violated": f"{rule_text} — credentials must not be stored in source code",
            "business_impact": impact,
            "exact_fix": random.choice(_SECRETS_FIX).format(
                rule_id=rule_id, file=file, line=line, preview=preview
            ),
        }

    if dimension == "vulnerability_risk":
        pkg = v.get("package", "package")
        version = v.get("installed_version", "unknown")
        return {
            "what_it_means": f"{pkg}@{version} is listed in OSV advisory {rule_id} as vulnerable. Any application importing this package inherits the vulnerability.",
            "regulation_violated": f"{rule_text} — known vulnerabilities must be remediated before deployment",
            "business_impact": f"Exploiting {rule_id} in {pkg} could compromise application integrity or expose user data to attackers.",
            "exact_fix": random.choice(_DEP_FIX).format(
                pkg=pkg, version=version, rule_id=rule_id
            ),
        }

    if dimension == "infrastructure_risk":
        return {
            "what_it_means": random.choice(_INFRA_WHAT).format(
                rule_id=rule_id, file=file
            ),
            "regulation_violated": f"{rule_text} — secure infrastructure configuration required",
            "business_impact": f"This misconfiguration in {file} can expose internal services, data, or compute resources to the public internet.",
            "exact_fix": random.choice(_INFRA_FIX).format(
                rule_id=rule_id, file=file
            ),
        }

    return {
        "what_it_means": f"{rule_id} detected in {file} at line {line}.",
        "regulation_violated": rule_text,
        "business_impact": "May introduce security and compliance risks specific to the affected component.",
        "exact_fix": f"Review {file} line {line} and remediate according to the matched regulation.",
    }


# ── Main ─────────────────────────────────────────────────

async def explain_violation(v, retriever, use_llm: bool = False):
    """Explain a single violation using deterministic rules.
    LLM is disabled by default for offline CI usage.
    """
    rules = retriever.retrieve_rules(v, top_k=3)

    base = _contextual_explanation(v, rules)
    explanation = {
        "what_it_means": _sanitize(base["what_it_means"], ""),
        "regulation_violated": _sanitize(base["regulation_violated"], ""),
        "business_impact": _sanitize(base["business_impact"], ""),
        "exact_fix": _sanitize(base["exact_fix"], ""),
    }

    return {
        **v,
        "explanation": explanation,
        "matched_rules": rules,
        "llm_enriched": False,
    }


async def explain_all(findings):
    """Explain a batch of findings deterministically (no LLM)."""
    if not findings:
        return []

    retriever = RuleRetriever()

    tasks = [
        explain_violation(v, retriever, use_llm=False)
        for v in findings
    ]
    return await asyncio.gather(*tasks)
