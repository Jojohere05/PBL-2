import asyncio
import json
import os
from typing import Any

import httpx

from .retriever import RuleRetriever


# -------------------------
# HELPERS
# -------------------------

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


# -------------------------
# CONTEXTUAL ENGINE (RULE-BASED BASELINE)
# -------------------------

import random

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

# -------------------------
# GROQ LLM INTEGRATION
# -------------------------

_GROQ_API_KEY = os.getenv("GROQ_API_KEY")
_GROQ_MODEL = os.getenv("GROQ_MODEL", "llama-3.1-8b-instant")
_GROQ_TIMEOUT = float(os.getenv("GROQ_TIMEOUT", "10"))


async def _groq_explain(v: dict, rules: list[dict], sem: asyncio.Semaphore) -> dict[str, str] | None:
    if not _GROQ_API_KEY:
        return None

    file = str(v.get("file", "unknown"))
    line = v.get("line") or "N/A"
    rule_id = str(v.get("rule_id", "unknown"))
    severity = str(v.get("adjusted_severity", v.get("severity", "")))
    dimension = str(v.get("dimension", ""))
    preview = str(v.get("line_preview", "")).strip()[:160]

    rules_text = "\n".join(
        [
            f"- [{r.get('framework')}] §{r.get('section')}: {r.get('title')} — {r.get('description')}"
            for r in rules
        ]
    ) or "(No specific rules matched; rely on general security best practices.)"

    user_prompt = f"""
FinGuard is a compliance scanner for Indian fintech startups. 
Deterministic agents have ALREADY decided this is a violation. 
Your ONLY job is to explain that decision clearly.

You are a security and compliance expert for RBI IT Framework, PCI-DSS, DPDP Act 2023, and SEBI Cybersecurity Guidelines.

TASK:
- Explain this specific violation in a way that a backend developer and a non-technical compliance officer can both understand.
- Make the explanation concrete to THIS file, THIS line, and THIS rule.

RESPONSE FORMAT (STRICT JSON, no markdown, no extra keys):
{{
  "what_it_means": "...",
  "regulation_violated": "...",
  "business_impact": "...",
  "exact_fix": "..."
}}

Repository context:
- file: {file}
- line: {line}
- rule_id: {rule_id}
- severity: {severity}
- dimension: {dimension}
- code_or_config_snippet: {preview}

Matched compliance rules (Indian + PCI/DPDP/SEBI/RBI):
{rules_text}

Guidelines:
- In what_it_means, explicitly name the file, line, and rule_id (for example: "In terraform/aws/db-app.tf at line 12, rule TF_DB_PUBLIC means ...").
- In regulation_violated, mention at least one concrete section (for example: "RBI IT Framework §4.2" or "PCI-DSS v4 §8.6.1") taken from the matched rules.
- In business_impact, describe impact in Indian fintech terms (RBI penalties, DPDP liability, SEBI actions, loss of UPI/card/payment trust).
- In exact_fix, give the precise code or Terraform change (mention the attribute to change, or that the secret must move to env vars / KMS / Secrets Manager).
- Do NOT talk about probabilities; the violation is already confirmed. Focus on clear, actionable remediation.
""".strip()

    payload = {
        "model": _GROQ_MODEL,
        "messages": [
            {
                "role": "system",
                "content": (
                    "You are a precise security and compliance assistant. "
                    "You always return STRICT JSON, no markdown, no extra text."
                ),
            },
            {"role": "user", "content": user_prompt},
        ],
        "temperature": 0.2,
        "max_tokens": 512,
        "response_format": {"type": "json_object"},
    }

    async with sem:
        try:
            async with httpx.AsyncClient(timeout=_GROQ_TIMEOUT) as client:
                resp = await client.post(
                    "https://api.groq.com/openai/v1/chat/completions",
                    headers={
                        "Authorization": f"Bearer {_GROQ_API_KEY}",
                        "Content-Type": "application/json",
                    },
                    json=payload,
                )
            resp.raise_for_status()
            data = resp.json()
            content = data["choices"][0]["message"]["content"]
            parsed = json.loads(content)
        except Exception:
            return None

    return {
        "what_it_means": _sanitize(parsed.get("what_it_means"), ""),
        "regulation_violated": _sanitize(parsed.get("regulation_violated"), ""),
        "business_impact": _sanitize(parsed.get("business_impact"), ""),
        "exact_fix": _sanitize(parsed.get("exact_fix"), ""),
    }


# -------------------------
# MAIN
# -------------------------

async def explain_violation(v, retriever, sem, use_llm: bool = True):
    """Explain a single violation.

    If use_llm is False or Groq fails/disabled, falls back to deterministic
    rule-based explanation.
    """

    rules = retriever.retrieve_rules(v, top_k=3)

    llm_explanation = None
    if use_llm:
        llm_explanation = await _groq_explain(v, rules, sem)

    if llm_explanation is None:
        base = _contextual_explanation(v, rules)
        explanation = {
            "what_it_means": _sanitize(base["what_it_means"], ""),
            "regulation_violated": _sanitize(base["regulation_violated"], ""),
            "business_impact": _sanitize(base["business_impact"], ""),
            "exact_fix": _sanitize(base["exact_fix"], ""),
        }
        llm_flag = False
    else:
        explanation = llm_explanation
        llm_flag = True

    return {
        **v,
        "explanation": explanation,
        "matched_rules": rules,
        "llm_enriched": llm_flag,
    }


async def explain_all(findings):
    """Explain a batch of findings.

    To keep cloud deployments responsive and within Groq limits, we:
    - Only send the most severe N violations to Groq (configurable).
    - Explain the rest deterministically.
    """

    if not findings:
        return []

    retriever = RuleRetriever()
    sem = asyncio.Semaphore(int(os.getenv("GROQ_CONCURRENCY", "5")))

    # Rank by severity (CRITICAL > HIGH > MEDIUM > LOW)
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}

    indexed = list(enumerate(findings))

    def sev_rank(v: dict) -> int:
        sev = str(v.get("adjusted_severity", v.get("severity", "LOW"))).upper()
        return order.get(sev, 3)

    ranked = sorted(indexed, key=lambda iv: sev_rank(iv[1]))

    max_llm = int(os.getenv("GROQ_MAX_VIOLATIONS", "12"))
    use_llm_indices = {idx for idx, _ in ranked[:max_llm]}

    tasks = [
        explain_violation(v, retriever, sem, use_llm=(idx in use_llm_indices))
        for idx, v in enumerate(findings)
    ]
    return await asyncio.gather(*tasks)


# -------------------------
# WRAPPER
# -------------------------

class FindingExplainer:
    async def explain_finding(self, finding):
        retriever = RuleRetriever()
        sem = asyncio.Semaphore(1)
        res = await explain_violation(finding, retriever, sem, use_llm=True)
        return res["explanation"]


def create_explainer():
    return FindingExplainer()