import json
import os
from google.adk.agents import Agent
from google.adk.tools   import FunctionTool

from api.adk_agents.secrets_agent    import scan_files_for_secrets
from api.adk_agents.dependency_agent import scan_dependencies
from api.adk_agents.terraform_agent  import scan_terraform_files
from api.rag.retriever               import (
    retrieve_rules,
    retrieve_rules_by_query,
    get_rules_by_framework
)

# ── Tool wrappers ─────────────────────────────────────────────────

def tool_scan_secrets(repo_path: str) -> str:
    """
    Scans repository for leaked secrets, API keys, tokens,
    and credentials using gitleaks regex rules.
    Returns JSON string with violations list.
    """
    result = scan_files_for_secrets(repo_path)
    return json.dumps(result)


def tool_scan_dependencies(repo_path: str) -> str:
    """
    Scans requirements.txt and package.json for known CVEs
    using the OSV vulnerability database.
    Returns JSON string with violations list.
    """
    result = scan_dependencies(repo_path)
    return json.dumps(result)


def tool_scan_terraform(repo_path: str) -> str:
    """
    Scans Terraform .tf files for infrastructure misconfigurations
    including public DBs, unencrypted storage, open security groups.
    Returns JSON string with violations list.
    """
    result = scan_terraform_files(repo_path)
    return json.dumps(result)


def tool_retrieve_compliance_rules(query: str) -> str:
    """
    Agentic RAG: retrieve relevant Indian compliance rules
    (RBI, PCI-DSS, DPDP, SEBI) based on a free-text query.

    Use this when you need more specific regulatory context
    for a violation you have found.

    Example queries:
    - "RBI rules about database encryption"
    - "PCI DSS requirements for API key storage"
    - "DPDP Act data exposure penalties"
    - "SEBI cybersecurity patch management"

    Returns JSON string with matching compliance rules.
    """
    rules = retrieve_rules_by_query(query, top_k=4)
    return json.dumps(rules)


def tool_retrieve_rules_for_violation(violation_json: str) -> str:
    """
    Standard RAG: given a violation as JSON string,
    retrieve the most relevant compliance rules for it.
    Use this to get regulatory context for a specific violation.
    Returns JSON string with matching compliance rules.
    """
    try:
        violation = json.loads(violation_json)
    except Exception:
        return json.dumps([])
    rules = retrieve_rules(violation, top_k=3)
    return json.dumps(rules)


def tool_get_framework_rules(framework: str) -> str:
    """
    Retrieve rules for a specific compliance framework.
    Valid frameworks: RBI, PCI-DSS, DPDP, SEBI
    Use this when you want to check all rules for one framework.
    Returns JSON string with rules list.
    """
    rules = get_rules_by_framework(framework, top_k=5)
    return json.dumps(rules)


def tool_validate_violation(violation_json: str,
                             compliance_context_json: str) -> str:
    """
    LLM validation tool: given a violation and its compliance context,
    decide: CONFIRM, ESCALATE, or DISMISS.

    This is where the LLM does primary detection + validation:
    - CONFIRM: violation is real and severity is correct
    - ESCALATE: violation is real but more severe than detected
      (e.g. payment context makes it CRITICAL)
    - DISMISS: likely false positive (e.g. test file, example value)

    Returns JSON:
    {
      "verdict": "CONFIRM" | "ESCALATE" | "DISMISS",
      "adjusted_severity": "CRITICAL"|"HIGH"|"MEDIUM"|"LOW",
      "reasoning": "...",
      "false_positive_reason": "..." (only if DISMISS)
    }
    """
    # This tool is called BY the ADK agent (Gemini) itself
    # The agent fills this in through reasoning
    # We return a prompt scaffold — Gemini completes the reasoning
    try:
        v   = json.loads(violation_json)
        ctx = json.loads(compliance_context_json)
    except Exception:
        return json.dumps({"verdict": "CONFIRM",
                           "adjusted_severity": "HIGH",
                           "reasoning": "Could not parse inputs"})

    # Build context string for Gemini to reason over
    rules_text = "\n".join(
        f"- [{r.get('framework')}] §{r.get('section')} "
        f"{r.get('title')}: {r.get('description')}"
        for r in ctx
    ) if ctx else "No specific rules retrieved."

    # Return structured context for the agent to reason on
    return json.dumps({
        "violation":         v,
        "compliance_rules":  rules_text,
        "instruction": (
            "Based on the violation and compliance rules above, "
            "return verdict as CONFIRM/ESCALATE/DISMISS, "
            "adjusted_severity, and reasoning."
        )
    })


# ── ADK Orchestrator Agent ────────────────────────────────────────

orchestrator_agent = Agent(
    name="finguard_orchestrator",
    model="gemini-2.0-flash",
    description=(
        "FinGuard compliance orchestrator. Coordinates all security "
        "agents, retrieves relevant Indian compliance regulations via "
        "RAG, and validates each violation using LLM reasoning."
    ),
    instruction="""
You are the FinGuard DevSecOps compliance orchestrator for Indian
fintech companies. Your job is to run a complete security scan and
return validated, enriched violations.

## YOUR WORKFLOW — follow exactly in order:

### PHASE 1: Run all 3 scan tools
Call all three tools with the repo_path from the user message:
1. tool_scan_secrets(repo_path)
2. tool_scan_dependencies(repo_path)
3. tool_scan_terraform(repo_path)

Parse the JSON from each tool result. Collect ALL violations from
all three tools into one list. Never drop any violation at this stage.

### PHASE 2: Static RAG — inject compliance context
For each violation in your collected list:
- Call tool_retrieve_rules_for_violation(violation_as_json_string)
- Store the returned rules as "matched_rules" for that violation

### PHASE 3: Agentic RAG — targeted retrieval
For violations that involve payment, authentication, or PII:
- Call tool_retrieve_compliance_rules with a targeted query
  Examples:
  - "RBI IT Framework database security requirements"
  - "PCI DSS cardholder data protection API keys"
  - "DPDP Act personal data breach penalties India"
- Use the retrieved rules to inform your validation in Phase 4

### PHASE 4: LLM Validation — confirm, escalate, or dismiss
For each violation, reason carefully:

CONFIRM when:
- The pattern clearly indicates a real secret/misconfiguration
- The value looks like a real credential (not "example", "test",
  "fake", "placeholder", "changeme", "your_key_here", "xxxx")
- The misconfiguration is in production infrastructure code
- The CVE affects the exact installed version

ESCALATE when:
- The file is in a payment or financial context
  (stripe, razorpay, upi, payment, wallet, card, transaction)
- The secret is in a Terraform or deployment file (not just .env)
- The CVE has CVSS score >= 9.0 but was detected as HIGH
- Multiple violations compound each other (e.g. public DB + no encryption)

DISMISS when:
- The "secret" contains test values: test, example, fake, placeholder,
  changeme, your_key, xxx, 000000, dummy, sample
- The file is clearly a test file: test_, _test, spec, fixture, mock
- The violation is in a comment or documentation string
- The CVE does not apply to the actual usage pattern

### PHASE 5: Return final result
Return ONLY this exact JSON — no markdown, no extra text:

{
  "all_violations": [
    {
      "rule_id": "...",
      "file": "...",
      "severity": "CRITICAL|HIGH|MEDIUM|LOW",
      "dimension": "...",
      "message": "...",
      "verdict": "CONFIRM|ESCALATE|DISMISS",
      "adjusted_severity": "CRITICAL|HIGH|MEDIUM|LOW",
      "validation_reasoning": "one sentence why",
      "matched_rules": [...compliance rules from RAG...],
      "rag_context": "which frameworks apply and why"
    }
  ],
  "agent_counts": {
    "secrets": <number from secrets scan>,
    "dependencies": <number from deps scan>,
    "terraform": <number from terraform scan>
  },
  "dismissed_count": <number of DISMISS verdicts>,
  "escalated_count": <number of ESCALATE verdicts>
}

CRITICAL RULES:
- Include ALL violations including DISMISS — do not drop them
- Only violations with verdict CONFIRM or ESCALATE affect risk score
- DISMISSED violations are kept for audit trail with verdict=DISMISS
- Never invent violations the tools did not find
- Never change rule_id, file, or line values
- adjusted_severity must be >= original severity for ESCALATE
- adjusted_severity must equal original severity for CONFIRM
""",
    tools=[
        FunctionTool(func=tool_scan_secrets),
        FunctionTool(func=tool_scan_dependencies),
        FunctionTool(func=tool_scan_terraform),
        FunctionTool(func=tool_retrieve_compliance_rules),
        FunctionTool(func=tool_retrieve_rules_for_violation),
        FunctionTool(func=tool_get_framework_rules),
        FunctionTool(func=tool_validate_violation),
    ]
)