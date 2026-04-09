#!/usr/bin/env python3
"""
FinGuard Compliance Scanner — CLI Entry Point

Usage:
  python finguard/main.py [repo_path]

Examples:
  python finguard/main.py .              # scan current directory
  python finguard/main.py /path/to/repo  # scan specific path

If no repo_path is provided, defaults to current working directory.

Exit codes:
  0 — Pipeline PASSED (ALLOW / WARN / REVIEW)
  1 — Pipeline BLOCKED (BLOCK)
"""

import sys
import os
import json
import time
import asyncio
from datetime import datetime

# ── Ensure project root is on sys.path so `finguard.*` imports work ──
_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT = os.path.dirname(_SCRIPT_DIR)
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)


# ══════════════════════════════════════════════════════════
# TERMINAL COLORS — identical to scripts/test_scan.py
# ══════════════════════════════════════════════════════════

class C:
    RED = "\033[91m"
    ORANGE = "\033[33m"
    YELLOW = "\033[93m"
    GREEN = "\033[92m"
    BLUE = "\033[94m"
    CYAN = "\033[96m"
    MAGENTA = "\033[95m"
    WHITE = "\033[97m"
    GRAY = "\033[90m"
    BOLD = "\033[1m"
    RESET = "\033[0m"


def sev_color(sev: str) -> str:
    return {
        "CRITICAL": C.RED,
        "HIGH": C.ORANGE,
        "MEDIUM": C.YELLOW,
        "LOW": C.BLUE,
    }.get(sev.upper(), C.WHITE)


def dec_color(dec: str) -> str:
    return {
        "BLOCK": C.RED,
        "REVIEW": C.ORANGE,
        "WARN": C.YELLOW,
        "ALLOW": C.GREEN,
    }.get(dec.upper(), C.WHITE)


def verdict_color(v: str) -> str:
    return {
        "ESCALATE": C.RED,
        "CONFIRM": C.YELLOW,
        "DISMISS": C.GREEN,
    }.get(v.upper(), C.WHITE)


def banner(text: str, color=C.CYAN):
    width = 62
    print(f"\n{color}{C.BOLD}{'═' * width}")
    print(f"  {text}")
    print(f"{'═' * width}{C.RESET}")


def section(text: str, color=C.BLUE):
    print(f"\n{color}{C.BOLD}── {text} {'─' * (55 - len(text))}{C.RESET}")


def dim(text: str) -> str:
    return f"{C.GRAY}{text}{C.RESET}"


# ══════════════════════════════════════════════════════════
# OUTPUT FORMATTERS — identical to scripts/test_scan.py
# ══════════════════════════════════════════════════════════

def print_agent_results(agent_name: str, violations: list, color: str):
    section(f"{agent_name} ({len(violations)} found)", color)
    if not violations:
        print(f"  {C.GREEN}✓ No violations found{C.RESET}")
        return
    for v in violations:
        sev = v.get("severity", "?")
        sc = sev_color(sev)
        print(f"  {sc}[{sev:8s}]{C.RESET} {C.WHITE}{v.get('rule_id', '?')}{C.RESET}")
        print(
            f"           {dim('File: ')}{v.get('file', '?')}"
            + (f":{v['line']}" if v.get("line") else "")
        )
        if v.get("package"):
            print(f"           {dim('Pkg:  ')}{v['package']}@{v.get('installed_version', '?')}")
        if v.get("resource"):
            print(f"           {dim('Res:  ')}{v['resource']}")
        msg = v.get("message", "")
        if msg:
            print(f"           {dim('Msg:  ')}{msg[:80]}")
        print()


def print_adk_violations(violations: list, dismissed: list):
    section("ADK Orchestrator - Validated Violations", C.MAGENTA)

    if not violations and not dismissed:
        print(f"  {C.GREEN}✓ No violations after ADK validation{C.RESET}")
        return

    print(f"  {C.BOLD}Active ({len(violations)}):{C.RESET}")
    for v in violations:
        sev = v.get("severity", v.get("adjusted_severity", "?"))
        verdict = v.get("verdict", "CONFIRM")
        sc = sev_color(sev)
        vc = verdict_color(verdict)

        print(
            f"\n  {sc}[{sev:8s}]{C.RESET} "
            f"{vc}[{verdict:8s}]{C.RESET} "
            f"{C.WHITE}{v.get('rule_id', '?')}{C.RESET}"
        )
        print(f"    {dim('File:    ')}{v.get('file', '?')}")

        reasoning = v.get("validation_reasoning", "")
        if reasoning:
            print(f"    {dim('ADK:     ')}{C.MAGENTA}{reasoning[:90]}{C.RESET}")

        matched = v.get("matched_rules", [])
        if matched:
            rules_str = " | ".join(
                f"{r.get('framework')} §{r.get('section')}" for r in matched[:3]
            )
            print(f"    {dim('RAG:     ')}{C.CYAN}{rules_str}{C.RESET}")

        rag_ctx = v.get("rag_context", "")
        if rag_ctx:
            print(f"    {dim('Context: ')}{C.CYAN}{rag_ctx[:90]}{C.RESET}")

        exp = v.get("explanation", {})
        if isinstance(exp, str):
            exp = {
                "what_it_means": exp,
                "regulation_violated": "N/A",
                "business_impact": "N/A",
                "exact_fix": "N/A",
            }
        elif not isinstance(exp, dict):
            exp = {}

        if exp.get("what_it_means"):
            print(f"    {dim('Meaning: ')}{exp['what_it_means'][:90]}")
        if exp.get("regulation_violated"):
            print(f"    {dim('Law:     ')}{C.BLUE}{exp['regulation_violated'][:70]}{C.RESET}")
        if exp.get("business_impact"):
            print(f"    {dim('Impact:  ')}{C.YELLOW}{exp['business_impact'][:80]}{C.RESET}")
        if exp.get("exact_fix"):
            print(f"    {dim('Fix:     ')}{C.GREEN}{exp['exact_fix'][:80]}{C.RESET}")

    if dismissed:
        print(f"\n  {C.BOLD}Dismissed by ADK ({len(dismissed)}) - false positives:{C.RESET}")
        for v in dismissed:
            reason = v.get("false_positive_reason", v.get("validation_reasoning", ""))
            print(f"  {C.GRAY}[DISMISSED] {v.get('rule_id', '?')} ← {v.get('file', '?')}")
            if reason:
                print(f"              Reason: {reason[:80]}{C.RESET}")


def print_risk_score(result: dict):
    section("Risk Score & Decision", C.WHITE)

    score = result.get("risk_score", 0)
    decision = result.get("decision", "ALLOW")
    summary = result.get("summary", {})
    by_sev = summary.get("by_severity", {})
    ctx = result.get("context", {})

    dc = dec_color(decision)
    sc = sev_color(
        "CRITICAL"
        if score >= 76
        else "HIGH"
        if score >= 56
        else "MEDIUM"
        if score >= 31
        else "LOW"
    )

    print(f"\n  Risk Score : {sc}{C.BOLD}{score}/100{C.RESET}")
    print(f"  Decision   : {dc}{C.BOLD}{decision}{C.RESET}")

    if result.get("amplified"):
        print(f"  Amplified  : {C.RED}YES x1.3 (fintech + secrets){C.RESET}")

    print(f"\n  {dim('Context:')}")
    print(f"    Terraform : {'Yes' if ctx.get('has_terraform') else 'No'}")
    print(f"    Fintech   : {'⚠️  YES' if ctx.get('is_fintech') else 'No'}")
    print(f"    Docker    : {'Yes' if ctx.get('has_docker') else 'No'}")
    print(f"    Deps      : {'Yes' if ctx.get('has_dependencies') else 'No'}")

    print(f"\n  {dim('Violations:')}")
    print(f"    🔴 CRITICAL : {by_sev.get('CRITICAL', 0)}")
    print(f"    🟠 HIGH     : {by_sev.get('HIGH', 0)}")
    print(f"    🟡 MEDIUM   : {by_sev.get('MEDIUM', 0)}")
    print(f"    🟢 LOW      : {by_sev.get('LOW', 0)}")
    print(f"    📦 Secrets  : {summary.get('secrets', 0)}")
    print(f"    🔗 CVEs     : {summary.get('dependencies', 0)}")
    print(f"    🏗️  Terraform: {summary.get('terraform', 0)}")
    print(f"    ✗ Dismissed : {summary.get('dismissed', 0)}")
    print(f"    ⬆ Escalated : {summary.get('escalated', 0)}")


def print_github_simulation(repo_name: str, result: dict):
    section("GitHub Plugin Output Simulation", C.CYAN)

    decision = result.get("decision", "ALLOW")
    score = result.get("risk_score", 0)
    summary = result.get("summary", {})
    by_sev = summary.get("by_severity", {})
    dc = dec_color(decision)

    check_icon = {"BLOCK": "❌", "REVIEW": "🔍", "WARN": "⚠️", "ALLOW": "✅"}
    print(f"\n  {C.BOLD}── GitHub Check Run ──{C.RESET}")
    print(f"  {check_icon.get(decision, 'ℹ️')} FinGuard Compliance Scanner")
    print(f"     Risk Score: {score}/100 — {dc}{decision}{C.RESET}")
    print(
        f"     CRITICAL:{by_sev.get('CRITICAL', 0)} "
        f"HIGH:{by_sev.get('HIGH', 0)} "
        f"MEDIUM:{by_sev.get('MEDIUM', 0)} "
        f"LOW:{by_sev.get('LOW', 0)}"
    )

    state = {
        "BLOCK": "failure",
        "REVIEW": "pending",
        "WARN": "success",
        "ALLOW": "success",
    }.get(decision, "pending")
    print(f"\n  {C.BOLD}── Commit Status Badge ──{C.RESET}")
    print(f"  finguard/compliance-scan — {state}")
    print(f"  Risk: {score}/100 — {decision}")

    print(f"\n  {C.BOLD}── PR Comment Preview ──{C.RESET}")
    emoji = {"BLOCK": "🚫", "REVIEW": "🔍", "WARN": "⚠️", "ALLOW": "✅"}
    print(f"  {emoji.get(decision, 'ℹ️')} FinGuard Compliance Scan — {dc}{decision}{C.RESET}")
    print(f"  Risk Score: {score}/100")
    print()
    print("  | Category        | Count |")
    print("  |-----------------|-------|")
    print(f"  | 🔐 Secrets      | {summary.get('secrets', 0):5d} |")
    print(f"  | 📦 Dependencies | {summary.get('dependencies', 0):5d} |")
    print(f"  | 🏗️  Terraform    | {summary.get('terraform', 0):5d} |")
    print()

    violations = result.get("violations", [])
    if violations:
        print("  | Severity | Rule | File | Law |")
        print("  |----------|------|------|-----|")
        for v in violations[:5]:
            sev = v.get("severity", "?")
            rid = v.get("rule_id", "?")
            fil = v.get("file", "?")[:30]
            exp = v.get("explanation", {})
            reg = exp.get("regulation_violated", "—")[:30]
            print(f"  | {sev:8s} | {rid:20s} | {fil:30s} | {reg} |")

    # ── GitHub Actions Output (CI-friendly) ──
    print(f"\n  {C.BOLD}── GitHub Actions Output ──{C.RESET}")
    print("  " + "=" * 52)
    print("    FinGuard Compliance Scan")
    print("  " + "=" * 52)
    print(f"    Risk Score : {score}/100")
    print(f"    Decision   : {dc}{decision}{C.RESET}")
    print(f"    CRITICAL   : {by_sev.get('CRITICAL', 0)}")
    print(f"    HIGH       : {by_sev.get('HIGH', 0)}")
    print("  " + "=" * 52)

    if decision == "BLOCK":
        print(f"\n  {C.RED}🚫 Pipeline BLOCKED - exit code 1{C.RESET}")
        print("  Fix CRITICAL violations before merging")
    elif decision == "REVIEW":
        print(f"\n  {C.ORANGE}🔍 REVIEW required{C.RESET}")
    elif decision == "WARN":
        print(f"\n  {C.YELLOW}⚠️  WARNING - not blocking{C.RESET}")
    else:
        print(f"\n  {C.GREEN}✅ ALLOW - all checks passed{C.RESET}")


# ══════════════════════════════════════════════════════════
# CI-FRIENDLY FINAL OUTPUT — exactly as specified
# ══════════════════════════════════════════════════════════

def print_ci_output(result: dict):
    """Print the exact CI-friendly output block required by GitHub Actions."""
    score = result.get("risk_score", 0)
    decision = result.get("decision", "ALLOW")
    by_sev = result.get("summary", {}).get("by_severity", {})

    print()
    print("=" * 50)
    print("FinGuard Compliance Scan")
    print("========================")
    print()
    print(f"Risk Score : {score}/100")
    print(f"Decision   : {decision}")
    print(f"CRITICAL   : {by_sev.get('CRITICAL', 0)}")
    print(f"HIGH       : {by_sev.get('HIGH', 0)}")
    print(f"MEDIUM     : {by_sev.get('MEDIUM', 0)}")
    print(f"LOW        : {by_sev.get('LOW', 0)}")
    print("====================")


# ══════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════

def main():
    # ── Parse args ───────────────────────────────────────
    repo_path = sys.argv[1] if len(sys.argv) > 1 else "."
    repo_path = os.path.abspath(repo_path)

    if not os.path.isdir(repo_path):
        print(f"{C.RED}ERROR: '{repo_path}' is not a valid directory.{C.RESET}")
        sys.exit(1)

    repo_name = os.path.basename(repo_path) or "local-repo"

    banner(f"FinGuard Compliance Scan — {repo_name}", C.CYAN)
    print(f"  Started : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  Path    : {repo_path}")

    total_start = time.time()

    # ── 1. Context Classifier ────────────────────────────
    section("Context Classifier", C.BLUE)
    t = time.time()
    from finguard.context_classifier import classify_context
    context = classify_context(repo_path)
    print(f"  Done in {time.time() - t:.1f}s")
    print(f"  Terraform : {context['has_terraform']}")
    print(f"  Fintech   : {context['is_fintech']}")
    print(f"  Docker    : {context['has_docker']}")
    print(f"  Deps      : {context['has_dependencies']}")

    # ── 2. Agent 1 — Secrets Scanner (raw) ───────────────
    section("Agent 1 - Secrets Scanner (raw)", C.RED)
    t = time.time()
    from finguard.agents.secrets_agent import scan_files_for_secrets
    s_result = scan_files_for_secrets(repo_path)
    print(f"  Done in {time.time() - t:.1f}s")
    print_agent_results("Secrets Agent", s_result.get("violations", []), C.RED)

    # ── 3. Agent 2 — Dependency Scanner (raw) ────────────
    section("Agent 2 - Dependency Scanner (raw)", C.ORANGE)
    t = time.time()
    from finguard.agents.dependency_agent import scan_dependencies
    d_result = scan_dependencies(repo_path)
    print(f"  Done in {time.time() - t:.1f}s")
    print_agent_results("Dependency Agent", d_result.get("violations", []), C.ORANGE)

    # ── 4. Agent 3 — Terraform Scanner (raw) ─────────────
    section("Agent 3 - Terraform Scanner (raw)", C.YELLOW)
    t = time.time()
    from finguard.agents.terraform_agent import scan_terraform_files
    t_result = scan_terraform_files(repo_path)
    print(f"  Done in {time.time() - t:.1f}s")
    print_agent_results("Terraform Agent", t_result.get("violations", []), C.YELLOW)

    # ── 5. Raw summary ───────────────────────────────────
    raw_total = s_result.get("count", 0) + d_result.get("count", 0) + t_result.get("count", 0)
    section(f"Raw Agent Summary - {raw_total} total", C.WHITE)
    print(f"  Secrets    : {s_result.get('count', 0)}")
    print(f"  Deps       : {d_result.get('count', 0)}")
    print(f"  Terraform  : {t_result.get('count', 0)}")

    # ── 6. ADK Orchestrator — Validation ─────────────────
    section("ADK Orchestrator - Gemini + RAG + Validation", C.MAGENTA)
    print(f"  {C.GRAY}Running orchestrator validation...{C.RESET}")
    t = time.time()

    from finguard.agents.orchestrator import run_agents_sync
    adk = run_agents_sync(repo_path)

    adk_time = time.time() - t
    violations = adk.get("all_violations", [])
    dismissed = adk.get("dismissed", [])
    agent_counts = adk.get("agent_counts", {})

    print(f"  Done in {adk_time:.1f}s")
    print(f"  Active   : {len(violations)}")
    print(f"  Dismissed: {len(dismissed)}")
    print(f"  Escalated: {adk.get('escalated_count', 0)}")

    # ── 7. Propagate adjusted severity ───────────────────
    for v in violations:
        if v.get("adjusted_severity"):
            v["severity"] = v["adjusted_severity"]

    # ── 8. Risk Engine ───────────────────────────────────
    from finguard.risk_engine import compute_risk
    risk = compute_risk(violations, context)

    # ── 9. RAG Explanations (deterministic, offline) ─────
    section("RAG Explanations", C.BLUE)
    print(f"  {C.GRAY}Getting explanations for {len(violations)} violations...{C.RESET}")
    t = time.time()

    from finguard.rag.explainer import explain_all
    enriched = asyncio.run(explain_all(violations))

    print(f"  Done in {time.time() - t:.1f}s")

    # ── 10. Build summary ────────────────────────────────
    def count_sev(v_list):
        c = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for v in v_list:
            s = v.get("adjusted_severity", v.get("severity", "LOW")).upper()
            if s in c:
                c[s] += 1
        return c

    summary = {
        "total": len(enriched),
        "secrets": agent_counts.get("secrets", 0),
        "dependencies": agent_counts.get("dependencies", 0),
        "terraform": agent_counts.get("terraform", 0),
        "dismissed": adk.get("dismissed_count", 0),
        "escalated": adk.get("escalated_count", 0),
        "by_severity": count_sev(enriched),
    }

    result = {
        "risk_score": risk["score"],
        "decision": risk["decision"],
        "amplified": risk["amplified"],
        "context": context,
        "violations": enriched,
        "dismissed": dismissed,
        "summary": summary,
    }

    # ── 11. Print all formatted output ───────────────────
    print_adk_violations(enriched, dismissed)
    print_risk_score(result)
    print_github_simulation(repo_name, result)

    # ── 12. Save result.json ─────────────────────────────
    result_path = os.path.join(os.getcwd(), "result.json")
    with open(result_path, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, default=str)

    total_time = time.time() - total_start

    banner(
        f"Scan Complete in {total_time:.1f}s — Result saved: result.json",
        dec_color(result["decision"]),
    )

    # ── 13. CI-Friendly Output (EXACT FORMAT) ────────────
    print_ci_output(result)

    decision = result["decision"]

    if decision == "BLOCK":
        print("❌ Pipeline BLOCKED - exit code 1")
        print("Fix CRITICAL violations before merging")
        sys.exit(1)
    else:
        print("✅ Pipeline PASSED")
        sys.exit(0)


if __name__ == "__main__":
    main()
