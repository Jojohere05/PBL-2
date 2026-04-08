#!/usr/bin/env python3
"""
FinGuard Public Repo Scanner - CLI Test Tool

Usage:
  python scripts/test_scan.py <github_repo_url_or_shorthand>

Examples:
  python scripts/test_scan.py bridgecrewio/terragoat
  python scripts/test_scan.py trufflesecurity/test_keys
  python scripts/test_scan.py https://github.com/OWASP/NodeGoat
  python scripts/test_scan.py maybe-finance/maybe
  python scripts/test_scan.py firefly-iii/firefly-iii
"""

import sys
import os
import json
import time
import tempfile
import asyncio
import httpx
import zipfile
from datetime import datetime

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Load env
from dotenv import load_dotenv
load_dotenv()


# Terminal colors
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


def parse_repo_input(inp: str) -> tuple[str, str]:
    """
    Accepts:
      - bridgecrewio/terragoat
      - https://github.com/bridgecrewio/terragoat
      - https://github.com/bridgecrewio/terragoat.git
    Returns (owner/repo, zip_url)
    """
    inp = inp.strip().rstrip("/").replace(".git", "")
    if inp.startswith("https://github.com/"):
        repo = inp.replace("https://github.com/", "")
    elif inp.startswith("github.com/"):
        repo = inp.replace("github.com/", "")
    else:
        repo = inp

    parts = repo.split("/")
    if len(parts) < 2:
        print(f"{C.RED}ERROR: Invalid repo format.{C.RESET}")
        print("Use: owner/repo or https://github.com/owner/repo")
        sys.exit(1)

    repo_full = f"{parts[0]}/{parts[1]}"
    zip_url = f"https://github.com/{repo_full}/archive/refs/heads/main.zip"
    return repo_full, zip_url


def download_repo(repo_full: str, zip_url: str, tmpdir: str) -> str:
    print(f"\n{C.CYAN}⬇  Downloading {repo_full}...{C.RESET}")

    zip_path = os.path.join(tmpdir, "repo.zip")

    # Try main branch first, then master
    for branch in ["main", "master"]:
        url = f"https://github.com/{repo_full}/archive/refs/heads/{branch}.zip"
        try:
            with httpx.Client(timeout=120, follow_redirects=True) as client:
                resp = client.get(url)
                if resp.status_code == 200:
                    with open(zip_path, "wb") as f:
                        f.write(resp.content)
                    size_mb = len(resp.content) / 1024 / 1024
                    print(
                        f"   {C.GREEN}✓ Downloaded ({size_mb:.1f} MB) "
                        f"from branch '{branch}'{C.RESET}"
                    )
                    return zip_path
        except Exception as e:
            print(f"   {C.YELLOW}Branch '{branch}' failed: {e}{C.RESET}")

    print(f"{C.RED}ERROR: Could not download repo.{C.RESET}")
    sys.exit(1)


def extract(zip_path: str, tmpdir: str) -> str:
    extract_dir = os.path.join(tmpdir, "repo")
    os.makedirs(extract_dir, exist_ok=True)
    with zipfile.ZipFile(zip_path, "r") as z:
        z.extractall(extract_dir)
    entries = [
        e
        for e in os.listdir(extract_dir)
        if os.path.isdir(os.path.join(extract_dir, e)) and e != "__MACOSX"
    ]
    if entries:
        return os.path.join(extract_dir, entries[0])
    return extract_dir


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


def print_github_simulation(repo_full: str, result: dict):
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


def print_frontend_simulation(repo_full: str, result: dict):
    section("Frontend Dashboard Simulation", C.MAGENTA)

    score = result.get("risk_score", 0)
    decision = result.get("decision", "ALLOW")
    summary = result.get("summary", {})
    dc = dec_color(decision)

    print(f"\n  {C.BOLD}── Live Alert Toast (WebSocket) ──{C.RESET}")
    print("  ┌─────────────────────────────────────┐")
    print(f"  │ {dc}{decision:6s}{C.RESET}  {repo_full[:28]:28s} │")
    print(f"  │ Score: {score}/100  Violations: {summary.get('total', 0):3d}          │")
    print("  └─────────────────────────────────────┘")

    print(f"\n  {C.BOLD}── Dashboard Table Row ──{C.RESET}")
    print(f"  {repo_full:35s} | {score:3d}/100 | {dc}{decision}{C.RESET}")

    print(f"\n  {C.BOLD}── WebSocket Message ──{C.RESET}")
    ws_msg = {
        "type": "new_scan",
        "repo": repo_full,
        "score": score,
        "decision": decision,
        "summary": summary,
    }
    print(f"  {C.GRAY}{json.dumps(ws_msg, indent=4)}{C.RESET}")


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(0)

    inp = sys.argv[1]
    repo_full, zip_url = parse_repo_input(inp)

    banner(f"FinGuard Agent Test - {repo_full}", C.CYAN)
    print(f"  Started : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  Repo    : https://github.com/{repo_full}")

    total_start = time.time()

    with tempfile.TemporaryDirectory() as tmpdir:
        zip_path = download_repo(repo_full, zip_url, tmpdir)
        repo_path = extract(zip_path, tmpdir)

        section("Context Classifier", C.BLUE)
        t = time.time()
        from api.context_classifier import classify_context

        context = classify_context(repo_path)
        print(f"  Done in {time.time() - t:.1f}s")
        print(f"  Terraform : {context['has_terraform']}")
        print(f"  Fintech   : {context['is_fintech']}")
        print(f"  Docker    : {context['has_docker']}")
        print(f"  Deps      : {context['has_dependencies']}")

        section("Agent 1 - Secrets Scanner (raw)", C.RED)
        t = time.time()
        from api.adk_agents.secrets_agent import scan_files_for_secrets

        s_result = scan_files_for_secrets(repo_path)
        print(f"  Done in {time.time() - t:.1f}s")
        print_agent_results("Secrets Agent", s_result.get("violations", []), C.RED)

        section("Agent 2 - Dependency Scanner (raw)", C.ORANGE)
        t = time.time()
        from api.adk_agents.dependency_agent import scan_dependencies

        d_result = scan_dependencies(repo_path)
        print(f"  Done in {time.time() - t:.1f}s")
        print_agent_results("Dependency Agent", d_result.get("violations", []), C.ORANGE)

        section("Agent 3 - Terraform Scanner (raw)", C.YELLOW)
        t = time.time()
        from api.adk_agents.terraform_agent import scan_terraform_files

        t_result = scan_terraform_files(repo_path)
        print(f"  Done in {time.time() - t:.1f}s")
        print_agent_results("Terraform Agent", t_result.get("violations", []), C.YELLOW)

        raw_total = s_result.get("count", 0) + d_result.get("count", 0) + t_result.get("count", 0)
        section(f"Raw Agent Summary - {raw_total} total", C.WHITE)
        print(f"  Secrets    : {s_result.get('count', 0)}")
        print(f"  Deps       : {d_result.get('count', 0)}")
        print(f"  Terraform  : {t_result.get('count', 0)}")

        section("ADK Orchestrator - Gemini + RAG + Validation", C.MAGENTA)
        print(f"  {C.GRAY}Running Gemini orchestration...{C.RESET}")
        t = time.time()

        from api.adk_agents.runner import run_agents_sync

        adk = run_agents_sync(repo_path)

        adk_time = time.time() - t
        violations = adk.get("all_violations", [])
        dismissed = adk.get("dismissed", [])
        agent_counts = adk.get("agent_counts", {})

        print(f"  Done in {adk_time:.1f}s")
        print(f"  Active   : {len(violations)}")
        print(f"  Dismissed: {len(dismissed)}")
        print(f"  Escalated: {adk.get('escalated_count', 0)}")

        for v in violations:
            if v.get("adjusted_severity"):
                v["severity"] = v["adjusted_severity"]

        from api.risk_engine import compute_risk

        risk = compute_risk(violations, context)

        section("Gemini - LLM Explanations", C.BLUE)
        print(f"  {C.GRAY}Getting explanations for {len(violations)} violations...{C.RESET}")
        t = time.time()

        from api.rag.explainer import explain_all

        enriched = asyncio.run(explain_all(violations))

        print(f"  Done in {time.time() - t:.1f}s")

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

        print_adk_violations(enriched, dismissed)
        print_risk_score(result)
        print_github_simulation(repo_full, result)
        print_frontend_simulation(repo_full, result)

        out_dir = "test_results"
        os.makedirs(out_dir, exist_ok=True)
        repo_slug = repo_full.replace("/", "_")
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        out_file = f"{out_dir}/{repo_slug}_{ts}.json"

        with open(out_file, "w") as f:
            json.dump(result, f, indent=2, default=str)

        total_time = time.time() - total_start

        banner(
            f"Scan Complete in {total_time:.1f}s - Result saved: {out_file}",
            dec_color(result["decision"]),
        )


if __name__ == "__main__":
    main()
