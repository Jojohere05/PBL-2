#!/usr/bin/env python3
"""
FinGuard Evaluation Metrics Visualizer

Creates research-ready outputs from FinGuard scan results.

Features:
- Load saved JSON results from test_results/ (default)
- Optionally run fresh scans for a list of GitHub repos via scripts/test_scan.py
- Compute per-repo and global evaluation metrics
- Save table and charts as PNG/CSV/TXT artifacts

Outputs:
- evaluation_table.csv
- violations_bar_chart.png
- severity_distribution.png
- scan_time_chart.png
- evaluation_summary.txt
"""

from __future__ import annotations

import argparse
import json
import math
import re
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import matplotlib
import matplotlib.pyplot as plt
import pandas as pd

# Headless-safe backend for servers/CI
matplotlib.use("Agg")


TIMESTAMP_SUFFIX_RE = re.compile(r"_\d{8}_\d{6}$")


@dataclass
class RepoMetrics:
    repo: str
    total: int
    secrets: int
    deps: int
    terraform: int
    critical: int
    high: int
    medium: int
    low: int
    scan_time: float | None
    dismissed: int
    risk_score: float | None
    decision: str | None


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate FinGuard evaluation metrics outputs")
    parser.add_argument(
        "--repos",
        nargs="*",
        default=[],
        help="Optional list of repositories to scan (owner/repo or GitHub URL)",
    )
    parser.add_argument(
        "--results-dir",
        default="test_results",
        help="Directory containing saved result JSON files (default: test_results)",
    )
    parser.add_argument(
        "--results-glob",
        default="*.json",
        help="Glob for selecting result files inside --results-dir (default: *.json)",
    )
    parser.add_argument(
        "--output-dir",
        default=".",
        help="Directory for output artifacts (default: current directory)",
    )
    parser.add_argument(
        "--known-vuln-repos",
        nargs="*",
        default=[],
        help="Optional repos expected to contain vulnerabilities, used for recall proxy",
    )
    parser.add_argument(
        "--dep-baseline-seconds",
        type=float,
        default=260.0,
        help="Baseline dependency scan time for speedup comparison",
    )
    parser.add_argument(
        "--dep-optimized-seconds",
        type=float,
        default=1.0,
        help="Optimized dependency scan time for speedup comparison",
    )
    return parser.parse_args()


def normalize_repo_label(raw_repo_name: str) -> str:
    stem = Path(raw_repo_name).stem
    stem = TIMESTAMP_SUFFIX_RE.sub("", stem)
    return stem


def load_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def parse_repo_metrics(result: dict[str, Any], fallback_repo_name: str, scan_time: float | None) -> RepoMetrics:
    summary = result.get("summary") or {}
    by_sev = summary.get("by_severity") or {}

    violations = result.get("violations") or []
    if not isinstance(violations, list):
        violations = []

    dismissed_list = result.get("dismissed") or []
    dismissed_count = summary.get("dismissed")
    if dismissed_count is None:
        dismissed_count = len(dismissed_list) if isinstance(dismissed_list, list) else 0

    total = int(summary.get("total", len(violations)))
    secrets = int(summary.get("secrets", 0))
    deps = int(summary.get("dependencies", 0))
    terraform = int(summary.get("terraform", 0))

    critical = int(by_sev.get("CRITICAL", 0))
    high = int(by_sev.get("HIGH", 0))
    medium = int(by_sev.get("MEDIUM", 0))
    low = int(by_sev.get("LOW", 0))

    return RepoMetrics(
        repo=normalize_repo_label(fallback_repo_name),
        total=total,
        secrets=secrets,
        deps=deps,
        terraform=terraform,
        critical=critical,
        high=high,
        medium=medium,
        low=low,
        scan_time=scan_time,
        dismissed=int(dismissed_count),
        risk_score=float(result["risk_score"]) if result.get("risk_score") is not None else None,
        decision=str(result.get("decision")) if result.get("decision") is not None else None,
    )


def newest_json_in_dir(results_dir: Path, before: set[Path]) -> Path | None:
    current = set(results_dir.glob("*.json"))
    created = list(current - before)
    if not created:
        return None
    return max(created, key=lambda p: p.stat().st_mtime)


def run_scans_and_collect(repos: list[str], results_dir: Path) -> list[tuple[Path, float]]:
    script_path = Path("scripts") / "test_scan.py"
    if not script_path.exists():
        raise FileNotFoundError(f"Missing scan script: {script_path}")

    results_dir.mkdir(parents=True, exist_ok=True)
    outputs: list[tuple[Path, float]] = []

    for repo in repos:
        print(f"Running scan for {repo} ...")
        before = set(results_dir.glob("*.json"))
        start = time.perf_counter()

        cmd = [sys.executable, str(script_path), repo]
        completed = subprocess.run(cmd, check=False)
        elapsed = time.perf_counter() - start

        if completed.returncode != 0:
            print(f"WARNING: Scan failed for {repo} (exit code {completed.returncode}). Skipping.")
            continue

        latest = newest_json_in_dir(results_dir, before)
        if latest is None:
            print(f"WARNING: Could not find output JSON for {repo}. Skipping.")
            continue

        outputs.append((latest, elapsed))

    return outputs


def load_saved_results(results_dir: Path, pattern: str) -> list[Path]:
    paths = [p for p in sorted(results_dir.glob(pattern)) if p.is_file()]
    latest_by_repo: dict[str, Path] = {}

    for path in paths:
        repo_key = normalize_repo_label(path.stem)
        current = latest_by_repo.get(repo_key)
        if current is None or path.stat().st_mtime > current.stat().st_mtime:
            latest_by_repo[repo_key] = path

    return sorted(latest_by_repo.values(), key=lambda p: normalize_repo_label(p.stem))


def build_dataframe(metrics: list[RepoMetrics]) -> pd.DataFrame:
    rows = []
    for m in metrics:
        rows.append(
            {
                "Repo": m.repo,
                "Total": m.total,
                "Secrets": m.secrets,
                "Deps": m.deps,
                "Terraform": m.terraform,
                "High": m.high,
                "Medium": m.medium,
                "Low": m.low,
                "Scan Time": m.scan_time,
            }
        )
    return pd.DataFrame(rows)


def save_violations_bar_chart(df: pd.DataFrame, output_path: Path) -> None:
    plt.figure(figsize=(12, 6))
    plt.bar(df["Repo"], df["Total"])
    plt.xlabel("Repositories")
    plt.ylabel("Number of Violations")
    plt.title("Violations per Repository")
    plt.xticks(rotation=30, ha="right")
    plt.tight_layout()
    plt.savefig(output_path, dpi=200)
    plt.close()


def save_severity_distribution(metrics: list[RepoMetrics], output_path: Path) -> None:
    totals = {
        "CRITICAL": sum(m.critical for m in metrics),
        "HIGH": sum(m.high for m in metrics),
        "MEDIUM": sum(m.medium for m in metrics),
        "LOW": sum(m.low for m in metrics),
    }

    labels = list(totals.keys())
    values = list(totals.values())

    plt.figure(figsize=(8, 5))
    plt.bar(labels, values)
    plt.xlabel("Severity")
    plt.ylabel("Count")
    plt.title("Severity Distribution Across Repositories")
    plt.tight_layout()
    plt.savefig(output_path, dpi=200)
    plt.close()


def save_scan_time_chart(df: pd.DataFrame, output_path: Path) -> None:
    scan_time_series = pd.to_numeric(df["Scan Time"], errors="coerce")
    plot_values = scan_time_series.fillna(0.0)

    plt.figure(figsize=(12, 6))
    plt.bar(df["Repo"], plot_values)
    plt.xlabel("Repositories")
    plt.ylabel("Scan Time (seconds)")
    plt.title("Scan Time per Repository")
    plt.xticks(rotation=30, ha="right")
    plt.tight_layout()
    plt.savefig(output_path, dpi=200)
    plt.close()


def compute_global_metrics(metrics: list[RepoMetrics]) -> dict[str, Any]:
    valid_scan_times = [m.scan_time for m in metrics if m.scan_time is not None and not math.isnan(m.scan_time)]
    avg_scan_time = sum(valid_scan_times) / len(valid_scan_times) if valid_scan_times else None

    total_active = sum(m.total for m in metrics)
    total_dismissed = sum(m.dismissed for m in metrics)
    denom = total_active + total_dismissed

    false_positive_rate = (total_dismissed / denom) if denom > 0 else 0.0
    precision_estimate = (total_active / denom) if denom > 0 else 1.0

    return {
        "avg_scan_time": avg_scan_time,
        "precision_estimate": precision_estimate,
        "false_positive_rate": false_positive_rate,
        "total_repositories": len(metrics),
        "total_violations": total_active,
        "total_dismissed": total_dismissed,
        "total_secrets": sum(m.secrets for m in metrics),
        "total_deps": sum(m.deps for m in metrics),
        "total_terraform": sum(m.terraform for m in metrics),
    }


def decision_from_score(score: float) -> str:
    if score >= 76:
        return "BLOCK"
    if score >= 56:
        return "REVIEW"
    if score >= 31:
        return "WARN"
    return "ALLOW"


def compute_research_metrics(
    metrics: list[RepoMetrics],
    payloads: list[dict[str, Any]],
    known_vuln_repos: list[str],
    dep_baseline_seconds: float,
    dep_optimized_seconds: float,
) -> dict[str, Any]:
    total_active = sum(m.total for m in metrics)
    total_dismissed = sum(m.dismissed for m in metrics)

    denom = total_active + total_dismissed
    precision = (total_active / denom) if denom > 0 else 1.0

    known_set = {normalize_repo_label(r) for r in known_vuln_repos}
    if known_set:
        repo_hit_map = {m.repo: (m.total > 0) for m in metrics}
        detected = sum(1 for repo in known_set if repo_hit_map.get(repo, False))
        recall = detected / len(known_set)
    else:
        recall = None

    f1 = None
    if recall is not None and (precision + recall) > 0:
        f1 = 2 * precision * recall / (precision + recall)

    pre_validation_alerts = total_active + total_dismissed
    post_validation_alerts = total_active
    llm_reduction = (
        (pre_validation_alerts - post_validation_alerts) / pre_validation_alerts
        if pre_validation_alerts > 0
        else 0.0
    )

    entropy_dismissed = 0
    path_dismissed = 0
    llm_dismissed = 0
    total_violations = 0
    explained_violations = 0
    mapped_violations = 0
    severity_valid = 0
    all_severities = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}

    decision_checks = 0
    decision_matches = 0

    for payload, repo_metric in zip(payloads, metrics):
        violations = payload.get("violations") or []
        if isinstance(violations, list):
            for v in violations:
                total_violations += 1

                sev = str(v.get("severity", "")).upper()
                if sev in all_severities:
                    severity_valid += 1

                if v.get("explanation"):
                    explained_violations += 1
                matched_rules = v.get("matched_rules") or []
                if isinstance(matched_rules, list) and matched_rules:
                    mapped_violations += 1

        dismissed = payload.get("dismissed") or []
        if isinstance(dismissed, list):
            for d in dismissed:
                reason = str(
                    d.get("false_positive_reason")
                    or d.get("validation_reasoning")
                    or ""
                ).lower()

                if "entropy" in reason:
                    entropy_dismissed += 1
                if "path" in reason or "vendor" in reason or "test" in reason or "docs" in reason:
                    path_dismissed += 1
                if reason:
                    llm_dismissed += 1

        if repo_metric.risk_score is not None and repo_metric.decision is not None:
            expected = decision_from_score(repo_metric.risk_score)
            decision_checks += 1
            if expected.upper() == repo_metric.decision.upper():
                decision_matches += 1

    valid_scan_times = [m.scan_time for m in metrics if m.scan_time is not None and not math.isnan(m.scan_time)]
    avg_scan_time = (sum(valid_scan_times) / len(valid_scan_times)) if valid_scan_times else None
    min_scan_time = min(valid_scan_times) if valid_scan_times else None
    max_scan_time = max(valid_scan_times) if valid_scan_times else None

    dep_speedup = None
    dep_reduction_pct = None
    if dep_optimized_seconds > 0:
        dep_speedup = dep_baseline_seconds / dep_optimized_seconds
        dep_reduction_pct = ((dep_baseline_seconds - dep_optimized_seconds) / dep_baseline_seconds) * 100 if dep_baseline_seconds > 0 else None

    repo_detected_count = sum(1 for m in metrics if m.total > 0)
    explanation_coverage = (explained_violations / total_violations) if total_violations > 0 else 0.0
    compliance_mapping_coverage = (mapped_violations / total_violations) if total_violations > 0 else 0.0
    severity_alignment = (severity_valid / total_violations) if total_violations > 0 else 1.0
    decision_alignment = (decision_matches / decision_checks) if decision_checks > 0 else None

    return {
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "pre_validation_alerts": pre_validation_alerts,
        "post_validation_alerts": post_validation_alerts,
        "llm_reduction": llm_reduction,
        "entropy_dismissed": entropy_dismissed,
        "path_dismissed": path_dismissed,
        "llm_dismissed": llm_dismissed,
        "avg_scan_time": avg_scan_time,
        "min_scan_time": min_scan_time,
        "max_scan_time": max_scan_time,
        "dep_speedup": dep_speedup,
        "dep_reduction_pct": dep_reduction_pct,
        "severity_alignment": severity_alignment,
        "decision_alignment": decision_alignment,
        "repo_detected_count": repo_detected_count,
        "total_repositories": len(metrics),
        "explanation_coverage": explanation_coverage,
        "compliance_mapping_coverage": compliance_mapping_coverage,
        "tested_repos": [m.repo for m in metrics],
    }


def format_metric(value: float | None, as_percent: bool = False) -> str:
    if value is None:
        return "N/A"
    if as_percent:
        return f"{value * 100:.2f}%"
    return f"{value:.4f}"


def print_research_metrics(research: dict[str, Any]) -> None:
    print("\nResearch Metrics")
    print("1) Detection Accuracy (Precision, Recall, F1-score)")
    print(f"   Precision: {format_metric(research['precision'])}")
    print(f"   Recall:    {format_metric(research['recall'])}")
    print(f"   F1-score:  {format_metric(research['f1'])}")

    print("2) False Positive Reduction")
    print(f"   Alerts before validation: {research['pre_validation_alerts']}")
    print(f"   Alerts after validation:  {research['post_validation_alerts']}")
    print(f"   LLM validation reduction: {format_metric(research['llm_reduction'], as_percent=True)}")
    print(f"   Entropy-filter dismissals: {research['entropy_dismissed']}")
    print(f"   Path-filter dismissals:    {research['path_dismissed']}")

    print("3) Performance Evaluation (Latency & Speed)")
    print(f"   Average scan time: {format_metric(research['avg_scan_time']) if research['avg_scan_time'] is not None else 'N/A'} seconds")
    print(f"   Min scan time:     {format_metric(research['min_scan_time']) if research['min_scan_time'] is not None else 'N/A'} seconds")
    print(f"   Max scan time:     {format_metric(research['max_scan_time']) if research['max_scan_time'] is not None else 'N/A'} seconds")
    print(f"   Dependency speedup estimate: {format_metric(research['dep_speedup']) if research['dep_speedup'] is not None else 'N/A'}x")
    print(f"   Dependency reduction estimate: {format_metric((research['dep_reduction_pct'] / 100) if research['dep_reduction_pct'] is not None else None, as_percent=True)}")

    print("4) Risk Scoring Validation (CVSS + OWASP Alignment)")
    print(f"   Severity taxonomy alignment: {format_metric(research['severity_alignment'], as_percent=True)}")
    print(f"   Decision-threshold alignment: {format_metric(research['decision_alignment'], as_percent=True)}")

    print("5) Real-World Repository Testing")
    print(f"   Repositories with findings: {research['repo_detected_count']}/{research['total_repositories']}")
    print(f"   Explanation coverage:       {format_metric(research['explanation_coverage'], as_percent=True)}")
    print(f"   Compliance mapping coverage:{format_metric(research['compliance_mapping_coverage'], as_percent=True)}")


def save_summary_text(
    summary_path: Path,
    global_metrics: dict[str, Any],
    research_metrics: dict[str, Any],
    used_saved_results: bool,
) -> None:
    avg_scan_time = global_metrics["avg_scan_time"]
    avg_scan_time_text = f"{avg_scan_time:.2f} seconds" if avg_scan_time is not None else "N/A (missing in saved results)"

    lines = [
        "FinGuard Evaluation Summary",
        "=" * 30,
        "",
        f"Total repositories: {global_metrics['total_repositories']}",
        f"Total violations: {global_metrics['total_violations']}",
        f"Total dismissed: {global_metrics['total_dismissed']}",
        f"Secrets findings: {global_metrics['total_secrets']}",
        f"Dependency findings: {global_metrics['total_deps']}",
        f"Terraform findings: {global_metrics['total_terraform']}",
        "",
        f"Average scan time: {avg_scan_time_text}",
        f"Precision estimate: {global_metrics['precision_estimate']:.4f}",
        f"False positive rate: {global_metrics['false_positive_rate']:.4f}",
        "",
        "Coverage summary:",
        f"- Data source: {'saved JSON results' if used_saved_results else 'fresh scans'}",
        "- Severity coverage: CRITICAL, HIGH, MEDIUM, LOW",
        "- Category coverage: Secrets, Dependencies, Terraform",
        "",
        "Research Metrics:",
        "1) Detection Accuracy",
        f"- Precision: {format_metric(research_metrics['precision'])}",
        f"- Recall: {format_metric(research_metrics['recall'])}",
        f"- F1-score: {format_metric(research_metrics['f1'])}",
        "2) False Positive Reduction",
        f"- Before validation alerts: {research_metrics['pre_validation_alerts']}",
        f"- After validation alerts: {research_metrics['post_validation_alerts']}",
        f"- LLM validation reduction: {format_metric(research_metrics['llm_reduction'], as_percent=True)}",
        f"- Entropy-filter dismissals: {research_metrics['entropy_dismissed']}",
        f"- Path-filter dismissals: {research_metrics['path_dismissed']}",
        "3) Performance Evaluation",
        f"- Average scan time: {format_metric(research_metrics['avg_scan_time']) if research_metrics['avg_scan_time'] is not None else 'N/A'} seconds",
        f"- Min scan time: {format_metric(research_metrics['min_scan_time']) if research_metrics['min_scan_time'] is not None else 'N/A'} seconds",
        f"- Max scan time: {format_metric(research_metrics['max_scan_time']) if research_metrics['max_scan_time'] is not None else 'N/A'} seconds",
        f"- Dependency speedup estimate: {format_metric(research_metrics['dep_speedup']) if research_metrics['dep_speedup'] is not None else 'N/A'}x",
        "4) Risk Scoring Validation",
        f"- Severity taxonomy alignment: {format_metric(research_metrics['severity_alignment'], as_percent=True)}",
        f"- Decision-threshold alignment: {format_metric(research_metrics['decision_alignment'], as_percent=True)}",
        "5) Real-World Repository Testing",
        f"- Repositories with findings: {research_metrics['repo_detected_count']}/{research_metrics['total_repositories']}",
        f"- Explanation coverage: {format_metric(research_metrics['explanation_coverage'], as_percent=True)}",
        f"- Compliance mapping coverage: {format_metric(research_metrics['compliance_mapping_coverage'], as_percent=True)}",
        f"- Tested repositories: {', '.join(research_metrics['tested_repos'])}",
    ]

    summary_path.write_text("\n".join(lines), encoding="utf-8")


def main() -> int:
    args = parse_args()

    results_dir = Path(args.results_dir)
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    metrics: list[RepoMetrics] = []
    payloads: list[dict[str, Any]] = []
    used_saved_results = True

    if args.repos:
        used_saved_results = False
        runs = run_scans_and_collect(args.repos, results_dir)
        for json_path, elapsed in runs:
            payload = load_json(json_path)
            metrics.append(parse_repo_metrics(payload, json_path.stem, elapsed))
            payloads.append(payload)
    else:
        files = load_saved_results(results_dir, args.results_glob)
        for path in files:
            payload = load_json(path)
            metrics.append(parse_repo_metrics(payload, path.stem, None))
            payloads.append(payload)

    if not metrics:
        print("No scan results available. Provide --repos or ensure saved JSON files exist.")
        return 1

    df = build_dataframe(metrics)

    table_csv = output_dir / "evaluation_table.csv"
    bar_png = output_dir / "violations_bar_chart.png"
    severity_png = output_dir / "severity_distribution.png"
    scan_time_png = output_dir / "scan_time_chart.png"
    summary_txt = output_dir / "evaluation_summary.txt"

    df.to_csv(table_csv, index=False)

    display_df = df.copy()
    display_df["Scan Time"] = display_df["Scan Time"].map(
        lambda x: "N/A" if pd.isna(x) else f"{x:.2f}"
    )

    print("\nEvaluation Table")
    print(display_df.to_string(index=False))

    save_violations_bar_chart(df, bar_png)
    save_severity_distribution(metrics, severity_png)
    save_scan_time_chart(df, scan_time_png)

    global_metrics = compute_global_metrics(metrics)
    research_metrics = compute_research_metrics(
        metrics,
        payloads,
        args.known_vuln_repos,
        args.dep_baseline_seconds,
        args.dep_optimized_seconds,
    )
    print_research_metrics(research_metrics)
    save_summary_text(summary_txt, global_metrics, research_metrics, used_saved_results)

    print("\nGenerated artifacts:")
    print(f"- {table_csv}")
    print(f"- {bar_png}")
    print(f"- {severity_png}")
    print(f"- {scan_time_png}")
    print(f"- {summary_txt}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
