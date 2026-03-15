"""
Background Worker - Handles async scan jobs
"""
import asyncio
from typing import Optional
import uuid
from datetime import datetime

from api.adk_agents.runner import run_scan
from .github_client import GitHubClient


# Simple in-memory queue (use Redis/RabbitMQ in production)
scan_queue = asyncio.Queue()
active_scans = {}


async def queue_scan(
    repo_url: str,
    repo_name: str,
    branch: str,
    trigger: str,
    pr_number: Optional[int] = None,
    commit_sha: Optional[str] = None,
    installation_id: Optional[int] = None
) -> str:
    """Queue a scan job"""
    scan_id = str(uuid.uuid4())
    
    job = {
        "scan_id": scan_id,
        "repo_url": repo_url,
        "repo_name": repo_name,
        "branch": branch,
        "trigger": trigger,
        "pr_number": pr_number,
        "commit_sha": commit_sha,
        "installation_id": installation_id,
        "queued_at": datetime.utcnow().isoformat(),
        "status": "queued"
    }
    
    await scan_queue.put(job)
    active_scans[scan_id] = job
    
    return scan_id


async def process_scan_queue():
    """Process scans from queue"""
    while True:
        try:
            job = await scan_queue.get()
            scan_id = job["scan_id"]
            
            # Update status
            active_scans[scan_id]["status"] = "running"
            
            # Create GitHub client if installation ID provided
            github_client = None
            if job.get("installation_id"):
                github_client = GitHubClient(installation_id=job["installation_id"])
                
                # Create check run or status
                if job.get("commit_sha"):
                    owner, repo = job["repo_name"].split("/")
                    await github_client.create_commit_status(
                        owner=owner,
                        repo=repo,
                        sha=job["commit_sha"],
                        state="pending",
                        description="Security scan in progress..."
                    )
            
            try:
                # Run the scan
                results = await run_scan(
                    scan_id=scan_id,
                    repo_url=job["repo_url"],
                    branch=job["branch"]
                )
                
                active_scans[scan_id]["status"] = "completed"
                active_scans[scan_id]["results"] = results
                
                # Update GitHub status
                if github_client and job.get("commit_sha"):
                    owner, repo = job["repo_name"].split("/")
                    
                    # Determine status based on findings
                    critical = results["summary"]["by_severity"].get("critical", 0)
                    high = results["summary"]["by_severity"].get("high", 0)
                    
                    if critical > 0:
                        state = "failure"
                        description = f"Found {critical} critical issues"
                    elif high > 0:
                        state = "failure"
                        description = f"Found {high} high severity issues"
                    else:
                        state = "success"
                        description = "No critical or high severity issues found"
                    
                    await github_client.create_commit_status(
                        owner=owner,
                        repo=repo,
                        sha=job["commit_sha"],
                        state=state,
                        description=description
                    )
                    
                    # Comment on PR if applicable
                    if job.get("pr_number"):
                        comment = format_pr_comment(results)
                        await github_client.create_pull_request_comment(
                            owner=owner,
                            repo=repo,
                            pr_number=job["pr_number"],
                            body=comment
                        )
                
            except Exception as e:
                active_scans[scan_id]["status"] = "failed"
                active_scans[scan_id]["error"] = str(e)
                
                # Update GitHub status to error
                if github_client and job.get("commit_sha"):
                    owner, repo = job["repo_name"].split("/")
                    await github_client.create_commit_status(
                        owner=owner,
                        repo=repo,
                        sha=job["commit_sha"],
                        state="error",
                        description="Scan failed"
                    )
            
            scan_queue.task_done()
            
        except Exception as e:
            print(f"Queue processing error: {e}")
            await asyncio.sleep(1)


def format_pr_comment(results: dict) -> str:
    """Format scan results as PR comment"""
    summary = results["summary"]
    findings = results["findings"]
    
    comment = "## 🔒 FinGuard Security Scan Results\n\n"
    
    # Summary table
    comment += "| Severity | Count |\n"
    comment += "|----------|-------|\n"
    comment += f"| 🔴 Critical | {summary['by_severity'].get('critical', 0)} |\n"
    comment += f"| 🟠 High | {summary['by_severity'].get('high', 0)} |\n"
    comment += f"| 🟡 Medium | {summary['by_severity'].get('medium', 0)} |\n"
    comment += f"| 🟢 Low | {summary['by_severity'].get('low', 0)} |\n"
    
    comment += f"\n**Risk Score:** {summary.get('risk_score', 0)}/100\n"
    
    # Top findings
    critical_high = [f for f in findings if f.get("severity") in ["critical", "high"]]
    if critical_high:
        comment += "\n### ⚠️ Critical/High Findings\n\n"
        for finding in critical_high[:5]:
            comment += f"- **{finding['rule_id']}**: {finding['description']}\n"
            comment += f"  - File: `{finding['file_path']}` (line {finding.get('line', 'N/A')})\n"
    
    comment += "\n---\n*Powered by FinGuard*"
    
    return comment


async def start_background_worker():
    """Start the background worker"""
    asyncio.create_task(process_scan_queue())


def get_scan_status(scan_id: str) -> dict:
    """Get status of a scan"""
    return active_scans.get(scan_id, {"status": "not_found"})
