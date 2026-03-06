"""
GitHub App Webhook Handler
"""
from fastapi import Request, HTTPException, Header
import hmac
import hashlib
import os
from typing import Optional

from .github_client import GitHubClient
from .background_worker import queue_scan


async def verify_webhook_signature(
    request: Request,
    x_hub_signature_256: Optional[str] = Header(None)
) -> bool:
    """Verify GitHub webhook signature"""
    secret = os.getenv("GITHUB_WEBHOOK_SECRET", "")
    if not secret:
        return True  # Skip verification if no secret configured
    
    if not x_hub_signature_256:
        raise HTTPException(status_code=401, detail="Missing signature")
    
    body = await request.body()
    expected_signature = "sha256=" + hmac.new(
        secret.encode(),
        body,
        hashlib.sha256
    ).hexdigest()
    
    if not hmac.compare_digest(x_hub_signature_256, expected_signature):
        raise HTTPException(status_code=401, detail="Invalid signature")
    
    return True


async def handle_webhook(request: Request, event_type: str):
    """Handle incoming GitHub webhook"""
    payload = await request.json()
    
    handlers = {
        "push": handle_push_event,
        "pull_request": handle_pull_request_event,
        "installation": handle_installation_event,
        "installation_repositories": handle_installation_repos_event,
    }
    
    handler = handlers.get(event_type)
    if handler:
        return await handler(payload)
    
    return {"status": "ignored", "event": event_type}


async def handle_push_event(payload: dict):
    """Handle push events - trigger scan on main branch pushes"""
    ref = payload.get("ref", "")
    repo = payload.get("repository", {})
    
    # Only scan pushes to main/master
    if ref not in ["refs/heads/main", "refs/heads/master"]:
        return {"status": "skipped", "reason": "not main branch"}
    
    repo_url = repo.get("html_url")
    repo_name = repo.get("full_name")
    
    # Queue scan
    scan_id = await queue_scan(
        repo_url=repo_url,
        repo_name=repo_name,
        branch="main",
        trigger="push"
    )
    
    return {"status": "queued", "scan_id": scan_id}


async def handle_pull_request_event(payload: dict):
    """Handle pull request events"""
    action = payload.get("action")
    
    if action not in ["opened", "synchronize", "reopened"]:
        return {"status": "skipped", "reason": f"action {action} not handled"}
    
    pr = payload.get("pull_request", {})
    repo = payload.get("repository", {})
    
    repo_url = repo.get("html_url")
    repo_name = repo.get("full_name")
    pr_number = pr.get("number")
    head_sha = pr.get("head", {}).get("sha")
    head_branch = pr.get("head", {}).get("ref")
    
    # Queue scan
    scan_id = await queue_scan(
        repo_url=repo_url,
        repo_name=repo_name,
        branch=head_branch,
        trigger="pull_request",
        pr_number=pr_number,
        commit_sha=head_sha
    )
    
    return {"status": "queued", "scan_id": scan_id, "pr_number": pr_number}


async def handle_installation_event(payload: dict):
    """Handle app installation events"""
    action = payload.get("action")
    installation = payload.get("installation", {})
    
    if action == "created":
        # New installation
        account = installation.get("account", {})
        return {
            "status": "installed",
            "account": account.get("login"),
            "account_type": account.get("type")
        }
    elif action == "deleted":
        return {"status": "uninstalled"}
    
    return {"status": "ignored", "action": action}


async def handle_installation_repos_event(payload: dict):
    """Handle repository addition/removal from installation"""
    action = payload.get("action")
    
    repos_added = payload.get("repositories_added", [])
    repos_removed = payload.get("repositories_removed", [])
    
    return {
        "status": "processed",
        "action": action,
        "repos_added": len(repos_added),
        "repos_removed": len(repos_removed)
    }
