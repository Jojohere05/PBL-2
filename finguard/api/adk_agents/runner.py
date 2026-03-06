"""
Agent Runner - Executes scans using the orchestrator
"""
from typing import List, Optional
import asyncio
import aiohttp
from pathlib import Path

from .orchestrator_agent import OrchestratorAgent
from routes.ws import get_connection_manager


async def run_scan(
    scan_id: str,
    repo_url: str,
    branch: str = "main",
    scan_types: Optional[List[str]] = None
):
    """Run a complete scan on a repository"""
    ws_manager = get_connection_manager()
    orchestrator = OrchestratorAgent()
    
    try:
        # Notify scan started
        await ws_manager.send_progress(scan_id, 0, "initializing", "Starting scan...")
        
        # Clone or fetch repository
        await ws_manager.send_progress(scan_id, 10, "fetching", "Fetching repository...")
        files = await fetch_repository(repo_url, branch)
        
        # Define progress callback
        async def progress_callback(progress: int, file_path: str):
            adjusted_progress = 10 + int(progress * 0.8)  # Scale to 10-90%
            await ws_manager.send_progress(scan_id, adjusted_progress, "scanning", f"Scanning {file_path}")
        
        # Run scan
        results = await orchestrator.scan_repository(
            files=files,
            scan_types=scan_types,
            progress_callback=progress_callback
        )
        
        # Send findings as they're processed
        for finding in results["findings"]:
            await ws_manager.send_finding(scan_id, finding)
        
        # Calculate risk score
        from risk_engine import calculate_risk_score
        risk_score = calculate_risk_score(results["findings"])
        results["summary"]["risk_score"] = risk_score
        
        # Store results in database
        await store_scan_results(scan_id, repo_url, results)
        
        # Notify completion
        await ws_manager.send_progress(scan_id, 100, "complete", "Scan completed")
        await ws_manager.send_complete(scan_id, results["summary"])
        
        return results
        
    except Exception as e:
        await ws_manager.send_progress(scan_id, -1, "error", str(e))
        raise


async def fetch_repository(repo_url: str, branch: str) -> dict:
    """Fetch repository files"""
    # For GitHub repos, use API to fetch files
    if "github.com" in repo_url:
        return await fetch_github_repo(repo_url, branch)
    
    # For local paths
    if Path(repo_url).exists():
        return await fetch_local_repo(repo_url)
    
    raise ValueError(f"Unsupported repository URL: {repo_url}")


async def fetch_github_repo(repo_url: str, branch: str) -> dict:
    """Fetch files from GitHub repository"""
    # Parse owner/repo from URL
    parts = repo_url.rstrip("/").split("/")
    owner = parts[-2]
    repo = parts[-1].replace(".git", "")
    
    files = {}
    
    async with aiohttp.ClientSession() as session:
        # Get repository tree
        api_url = f"https://api.github.com/repos/{owner}/{repo}/git/trees/{branch}?recursive=1"
        async with session.get(api_url) as response:
            if response.status != 200:
                raise ValueError(f"Failed to fetch repository: {response.status}")
            
            data = await response.json()
            tree = data.get("tree", [])
        
        # Fetch file contents (limit to text files)
        text_extensions = {
            ".py", ".js", ".ts", ".jsx", ".tsx", ".json", ".yaml", ".yml",
            ".tf", ".tfvars", ".go", ".rs", ".java", ".rb", ".php",
            ".sh", ".bash", ".zsh", ".ps1", ".bat", ".cmd",
            ".md", ".txt", ".env", ".ini", ".cfg", ".conf",
            ".html", ".css", ".scss", ".less", ".xml"
        }
        
        for item in tree:
            if item["type"] == "blob":
                path = item["path"]
                ext = Path(path).suffix.lower()
                
                if ext in text_extensions or any(
                    name in path.lower() for name in 
                    ["dockerfile", "makefile", "gemfile", "requirements", "package"]
                ):
                    # Fetch file content
                    raw_url = f"https://raw.githubusercontent.com/{owner}/{repo}/{branch}/{path}"
                    try:
                        async with session.get(raw_url) as file_response:
                            if file_response.status == 200:
                                content = await file_response.text()
                                files[path] = content
                    except Exception:
                        continue
    
    return files


async def fetch_local_repo(path: str) -> dict:
    """Fetch files from local repository"""
    files = {}
    repo_path = Path(path)
    
    text_extensions = {
        ".py", ".js", ".ts", ".jsx", ".tsx", ".json", ".yaml", ".yml",
        ".tf", ".tfvars", ".go", ".rs", ".java", ".rb", ".php",
        ".sh", ".bash", ".md", ".txt", ".env"
    }
    
    for file_path in repo_path.rglob("*"):
        if file_path.is_file():
            ext = file_path.suffix.lower()
            if ext in text_extensions:
                try:
                    content = file_path.read_text(encoding="utf-8")
                    relative_path = str(file_path.relative_to(repo_path))
                    files[relative_path] = content
                except Exception:
                    continue
    
    return files


async def store_scan_results(scan_id: str, repo_url: str, results: dict):
    """Store scan results in database"""
    from database import get_db
    
    # TODO: Implement database storage
    pass
