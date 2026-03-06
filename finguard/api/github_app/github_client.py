"""
GitHub API Client
"""
import os
import aiohttp
import jwt
import time
from typing import Optional, List, Dict, Any


class GitHubClient:
    """Client for GitHub API interactions"""
    
    def __init__(
        self,
        installation_id: Optional[int] = None,
        access_token: Optional[str] = None
    ):
        self.app_id = os.getenv("GITHUB_APP_ID")
        self.private_key = os.getenv("GITHUB_APP_PRIVATE_KEY", "").replace("\\n", "\n")
        self.installation_id = installation_id
        self.access_token = access_token
        self.base_url = "https://api.github.com"
    
    async def get_installation_token(self) -> str:
        """Get installation access token"""
        if self.access_token:
            return self.access_token
        
        # Generate JWT
        jwt_token = self._generate_jwt()
        
        async with aiohttp.ClientSession() as session:
            url = f"{self.base_url}/app/installations/{self.installation_id}/access_tokens"
            headers = {
                "Authorization": f"Bearer {jwt_token}",
                "Accept": "application/vnd.github+json"
            }
            
            async with session.post(url, headers=headers) as response:
                if response.status != 201:
                    raise Exception(f"Failed to get installation token: {response.status}")
                
                data = await response.json()
                self.access_token = data["token"]
                return self.access_token
    
    def _generate_jwt(self) -> str:
        """Generate JWT for GitHub App authentication"""
        now = int(time.time())
        payload = {
            "iat": now - 60,
            "exp": now + (10 * 60),
            "iss": self.app_id
        }
        return jwt.encode(payload, self.private_key, algorithm="RS256")
    
    async def _request(
        self,
        method: str,
        endpoint: str,
        data: Optional[dict] = None
    ) -> dict:
        """Make authenticated request to GitHub API"""
        token = await self.get_installation_token()
        
        async with aiohttp.ClientSession() as session:
            url = f"{self.base_url}{endpoint}"
            headers = {
                "Authorization": f"token {token}",
                "Accept": "application/vnd.github+json"
            }
            
            async with session.request(method, url, headers=headers, json=data) as response:
                if response.status >= 400:
                    error_text = await response.text()
                    raise Exception(f"GitHub API error: {response.status} - {error_text}")
                
                return await response.json()
    
    async def create_check_run(
        self,
        owner: str,
        repo: str,
        name: str,
        head_sha: str,
        status: str = "queued",
        details_url: Optional[str] = None
    ) -> dict:
        """Create a check run"""
        data = {
            "name": name,
            "head_sha": head_sha,
            "status": status,
        }
        if details_url:
            data["details_url"] = details_url
        
        return await self._request(
            "POST",
            f"/repos/{owner}/{repo}/check-runs",
            data
        )
    
    async def update_check_run(
        self,
        owner: str,
        repo: str,
        check_run_id: int,
        status: str,
        conclusion: Optional[str] = None,
        output: Optional[dict] = None
    ) -> dict:
        """Update a check run"""
        data = {"status": status}
        if conclusion:
            data["conclusion"] = conclusion
        if output:
            data["output"] = output
        
        return await self._request(
            "PATCH",
            f"/repos/{owner}/{repo}/check-runs/{check_run_id}",
            data
        )
    
    async def create_commit_status(
        self,
        owner: str,
        repo: str,
        sha: str,
        state: str,
        description: str,
        context: str = "FinGuard Security Scan",
        target_url: Optional[str] = None
    ) -> dict:
        """Create a commit status"""
        data = {
            "state": state,
            "description": description[:140],
            "context": context
        }
        if target_url:
            data["target_url"] = target_url
        
        return await self._request(
            "POST",
            f"/repos/{owner}/{repo}/statuses/{sha}",
            data
        )
    
    async def create_pull_request_comment(
        self,
        owner: str,
        repo: str,
        pr_number: int,
        body: str
    ) -> dict:
        """Create a comment on a pull request"""
        return await self._request(
            "POST",
            f"/repos/{owner}/{repo}/issues/{pr_number}/comments",
            {"body": body}
        )
    
    async def get_pull_request_files(
        self,
        owner: str,
        repo: str,
        pr_number: int
    ) -> List[dict]:
        """Get files changed in a pull request"""
        return await self._request(
            "GET",
            f"/repos/{owner}/{repo}/pulls/{pr_number}/files"
        )
    
    async def get_file_content(
        self,
        owner: str,
        repo: str,
        path: str,
        ref: str = "main"
    ) -> str:
        """Get content of a file"""
        import base64
        
        data = await self._request(
            "GET",
            f"/repos/{owner}/{repo}/contents/{path}?ref={ref}"
        )
        
        content = data.get("content", "")
        return base64.b64decode(content).decode("utf-8")


def create_client(installation_id: int = None, access_token: str = None) -> GitHubClient:
    """Factory function to create GitHub client"""
    return GitHubClient(installation_id=installation_id, access_token=access_token)
