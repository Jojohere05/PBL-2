"""
Orchestrator Agent - Coordinates all scanning agents
"""
from typing import List, Dict, Any, Optional
import asyncio

from .secrets_agent import SecretsAgent
from .dependency_agent import DependencyAgent
from .terraform_agent import TerraformAgent


class OrchestratorAgent:
    """Orchestrates multiple scanning agents"""
    
    def __init__(self):
        self.agents = {
            "secrets": SecretsAgent(),
            "dependencies": DependencyAgent(),
            "terraform": TerraformAgent()
        }
        self.name = "orchestrator_agent"
        self.description = "Coordinates security scanning across all agents"
    
    async def scan_file(
        self,
        content: str,
        file_path: str,
        scan_types: Optional[List[str]] = None
    ) -> Dict[str, List[Dict[str, Any]]]:
        """Scan a single file with relevant agents"""
        if scan_types is None:
            scan_types = list(self.agents.keys())
        
        results = {}
        tasks = []
        
        for scan_type in scan_types:
            if scan_type in self.agents:
                agent = self.agents[scan_type]
                if self._should_scan(file_path, scan_type):
                    tasks.append(self._run_agent(agent, content, file_path, scan_type))
        
        completed = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in completed:
            if isinstance(result, tuple):
                scan_type, findings = result
                results[scan_type] = findings
            elif isinstance(result, Exception):
                # Log error but continue
                pass
        
        return results
    
    async def _run_agent(
        self,
        agent,
        content: str,
        file_path: str,
        scan_type: str
    ) -> tuple:
        """Run a single agent and return results"""
        findings = await agent.scan(content, file_path)
        return (scan_type, findings)
    
    def _should_scan(self, file_path: str, scan_type: str) -> bool:
        """Determine if file should be scanned by agent type"""
        file_lower = file_path.lower()
        
        if scan_type == "secrets":
            # Scan most files for secrets
            excluded = [".png", ".jpg", ".gif", ".ico", ".woff", ".ttf", ".eot"]
            return not any(file_lower.endswith(ext) for ext in excluded)
        
        elif scan_type == "dependencies":
            dep_files = [
                "requirements.txt", "package.json", "package-lock.json",
                "gemfile", "gemfile.lock", "go.mod", "go.sum",
                "cargo.toml", "cargo.lock", "pom.xml", "build.gradle"
            ]
            return any(file_lower.endswith(f) for f in dep_files)
        
        elif scan_type == "terraform":
            return file_lower.endswith(".tf") or file_lower.endswith(".tf.json")
        
        return False
    
    async def scan_repository(
        self,
        files: Dict[str, str],
        scan_types: Optional[List[str]] = None,
        progress_callback=None
    ) -> Dict[str, Any]:
        """Scan entire repository"""
        all_findings = []
        summary = {
            "total_files": len(files),
            "scanned_files": 0,
            "total_findings": 0,
            "by_severity": {"critical": 0, "high": 0, "medium": 0, "low": 0},
            "by_type": {}
        }
        
        for idx, (file_path, content) in enumerate(files.items()):
            results = await self.scan_file(content, file_path, scan_types)
            
            for scan_type, findings in results.items():
                all_findings.extend(findings)
                summary["by_type"][scan_type] = summary["by_type"].get(scan_type, 0) + len(findings)
                
                for finding in findings:
                    severity = finding.get("severity", "medium")
                    summary["by_severity"][severity] = summary["by_severity"].get(severity, 0) + 1
            
            summary["scanned_files"] += 1
            
            if progress_callback:
                progress = int((idx + 1) / len(files) * 100)
                await progress_callback(progress, file_path)
        
        summary["total_findings"] = len(all_findings)
        
        return {
            "findings": all_findings,
            "summary": summary
        }


def create_agent() -> OrchestratorAgent:
    """Factory function to create orchestrator agent"""
    return OrchestratorAgent()
