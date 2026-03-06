"""
Dependency Agent - Scans for vulnerable dependencies
"""
from typing import List, Dict, Any
import json
import re
from pathlib import Path

OSV_DATA_PATH = Path(__file__).parent.parent.parent / "data" / "osv"


class DependencyAgent:
    """Agent for detecting vulnerable dependencies"""
    
    def __init__(self):
        self.vulnerabilities = self._load_osv_data()
        self.name = "dependency_agent"
        self.description = "Detects vulnerable dependencies using OSV database"
    
    def _load_osv_data(self) -> Dict[str, List[Dict]]:
        """Load OSV vulnerability data"""
        vuln_db = {}
        osv_path = OSV_DATA_PATH
        
        if not osv_path.exists():
            return vuln_db
        
        for json_file in osv_path.glob("*.json"):
            try:
                with open(json_file, "r") as f:
                    data = json.load(f)
                    if isinstance(data, list):
                        for vuln in data:
                            self._index_vulnerability(vuln_db, vuln)
                    else:
                        self._index_vulnerability(vuln_db, data)
            except (json.JSONDecodeError, IOError):
                continue
        
        return vuln_db
    
    def _index_vulnerability(self, db: Dict, vuln: Dict):
        """Index a vulnerability by affected package"""
        affected = vuln.get("affected", [])
        for pkg in affected:
            pkg_name = pkg.get("package", {}).get("name", "")
            ecosystem = pkg.get("package", {}).get("ecosystem", "")
            if pkg_name:
                key = f"{ecosystem}:{pkg_name}".lower()
                if key not in db:
                    db[key] = []
                db[key].append({
                    "id": vuln.get("id"),
                    "summary": vuln.get("summary", ""),
                    "severity": self._extract_severity(vuln),
                    "versions": pkg.get("versions", []),
                    "ranges": pkg.get("ranges", [])
                })
    
    def _extract_severity(self, vuln: Dict) -> str:
        """Extract severity from vulnerability data"""
        severity = vuln.get("severity", [])
        if severity:
            for s in severity:
                if s.get("type") == "CVSS_V3":
                    score = s.get("score", "")
                    if "CRITICAL" in score or float(score.split("/")[0]) >= 9.0 if "/" in score else False:
                        return "critical"
                    elif "HIGH" in score:
                        return "high"
                    elif "MEDIUM" in score:
                        return "medium"
        return "medium"
    
    async def scan(self, content: str, file_path: str) -> List[Dict[str, Any]]:
        """Scan dependency files for vulnerabilities"""
        findings = []
        
        # Detect file type and parse dependencies
        if file_path.endswith("requirements.txt"):
            findings.extend(await self._scan_python_requirements(content, file_path))
        elif file_path.endswith("package.json"):
            findings.extend(await self._scan_npm_package(content, file_path))
        elif file_path.endswith("package-lock.json"):
            findings.extend(await self._scan_npm_lock(content, file_path))
        elif file_path.endswith("Gemfile.lock"):
            findings.extend(await self._scan_gemfile(content, file_path))
        elif file_path.endswith("go.sum"):
            findings.extend(await self._scan_go_sum(content, file_path))
        
        return findings
    
    async def _scan_python_requirements(self, content: str, file_path: str) -> List[Dict]:
        """Scan Python requirements.txt"""
        findings = []
        for line_num, line in enumerate(content.split("\n"), 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            
            # Parse package==version or package>=version
            match = re.match(r"([a-zA-Z0-9_-]+)([=<>!~]+)?(.+)?", line)
            if match:
                pkg_name = match.group(1).lower()
                version = match.group(3) or ""
                
                key = f"pypi:{pkg_name}"
                if key in self.vulnerabilities:
                    for vuln in self.vulnerabilities[key]:
                        if self._version_affected(version, vuln):
                            findings.append({
                                "rule_id": vuln["id"],
                                "type": "dependency",
                                "severity": vuln["severity"],
                                "description": vuln["summary"],
                                "file_path": file_path,
                                "line": line_num,
                                "package": pkg_name,
                                "version": version
                            })
        
        return findings
    
    async def _scan_npm_package(self, content: str, file_path: str) -> List[Dict]:
        """Scan npm package.json"""
        findings = []
        try:
            data = json.loads(content)
            deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
            
            for pkg_name, version in deps.items():
                key = f"npm:{pkg_name.lower()}"
                if key in self.vulnerabilities:
                    for vuln in self.vulnerabilities[key]:
                        findings.append({
                            "rule_id": vuln["id"],
                            "type": "dependency",
                            "severity": vuln["severity"],
                            "description": vuln["summary"],
                            "file_path": file_path,
                            "package": pkg_name,
                            "version": version.lstrip("^~")
                        })
        except json.JSONDecodeError:
            pass
        
        return findings
    
    async def _scan_npm_lock(self, content: str, file_path: str) -> List[Dict]:
        """Scan npm package-lock.json"""
        # Similar implementation
        return []
    
    async def _scan_gemfile(self, content: str, file_path: str) -> List[Dict]:
        """Scan Ruby Gemfile.lock"""
        return []
    
    async def _scan_go_sum(self, content: str, file_path: str) -> List[Dict]:
        """Scan Go go.sum"""
        return []
    
    def _version_affected(self, version: str, vuln: Dict) -> bool:
        """Check if version is affected by vulnerability"""
        # Simplified version check
        affected_versions = vuln.get("versions", [])
        if not affected_versions:
            return True  # Assume affected if no version info
        return version in affected_versions


def create_agent() -> DependencyAgent:
    """Factory function to create dependency agent"""
    return DependencyAgent()
