"""
Secrets Agent - Detects secrets and credentials in code
"""
from typing import List, Dict, Any
import re
import json
from pathlib import Path

GITLEAKS_RULES_PATH = Path(__file__).parent.parent.parent / "data" / "gitleaks" / "gitleaks_rules.json"


class SecretsAgent:
    """Agent for detecting secrets, API keys, and credentials"""
    
    def __init__(self):
        self.rules = self._load_rules()
        self.name = "secrets_agent"
        self.description = "Detects hardcoded secrets, API keys, and credentials"
    
    def _load_rules(self) -> List[Dict]:
        """Load gitleaks rules"""
        try:
            with open(GITLEAKS_RULES_PATH, "r") as f:
                data = json.load(f)
                return data.get("rules", [])
        except FileNotFoundError:
            return self._default_rules()
    
    def _default_rules(self) -> List[Dict]:
        """Default secret detection rules"""
        return [
            {
                "id": "aws-access-key",
                "description": "AWS Access Key ID",
                "regex": r"AKIA[0-9A-Z]{16}",
                "severity": "critical"
            },
            {
                "id": "aws-secret-key",
                "description": "AWS Secret Access Key",
                "regex": r"(?i)aws(.{0,20})?(?-i)['\"][0-9a-zA-Z/+]{40}['\"]",
                "severity": "critical"
            },
            {
                "id": "github-token",
                "description": "GitHub Token",
                "regex": r"ghp_[0-9a-zA-Z]{36}|github_pat_[0-9a-zA-Z_]{22,}",
                "severity": "critical"
            },
            {
                "id": "generic-api-key",
                "description": "Generic API Key",
                "regex": r"(?i)(api[_-]?key|apikey|api_secret)['\"]?\s*[:=]\s*['\"][a-zA-Z0-9]{16,}['\"]",
                "severity": "high"
            },
            {
                "id": "private-key",
                "description": "Private Key",
                "regex": r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
                "severity": "critical"
            },
            {
                "id": "password-in-code",
                "description": "Hardcoded Password",
                "regex": r"(?i)(password|passwd|pwd)['\"]?\s*[:=]\s*['\"][^'\"]{8,}['\"]",
                "severity": "high"
            }
        ]
    
    async def scan(self, content: str, file_path: str) -> List[Dict[str, Any]]:
        """Scan content for secrets"""
        findings = []
        lines = content.split("\n")
        
        for rule in self.rules:
            pattern = re.compile(rule["regex"])
            for line_num, line in enumerate(lines, 1):
                matches = pattern.finditer(line)
                for match in matches:
                    findings.append({
                        "rule_id": rule["id"],
                        "type": "secret",
                        "severity": rule.get("severity", "high"),
                        "description": rule["description"],
                        "file_path": file_path,
                        "line": line_num,
                        "column": match.start(),
                        "match": self._redact_secret(match.group()),
                        "context": line.strip()[:100]
                    })
        
        return findings
    
    def _redact_secret(self, secret: str) -> str:
        """Redact secret value for safe display"""
        if len(secret) <= 8:
            return "*" * len(secret)
        return secret[:4] + "*" * (len(secret) - 8) + secret[-4:]


def create_agent() -> SecretsAgent:
    """Factory function to create secrets agent"""
    return SecretsAgent()
