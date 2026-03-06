"""
RAG Retriever - Retrieves relevant context for findings
"""
from typing import List, Dict, Any, Optional
import json
from pathlib import Path


class RuleRetriever:
    """Retrieves relevant rules and context for findings"""
    
    def __init__(self):
        self.compliance_rules = self._load_compliance_rules()
        self.gitleaks_rules = self._load_gitleaks_rules()
        self.osv_data = self._load_osv_data()
    
    def _load_compliance_rules(self) -> Dict:
        """Load compliance rules"""
        path = Path(__file__).parent.parent.parent / "data" / "rules" / "compliance_rules.json"
        try:
            with open(path, "r") as f:
                return json.load(f)
        except FileNotFoundError:
            return {"rules": []}
    
    def _load_gitleaks_rules(self) -> Dict:
        """Load gitleaks rules"""
        path = Path(__file__).parent.parent.parent / "data" / "gitleaks" / "gitleaks_rules.json"
        try:
            with open(path, "r") as f:
                return json.load(f)
        except FileNotFoundError:
            return {"rules": []}
    
    def _load_osv_data(self) -> Dict:
        """Load OSV vulnerability index"""
        # Return indexed data for quick lookup
        return {}
    
    def get_rule_context(self, rule_id: str) -> Optional[Dict]:
        """Get full context for a rule"""
        # Search in compliance rules
        for rule in self.compliance_rules.get("rules", []):
            if rule.get("id") == rule_id:
                return {
                    "source": "compliance",
                    "rule": rule,
                    "remediation": rule.get("remediation", ""),
                    "references": rule.get("references", [])
                }
        
        # Search in gitleaks rules
        for rule in self.gitleaks_rules.get("rules", []):
            if rule.get("id") == rule_id:
                return {
                    "source": "gitleaks",
                    "rule": rule,
                    "remediation": self._get_secret_remediation(rule),
                    "references": []
                }
        
        return None
    
    def get_vulnerability_context(self, vuln_id: str) -> Optional[Dict]:
        """Get context for a vulnerability"""
        osv_path = Path(__file__).parent.parent.parent / "data" / "osv"
        
        for json_file in osv_path.glob("*.json"):
            try:
                with open(json_file, "r") as f:
                    data = json.load(f)
                    if isinstance(data, dict) and data.get("id") == vuln_id:
                        return {
                            "source": "osv",
                            "vulnerability": data,
                            "remediation": self._get_vuln_remediation(data),
                            "references": data.get("references", [])
                        }
            except (json.JSONDecodeError, IOError):
                continue
        
        return None
    
    def _get_secret_remediation(self, rule: Dict) -> str:
        """Get remediation advice for secret finding"""
        rule_id = rule.get("id", "")
        
        remediations = {
            "aws": "Rotate the AWS credentials immediately. Use IAM roles or AWS Secrets Manager instead of hardcoded credentials.",
            "github": "Revoke the GitHub token immediately. Use GitHub Actions secrets or environment variables.",
            "api": "Remove the API key from code. Use environment variables or a secrets management service.",
            "private-key": "Remove the private key from the repository. Use a secrets manager or secure key storage.",
            "password": "Remove hardcoded passwords. Use environment variables or a secrets management service."
        }
        
        for key, remediation in remediations.items():
            if key in rule_id.lower():
                return remediation
        
        return "Remove the secret from code and use environment variables or a secrets management service."
    
    def _get_vuln_remediation(self, vuln: Dict) -> str:
        """Get remediation advice for vulnerability"""
        affected = vuln.get("affected", [])
        
        if affected:
            pkg = affected[0]
            ranges = pkg.get("ranges", [])
            for r in ranges:
                events = r.get("events", [])
                for event in events:
                    if "fixed" in event:
                        return f"Upgrade to version {event['fixed']} or later."
        
        return "Check the vulnerability details for specific remediation steps."
    
    def search_similar_rules(self, query: str, limit: int = 5) -> List[Dict]:
        """Search for rules similar to query"""
        # Simple keyword matching (replace with vector search in production)
        results = []
        query_lower = query.lower()
        
        for rule in self.compliance_rules.get("rules", []):
            description = rule.get("description", "").lower()
            if any(word in description for word in query_lower.split()):
                results.append({"source": "compliance", "rule": rule})
        
        for rule in self.gitleaks_rules.get("rules", []):
            description = rule.get("description", "").lower()
            if any(word in description for word in query_lower.split()):
                results.append({"source": "gitleaks", "rule": rule})
        
        return results[:limit]


def create_retriever() -> RuleRetriever:
    """Factory function to create retriever"""
    return RuleRetriever()
