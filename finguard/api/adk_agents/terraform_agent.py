"""
Terraform Agent - Scans Terraform configurations for security issues
"""
from typing import List, Dict, Any
import re
import json
from pathlib import Path

COMPLIANCE_RULES_PATH = Path(__file__).parent.parent.parent / "data" / "rules" / "compliance_rules.json"


class TerraformAgent:
    """Agent for detecting security issues in Terraform configurations"""
    
    def __init__(self):
        self.rules = self._load_rules()
        self.name = "terraform_agent"
        self.description = "Detects security misconfigurations in Terraform code"
    
    def _load_rules(self) -> List[Dict]:
        """Load compliance rules"""
        try:
            with open(COMPLIANCE_RULES_PATH, "r") as f:
                data = json.load(f)
                return [r for r in data.get("rules", []) if r.get("type") == "terraform"]
        except FileNotFoundError:
            return self._default_rules()
    
    def _default_rules(self) -> List[Dict]:
        """Default Terraform security rules"""
        return [
            {
                "id": "tf-aws-s3-public-read",
                "description": "S3 bucket should not have public read access",
                "pattern": r'acl\s*=\s*"public-read"',
                "severity": "critical",
                "resource_type": "aws_s3_bucket"
            },
            {
                "id": "tf-aws-s3-no-encryption",
                "description": "S3 bucket should have server-side encryption enabled",
                "pattern": r'resource\s+"aws_s3_bucket"\s+"[^"]+"\s*{(?:(?!server_side_encryption_configuration).)*}',
                "severity": "high",
                "resource_type": "aws_s3_bucket"
            },
            {
                "id": "tf-aws-sg-open-ingress",
                "description": "Security group should not allow unrestricted ingress",
                "pattern": r'cidr_blocks\s*=\s*\[\s*"0\.0\.0\.0/0"\s*\]',
                "severity": "high",
                "resource_type": "aws_security_group"
            },
            {
                "id": "tf-aws-rds-no-encryption",
                "description": "RDS instance should have encryption enabled",
                "pattern": r'storage_encrypted\s*=\s*false',
                "severity": "high",
                "resource_type": "aws_db_instance"
            },
            {
                "id": "tf-aws-rds-public",
                "description": "RDS instance should not be publicly accessible",
                "pattern": r'publicly_accessible\s*=\s*true',
                "severity": "critical",
                "resource_type": "aws_db_instance"
            },
            {
                "id": "tf-aws-ec2-no-imdsv2",
                "description": "EC2 instance should use IMDSv2",
                "pattern": r'http_tokens\s*=\s*"optional"',
                "severity": "medium",
                "resource_type": "aws_instance"
            },
            {
                "id": "tf-azure-storage-https-only",
                "description": "Azure storage account should enforce HTTPS",
                "pattern": r'enable_https_traffic_only\s*=\s*false',
                "severity": "high",
                "resource_type": "azurerm_storage_account"
            },
            {
                "id": "tf-hardcoded-secret",
                "description": "Hardcoded secret in Terraform configuration",
                "pattern": r'(password|secret|api_key|access_key)\s*=\s*"[^"]{8,}"',
                "severity": "critical",
                "resource_type": "any"
            }
        ]
    
    async def scan(self, content: str, file_path: str) -> List[Dict[str, Any]]:
        """Scan Terraform file for security issues"""
        if not file_path.endswith(".tf"):
            return []
        
        findings = []
        lines = content.split("\n")
        
        for rule in self.rules:
            pattern = re.compile(rule["pattern"], re.IGNORECASE | re.MULTILINE | re.DOTALL)
            
            # Search in full content for multi-line patterns
            matches = pattern.finditer(content)
            for match in matches:
                # Find line number
                line_num = content[:match.start()].count("\n") + 1
                
                findings.append({
                    "rule_id": rule["id"],
                    "type": "terraform",
                    "severity": rule.get("severity", "medium"),
                    "description": rule["description"],
                    "file_path": file_path,
                    "line": line_num,
                    "resource_type": rule.get("resource_type", "unknown"),
                    "match": match.group()[:100]
                })
        
        # Additional checks
        findings.extend(await self._check_missing_tags(content, file_path))
        findings.extend(await self._check_deprecated_resources(content, file_path))
        
        return findings
    
    async def _check_missing_tags(self, content: str, file_path: str) -> List[Dict]:
        """Check for resources missing required tags"""
        findings = []
        # Pattern to find resources without tags block
        resource_pattern = re.compile(r'resource\s+"([^"]+)"\s+"([^"]+)"\s*{([^}]*)}', re.DOTALL)
        
        for match in resource_pattern.finditer(content):
            resource_type = match.group(1)
            resource_name = match.group(2)
            resource_body = match.group(3)
            
            if "tags" not in resource_body.lower():
                line_num = content[:match.start()].count("\n") + 1
                findings.append({
                    "rule_id": "tf-missing-tags",
                    "type": "terraform",
                    "severity": "low",
                    "description": f"Resource {resource_type}.{resource_name} is missing tags",
                    "file_path": file_path,
                    "line": line_num,
                    "resource_type": resource_type
                })
        
        return findings
    
    async def _check_deprecated_resources(self, content: str, file_path: str) -> List[Dict]:
        """Check for deprecated resource types"""
        deprecated = [
            ("aws_s3_bucket_object", "aws_s3_object"),
            ("aws_elasticsearch_domain", "aws_opensearch_domain")
        ]
        
        findings = []
        for old, new in deprecated:
            if f'resource "{old}"' in content:
                line_num = content.find(f'resource "{old}"')
                line_num = content[:line_num].count("\n") + 1
                findings.append({
                    "rule_id": "tf-deprecated-resource",
                    "type": "terraform",
                    "severity": "low",
                    "description": f"Deprecated resource type {old}, use {new} instead",
                    "file_path": file_path,
                    "line": line_num,
                    "resource_type": old
                })
        
        return findings


def create_agent() -> TerraformAgent:
    """Factory function to create terraform agent"""
    return TerraformAgent()
