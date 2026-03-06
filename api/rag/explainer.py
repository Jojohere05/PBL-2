"""
RAG Explainer - Generates explanations for findings using LLM
"""
from typing import Dict, Any, Optional
import os
import aiohttp

from .retriever import RuleRetriever


class FindingExplainer:
    """Generates human-readable explanations for security findings"""
    
    def __init__(self):
        self.retriever = RuleRetriever()
        self.llm_api_key = os.getenv("OPENAI_API_KEY", "")
        self.llm_model = os.getenv("LLM_MODEL", "gpt-3.5-turbo")
    
    async def explain_finding(self, finding: Dict[str, Any]) -> Dict[str, str]:
        """Generate explanation for a finding"""
        rule_id = finding.get("rule_id", "")
        finding_type = finding.get("type", "")
        
        # Get context from retriever
        if finding_type == "dependency":
            context = self.retriever.get_vulnerability_context(rule_id)
        else:
            context = self.retriever.get_rule_context(rule_id)
        
        # Generate explanation
        if self.llm_api_key:
            explanation = await self._generate_llm_explanation(finding, context)
        else:
            explanation = self._generate_template_explanation(finding, context)
        
        return explanation
    
    async def _generate_llm_explanation(
        self,
        finding: Dict,
        context: Optional[Dict]
    ) -> Dict[str, str]:
        """Generate explanation using LLM"""
        prompt = self._build_prompt(finding, context)
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    "https://api.openai.com/v1/chat/completions",
                    headers={
                        "Authorization": f"Bearer {self.llm_api_key}",
                        "Content-Type": "application/json"
                    },
                    json={
                        "model": self.llm_model,
                        "messages": [
                            {
                                "role": "system",
                                "content": "You are a security expert explaining vulnerabilities to developers. Be concise but thorough."
                            },
                            {"role": "user", "content": prompt}
                        ],
                        "max_tokens": 500
                    }
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        explanation_text = data["choices"][0]["message"]["content"]
                        return self._parse_llm_response(explanation_text, context)
        except Exception as e:
            pass
        
        return self._generate_template_explanation(finding, context)
    
    def _build_prompt(self, finding: Dict, context: Optional[Dict]) -> str:
        """Build prompt for LLM"""
        prompt = f"""Explain this security finding:

Type: {finding.get('type')}
Rule ID: {finding.get('rule_id')}
Description: {finding.get('description')}
Severity: {finding.get('severity')}
File: {finding.get('file_path')}
Line: {finding.get('line', 'N/A')}

"""
        if context:
            prompt += f"Additional context: {context.get('rule', context.get('vulnerability', {}))}\n"
        
        prompt += """
Please provide:
1. A brief explanation of why this is a security issue
2. The potential impact if exploited
3. How to fix this issue
"""
        return prompt
    
    def _parse_llm_response(self, response: str, context: Optional[Dict]) -> Dict[str, str]:
        """Parse LLM response into structured explanation"""
        return {
            "explanation": response,
            "remediation": context.get("remediation", "") if context else "",
            "references": context.get("references", []) if context else []
        }
    
    def _generate_template_explanation(
        self,
        finding: Dict,
        context: Optional[Dict]
    ) -> Dict[str, str]:
        """Generate explanation using templates"""
        finding_type = finding.get("type", "")
        severity = finding.get("severity", "medium")
        description = finding.get("description", "")
        
        explanations = {
            "secret": f"""
**Security Issue**: {description}

**Why it matters**: Hardcoded secrets in code can be exposed through version control, 
logs, or unauthorized access. Attackers can use these credentials to access sensitive 
systems and data.

**Impact**: {self._get_impact_by_severity(severity)}

**How to fix**: Remove the secret from code and:
1. Use environment variables
2. Use a secrets management service (AWS Secrets Manager, HashiCorp Vault, etc.)
3. Rotate the compromised credentials immediately
""",
            "dependency": f"""
**Vulnerable Dependency**: {description}

**Why it matters**: Using packages with known vulnerabilities can expose your 
application to attacks. Attackers can exploit these vulnerabilities to gain 
unauthorized access or cause damage.

**Impact**: {self._get_impact_by_severity(severity)}

**How to fix**: 
1. Update the package to a patched version
2. If no patch is available, consider alternative packages
3. Implement additional security controls as a temporary measure
""",
            "terraform": f"""
**Infrastructure Misconfiguration**: {description}

**Why it matters**: Misconfigurations in infrastructure code can lead to 
security vulnerabilities when resources are deployed. This can expose 
sensitive data or allow unauthorized access.

**Impact**: {self._get_impact_by_severity(severity)}

**How to fix**: 
1. Apply the recommended secure configuration
2. Follow the principle of least privilege
3. Enable encryption and logging where applicable
"""
        }
        
        explanation = explanations.get(finding_type, f"Security issue: {description}")
        remediation = context.get("remediation", "") if context else ""
        references = context.get("references", []) if context else []
        
        return {
            "explanation": explanation.strip(),
            "remediation": remediation,
            "references": references
        }
    
    def _get_impact_by_severity(self, severity: str) -> str:
        """Get impact description by severity"""
        impacts = {
            "critical": "This is a critical issue that could lead to immediate compromise of your system or data.",
            "high": "This is a high severity issue that could lead to significant security breaches.",
            "medium": "This is a medium severity issue that should be addressed to improve security posture.",
            "low": "This is a low severity issue that represents a minor security concern."
        }
        return impacts.get(severity, impacts["medium"])


def create_explainer() -> FindingExplainer:
    """Factory function to create explainer"""
    return FindingExplainer()
