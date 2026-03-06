"""
Context Classifier - Classifies code context for better finding relevance
"""
from typing import List, Dict, Any, Optional
import re


class ContextClassifier:
    """Classifies code context to improve finding relevance"""
    
    def __init__(self):
        # Patterns for context detection
        self.test_patterns = [
            r"test[_/]",
            r"_test\.",
            r"\.test\.",
            r"spec[_/]",
            r"_spec\.",
            r"\.spec\.",
            r"__tests__",
            r"\.mock\.",
            r"fixture"
        ]
        
        self.example_patterns = [
            r"example[s]?[_/]",
            r"sample[s]?[_/]",
            r"demo[_/]",
            r"tutorial[_/]"
        ]
        
        self.config_patterns = [
            r"\.env(\.|$)",
            r"\.env\.example",
            r"config[_/]",
            r"settings[_/]"
        ]
        
        self.vendor_patterns = [
            r"node_modules[/]",
            r"vendor[/]",
            r"third[_-]?party",
            r"external[/]"
        ]
    
    def classify_file(self, file_path: str) -> Dict[str, Any]:
        """Classify a file based on its path"""
        file_lower = file_path.lower()
        
        classification = {
            "is_test": False,
            "is_example": False,
            "is_config": False,
            "is_vendor": False,
            "context_type": "production",
            "relevance_multiplier": 1.0
        }
        
        # Check patterns
        if self._matches_any(file_lower, self.test_patterns):
            classification["is_test"] = True
            classification["context_type"] = "test"
            classification["relevance_multiplier"] = 0.5
        
        elif self._matches_any(file_lower, self.example_patterns):
            classification["is_example"] = True
            classification["context_type"] = "example"
            classification["relevance_multiplier"] = 0.3
        
        elif self._matches_any(file_lower, self.config_patterns):
            classification["is_config"] = True
            classification["context_type"] = "config"
            classification["relevance_multiplier"] = 1.2  # Config issues are important
        
        elif self._matches_any(file_lower, self.vendor_patterns):
            classification["is_vendor"] = True
            classification["context_type"] = "vendor"
            classification["relevance_multiplier"] = 0.2
        
        return classification
    
    def _matches_any(self, text: str, patterns: List[str]) -> bool:
        """Check if text matches any pattern"""
        return any(re.search(pattern, text) for pattern in patterns)
    
    def classify_finding(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """Add context classification to a finding"""
        file_path = finding.get("file_path", "")
        classification = self.classify_file(file_path)
        
        # Add classification to finding
        finding["context"] = classification
        
        # Adjust severity based on context
        if classification["context_type"] == "test":
            finding["adjusted_severity"] = self._lower_severity(finding.get("severity", "medium"))
            finding["context_note"] = "Finding in test file - may be intentional for testing"
        elif classification["context_type"] == "example":
            finding["adjusted_severity"] = self._lower_severity(finding.get("severity", "medium"), 2)
            finding["context_note"] = "Finding in example/demo file - likely not production code"
        elif classification["context_type"] == "vendor":
            finding["adjusted_severity"] = finding.get("severity", "medium")
            finding["context_note"] = "Finding in vendor/third-party code - consider updating dependency"
        else:
            finding["adjusted_severity"] = finding.get("severity", "medium")
        
        return finding
    
    def _lower_severity(self, severity: str, levels: int = 1) -> str:
        """Lower severity by specified levels"""
        severity_order = ["critical", "high", "medium", "low"]
        
        try:
            current_idx = severity_order.index(severity)
            new_idx = min(len(severity_order) - 1, current_idx + levels)
            return severity_order[new_idx]
        except ValueError:
            return severity
    
    def filter_findings(
        self,
        findings: List[Dict[str, Any]],
        include_test: bool = True,
        include_example: bool = False,
        include_vendor: bool = False
    ) -> List[Dict[str, Any]]:
        """Filter findings based on context"""
        filtered = []
        
        for finding in findings:
            # Classify if not already done
            if "context" not in finding:
                finding = self.classify_finding(finding)
            
            context = finding.get("context", {})
            
            # Apply filters
            if context.get("is_test") and not include_test:
                continue
            if context.get("is_example") and not include_example:
                continue
            if context.get("is_vendor") and not include_vendor:
                continue
            
            filtered.append(finding)
        
        return filtered
    
    def get_context_summary(self, findings: List[Dict[str, Any]]) -> Dict[str, int]:
        """Get summary of findings by context"""
        summary = {
            "production": 0,
            "test": 0,
            "example": 0,
            "config": 0,
            "vendor": 0
        }
        
        for finding in findings:
            if "context" not in finding:
                finding = self.classify_finding(finding)
            
            context_type = finding.get("context", {}).get("context_type", "production")
            summary[context_type] = summary.get(context_type, 0) + 1
        
        return summary


def create_classifier() -> ContextClassifier:
    """Factory function to create context classifier"""
    return ContextClassifier()
