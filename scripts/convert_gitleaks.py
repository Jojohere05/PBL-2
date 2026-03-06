"""
Convert Gitleaks - Converts gitleaks.toml to JSON format
"""
import sys
import json
import re
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any


def parse_toml_manually(content: str) -> List[Dict]:
    """Parse gitleaks TOML format manually"""
    rules = []
    current_rule = None
    
    lines = content.split("\n")
    i = 0
    
    while i < len(lines):
        line = lines[i].strip()
        
        # Start of a new rule
        if line.startswith("[[rules]]"):
            if current_rule:
                rules.append(current_rule)
            current_rule = {}
        
        # Parse key-value pairs
        elif current_rule is not None and "=" in line:
            # Handle different value types
            match = re.match(r'(\w+)\s*=\s*(.+)', line)
            if match:
                key = match.group(1)
                value = match.group(2).strip()
                
                # Handle string values
                if value.startswith('"') or value.startswith("'"):
                    # Handle multi-line strings
                    if value.startswith('"""') or value.startswith("'''"):
                        quote = value[:3]
                        value = value[3:]
                        while not value.endswith(quote):
                            i += 1
                            if i < len(lines):
                                value += "\n" + lines[i]
                        value = value[:-3]
                    else:
                        # Single line string
                        value = value[1:-1] if value.endswith(value[0]) else value[1:]
                
                # Handle arrays
                elif value.startswith("["):
                    # Simple array parsing
                    array_str = value
                    while not array_str.endswith("]"):
                        i += 1
                        if i < len(lines):
                            array_str += lines[i].strip()
                    
                    # Parse array items
                    items = re.findall(r'"([^"]*)"', array_str)
                    value = items
                
                # Handle booleans and numbers
                elif value.lower() == "true":
                    value = True
                elif value.lower() == "false":
                    value = False
                elif value.isdigit():
                    value = int(value)
                
                current_rule[key] = value
        
        i += 1
    
    # Don't forget the last rule
    if current_rule:
        rules.append(current_rule)
    
    return rules


def convert_gitleaks_to_json(input_path: str, output_path: str = None):
    """Convert gitleaks TOML file to JSON format"""
    input_file = Path(input_path)
    if not input_file.exists():
        print(f"File not found: {input_path}")
        sys.exit(1)
    
    if output_path is None:
        output_path = Path(__file__).parent.parent / "data" / "gitleaks" / "gitleaks_rules.json"
    else:
        output_path = Path(output_path)
    
    print(f"Converting: {input_file.name}")
    print(f"Output: {output_path}")
    
    # Read TOML file
    with open(input_file, "r", encoding="utf-8") as f:
        content = f.read()
    
    # Try using toml library first
    try:
        import toml
        data = toml.loads(content)
        raw_rules = data.get("rules", [])
    except ImportError:
        print("toml library not found, using manual parser")
        raw_rules = parse_toml_manually(content)
    except Exception as e:
        print(f"TOML parsing failed: {e}, using manual parser")
        raw_rules = parse_toml_manually(content)
    
    # Convert to our format
    rules = []
    for raw_rule in raw_rules:
        rule = {
            "id": raw_rule.get("id", raw_rule.get("description", "unknown")),
            "description": raw_rule.get("description", ""),
            "regex": raw_rule.get("regex", raw_rule.get("pattern", "")),
            "severity": map_severity(raw_rule),
            "tags": raw_rule.get("tags", []),
            "keywords": raw_rule.get("keywords", [])
        }
        
        # Optional fields
        if "secretGroup" in raw_rule:
            rule["secret_group"] = raw_rule["secretGroup"]
        
        if "entropy" in raw_rule:
            rule["entropy"] = raw_rule["entropy"]
        
        if "allowlist" in raw_rule:
            rule["allowlist"] = raw_rule["allowlist"]
        
        rules.append(rule)
    
    # Create output structure
    output = {
        "metadata": {
            "generated_at": datetime.now().isoformat(),
            "source": input_file.name,
            "version": "1.0.0",
            "total_rules": len(rules)
        },
        "rules": rules
    }
    
    # Ensure output directory exists
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    # Write JSON
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)
    
    print(f"\nConverted {len(rules)} rules")
    print(f"Output written to: {output_path}")
    
    # Summary by severity
    severity_counts = {}
    for rule in rules:
        sev = rule.get("severity", "unknown")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
    
    print(f"\nBy severity:")
    for sev, count in sorted(severity_counts.items()):
        print(f"  {sev}: {count}")


def map_severity(rule: Dict) -> str:
    """Map rule to severity based on type"""
    rule_id = rule.get("id", "").lower()
    description = rule.get("description", "").lower()
    
    # Critical: Cloud provider credentials, database passwords
    if any(term in rule_id for term in ["aws", "gcp", "azure", "database", "db-"]):
        return "critical"
    
    # Critical: Private keys
    if "private" in rule_id and "key" in rule_id:
        return "critical"
    
    # High: API keys, tokens
    if any(term in rule_id for term in ["api-key", "token", "secret"]):
        return "high"
    
    # High: Passwords
    if "password" in rule_id or "passwd" in rule_id:
        return "high"
    
    # Medium: Generic patterns
    if "generic" in rule_id:
        return "medium"
    
    return "high"  # Default to high for secrets


if __name__ == "__main__":
    if len(sys.argv) < 2:
        # Default paths
        input_path = Path(__file__).parent.parent / "data" / "raw" / "gitleaks.toml"
        if input_path.exists():
            convert_gitleaks_to_json(str(input_path))
        else:
            print("Usage: python convert_gitleaks.py <input_toml_path> [output_json_path]")
            print(f"\nOr place your file at: {input_path}")
    else:
        output = sys.argv[2] if len(sys.argv) > 2 else None
        convert_gitleaks_to_json(sys.argv[1], output)
