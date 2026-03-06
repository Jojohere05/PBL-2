"""
Validate Datasets - Validates all data files are properly formatted
"""
import sys
import json
from pathlib import Path
from typing import Dict, List, Tuple


def validate_json_file(file_path: Path) -> Tuple[bool, str]:
    """Validate a JSON file"""
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return True, f"Valid JSON with {len(str(data))} characters"
    except json.JSONDecodeError as e:
        return False, f"Invalid JSON: {e}"
    except Exception as e:
        return False, f"Error reading file: {e}"


def validate_compliance_rules(file_path: Path) -> Tuple[bool, List[str]]:
    """Validate compliance rules JSON"""
    issues = []
    
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        return False, [f"Cannot read file: {e}"]
    
    # Check structure
    if "rules" not in data:
        issues.append("Missing 'rules' array")
    
    if "metadata" not in data:
        issues.append("Missing 'metadata' object")
    
    rules = data.get("rules", [])
    
    for i, rule in enumerate(rules):
        if "id" not in rule:
            issues.append(f"Rule {i}: missing 'id'")
        
        if "description" not in rule:
            issues.append(f"Rule {i} ({rule.get('id', 'unknown')}): missing 'description'")
        
        if "severity" not in rule:
            issues.append(f"Rule {i} ({rule.get('id', 'unknown')}): missing 'severity'")
        elif rule["severity"] not in ["critical", "high", "medium", "low"]:
            issues.append(f"Rule {i} ({rule.get('id', 'unknown')}): invalid severity '{rule['severity']}'")
    
    return len(issues) == 0, issues


def validate_gitleaks_rules(file_path: Path) -> Tuple[bool, List[str]]:
    """Validate gitleaks rules JSON"""
    issues = []
    
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        return False, [f"Cannot read file: {e}"]
    
    rules = data.get("rules", [])
    
    for i, rule in enumerate(rules):
        if "id" not in rule:
            issues.append(f"Rule {i}: missing 'id'")
        
        if "regex" not in rule:
            issues.append(f"Rule {i} ({rule.get('id', 'unknown')}): missing 'regex'")
        else:
            # Validate regex
            import re
            try:
                re.compile(rule["regex"])
            except re.error as e:
                issues.append(f"Rule {i} ({rule.get('id', 'unknown')}): invalid regex - {e}")
    
    return len(issues) == 0, issues


def validate_osv_files(osv_dir: Path) -> Tuple[int, int, List[str]]:
    """Validate OSV JSON files"""
    valid_count = 0
    invalid_count = 0
    issues = []
    
    json_files = list(osv_dir.glob("*.json"))
    
    for json_file in json_files:
        try:
            with open(json_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            
            # Basic validation
            if isinstance(data, dict):
                if "id" not in data:
                    issues.append(f"{json_file.name}: missing 'id'")
                    invalid_count += 1
                else:
                    valid_count += 1
            elif isinstance(data, list):
                valid_count += 1
            else:
                issues.append(f"{json_file.name}: unexpected root type")
                invalid_count += 1
                
        except json.JSONDecodeError as e:
            issues.append(f"{json_file.name}: invalid JSON - {e}")
            invalid_count += 1
        except Exception as e:
            issues.append(f"{json_file.name}: error - {e}")
            invalid_count += 1
    
    return valid_count, invalid_count, issues


def main():
    """Main validation function"""
    data_dir = Path(__file__).parent.parent / "data"
    
    print("=" * 60)
    print("FinGuard Data Validation")
    print("=" * 60)
    
    all_valid = True
    
    # Validate compliance rules
    compliance_file = data_dir / "rules" / "compliance_rules.json"
    print(f"\n[1] Compliance Rules: {compliance_file}")
    if compliance_file.exists():
        valid, issues = validate_compliance_rules(compliance_file)
        if valid:
            with open(compliance_file) as f:
                data = json.load(f)
            print(f"    ✓ Valid - {len(data.get('rules', []))} rules")
        else:
            print(f"    ✗ Invalid:")
            for issue in issues[:10]:  # Show first 10 issues
                print(f"      - {issue}")
            if len(issues) > 10:
                print(f"      ... and {len(issues) - 10} more issues")
            all_valid = False
    else:
        print(f"    ⚠ File not found")
    
    # Validate gitleaks rules
    gitleaks_file = data_dir / "gitleaks" / "gitleaks_rules.json"
    print(f"\n[2] Gitleaks Rules: {gitleaks_file}")
    if gitleaks_file.exists():
        valid, issues = validate_gitleaks_rules(gitleaks_file)
        if valid:
            with open(gitleaks_file) as f:
                data = json.load(f)
            print(f"    ✓ Valid - {len(data.get('rules', []))} rules")
        else:
            print(f"    ✗ Invalid:")
            for issue in issues[:10]:
                print(f"      - {issue}")
            if len(issues) > 10:
                print(f"      ... and {len(issues) - 10} more issues")
            all_valid = False
    else:
        print(f"    ⚠ File not found")
    
    # Validate OSV files
    osv_dir = data_dir / "osv"
    print(f"\n[3] OSV Vulnerability Data: {osv_dir}")
    if osv_dir.exists():
        valid, invalid, issues = validate_osv_files(osv_dir)
        if invalid == 0:
            print(f"    ✓ Valid - {valid} files")
        else:
            print(f"    ⚠ {valid} valid, {invalid} invalid files")
            for issue in issues[:5]:
                print(f"      - {issue}")
            if len(issues) > 5:
                print(f"      ... and {len(issues) - 5} more issues")
    else:
        print(f"    ⚠ Directory not found")
    
    # Validate feedback weights
    weights_file = data_dir / "feedback" / "rule_weights.json"
    print(f"\n[4] Feedback Weights: {weights_file}")
    if weights_file.exists():
        valid, msg = validate_json_file(weights_file)
        if valid:
            print(f"    ✓ {msg}")
        else:
            print(f"    ✗ {msg}")
            all_valid = False
    else:
        print(f"    ⚠ File not found (will be auto-created)")
    
    # Summary
    print("\n" + "=" * 60)
    if all_valid:
        print("✓ All datasets valid")
    else:
        print("✗ Some datasets have issues")
    print("=" * 60)
    
    return 0 if all_valid else 1


if __name__ == "__main__":
    sys.exit(main())
