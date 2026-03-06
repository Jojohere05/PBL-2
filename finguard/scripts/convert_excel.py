"""
Convert Excel - Converts compliance Excel to JSON format
"""
import sys
import json
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any


def convert_excel_to_json(input_path: str, output_path: str = None):
    """Convert compliance Excel file to JSON format"""
    try:
        import pandas as pd
    except ImportError:
        print("Please install pandas: pip install pandas openpyxl")
        sys.exit(1)
    
    input_file = Path(input_path)
    if not input_file.exists():
        print(f"File not found: {input_path}")
        sys.exit(1)
    
    if output_path is None:
        output_path = Path(__file__).parent.parent / "data" / "rules" / "compliance_rules.json"
    else:
        output_path = Path(output_path)
    
    print(f"Converting: {input_file.name}")
    print(f"Output: {output_path}")
    
    # Read Excel file
    df = pd.read_excel(input_path)
    
    # Convert to rules format
    rules = []
    
    # Try to map columns (adjust based on actual Excel structure)
    column_mappings = {
        "id": ["id", "rule_id", "ID", "Rule ID", "rule id"],
        "description": ["description", "desc", "Description", "rule description"],
        "severity": ["severity", "Severity", "risk level", "Risk Level"],
        "category": ["category", "Category", "type", "Type"],
        "remediation": ["remediation", "Remediation", "fix", "Fix", "solution"],
        "references": ["references", "References", "ref", "links"],
        "regex": ["regex", "pattern", "Pattern", "detection pattern"],
        "framework": ["framework", "Framework", "compliance framework"]
    }
    
    def find_column(df: pd.DataFrame, possible_names: List[str]) -> str:
        """Find matching column name"""
        for name in possible_names:
            if name in df.columns:
                return name
            # Case-insensitive match
            for col in df.columns:
                if col.lower() == name.lower():
                    return col
        return None
    
    # Map actual columns
    mapped_columns = {}
    for target, possibilities in column_mappings.items():
        col = find_column(df, possibilities)
        if col:
            mapped_columns[target] = col
    
    print(f"\nMapped columns: {mapped_columns}")
    
    # Convert each row to a rule
    for idx, row in df.iterrows():
        rule = {
            "id": str(row.get(mapped_columns.get("id", ""), f"RULE-{idx+1}")),
            "type": "compliance"
        }
        
        if "description" in mapped_columns:
            rule["description"] = str(row[mapped_columns["description"]])
        
        if "severity" in mapped_columns:
            severity = str(row[mapped_columns["severity"]]).lower()
            if severity in ["critical", "high", "medium", "low"]:
                rule["severity"] = severity
            else:
                rule["severity"] = "medium"
        else:
            rule["severity"] = "medium"
        
        if "category" in mapped_columns:
            rule["category"] = str(row[mapped_columns["category"]])
        
        if "remediation" in mapped_columns:
            rule["remediation"] = str(row[mapped_columns["remediation"]])
        
        if "references" in mapped_columns:
            refs = str(row[mapped_columns["references"]])
            if refs and refs != "nan":
                rule["references"] = [r.strip() for r in refs.split(",")]
        
        if "regex" in mapped_columns:
            pattern = str(row[mapped_columns["regex"]])
            if pattern and pattern != "nan":
                rule["pattern"] = pattern
        
        if "framework" in mapped_columns:
            rule["framework"] = str(row[mapped_columns["framework"]])
        
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


if __name__ == "__main__":
    if len(sys.argv) < 2:
        # Default paths
        input_path = Path(__file__).parent.parent / "data" / "raw" / "compliance.xlsx"
        if input_path.exists():
            convert_excel_to_json(str(input_path))
        else:
            print("Usage: python convert_excel.py <input_excel_path> [output_json_path]")
            print(f"\nOr place your file at: {input_path}")
    else:
        output = sys.argv[2] if len(sys.argv) > 2 else None
        convert_excel_to_json(sys.argv[1], output)
