"""
Inspect Excel - Utility to inspect Excel file structure
"""
import sys
from pathlib import Path


def inspect_excel(file_path: str):
    """Inspect Excel file structure and contents"""
    try:
        import pandas as pd
        import openpyxl
    except ImportError:
        print("Please install required packages: pip install pandas openpyxl")
        sys.exit(1)
    
    path = Path(file_path)
    if not path.exists():
        print(f"File not found: {file_path}")
        sys.exit(1)
    
    print(f"\n{'=' * 60}")
    print(f"Inspecting: {path.name}")
    print(f"{'=' * 60}\n")
    
    # Load workbook to get sheet names
    wb = openpyxl.load_workbook(file_path, read_only=True)
    sheets = wb.sheetnames
    print(f"Sheets found: {len(sheets)}")
    for i, sheet in enumerate(sheets, 1):
        print(f"  {i}. {sheet}")
    
    print(f"\n{'=' * 60}")
    
    # Inspect each sheet
    for sheet_name in sheets:
        print(f"\nSheet: {sheet_name}")
        print("-" * 40)
        
        df = pd.read_excel(file_path, sheet_name=sheet_name)
        
        print(f"Rows: {len(df)}")
        print(f"Columns: {len(df.columns)}")
        print(f"\nColumn names:")
        for col in df.columns:
            dtype = df[col].dtype
            non_null = df[col].count()
            print(f"  - {col} ({dtype}, {non_null} non-null values)")
        
        print(f"\nFirst 5 rows:")
        print(df.head().to_string())
        
        print(f"\n{'=' * 60}")
    
    wb.close()


if __name__ == "__main__":
    if len(sys.argv) < 2:
        # Default path
        default_path = Path(__file__).parent.parent / "data" / "raw" / "compliance.xlsx"
        if default_path.exists():
            inspect_excel(str(default_path))
        else:
            print("Usage: python inspect_excel.py <path_to_excel_file>")
            print(f"\nOr place your file at: {default_path}")
    else:
        inspect_excel(sys.argv[1])
