# scripts/inspect_excel.py
import pandas as pd

df = pd.read_excel("data/raw/compliance.xlsx")
print("Shape:", df.shape)
print("\nColumns:", df.columns.tolist())
print("\nFirst 3 rows:")
print(df.head(3).to_string())
print("\nNull counts:")
print(df.isnull().sum())