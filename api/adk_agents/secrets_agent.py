import json
import math
import os
import re
from collections import Counter
from typing import Any

RULES_PATH = "data/gitleaks/gitleaks_rules.json"
MAX_FILE_SIZE = 500 * 1024

SKIP_DIRS = {
    ".git",
    "node_modules",
    "__pycache__",
    ".venv",
    "venv",
    "vendor",
    "dist",
    "build",
    ".next",
    "public",
    "static",
    "assets",
    "record",
    "records",
    "cassette",
    "cassettes",
    "vcr",
    "fixtures",
    "fixture",
    "__fixtures__",
    ".pytest_cache",
    ".tox",
    "coverage",
    "htmlcov",
    "site-packages",
    "test",
    "tests",
    "spec",
    "__tests__",
}

SCAN_EXTENSIONS = {
    ".py",
    ".js",
    ".ts",
    ".jsx",
    ".tsx",
    ".env",
    ".cfg",
    ".conf",
    ".config",
    ".yaml",
    ".yml",
    ".toml",
    ".ini",
    ".tf",
    ".tfvars",
    ".sh",
    ".bash",
    ".rb",
    ".php",
    ".go",
    ".java",
    ".properties",
}

SKIP_FILENAMES = {
    "package-lock.json",
    "yarn.lock",
    "composer.lock",
    "poetry.lock",
    "gemfile.lock",
    "go.sum",
    "go.mod",
    "changelog.md",
    "changelog",
    "readme.md",
    "readme",
    "license",
    "license.md",
    ".gitignore",
    ".dockerignore",
}

YAML_CASSETTE_PATH_TERMS = {"record", "http", "cassette", "vcr", "test_http", "recorded"}

GENERIC_PLACEHOLDER_TERMS = {
    "test",
    "example",
    "fake",
    "dummy",
    "changeme",
    "placeholder",
    "your_",
    "insert",
    "api_key_here",
    "xxxx",
    "0000",
    "aaaa",
    "sk_test",
    "rzp_test",
    "sandbox",
}


def _load_rules() -> list[dict[str, Any]]:
    with open(RULES_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def _compile_rules(rules: list[dict[str, Any]]) -> list[dict[str, Any]]:
    compiled: list[dict[str, Any]] = []
    for rule in rules:
        rule_id = str(rule.get("id", "unknown"))
        pattern = str(rule.get("regex", ""))
        if not pattern:
            continue
        try:
            compiled.append(
                {
                    "id": rule_id,
                    "severity": str(rule.get("severity", "HIGH")).upper(),
                    "regex": re.compile(pattern),
                }
            )
        except re.error:
            continue
    return compiled


def _entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    length = len(value)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def _extract_value_after_assignment(line: str) -> str:
    if "=" in line:
        value = line.split("=", 1)[1]
    elif ":" in line:
        value = line.split(":", 1)[1]
    else:
        value = line

    value = value.strip().strip("\"'")
    return value


def _normalize_path(path: str) -> str:
    return path.replace("\\", "/").lower()


def _should_skip_file(abs_path: str, rel_path: str) -> bool:
    rel_norm = _normalize_path(rel_path)
    filename = os.path.basename(rel_norm)
    ext = os.path.splitext(filename)[1]

    if filename in SKIP_FILENAMES:
        return True

    if ext and ext not in SCAN_EXTENSIONS:
        return True

    if ext in {".yaml", ".yml"} and any(term in rel_norm for term in YAML_CASSETTE_PATH_TERMS):
        return True

    try:
        if os.path.getsize(abs_path) > MAX_FILE_SIZE:
            return True
    except OSError:
        return True

    return False


def _should_skip_generic_api_key(line: str) -> bool:
    # Disabled: rely on the underlying gitleaks rule without extra filtering
    return False


def scan_files_for_secrets(repo_path: str) -> dict[str, Any]:
    try:
        rules = _load_rules()
        compiled_rules = _compile_rules(rules)
    except Exception as exc:
        return {
            "violations": [],
            "count": 0,
            "error": f"Cannot load secret rules: {exc}",
        }

    violations: list[dict[str, Any]] = []

    for root, dirs, files in os.walk(repo_path):
        dirs[:] = [d for d in dirs if d.lower() not in SKIP_DIRS]

        for fname in files:
            abs_path = os.path.join(root, fname)
            rel_path = os.path.relpath(abs_path, repo_path)
            rel_norm = _normalize_path(rel_path)

            if _should_skip_file(abs_path, rel_path):
                continue

            try:
                with open(abs_path, "r", encoding="utf-8", errors="ignore") as f:
                    lines = f.readlines()
            except Exception:
                continue

            for rule in compiled_rules:
                rule_id = rule["id"]
                regex = rule["regex"]

                for lineno, line in enumerate(lines, start=1):
                    if not regex.search(line):
                        continue

                    if rule_id == "generic-api-key" and _should_skip_generic_api_key(line):
                        continue

                    violations.append(
                        {
                            "rule_id": rule_id,
                            "file": rel_norm,
                            "line": lineno,
                            "severity": rule["severity"],
                            "dimension": "data_sensitivity_risk",
                            "message": f"Pattern '{rule_id}' matched",
                            "line_preview": line.strip()[:120],
                        }
                    )
                    break

    return {"violations": violations, "count": len(violations)}
