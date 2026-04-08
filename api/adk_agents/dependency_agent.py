import json
import os
import pickle
import re
from typing import Any

from packaging.version import InvalidVersion, Version

OSV_DIR = "data/osv"
INDEX_PATH = "data/osv_index.pkl"

_index_cache: dict[str, dict[str, list[dict[str, Any]]]] | None = None


# -------------------------
# OSV INDEX HANDLING
# -------------------------

def _pair_events(events: list[dict[str, Any]]) -> list[dict[str, str | None]]:
    pairs = []
    introduced = None

    for event in events:
        if "introduced" in event:
            introduced = str(event["introduced"])
        elif "fixed" in event:
            if introduced is None:
                introduced = "0"
            pairs.append({"introduced": introduced, "fixed": str(event["fixed"])})
            introduced = None

    if introduced is not None:
        pairs.append({"introduced": introduced, "fixed": None})

    return pairs


def _build_and_save_index():
    index = {"PyPI": {}, "npm": {}, "RubyGems": {}}

    if not os.path.exists(OSV_DIR):
        return index

    for fname in os.listdir(OSV_DIR):
        if not fname.endswith(".json"):
            continue

        try:
            with open(os.path.join(OSV_DIR, fname), "r", encoding="utf-8") as f:
                osv = json.load(f)
        except Exception:
            continue

        for affected in osv.get("affected", []):
            pkg = affected.get("package", {})
            ecosystem = pkg.get("ecosystem", "")
            name = str(pkg.get("name", "")).lower()

            if ecosystem in index and name:
                index[ecosystem].setdefault(name, []).append(osv)

    os.makedirs(os.path.dirname(INDEX_PATH), exist_ok=True)
    with open(INDEX_PATH, "wb") as f:
        pickle.dump(index, f)

    print("[OSV] Index built")
    return index


def _load_index():
    global _index_cache

    if _index_cache is not None:
        return _index_cache

    if os.path.exists(INDEX_PATH):
        try:
            with open(INDEX_PATH, "rb") as f:
                _index_cache = pickle.load(f)
                if "RubyGems" not in _index_cache:
                    _index_cache = _build_and_save_index()
                return _index_cache
        except Exception:
            pass

    _index_cache = _build_and_save_index()
    return _index_cache


# -------------------------
# PARSERS
# -------------------------

def _normalize(name: str) -> str:
    return name.strip().lower().replace("_", "-")


def _parse_requirements(path):
    deps = {}
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            for sep in ["==", ">=", "<=", "~=", "!=", ">", "<"]:
                if sep in line:
                    name, version = line.split(sep, 1)
                    deps[_normalize(name)] = version.strip()
                    break
            else:
                deps[_normalize(line)] = None

    return deps


def _parse_package_json(path):
    deps = {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception:
        return deps

    for section in ["dependencies", "devDependencies"]:
        for k, v in data.get(section, {}).items():
            v = str(v).lstrip("^~>=< ")
            deps[_normalize(k)] = v or None

    return deps


def _parse_gemfile_lock(path):
    deps = {}
    in_specs = False

    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            if line.strip() == "specs:":
                in_specs = True
                continue

            if in_specs and not line.startswith(" "):
                break

            if in_specs:
                m = re.match(r"^\s{4}([A-Za-z0-9_.-]+)\s+\(([^)]+)\)", line)
                if m:
                    name = _normalize(m.group(1))
                    version = m.group(2).split(",")[0].strip()
                    deps[name] = version

    return deps


def _collect_files(repo):
    result = []
    for root, dirs, files in os.walk(repo):
        dirs[:] = [d for d in dirs if d not in {".git", "node_modules"}]
        for f in files:
            if f in {"requirements.txt", "package.json", "Gemfile.lock"}:
                result.append(os.path.join(root, f))
    return result


def _parse_deps(path):
    name = os.path.basename(path)
    if name == "requirements.txt":
        return "PyPI", _parse_requirements(path)
    if name == "package.json":
        return "npm", _parse_package_json(path)
    return "RubyGems", _parse_gemfile_lock(path)


# -------------------------
# MATCHING LOGIC
# -------------------------

def _loose_match(index, ecosystem, package):
    records = []
    eco_index = index.get(ecosystem, {})

    for name, recs in eco_index.items():
        if name == package or name in package or package in name:
            records.extend(recs)

    return records


def _version_match(version, affected):
    if version is None:
        return True

    try:
        v = Version(version)
    except InvalidVersion:
        return True  # safer assumption

    for r in affected.get("ranges", []):
        if r.get("type") != "ECOSYSTEM":
            continue

        for pair in _pair_events(r.get("events", [])):
            introduced = pair.get("introduced") or "0"
            fixed = pair.get("fixed")

            try:
                if introduced != "0" and v < Version(introduced):
                    continue
            except:
                pass

            if fixed is None:
                return True

            try:
                if v < Version(fixed):
                    return True
            except:
                return True

    return False


def _severity(osv):
    score = None
    for s in osv.get("severity", []):
        try:
            score = float(str(s.get("score", "")).split("/")[0])
            break
        except:
            continue

    if score is None:
        return "HIGH"
    if score >= 9:
        return "CRITICAL"
    if score >= 7:
        return "HIGH"
    if score >= 4:
        return "MEDIUM"
    return "LOW"


# -------------------------
# MAIN FUNCTION
# -------------------------

def scan_dependencies(repo_path: str):
    index = _load_index()
    violations = []

    dep_files = _collect_files(repo_path)

    for file in dep_files:
        ecosystem, deps = _parse_deps(file)

        for pkg, version in deps.items():
            records = _loose_match(index, ecosystem, pkg)

            for osv in records:
                for affected in osv.get("affected", []):
                    if _version_match(version, affected):
                        violations.append({
                            "rule_id": osv.get("id", "unknown"),
                            "file": os.path.relpath(file, repo_path),
                            "severity": _severity(osv),
                            "dimension": "vulnerability_risk",
                            "message": f"{pkg}@{version or 'unknown'} vulnerable",
                            "package": pkg,
                            "installed_version": version or "unknown",
                            "line": None,
                            "line_preview": (osv.get("summary") or "")[:120],
                        })
                        break

    return {
        "violations": violations,
        "count": len(violations)
    }