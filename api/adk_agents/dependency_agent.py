import os
import json
from packaging.version import Version, InvalidVersion

OSV_DIR   = "data/osv"
_osv_cache = None


def _load_osv_db() -> list:
    global _osv_cache
    if _osv_cache is not None:
        return _osv_cache
    records = []
    if not os.path.exists(OSV_DIR):
        return records
    for fname in os.listdir(OSV_DIR):
        if fname.endswith(".json"):
            try:
                with open(os.path.join(OSV_DIR, fname)) as f:
                    records.append(json.load(f))
            except Exception:
                pass
    _osv_cache = records
    return _osv_cache


def _parse_requirements(path: str) -> dict:
    deps = {}
    with open(path, "r", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith(("#", "-", "git+")):
                continue
            for sep in ["==", ">=", "<=", "~=", "!="]:
                if sep in line:
                    name, ver = line.split(sep, 1)
                    deps[name.strip().lower()] = ver.strip().split(",")[0]
                    break
            else:
                deps[line.split("[")[0].strip().lower()] = None
    return deps


def _parse_package_json(path: str) -> dict:
    deps = {}
    try:
        with open(path, "r", errors="ignore") as f:
            data = json.load(f)
        for sec in ("dependencies", "devDependencies", "peerDependencies"):
            for pkg, ver in data.get(sec, {}).items():
                deps[pkg.lower()] = ver.lstrip("^~>=<").split(" ")[0]
    except Exception:
        pass
    return deps


def _pair_events(events: list) -> list:
    pairs, intro = [], None
    for e in events:
        if "introduced" in e:
            intro = e["introduced"]
        elif "fixed" in e and intro is not None:
            pairs.append({"introduced": intro, "fixed": e["fixed"]})
            intro = None
    if intro is not None:
        pairs.append({"introduced": intro, "fixed": None})
    return pairs


def _in_range(ver_str: str, ranges: list) -> bool:
    if not ver_str:
        return True
    try:
        v = Version(ver_str)
    except InvalidVersion:
        return False
    for r in ranges:
        try:
            intro = r.get("introduced", "0")
            fixed = r.get("fixed")
            if intro == "0" and not fixed:
                return True
            if fixed and Version(intro) <= v < Version(fixed):
                return True
            elif not fixed and Version(intro) <= v:
                return True
        except InvalidVersion:
            continue
    return False


def _osv_severity(osv: dict) -> str:
    for s in osv.get("severity", []):
        if "CVSS" in s.get("type", ""):
            try:
                sc = float(s.get("score", "0").split("/")[0])
                return ("CRITICAL" if sc >= 9 else
                        "HIGH" if sc >= 7 else
                        "MEDIUM" if sc >= 4 else "LOW")
            except Exception:
                pass
    return "HIGH"


def scan_dependencies(repo_path: str) -> dict:
    """
    Scans requirements.txt and package.json against OSV database.
    Returns raw violations — no LLM, no decisions.
    """
    osv_db    = _load_osv_db()
    violations = []
    dep_files  = []

    for root, dirs, files in os.walk(repo_path):
        dirs[:] = [d for d in dirs
                   if d not in {".git", "node_modules", "__pycache__"}]
        for fname in files:
            if fname in ("requirements.txt", "package.json"):
                dep_files.append(os.path.join(root, fname))

    for dep_file in dep_files:
        fname = os.path.basename(dep_file)
        eco   = "PyPI" if fname == "requirements.txt" else "npm"
        pkgs  = (_parse_requirements(dep_file)
                 if eco == "PyPI" else _parse_package_json(dep_file))
        if not pkgs:
            continue

        for osv in osv_db:
            for aff in osv.get("affected", []):
                pkg  = aff.get("package", {})
                name = pkg.get("name", "").lower()
                if pkg.get("ecosystem") != eco or name not in pkgs:
                    continue
                ranges = []
                for r in aff.get("ranges", []):
                    if r.get("type") == "ECOSYSTEM":
                        ranges += _pair_events(r.get("events", []))
                installed = pkgs[name]
                if _in_range(installed, ranges):
                    violations.append({
                        "rule_id":           osv.get("id", "unknown"),
                        "package":           name,
                        "installed_version": installed or "unknown",
                        "file":              os.path.relpath(
                            dep_file, repo_path
                        ),
                        "severity":          _osv_severity(osv),
                        "details":           osv.get("details", "")[:200],
                        "dimension":         "vulnerability_risk",
                        "message": (
                            f"{name}@{installed or '?'} "
                            f"has CVE: {osv.get('id')}"
                        )
                    })
    return {"violations": violations, "count": len(violations)}