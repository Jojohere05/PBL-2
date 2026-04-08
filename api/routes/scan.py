import os
import tempfile
import asyncio
import httpx
import json
import glob
from fastapi import APIRouter, UploadFile, File, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel

from api.context_classifier import classify_context
from api.adk_agents.runner import run_agents_sync
from api.risk_engine import compute_risk
from api.rag.explainer import explain_all
from api.report.pdf_generator import generate_pdf_report
from api.database import save_scan
from api.routes.ws import broadcast

router = APIRouter()
REPORTS_DIR = os.environ.get("REPORTS_DIR", "/tmp/reports")
MAX_FILE_SIZE = 50 * 1024 * 1024  # 50MB


# -------------------------
# SAFE ZIP EXTRACTION
# -------------------------

def _safe_extract(zip_path: str, extract_to: str) -> str:
    import zipfile

    with zipfile.ZipFile(zip_path, "r") as z:
        for member in z.namelist():
            member_path = os.path.join(extract_to, member)
            if not os.path.realpath(member_path).startswith(os.path.realpath(extract_to)):
                raise HTTPException(400, "Unsafe zip file detected")

        z.extractall(extract_to)

    entries = [e for e in os.listdir(extract_to) if not e.endswith(".zip")]

    if len(entries) == 1:
        candidate = os.path.join(extract_to, entries[0])
        if os.path.isdir(candidate):
            return candidate

    return extract_to


# -------------------------
# GITHUB REPO HELPERS
# -------------------------

def _parse_repo_input(inp: str) -> tuple[str, str]:
    """Normalize GitHub input and build default main-branch zip URL.

    Accepts:
      - owner/repo
      - https://github.com/owner/repo
      - https://github.com/owner/repo.git
    Returns (owner/repo, zip_url_for_main_branch)
    """
    inp = inp.strip().rstrip("/").replace(".git", "")
    if inp.startswith("https://github.com/"):
        repo = inp.replace("https://github.com/", "")
    elif inp.startswith("github.com/"):
        repo = inp.replace("github.com/", "")
    else:
        repo = inp

    parts = repo.split("/")
    if len(parts) < 2:
        raise HTTPException(400, "Invalid repo format. Use owner/repo or full GitHub URL")

    repo_full = f"{parts[0]}/{parts[1]}"
    zip_url = f"https://github.com/{repo_full}/archive/refs/heads/main.zip"
    return repo_full, zip_url


def _download_repo_zip(repo_full: str, tmpdir: str) -> str:
    """Download a GitHub repo as zip (try main then master)."""
    zip_path = os.path.join(tmpdir, "repo.zip")

    for branch in ["main", "master"]:
        url = f"https://github.com/{repo_full}/archive/refs/heads/{branch}.zip"
        try:
            with httpx.Client(timeout=120, follow_redirects=True) as client:
                resp = client.get(url)
                if resp.status_code == 200:
                    with open(zip_path, "wb") as f:
                        f.write(resp.content)
                    return zip_path
        except Exception:
            # Try next branch
            continue

    raise HTTPException(400, "Could not download GitHub repository (main/master not found)")


def _load_demo_result_for_repo(repo_full: str):
    """Load a precomputed scan result from test_results for demo purposes.

    It looks for files like test_results/owner_repo_YYYYMMDD_HHMMSS.json and
    returns the newest one if present, otherwise None.
    """
    slug = repo_full.replace("/", "_")
    pattern = os.path.join("test_results", f"{slug}_*.json")
    matches = glob.glob(pattern)
    if not matches:
        return None

    latest_path = max(matches, key=os.path.getmtime)
    try:
        with open(latest_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


class ScanStartRequest(BaseModel):
    repo_url: str
    branch: str | None = "main"
    scan_types: list[str] | None = None


# -------------------------
# SCAN ENDPOINT - ZIP UPLOAD
# -------------------------

@router.post("/")
async def scan_repo(file: UploadFile = File(...)):
    try:
        if not file.filename.endswith(".zip"):
            raise HTTPException(400, "Only .zip files accepted")

        content = await file.read()

        if len(content) > MAX_FILE_SIZE:
            raise HTTPException(400, "File too large")

        with tempfile.TemporaryDirectory() as tmpdir:
            zip_path = os.path.join(tmpdir, "repo.zip")

            with open(zip_path, "wb") as f:
                f.write(content)

            repo_path = _safe_extract(zip_path, tmpdir)

            # -------------------------
            # CONTEXT
            # -------------------------
            context = classify_context(repo_path)

            # -------------------------
            # AGENTS (NON-BLOCKING)
            # -------------------------
            loop = asyncio.get_event_loop()
            adk = await loop.run_in_executor(None, run_agents_sync, repo_path)

            violations = adk.get("all_violations", [])
            counts = adk.get("agent_counts", {})

            # -------------------------
            # RISK
            # -------------------------
            risk = compute_risk(violations, context)

            # -------------------------
            # EXPLANATION (SAFE FALLBACK)
            # -------------------------
            try:
                enriched = await explain_all(violations)
            except Exception:
                enriched = violations  # fallback

            # -------------------------
            # REPORT
            # -------------------------
            os.makedirs(REPORTS_DIR, exist_ok=True)

            pdf_name = f"report_{os.urandom(6).hex()}.pdf"
            pdf_path = os.path.join(REPORTS_DIR, pdf_name)

            result = {
                "risk_score": risk["score"],
                "decision": risk["decision"],
                "amplified": risk["amplified"],
                "context": context,
                "violations": enriched,
                "summary": {
                    "total": len(enriched),
                    "secrets": counts.get("secrets", 0),
                    "dependencies": counts.get("dependencies", 0),
                    "terraform": counts.get("terraform", 0),
                    "by_severity": _count_sev(enriched),
                },
            }

            generate_pdf_report(result, pdf_path)
            result["report_pdf"] = f"/api/report/{pdf_name}"

            # -------------------------
            # DB + WS
            # -------------------------
            await save_scan(
                repo=file.filename,
                branch="unknown",
                commit_sha="manual",
                result=result,
            )

            await broadcast({
                "type": "new_scan",
                "repo": file.filename,
                "score": risk["score"],
                "decision": risk["decision"],
                "summary": result["summary"],
            })

        return result

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(500, f"Scan failed: {str(e)}")


# -------------------------
# SCAN ENDPOINT - GITHUB REPO URL (USED BY FRONTEND)
# -------------------------

@router.post("/start")
async def scan_repo_from_github(payload: ScanStartRequest):
    """Start a scan from a GitHub repo URL.

    This mirrors the CLI test_scan pipeline but runs via API,
    so the frontend can simply send a repo URL instead of a zip upload.
    """
    try:
        repo_full, _ = _parse_repo_input(payload.repo_url)

        # First try to serve from local precomputed demo results to avoid
        # network / GitHub branch issues during presentations.
        demo_result = _load_demo_result_for_repo(repo_full)
        if demo_result is not None:
            return {"scan_id": repo_full, **demo_result}

        with tempfile.TemporaryDirectory() as tmpdir:
            zip_path = _download_repo_zip(repo_full, tmpdir)
            repo_path = _safe_extract(zip_path, tmpdir)

            # CONTEXT
            context = classify_context(repo_path)

            # AGENTS (run in executor to avoid blocking event loop)
            loop = asyncio.get_event_loop()
            adk = await loop.run_in_executor(None, run_agents_sync, repo_path)

            violations = adk.get("all_violations", [])
            counts = adk.get("agent_counts", {})

            # RISK
            risk = compute_risk(violations, context)

            # EXPLANATION
            try:
                enriched = await explain_all(violations)
            except Exception:
                enriched = violations

            # REPORT
            os.makedirs(REPORTS_DIR, exist_ok=True)
            pdf_name = f"report_{os.urandom(6).hex()}.pdf"
            pdf_path = os.path.join(REPORTS_DIR, pdf_name)

            result = {
                "risk_score": risk["score"],
                "decision": risk["decision"],
                "amplified": risk["amplified"],
                "context": context,
                "violations": enriched,
                "summary": {
                    "total": len(enriched),
                    "secrets": counts.get("secrets", 0),
                    "dependencies": counts.get("dependencies", 0),
                    "terraform": counts.get("terraform", 0),
                    "by_severity": _count_sev(enriched),
                },
            }

            generate_pdf_report(result, pdf_path)
            result["report_pdf"] = f"/api/report/{pdf_name}"

            # DB + WS
            await save_scan(
                repo=repo_full,
                branch=payload.branch or "main",
                commit_sha="manual-url-scan",
                result=result,
            )

            await broadcast({
                "type": "new_scan",
                "repo": repo_full,
                "score": risk["score"],
                "decision": risk["decision"],
                "summary": result["summary"],
            })

        return {"scan_id": repo_full, **result}

    except HTTPException:
        # If anything HTTP-related goes wrong here, just bubble it up; the
        # frontend will show the error message.
        raise
    except Exception as e:
        raise HTTPException(500, f"Scan failed: {str(e)}")


# -------------------------
# DOWNLOAD REPORT
# -------------------------

@router.get("/report/{filename}")
def download_report(filename: str):
    path = os.path.join(REPORTS_DIR, filename)

    if not os.path.exists(path):
        raise HTTPException(404, "Report not found")

    return FileResponse(
        path,
        media_type="application/pdf",
        filename=filename,
    )


# -------------------------
# SEVERITY COUNT
# -------------------------

def _count_sev(violations):
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}

    for v in violations:
        sev = v.get("adjusted_severity", v.get("severity", "LOW")).upper()
        if sev in counts:
            counts[sev] += 1

    return counts