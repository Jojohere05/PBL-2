import os
import tempfile
import asyncio
from fastapi import APIRouter, UploadFile, File, HTTPException
from fastapi.responses import FileResponse
from api.context_classifier import classify_context
from api.adk_agents.runner import run_agents_sync
from api.risk_engine import compute_risk
from api.rag.explainer import explain_all
from api.report.pdf_generator import generate_pdf_report
from api.database import save_scan
from api.routes.ws import broadcast

router = APIRouter()
REPORTS_DIR = os.environ.get("REPORTS_DIR", "/tmp/reports")


def _extract_zip(zip_path: str, extract_to: str) -> str:
    import zipfile
    with zipfile.ZipFile(zip_path, "r") as z:
        z.extractall(extract_to)
    entries = os.listdir(extract_to)
    entries = [e for e in entries if not e.endswith(".zip")]
    if len(entries) == 1:
        candidate = os.path.join(extract_to, entries[0])
        if os.path.isdir(candidate):
            return candidate
    return extract_to


@router.post("/api/scan")
async def scan_repo(file: UploadFile = File(...)):
    if not file.filename.endswith(".zip"):
        raise HTTPException(400, "Only .zip files accepted")

    with tempfile.TemporaryDirectory() as tmpdir:
        zip_path = os.path.join(tmpdir, "repo.zip")
        with open(zip_path, "wb") as f:
            f.write(await file.read())

        repo_path = _extract_zip(zip_path, tmpdir)
        context   = classify_context(repo_path)

        adk        = run_agents_sync(repo_path)
        violations = adk.get("all_violations", [])
        counts     = adk.get("agent_counts", {})

        risk     = compute_risk(violations, context)
        enriched = await explain_all(violations)

        os.makedirs(REPORTS_DIR, exist_ok=True)
        pdf_name = f"report_{os.urandom(6).hex()}.pdf"
        pdf_path = os.path.join(REPORTS_DIR, pdf_name)

        result = {
            "risk_score": risk["score"],
            "decision":   risk["decision"],
            "amplified":  risk["amplified"],
            "context":    context,
            "violations": enriched,
            "summary": {
                "total":        len(enriched),
                "secrets":      counts.get("secrets", 0),
                "dependencies": counts.get("dependencies", 0),
                "terraform":    counts.get("terraform", 0),
                "by_severity":  _count_sev(enriched)
            }
        }

        generate_pdf_report(result, pdf_path)
        result["report_pdf"] = f"/api/report/{pdf_name}"

        await save_scan(
            repo=file.filename, branch="unknown",
            commit_sha="manual", result=result
        )
        await broadcast({
            "type":     "new_scan",
            "repo":     file.filename,
            "score":    risk["score"],
            "decision": risk["decision"],
            "summary":  result["summary"]
        })

    return result


@router.get("/api/report/{filename}")
def download_report(filename: str):
    path = os.path.join(REPORTS_DIR, filename)
    if not os.path.exists(path):
        raise HTTPException(404, "Report not found")
    return FileResponse(path, media_type="application/pdf",
                        filename=filename)


def _count_sev(violations):
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for v in violations:
        sev = v.get("severity", "LOW").upper()
        if sev in counts:
            counts[sev] += 1
    return counts