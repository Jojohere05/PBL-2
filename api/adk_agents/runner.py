import json
import asyncio
import re
from google.adk.runners  import Runner
from google.adk.sessions import InMemorySessionService
from google.genai.types  import Content, Part

from api.adk_agents.orchestrator_agent import orchestrator_agent

_session_service = InMemorySessionService()
APP_NAME         = "finguard"


def _extract_json(text: str) -> dict:
    if not text:
        return {}
    text = text.strip()
    text = re.sub(r"^```json\s*", "", text)
    text = re.sub(r"\s*```$",     "", text)
    text = text.strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    match = re.search(r'\{.*\}', text, re.DOTALL)
    if match:
        try:
            return json.loads(match.group())
        except json.JSONDecodeError:
            pass
    return {}


def _filter_active_violations(violations: list) -> list:
    """
    Keep all violations but mark dismissed ones.
    Only CONFIRM + ESCALATE violations affect risk scoring.
    """
    return [v for v in violations
            if v.get("verdict", "CONFIRM") != "DISMISS"]


async def run_adk_scan(repo_path: str) -> dict:
    """
    Runs ADK orchestrator which:
    1. Calls all 3 scan tools
    2. Retrieves compliance rules via RAG
    3. Does agentic RAG for targeted queries
    4. Validates each violation with LLM reasoning
    """
    runner = Runner(
        agent=orchestrator_agent,
        app_name=APP_NAME,
        session_service=_session_service
    )

    session = await _session_service.create_session(
        app_name=APP_NAME,
        user_id="system"
    )

    message = Content(
        role="user",
        parts=[Part(text=json.dumps({
            "repo_path": repo_path,
            "instruction": (
                "Run a complete FinGuard compliance scan on this "
                "repository. Follow all phases: scan all 3 tools, "
                "retrieve compliance rules via RAG, validate each "
                "violation, and return the complete JSON result."
            )
        }))]
    )

    result_text = ""
    try:
        async for event in runner.run_async(
            user_id="system",
            session_id=session.id,
            new_message=message
        ):
            if event.is_final_response():
                if event.content and event.content.parts:
                    result_text = event.content.parts[0].text
                break
    except Exception as e:
        print(f"[ADK] Runner error: {e} — using fallback")
        return await _fallback_scan(repo_path)

    parsed = _extract_json(result_text)

    # Validate structure
    if "all_violations" not in parsed:
        print("[ADK] Invalid response structure — using fallback")
        return await _fallback_scan(repo_path)

    # Separate active vs dismissed
    all_v    = parsed.get("all_violations", [])
    active_v = _filter_active_violations(all_v)
    dismissed = [v for v in all_v if v.get("verdict") == "DISMISS"]

    print(
        f"[ADK] Scan complete: {len(all_v)} found, "
        f"{len(active_v)} active, "
        f"{len(dismissed)} dismissed, "
        f"{parsed.get('escalated_count', 0)} escalated"
    )

    return {
        "all_violations":   active_v,   # only active go to risk engine
        "all_raw":          all_v,       # full audit trail
        "dismissed":        dismissed,
        "agent_counts":     parsed.get("agent_counts", {
            "secrets": 0, "dependencies": 0, "terraform": 0
        }),
        "dismissed_count":  parsed.get("dismissed_count", 0),
        "escalated_count":  parsed.get("escalated_count", 0)
    }


async def _fallback_scan(repo_path: str) -> dict:
    """
    Direct Python fallback when ADK fails.
    No LLM validation — raw violations only.
    """
    print("[ADK] Fallback: running agents directly")
    from api.adk_agents.secrets_agent    import scan_files_for_secrets
    from api.adk_agents.dependency_agent import scan_dependencies
    from api.adk_agents.terraform_agent  import scan_terraform_files

    loop = asyncio.get_event_loop()
    s, d, t = await asyncio.gather(
        loop.run_in_executor(None, scan_files_for_secrets, repo_path),
        loop.run_in_executor(None, scan_dependencies,      repo_path),
        loop.run_in_executor(None, scan_terraform_files,   repo_path),
    )

    all_v = (s.get("violations", []) +
             d.get("violations", []) +
             t.get("violations", []))

    return {
        "all_violations":  all_v,
        "all_raw":         all_v,
        "dismissed":       [],
        "agent_counts": {
            "secrets":      s.get("count", 0),
            "dependencies": d.get("count", 0),
            "terraform":    t.get("count", 0)
        },
        "dismissed_count": 0,
        "escalated_count": 0
    }


def run_agents_sync(repo_path: str) -> dict:
    """Sync wrapper for background threads."""
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        return loop.run_until_complete(run_adk_scan(repo_path))
    except Exception as e:
        print(f"[ADK] Sync error: {e}")
        return {
            "all_violations": [], "all_raw": [],
            "dismissed": [], "dismissed_count": 0,
            "escalated_count": 0,
            "agent_counts": {
                "secrets": 0, "dependencies": 0, "terraform": 0
            }
        }
    finally:
        loop.close()