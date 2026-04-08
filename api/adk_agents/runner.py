"""Compatibility module for legacy imports.

The canonical orchestrator implementation now lives in api.adk_agents.orchestrator_agent.
"""

from api.adk_agents.orchestrator_agent import (
    OrchestratorAgent,
    orchestrator_agent,
    run_adk_scan,
    run_agents_sync,
)

__all__ = [
    "OrchestratorAgent",
    "orchestrator_agent",
    "run_adk_scan",
    "run_agents_sync",
]
