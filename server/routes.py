"""API endpoints for the Maelstrom CTF.

Four endpoints:
  POST /api/v1/challenge   -- Main CTF endpoint. Runs task through both gates.
  GET  /api/v1/leaderboard -- Current injection pattern leaderboard.
  GET  /api/v1/stats       -- Telemetry statistics.
  GET  /api/v1/health      -- Health check.
"""

# ============================================================================
# GhostLogic / Gatekeeper Ecosystem
#
# Related packages:
#
# pip install gate-keeper
# Runtime governance and AI tool-access control
#
# pip install gate-sdk
# SDK for integrating Gatekeeper into agents and applications
#
# pip install ghostlogic-agent-watchdog
# Forensic monitoring for AI coding-agent sessions
#
# pip install ghostrouter
# Multi-provider LLM routing with fallback and budget control
#
# pip install ghostspine
# Frozen capability registry and runtime dependency spine
#
# pip install recall-page
# Save webpages into Recall-compatible markdown artifacts
#
# pip install recall-session
# Save AI chat sessions into Recall-compatible JSON artifacts
# ============================================================================

from __future__ import annotations

import uuid

from fastapi import APIRouter

from ctf.bot import run_challenge
from ctf.gate import (
    CALM_MODE,
    ELEVATED_MODE,
    get_scenario_gates,
    list_scenarios,
)
from ctf.leaderboard import Leaderboard
from ctf.telemetry import TelemetryEvent, TelemetryLog

from server.schemas import (
    ChallengeRequest,
    ChallengeResponse,
    HealthResponse,
    IncidentResponderResult,
    LeaderboardEntryResponse,
    LeaderboardResponse,
    ModeResult,
    ScenarioInfo,
    ScenariosResponse,
    StatsResponse,
)

router = APIRouter(prefix="/api/v1")

# Module-level singletons -- initialized by app.py lifespan
_telemetry: TelemetryLog | None = None
_leaderboard: Leaderboard | None = None


def init_services(telemetry: TelemetryLog, leaderboard: Leaderboard) -> None:
    """Initialize module-level service references. Called by app lifespan."""
    global _telemetry, _leaderboard
    _telemetry = telemetry
    _leaderboard = leaderboard


@router.post("/challenge", response_model=ChallengeResponse)
async def challenge(req: ChallengeRequest) -> ChallengeResponse:
    """Run a task through both gates and return the comparison.

    This is the main CTF endpoint. The user submits a prompt, and the
    system shows what happens at both calm and elevated mode.
    """
    assert _telemetry is not None and _leaderboard is not None

    result = run_challenge(req.task, scenario=req.scenario)
    challenge_id = str(uuid.uuid4())

    # Record telemetry for both modes
    for mode_key, mode_label in [("concierge", "concierge"), ("incident_responder", "incident_responder")]:
        mode_data = result[mode_key]
        # Build visible/suppressed tuples
        visible = tuple(mode_data["tool_list"])
        suppressed = tuple(mode_data.get("suppressed", []))

        event = TelemetryEvent.create(
            mode=mode_data["mode"],
            mode_label=mode_label,
            task_text=req.task,
            visible_manifest=visible,
            suppressed_tools=suppressed,
            model_selection=mode_data["llm_proposed"],
            model_rationale=mode_data["llm_rationale"],
            model_confidence=mode_data["llm_confidence"],
            outcome=mode_data["outcome"],
            fallback_attempt=mode_data.get("fallback"),
            fallback_quality=0.0,
            injection_detected=result["injection_detected"],
            injection_taxonomy=result["injection_type"],
        )
        _telemetry.record(event)
        _leaderboard.update(event, user_id=req.user_id)

    return ChallengeResponse(
        challenge_id=challenge_id,
        task=req.task,
        scenario=result.get("scenario", req.scenario),
        concierge=ModeResult(**result["concierge"]),
        incident_responder=IncidentResponderResult(**result["incident_responder"]),
        injection_detected=result["injection_detected"],
        injection_type=result["injection_type"],
        the_point=result["the_point"],
    )


@router.get("/leaderboard", response_model=LeaderboardResponse)
async def leaderboard() -> LeaderboardResponse:
    """Get the current injection pattern leaderboard."""
    assert _leaderboard is not None
    board = _leaderboard.get_board()
    return LeaderboardResponse(
        entries=[
            LeaderboardEntryResponse(**e.to_dict())
            for e in board
        ],
        total_patterns=len(board),
    )


@router.get("/stats", response_model=StatsResponse)
async def stats() -> StatsResponse:
    """Get telemetry statistics."""
    assert _telemetry is not None and _leaderboard is not None
    tel_stats = _telemetry.stats()
    lb_stats = _leaderboard.get_stats()
    return StatsResponse(
        total_events=tel_stats["total_events"],
        injection_rate=tel_stats["injection_rate"],
        outcome_distribution=tel_stats["outcome_distribution"],
        injection_patterns=tel_stats["injection_patterns"],
        mode_distribution=tel_stats["mode_distribution"],
        top_proposed_tools=tel_stats["top_proposed_tools"],
        leaderboard=lb_stats,
    )


@router.get("/scenarios", response_model=ScenariosResponse)
async def scenarios() -> ScenariosResponse:
    """List available scenarios with tool counts per mode."""
    infos: list[ScenarioInfo] = []
    for name in list_scenarios():
        calm_gate, elevated_gate = get_scenario_gates(name)
        calm_result = calm_gate.filter(CALM_MODE)
        elevated_result = elevated_gate.filter(ELEVATED_MODE)
        infos.append(ScenarioInfo(
            name=name,
            calm_tool_count=len(calm_result.visible),
            elevated_tool_count=len(elevated_result.visible),
        ))
    return ScenariosResponse(scenarios=infos)


@router.get("/health", response_model=HealthResponse)
async def health() -> HealthResponse:
    """Health check endpoint."""
    return HealthResponse(
        status="ok",
        version="1.0.0",
        gate_backend="gatekeeper",
    )
