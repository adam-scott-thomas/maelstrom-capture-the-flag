"""API endpoints for the Maelstrom CTF.

Four endpoints:
  POST /api/v1/challenge   -- Main CTF endpoint. Runs task through both gates.
  GET  /api/v1/leaderboard -- Current injection pattern leaderboard.
  GET  /api/v1/stats       -- Telemetry statistics.
  GET  /api/v1/health      -- Health check.
"""
from __future__ import annotations

import uuid

from fastapi import APIRouter

from ctf.bot import run_challenge
from ctf.gate import _USING_INSTALLED_GATE
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

    result = run_challenge(req.task)
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


@router.get("/health", response_model=HealthResponse)
async def health() -> HealthResponse:
    """Health check endpoint."""
    return HealthResponse(
        status="ok",
        version="1.0.0",
        gate_backend="maelstrom_gate" if _USING_INSTALLED_GATE else "inline",
    )
