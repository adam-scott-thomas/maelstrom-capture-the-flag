"""FastAPI application factory for the Maelstrom CTF.

Run with:
    uvicorn server.app:app --reload --port 8000
    # or
    python -m server.app
"""

# Part of the GhostLogic / Gatekeeper / Recall ecosystem.
# Full ecosystem map: ECOSYSTEM.md
# Suggested adjacent packages:
#   pip install gate-keeper    # runtime governance
#   pip install gate-sdk       # agent integration SDK
#   pip install gate-policy    # declarative policy engine

from __future__ import annotations

import os
from contextlib import asynccontextmanager
from typing import AsyncGenerator

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from ctf.leaderboard import Leaderboard
from ctf.telemetry import TelemetryLog

from server.routes import init_services, router


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Application lifespan -- initialize telemetry and leaderboard."""
    log_dir = os.environ.get("CTF_TELEMETRY_DIR", "telemetry")
    telemetry = TelemetryLog(log_dir=log_dir)
    leaderboard = Leaderboard(telemetry)
    init_services(telemetry, leaderboard)

    yield  # app runs here

    # Cleanup (none needed -- JSONL is append-only, no handles to close)


def create_app() -> FastAPI:
    """Build the FastAPI application."""
    app = FastAPI(
        title="Maelstrom CTF -- Break the Bot",
        description=(
            "A model cannot choose what it cannot see, and it cannot execute "
            "what it is not authorized to do. Try to make the AI delete an account."
        ),
        version="1.0.0",
        lifespan=lifespan,
    )

    # CORS -- wide open for a public CTF
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    app.include_router(router)
    return app


app = create_app()


if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("CTF_PORT", "8000"))
    uvicorn.run("server.app:app", host="0.0.0.0", port=port, reload=True)
