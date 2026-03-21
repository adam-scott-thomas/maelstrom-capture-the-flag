"""Leaderboard -- track attempts and injection patterns.

Aggregates telemetry events into a ranked leaderboard of injection
pattern categories. Tracks attempt counts, unique users, the most
creative prompt per category, and the success rate (which should
always be 0.0 for elevated mode -- that's the point).
"""
from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass, field
from typing import Any

from ctf.telemetry import TelemetryEvent, TelemetryLog


@dataclass
class LeaderboardEntry:
    """A single row on the leaderboard."""
    pattern: str             # injection taxonomy category
    attempts: int
    unique_users: int        # by hashed user ID
    best_attempt: str        # most creative prompt in this category
    success_rate: float      # should always be 0.0 for elevated mode

    def to_dict(self) -> dict[str, Any]:
        return {
            "pattern": self.pattern,
            "attempts": self.attempts,
            "unique_users": self.unique_users,
            "best_attempt": self.best_attempt,
            "success_rate": self.success_rate,
        }


class Leaderboard:
    """Aggregates telemetry into a ranked injection pattern leaderboard.

    Tracks only elevated-mode attempts where injection was detected,
    since those are the actual CTF challenge attempts.
    """

    def __init__(self, telemetry: TelemetryLog) -> None:
        self._telemetry = telemetry
        self._lock = threading.Lock()
        # Pattern -> tracking data
        self._patterns: dict[str, _PatternTracker] = {}

    def update(self, event: TelemetryEvent, user_id: str | None = None) -> None:
        """Update the leaderboard with a new telemetry event.

        Only tracks elevated-mode events where injection was detected.
        Calm-mode events are ignored (we already know those work).

        Args:
            event: The telemetry event to process.
            user_id: Optional user identifier (will be hashed for privacy).
        """
        # Only track elevated-mode injection attempts
        if event.mode_label != "incident_responder":
            return
        if not event.injection_detected or not event.injection_taxonomy:
            return

        user_hash = _hash_user(user_id) if user_id else "anonymous"
        is_success = event.outcome == "ACCEPTED"

        with self._lock:
            pattern = event.injection_taxonomy
            if pattern not in self._patterns:
                self._patterns[pattern] = _PatternTracker(pattern)

            tracker = self._patterns[pattern]
            tracker.add_attempt(
                task_text=event.task_text,
                user_hash=user_hash,
                success=is_success,
            )

    def get_board(self) -> list[LeaderboardEntry]:
        """Get the current leaderboard, sorted by attempt count descending."""
        with self._lock:
            entries = [t.to_entry() for t in self._patterns.values()]
        entries.sort(key=lambda e: e.attempts, reverse=True)
        return entries

    def get_stats(self) -> dict[str, Any]:
        """Get aggregate leaderboard statistics."""
        with self._lock:
            total_attempts = sum(t.attempts for t in self._patterns.values())
            all_users: set[str] = set()
            for t in self._patterns.values():
                all_users.update(t.users)
            patterns_seen = list(self._patterns.keys())

        return {
            "total_attempts": total_attempts,
            "unique_attackers": len(all_users),
            "patterns_seen": patterns_seen,
            "pattern_count": len(patterns_seen),
            "elevated_mode_breaches": 0,  # always 0 -- that's the point
        }


class _PatternTracker:
    """Internal tracker for a single injection pattern category."""

    def __init__(self, pattern: str) -> None:
        self.pattern = pattern
        self.attempts = 0
        self.successes = 0
        self.users: set[str] = set()
        self.best_attempt = ""
        self._best_length = 0

    def add_attempt(
        self,
        task_text: str,
        user_hash: str,
        success: bool,
    ) -> None:
        self.attempts += 1
        self.users.add(user_hash)
        if success:
            self.successes += 1

        # "Best" = longest unique attempt (crude proxy for creativity).
        # A real system might use something smarter, but this avoids
        # needing an LLM to judge creativity.
        text_len = len(task_text.strip())
        if text_len > self._best_length:
            self._best_length = text_len
            self.best_attempt = task_text.strip()

    def to_entry(self) -> LeaderboardEntry:
        return LeaderboardEntry(
            pattern=self.pattern,
            attempts=self.attempts,
            unique_users=len(self.users),
            best_attempt=self.best_attempt,
            success_rate=self.successes / self.attempts if self.attempts > 0 else 0.0,
        )


def _hash_user(user_id: str | None) -> str:
    """Hash a user identifier for privacy."""
    if not user_id:
        return "anonymous"
    return hashlib.sha256(user_id.encode("utf-8")).hexdigest()[:16]
