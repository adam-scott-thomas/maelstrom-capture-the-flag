"""Research telemetry -- append-only JSONL event log.

Every CTF attempt produces a TelemetryEvent that captures:
- What the user sent
- What the model saw (visible manifest)
- What the model proposed
- Whether the gate accepted or rejected it
- Whether an injection pattern was detected

This is the research instrument. The gate is the safety mechanism.
The telemetry is the data collection layer.

All writes are append-only. Records are never modified or deleted.
"""
from __future__ import annotations

import hashlib
import json
import os
import threading
import time
import uuid
from collections import Counter
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class TelemetryEvent:
    """A single CTF attempt record.

    Immutable by design. Every field is captured at the moment the event
    occurs and cannot be retroactively modified.
    """
    event_id: str
    timestamp: float
    mode: float
    mode_label: str               # "concierge" | "incident_responder"
    task_text: str                 # what the user sent
    visible_manifest: tuple[str, ...]
    suppressed_tools: tuple[str, ...]
    model_selection: str           # what tool the LLM proposed
    model_rationale: str           # why
    model_confidence: float
    outcome: str                   # ACCEPTED | REJECTED_NOT_IN_CATALOG | REJECTED_SUPPRESSED | NO_TOOL_PROPOSED
    fallback_attempt: str | None   # if rejected, what did it try instead?
    fallback_quality: float        # 0.0-1.0 estimated quality of fallback
    injection_detected: bool
    injection_taxonomy: str | None # classification of the injection attempt
    event_hash: str                # SHA-256 of all fields above

    @staticmethod
    def compute_hash(**fields: Any) -> str:
        """Compute deterministic hash of event fields."""
        raw = json.dumps(fields, sort_keys=True, separators=(",", ":"),
                         default=str)
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    @classmethod
    def create(
        cls,
        mode: float,
        mode_label: str,
        task_text: str,
        visible_manifest: tuple[str, ...],
        suppressed_tools: tuple[str, ...],
        model_selection: str,
        model_rationale: str,
        model_confidence: float,
        outcome: str,
        fallback_attempt: str | None = None,
        fallback_quality: float = 0.0,
        injection_detected: bool = False,
        injection_taxonomy: str | None = None,
    ) -> TelemetryEvent:
        """Factory method that auto-generates event_id, timestamp, and hash."""
        event_id = str(uuid.uuid4())
        timestamp = time.time()
        fields = {
            "event_id": event_id,
            "timestamp": timestamp,
            "mode": mode,
            "mode_label": mode_label,
            "task_text": task_text,
            "visible_manifest": visible_manifest,
            "suppressed_tools": suppressed_tools,
            "model_selection": model_selection,
            "model_rationale": model_rationale,
            "model_confidence": model_confidence,
            "outcome": outcome,
            "fallback_attempt": fallback_attempt,
            "fallback_quality": fallback_quality,
            "injection_detected": injection_detected,
            "injection_taxonomy": injection_taxonomy,
        }
        event_hash = cls.compute_hash(**fields)
        return cls(event_hash=event_hash, **fields)


class TelemetryLog:
    """Append-only research log. JSONL format, thread-safe.

    Each line in the JSONL file is a complete TelemetryEvent serialized
    as JSON. New events are appended; existing records are never modified.
    """

    def __init__(self, log_dir: str = "telemetry") -> None:
        self._log_dir = Path(log_dir)
        self._log_dir.mkdir(parents=True, exist_ok=True)
        self._log_path = self._log_dir / "events.jsonl"
        self._lock = threading.Lock()
        self._event_count = 0
        # Count existing events on init
        if self._log_path.exists():
            with open(self._log_path, "r", encoding="utf-8") as f:
                self._event_count = sum(1 for line in f if line.strip())

    def record(self, event: TelemetryEvent) -> None:
        """Append a telemetry event to the JSONL log.

        Thread-safe. Each event is written as a single JSON line followed
        by a newline. The file is flushed after each write.
        """
        data = asdict(event)
        # Convert tuples back to lists for JSON serialization
        data["visible_manifest"] = list(data["visible_manifest"])
        data["suppressed_tools"] = list(data["suppressed_tools"])
        line = json.dumps(data, separators=(",", ":"), sort_keys=True)

        with self._lock:
            with open(self._log_path, "a", encoding="utf-8") as f:
                f.write(line + "\n")
                f.flush()
                os.fsync(f.fileno())
            self._event_count += 1

    def _read_events(self) -> list[dict[str, Any]]:
        """Read all events from the log file."""
        if not self._log_path.exists():
            return []
        events = []
        with open(self._log_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    events.append(json.loads(line))
        return events

    def stats(self) -> dict[str, Any]:
        """Compute aggregate statistics from all recorded events.

        Returns:
            Dict with total_events, injection_rate, outcome_distribution,
            injection_patterns, mode_distribution, and top_proposed_tools.
        """
        events = self._read_events()
        if not events:
            return {
                "total_events": 0,
                "injection_rate": 0.0,
                "outcome_distribution": {},
                "injection_patterns": {},
                "mode_distribution": {},
                "top_proposed_tools": {},
            }

        total = len(events)
        injections = sum(1 for e in events if e.get("injection_detected"))
        outcomes: Counter[str] = Counter()
        patterns: Counter[str] = Counter()
        modes: Counter[str] = Counter()
        tools: Counter[str] = Counter()

        for e in events:
            outcomes[e.get("outcome", "UNKNOWN")] += 1
            modes[e.get("mode_label", "unknown")] += 1
            if e.get("model_selection"):
                tools[e["model_selection"]] += 1
            if e.get("injection_detected") and e.get("injection_taxonomy"):
                patterns[e["injection_taxonomy"]] += 1

        return {
            "total_events": total,
            "injection_rate": injections / total if total > 0 else 0.0,
            "outcome_distribution": dict(outcomes),
            "injection_patterns": dict(patterns.most_common()),
            "mode_distribution": dict(modes),
            "top_proposed_tools": dict(tools.most_common(10)),
        }

    def export(self) -> str:
        """Return the absolute path to the JSONL log file."""
        return str(self._log_path.resolve())
