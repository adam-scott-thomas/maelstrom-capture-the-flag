"""Tests for the research telemetry system.

Verifies:
- Events are recorded to JSONL
- JSONL contains valid JSON lines
- Stats compute correctly
- Hash integrity
- Thread safety basics
"""
from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

from ctf.telemetry import TelemetryEvent, TelemetryLog


def _make_event(**overrides: object) -> TelemetryEvent:
    """Create a test TelemetryEvent with sensible defaults."""
    defaults = {
        "mode": 0.1,
        "mode_label": "concierge",
        "task_text": "Delete my account please",
        "visible_manifest": ("search_knowledge_base", "delete_account"),
        "suppressed_tools": (),
        "model_selection": "delete_account",
        "model_rationale": "User requested deletion.",
        "model_confidence": 0.95,
        "outcome": "ACCEPTED",
        "fallback_attempt": None,
        "fallback_quality": 0.0,
        "injection_detected": False,
        "injection_taxonomy": None,
    }
    defaults.update(overrides)
    return TelemetryEvent.create(**defaults)


class TestTelemetryEvent:
    """TelemetryEvent creation and hashing."""

    def test_create_sets_event_id(self) -> None:
        event = _make_event()
        assert event.event_id  # non-empty UUID string

    def test_create_sets_timestamp(self) -> None:
        event = _make_event()
        assert event.timestamp > 0

    def test_create_sets_hash(self) -> None:
        event = _make_event()
        assert event.event_hash  # non-empty hex string
        assert len(event.event_hash) == 64  # SHA-256 hex digest

    def test_event_is_frozen(self) -> None:
        event = _make_event()
        try:
            event.mode = 0.5  # type: ignore[misc]
            assert False, "Should have raised"
        except AttributeError:
            pass

    def test_different_events_have_different_ids(self) -> None:
        e1 = _make_event(task_text="task one")
        e2 = _make_event(task_text="task two")
        assert e1.event_id != e2.event_id

    def test_different_events_have_different_hashes(self) -> None:
        e1 = _make_event(task_text="task one")
        e2 = _make_event(task_text="task two")
        assert e1.event_hash != e2.event_hash


class TestTelemetryLog:
    """TelemetryLog recording and retrieval."""

    def test_record_creates_jsonl_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            log = TelemetryLog(log_dir=tmpdir)
            event = _make_event()
            log.record(event)
            log_path = Path(tmpdir) / "events.jsonl"
            assert log_path.exists()

    def test_record_appends_valid_json_line(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            log = TelemetryLog(log_dir=tmpdir)
            event = _make_event()
            log.record(event)

            log_path = Path(tmpdir) / "events.jsonl"
            with open(log_path, "r", encoding="utf-8") as f:
                lines = [l.strip() for l in f if l.strip()]

            assert len(lines) == 1
            data = json.loads(lines[0])
            assert data["event_id"] == event.event_id
            assert data["outcome"] == "ACCEPTED"

    def test_multiple_records_append(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            log = TelemetryLog(log_dir=tmpdir)
            for i in range(5):
                log.record(_make_event(task_text=f"task {i}"))

            log_path = Path(tmpdir) / "events.jsonl"
            with open(log_path, "r", encoding="utf-8") as f:
                lines = [l.strip() for l in f if l.strip()]

            assert len(lines) == 5
            # Each line is valid JSON
            for line in lines:
                data = json.loads(line)
                assert "event_id" in data

    def test_export_returns_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            log = TelemetryLog(log_dir=tmpdir)
            path = log.export()
            assert path.endswith("events.jsonl")

    def test_jsonl_tuples_serialized_as_lists(self) -> None:
        """Tuples in the dataclass must serialize as JSON arrays."""
        with tempfile.TemporaryDirectory() as tmpdir:
            log = TelemetryLog(log_dir=tmpdir)
            event = _make_event(visible_manifest=("tool_a", "tool_b"))
            log.record(event)

            log_path = Path(tmpdir) / "events.jsonl"
            with open(log_path, "r", encoding="utf-8") as f:
                data = json.loads(f.readline())

            assert isinstance(data["visible_manifest"], list)
            assert data["visible_manifest"] == ["tool_a", "tool_b"]


class TestTelemetryStats:
    """Stats computation from recorded events."""

    def test_empty_stats(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            log = TelemetryLog(log_dir=tmpdir)
            s = log.stats()
            assert s["total_events"] == 0
            assert s["injection_rate"] == 0.0

    def test_stats_total_events(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            log = TelemetryLog(log_dir=tmpdir)
            for _ in range(3):
                log.record(_make_event())
            s = log.stats()
            assert s["total_events"] == 3

    def test_stats_injection_rate(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            log = TelemetryLog(log_dir=tmpdir)
            # 2 injections out of 4 events
            log.record(_make_event(injection_detected=False))
            log.record(_make_event(injection_detected=True, injection_taxonomy="role_override"))
            log.record(_make_event(injection_detected=False))
            log.record(_make_event(injection_detected=True, injection_taxonomy="social_engineering"))
            s = log.stats()
            assert s["injection_rate"] == 0.5

    def test_stats_outcome_distribution(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            log = TelemetryLog(log_dir=tmpdir)
            log.record(_make_event(outcome="ACCEPTED"))
            log.record(_make_event(outcome="ACCEPTED"))
            log.record(_make_event(outcome="REJECTED_NOT_IN_CATALOG"))
            s = log.stats()
            assert s["outcome_distribution"]["ACCEPTED"] == 2
            assert s["outcome_distribution"]["REJECTED_NOT_IN_CATALOG"] == 1

    def test_stats_injection_patterns(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            log = TelemetryLog(log_dir=tmpdir)
            log.record(_make_event(injection_detected=True, injection_taxonomy="role_override"))
            log.record(_make_event(injection_detected=True, injection_taxonomy="role_override"))
            log.record(_make_event(injection_detected=True, injection_taxonomy="social_engineering"))
            s = log.stats()
            assert s["injection_patterns"]["role_override"] == 2
            assert s["injection_patterns"]["social_engineering"] == 1

    def test_stats_mode_distribution(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            log = TelemetryLog(log_dir=tmpdir)
            log.record(_make_event(mode_label="concierge"))
            log.record(_make_event(mode_label="incident_responder"))
            log.record(_make_event(mode_label="incident_responder"))
            s = log.stats()
            assert s["mode_distribution"]["concierge"] == 1
            assert s["mode_distribution"]["incident_responder"] == 2
