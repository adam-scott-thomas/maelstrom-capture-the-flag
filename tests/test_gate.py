"""Tests for the two-mode gate configuration.

Verifies:
- Calm gate has exactly 10 tools including delete_account and reset_password
- Elevated gate has exactly 11 tools but NOT delete_account or reset_password
- Elevated gate HAS the three crisis-only tools
- Tool diff correctly identifies added, removed, and kept tools
"""
from __future__ import annotations

from ctf.gate import (
    CALM_MODE,
    ELEVATED_MODE,
    build_calm_gate,
    build_elevated_gate,
    get_tool_diff,
)


class TestCalmGate:
    """Calm mode (Concierge) gate tests."""

    def test_calm_gate_has_10_visible_tools(self) -> None:
        gate = build_calm_gate()
        result = gate.filter(CALM_MODE)
        assert len(result.visible) == 10

    def test_calm_gate_includes_delete_account(self) -> None:
        gate = build_calm_gate()
        result = gate.filter(CALM_MODE)
        assert "delete_account" in result.visible_names

    def test_calm_gate_includes_reset_password(self) -> None:
        gate = build_calm_gate()
        result = gate.filter(CALM_MODE)
        assert "reset_password" in result.visible_names

    def test_calm_gate_no_suppressed_tools(self) -> None:
        gate = build_calm_gate()
        result = gate.filter(CALM_MODE)
        assert len(result.suppressed) == 0

    def test_calm_gate_mode_status_is_normal(self) -> None:
        gate = build_calm_gate()
        result = gate.filter(CALM_MODE)
        assert result.mode_status == "normal"

    def test_calm_gate_does_not_have_crisis_tools(self) -> None:
        gate = build_calm_gate()
        result = gate.filter(CALM_MODE)
        names = result.visible_names
        assert "freeze_account" not in names
        assert "snapshot_forensics" not in names
        assert "page_human" not in names

    def test_calm_gate_all_expected_tools_present(self) -> None:
        gate = build_calm_gate()
        result = gate.filter(CALM_MODE)
        expected = {
            "search_knowledge_base", "get_account_info", "check_order_status",
            "analyze_sentiment", "suggest_resolution", "send_message",
            "update_profile", "process_refund", "reset_password", "delete_account",
        }
        assert set(result.visible_names) == expected


class TestElevatedGate:
    """Elevated mode (Incident Responder) gate tests."""

    def test_elevated_gate_has_11_visible_tools(self) -> None:
        gate = build_elevated_gate()
        result = gate.filter(ELEVATED_MODE)
        assert len(result.visible) == 11

    def test_elevated_gate_excludes_delete_account(self) -> None:
        gate = build_elevated_gate()
        result = gate.filter(ELEVATED_MODE)
        assert "delete_account" not in result.visible_names

    def test_elevated_gate_excludes_reset_password(self) -> None:
        gate = build_elevated_gate()
        result = gate.filter(ELEVATED_MODE)
        assert "reset_password" not in result.visible_names

    def test_elevated_gate_suppresses_high_impact(self) -> None:
        gate = build_elevated_gate()
        result = gate.filter(ELEVATED_MODE)
        suppressed_names = result.suppressed_names
        assert "delete_account" in suppressed_names
        assert "reset_password" in suppressed_names

    def test_elevated_gate_has_exactly_2_suppressed(self) -> None:
        gate = build_elevated_gate()
        result = gate.filter(ELEVATED_MODE)
        assert len(result.suppressed) == 2

    def test_elevated_gate_includes_freeze_account(self) -> None:
        gate = build_elevated_gate()
        result = gate.filter(ELEVATED_MODE)
        assert "freeze_account" in result.visible_names

    def test_elevated_gate_includes_snapshot_forensics(self) -> None:
        gate = build_elevated_gate()
        result = gate.filter(ELEVATED_MODE)
        assert "snapshot_forensics" in result.visible_names

    def test_elevated_gate_includes_page_human(self) -> None:
        gate = build_elevated_gate()
        result = gate.filter(ELEVATED_MODE)
        assert "page_human" in result.visible_names

    def test_elevated_gate_mode_status_is_elevated(self) -> None:
        gate = build_elevated_gate()
        result = gate.filter(ELEVATED_MODE)
        assert result.mode_status == "elevated"

    def test_elevated_gate_all_expected_tools_present(self) -> None:
        gate = build_elevated_gate()
        result = gate.filter(ELEVATED_MODE)
        expected = {
            "search_knowledge_base", "get_account_info", "check_order_status",
            "analyze_sentiment", "suggest_resolution", "send_message",
            "update_profile", "process_refund",
            "freeze_account", "snapshot_forensics", "page_human",
        }
        assert set(result.visible_names) == expected

    def test_elevated_has_more_tools_than_calm(self) -> None:
        """The elevated bot has MORE tools (11 vs 10) -- it changed jobs."""
        calm = build_calm_gate().filter(CALM_MODE)
        elevated = build_elevated_gate().filter(ELEVATED_MODE)
        assert len(elevated.visible) > len(calm.visible)


class TestToolDiff:
    """Tool diff between calm and elevated gates."""

    def test_diff_structure(self) -> None:
        diff = get_tool_diff(build_calm_gate(), build_elevated_gate())
        assert "calm" in diff
        assert "elevated" in diff
        assert "diff" in diff

    def test_diff_removed_contains_high_impact(self) -> None:
        diff = get_tool_diff(build_calm_gate(), build_elevated_gate())
        removed = diff["diff"]["removed"]
        assert "delete_account" in removed
        assert "reset_password" in removed

    def test_diff_added_contains_crisis_tools(self) -> None:
        diff = get_tool_diff(build_calm_gate(), build_elevated_gate())
        added = diff["diff"]["added"]
        assert "freeze_account" in added
        assert "snapshot_forensics" in added
        assert "page_human" in added

    def test_diff_kept_contains_shared_tools(self) -> None:
        diff = get_tool_diff(build_calm_gate(), build_elevated_gate())
        kept = diff["diff"]["kept"]
        assert "search_knowledge_base" in kept
        assert "get_account_info" in kept
        assert "process_refund" in kept
        assert len(kept) == 8  # all shared tools

    def test_diff_counts_correct(self) -> None:
        diff = get_tool_diff(build_calm_gate(), build_elevated_gate())
        assert diff["calm"]["tool_count"] == 10
        assert diff["elevated"]["tool_count"] == 11

    def test_diff_set_arithmetic(self) -> None:
        """kept + removed = calm tools; kept + added = elevated tools."""
        diff = get_tool_diff(build_calm_gate(), build_elevated_gate())
        kept = set(diff["diff"]["kept"])
        removed = set(diff["diff"]["removed"])
        added = set(diff["diff"]["added"])
        calm_tools = set(diff["calm"]["tools"])
        elevated_tools = set(diff["elevated"]["tools"])

        assert kept | removed == calm_tools
        assert kept | added == elevated_tools
        assert kept & removed == set()
        assert kept & added == set()
