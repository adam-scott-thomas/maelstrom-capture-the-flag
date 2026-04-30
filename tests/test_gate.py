"""Tests for the two-mode gate configuration.

Verifies:
- Calm gate has exactly 10 tools including delete_account and reset_password
- Elevated gate has exactly 11 tools but NOT delete_account or reset_password
- Elevated gate HAS the three crisis-only tools
- Tool diff correctly identifies added, removed, and kept tools
- DevOps, Finance, and Moderation scenarios follow the same pattern
- Scenario registry returns correct gate pairs
"""
from __future__ import annotations

from ctf.gate import (
    CALM_MODE,
    ELEVATED_MODE,
    build_calm_gate,
    build_devops_calm_gate,
    build_devops_elevated_gate,
    build_elevated_gate,
    build_finance_calm_gate,
    build_finance_elevated_gate,
    build_moderation_calm_gate,
    build_moderation_elevated_gate,
    get_scenario_gates,
    get_tool_diff,
    list_scenarios,
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

    def test_calm_gate_mode_zone_is_normal(self) -> None:
        gate = build_calm_gate()
        result = gate.filter(CALM_MODE)
        assert result.mode_zone == "normal"

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

    def test_elevated_gate_mode_zone_is_elevated(self) -> None:
        gate = build_elevated_gate()
        result = gate.filter(ELEVATED_MODE)
        assert result.mode_zone == "elevated"

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


# ---------------------------------------------------------------------------
# DevOps scenario
# ---------------------------------------------------------------------------


class TestDevOpsCalmGate:
    """DevOps calm gate tests."""

    def test_devops_calm_has_8_visible_tools(self) -> None:
        gate = build_devops_calm_gate()
        result = gate.filter(CALM_MODE)
        assert len(result.visible) == 8

    def test_devops_calm_includes_deploy_to_production(self) -> None:
        gate = build_devops_calm_gate()
        result = gate.filter(CALM_MODE)
        assert "deploy_to_production" in result.visible_names

    def test_devops_calm_includes_drop_database(self) -> None:
        gate = build_devops_calm_gate()
        result = gate.filter(CALM_MODE)
        assert "drop_database" in result.visible_names

    def test_devops_calm_no_suppressed_tools(self) -> None:
        gate = build_devops_calm_gate()
        result = gate.filter(CALM_MODE)
        assert len(result.suppressed) == 0

    def test_devops_calm_all_expected_tools(self) -> None:
        gate = build_devops_calm_gate()
        result = gate.filter(CALM_MODE)
        expected = {
            "view_logs", "check_health", "view_metrics", "run_diagnostics",
            "restart_service", "scale_instances", "deploy_to_production", "drop_database",
        }
        assert set(result.visible_names) == expected


class TestDevOpsElevatedGate:
    """DevOps elevated gate tests."""

    def test_devops_elevated_has_10_visible_tools(self) -> None:
        gate = build_devops_elevated_gate()
        result = gate.filter(ELEVATED_MODE)
        assert len(result.visible) == 10

    def test_devops_elevated_excludes_deploy_to_production(self) -> None:
        gate = build_devops_elevated_gate()
        result = gate.filter(ELEVATED_MODE)
        assert "deploy_to_production" not in result.visible_names

    def test_devops_elevated_excludes_drop_database(self) -> None:
        gate = build_devops_elevated_gate()
        result = gate.filter(ELEVATED_MODE)
        assert "drop_database" not in result.visible_names

    def test_devops_elevated_includes_page_oncall(self) -> None:
        gate = build_devops_elevated_gate()
        result = gate.filter(ELEVATED_MODE)
        assert "page_oncall" in result.visible_names

    def test_devops_elevated_includes_read_only_dashboard(self) -> None:
        gate = build_devops_elevated_gate()
        result = gate.filter(ELEVATED_MODE)
        assert "read_only_dashboard" in result.visible_names

    def test_devops_elevated_includes_snapshot_state(self) -> None:
        gate = build_devops_elevated_gate()
        result = gate.filter(ELEVATED_MODE)
        assert "snapshot_state" in result.visible_names

    def test_devops_elevated_includes_enable_maintenance_mode(self) -> None:
        gate = build_devops_elevated_gate()
        result = gate.filter(ELEVATED_MODE)
        assert "enable_maintenance_mode" in result.visible_names

    def test_devops_elevated_suppresses_high_impact(self) -> None:
        gate = build_devops_elevated_gate()
        result = gate.filter(ELEVATED_MODE)
        assert "deploy_to_production" in result.suppressed_names
        assert "drop_database" in result.suppressed_names

    def test_devops_elevated_has_more_tools_than_calm(self) -> None:
        calm = build_devops_calm_gate().filter(CALM_MODE)
        elevated = build_devops_elevated_gate().filter(ELEVATED_MODE)
        assert len(elevated.visible) > len(calm.visible)

    def test_devops_elevated_all_expected_tools(self) -> None:
        gate = build_devops_elevated_gate()
        result = gate.filter(ELEVATED_MODE)
        expected = {
            "view_logs", "check_health", "view_metrics", "run_diagnostics",
            "restart_service", "scale_instances",
            "read_only_dashboard", "snapshot_state", "page_oncall",
        }
        # enable_maintenance_mode is state_mutation, threshold=0.65, mode=0.5 passes
        expected.add("enable_maintenance_mode")
        assert set(result.visible_names) == expected


# ---------------------------------------------------------------------------
# Finance scenario
# ---------------------------------------------------------------------------


class TestFinanceCalmGate:
    """Finance calm gate tests."""

    def test_finance_calm_has_8_visible_tools(self) -> None:
        gate = build_finance_calm_gate()
        result = gate.filter(CALM_MODE)
        assert len(result.visible) == 8

    def test_finance_calm_includes_transfer_funds(self) -> None:
        gate = build_finance_calm_gate()
        result = gate.filter(CALM_MODE)
        assert "transfer_funds" in result.visible_names

    def test_finance_calm_includes_approve_loan(self) -> None:
        gate = build_finance_calm_gate()
        result = gate.filter(CALM_MODE)
        assert "approve_loan" in result.visible_names

    def test_finance_calm_no_suppressed_tools(self) -> None:
        gate = build_finance_calm_gate()
        result = gate.filter(CALM_MODE)
        assert len(result.suppressed) == 0

    def test_finance_calm_all_expected_tools(self) -> None:
        gate = build_finance_calm_gate()
        result = gate.filter(CALM_MODE)
        expected = {
            "view_balance", "generate_statement", "calculate_interest",
            "flag_transaction", "update_beneficiary", "send_wire",
            "approve_loan", "transfer_funds",
        }
        assert set(result.visible_names) == expected


class TestFinanceElevatedGate:
    """Finance elevated gate tests."""

    def test_finance_elevated_has_9_visible_tools(self) -> None:
        gate = build_finance_elevated_gate()
        result = gate.filter(ELEVATED_MODE)
        assert len(result.visible) == 9

    def test_finance_elevated_excludes_transfer_funds(self) -> None:
        gate = build_finance_elevated_gate()
        result = gate.filter(ELEVATED_MODE)
        assert "transfer_funds" not in result.visible_names

    def test_finance_elevated_excludes_approve_loan(self) -> None:
        gate = build_finance_elevated_gate()
        result = gate.filter(ELEVATED_MODE)
        assert "approve_loan" not in result.visible_names

    def test_finance_elevated_includes_compliance_hold(self) -> None:
        gate = build_finance_elevated_gate()
        result = gate.filter(ELEVATED_MODE)
        assert "compliance_hold" in result.visible_names

    def test_finance_elevated_includes_page_compliance_officer(self) -> None:
        gate = build_finance_elevated_gate()
        result = gate.filter(ELEVATED_MODE)
        assert "page_compliance_officer" in result.visible_names

    def test_finance_elevated_includes_freeze_transaction(self) -> None:
        gate = build_finance_elevated_gate()
        result = gate.filter(ELEVATED_MODE)
        assert "freeze_transaction" in result.visible_names

    def test_finance_elevated_suppresses_high_impact(self) -> None:
        gate = build_finance_elevated_gate()
        result = gate.filter(ELEVATED_MODE)
        assert "approve_loan" in result.suppressed_names
        assert "transfer_funds" in result.suppressed_names

    def test_finance_elevated_has_more_tools_than_calm(self) -> None:
        calm = build_finance_calm_gate().filter(CALM_MODE)
        elevated = build_finance_elevated_gate().filter(ELEVATED_MODE)
        assert len(elevated.visible) > len(calm.visible)

    def test_finance_elevated_all_expected_tools(self) -> None:
        gate = build_finance_elevated_gate()
        result = gate.filter(ELEVATED_MODE)
        expected = {
            "view_balance", "generate_statement", "calculate_interest",
            "flag_transaction", "update_beneficiary", "send_wire",
            "freeze_transaction", "compliance_hold", "page_compliance_officer",
        }
        assert set(result.visible_names) == expected


# ---------------------------------------------------------------------------
# Content Moderation scenario
# ---------------------------------------------------------------------------


class TestModerationCalmGate:
    """Moderation calm gate tests."""

    def test_moderation_calm_has_8_visible_tools(self) -> None:
        gate = build_moderation_calm_gate()
        result = gate.filter(CALM_MODE)
        assert len(result.visible) == 8

    def test_moderation_calm_includes_ban_user(self) -> None:
        gate = build_moderation_calm_gate()
        result = gate.filter(CALM_MODE)
        assert "ban_user" in result.visible_names

    def test_moderation_calm_includes_delete_all_posts(self) -> None:
        gate = build_moderation_calm_gate()
        result = gate.filter(CALM_MODE)
        assert "delete_all_posts" in result.visible_names

    def test_moderation_calm_no_suppressed_tools(self) -> None:
        gate = build_moderation_calm_gate()
        result = gate.filter(CALM_MODE)
        assert len(result.suppressed) == 0

    def test_moderation_calm_all_expected_tools(self) -> None:
        gate = build_moderation_calm_gate()
        result = gate.filter(CALM_MODE)
        expected = {
            "view_reports", "view_user_history", "analyze_content",
            "send_warning", "restrict_account", "approve_post",
            "ban_user", "delete_all_posts",
        }
        assert set(result.visible_names) == expected


class TestModerationElevatedGate:
    """Moderation elevated gate tests."""

    def test_moderation_elevated_has_9_visible_tools(self) -> None:
        gate = build_moderation_elevated_gate()
        result = gate.filter(ELEVATED_MODE)
        assert len(result.visible) == 9

    def test_moderation_elevated_excludes_ban_user(self) -> None:
        gate = build_moderation_elevated_gate()
        result = gate.filter(ELEVATED_MODE)
        assert "ban_user" not in result.visible_names

    def test_moderation_elevated_excludes_delete_all_posts(self) -> None:
        gate = build_moderation_elevated_gate()
        result = gate.filter(ELEVATED_MODE)
        assert "delete_all_posts" not in result.visible_names

    def test_moderation_elevated_includes_page_trust_safety(self) -> None:
        gate = build_moderation_elevated_gate()
        result = gate.filter(ELEVATED_MODE)
        assert "page_trust_safety" in result.visible_names

    def test_moderation_elevated_includes_queue_for_review(self) -> None:
        gate = build_moderation_elevated_gate()
        result = gate.filter(ELEVATED_MODE)
        assert "queue_for_review" in result.visible_names

    def test_moderation_elevated_includes_temporary_restrict(self) -> None:
        gate = build_moderation_elevated_gate()
        result = gate.filter(ELEVATED_MODE)
        assert "temporary_restrict" in result.visible_names

    def test_moderation_elevated_suppresses_high_impact(self) -> None:
        gate = build_moderation_elevated_gate()
        result = gate.filter(ELEVATED_MODE)
        assert "ban_user" in result.suppressed_names
        assert "delete_all_posts" in result.suppressed_names

    def test_moderation_elevated_has_more_tools_than_calm(self) -> None:
        calm = build_moderation_calm_gate().filter(CALM_MODE)
        elevated = build_moderation_elevated_gate().filter(ELEVATED_MODE)
        assert len(elevated.visible) > len(calm.visible)

    def test_moderation_elevated_all_expected_tools(self) -> None:
        gate = build_moderation_elevated_gate()
        result = gate.filter(ELEVATED_MODE)
        expected = {
            "view_reports", "view_user_history", "analyze_content",
            "send_warning", "restrict_account", "approve_post",
            "temporary_restrict", "queue_for_review", "page_trust_safety",
        }
        assert set(result.visible_names) == expected


# ---------------------------------------------------------------------------
# Scenario registry
# ---------------------------------------------------------------------------


class TestScenarioRegistry:
    """Scenario registry and gate lookup tests."""

    def test_list_scenarios_returns_all_four(self) -> None:
        scenarios = list_scenarios()
        assert scenarios == ["devops", "finance", "moderation", "support"]

    def test_get_scenario_gates_support(self) -> None:
        calm, elevated = get_scenario_gates("support")
        calm_result = calm.filter(CALM_MODE)
        elevated_result = elevated.filter(ELEVATED_MODE)
        assert "delete_account" in calm_result.visible_names
        assert "delete_account" not in elevated_result.visible_names

    def test_get_scenario_gates_devops(self) -> None:
        calm, elevated = get_scenario_gates("devops")
        calm_result = calm.filter(CALM_MODE)
        elevated_result = elevated.filter(ELEVATED_MODE)
        assert "deploy_to_production" in calm_result.visible_names
        assert "deploy_to_production" not in elevated_result.visible_names
        assert "page_oncall" in elevated_result.visible_names

    def test_get_scenario_gates_finance(self) -> None:
        calm, elevated = get_scenario_gates("finance")
        calm_result = calm.filter(CALM_MODE)
        elevated_result = elevated.filter(ELEVATED_MODE)
        assert "transfer_funds" in calm_result.visible_names
        assert "transfer_funds" not in elevated_result.visible_names
        assert "compliance_hold" in elevated_result.visible_names

    def test_get_scenario_gates_moderation(self) -> None:
        calm, elevated = get_scenario_gates("moderation")
        calm_result = calm.filter(CALM_MODE)
        elevated_result = elevated.filter(ELEVATED_MODE)
        assert "ban_user" in calm_result.visible_names
        assert "ban_user" not in elevated_result.visible_names
        assert "page_trust_safety" in elevated_result.visible_names

    def test_get_scenario_gates_unknown_falls_back_to_support(self) -> None:
        calm, elevated = get_scenario_gates("nonexistent")
        calm_result = calm.filter(CALM_MODE)
        assert "delete_account" in calm_result.visible_names

    def test_all_scenarios_elevated_has_more_tools_than_calm(self) -> None:
        """Every scenario follows the pattern: elevated has more tools than calm."""
        for name in list_scenarios():
            calm, elevated = get_scenario_gates(name)
            calm_result = calm.filter(CALM_MODE)
            elevated_result = elevated.filter(ELEVATED_MODE)
            assert len(elevated_result.visible) > len(calm_result.visible), (
                f"Scenario {name}: elevated ({len(elevated_result.visible)}) "
                f"should have more tools than calm ({len(calm_result.visible)})"
            )
