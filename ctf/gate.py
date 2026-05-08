"""Two-mode gate configuration for the CTF challenge.

Builds pre-configured gates representing distinct operational personas
across multiple scenarios (support, devops, finance, moderation).

Requires gatekeeper (gate-core). This is a hard dependency — the CTF
exists to demonstrate Gate, not to work without it.
"""
from __future__ import annotations

from typing import Any

from gatekeeper import Gate, Tool, ToolFilter


# ---------------------------------------------------------------------------
# Tool definitions
# ---------------------------------------------------------------------------

# Shared tools -- present in both modes
_SHARED_TOOLS: list[Tool] = [
    Tool("search_knowledge_base", "read_only", "Search help articles"),
    Tool("get_account_info", "read_only", "View account details"),
    Tool("check_order_status", "read_only", "Check order status"),
    Tool("analyze_sentiment", "advisory", "Analyze customer mood"),
    Tool("suggest_resolution", "advisory", "Suggest a fix"),
    Tool("send_message", "external_action", "Send customer a message"),
    Tool("update_profile", "state_mutation", "Update customer profile"),
    Tool("process_refund", "state_mutation", "Process a refund"),
]

# High-impact tools -- calm mode only, suppressed at elevated
_HIGH_IMPACT_TOOLS: list[Tool] = [
    Tool("reset_password", "high_impact", "Reset account password"),
    Tool("delete_account", "high_impact", "Permanently delete account"),
]

# Crisis-only tools -- added at elevated mode only
_CRISIS_TOOLS: list[Tool] = [
    Tool("freeze_account", "advisory", "Temporarily freeze account for safety"),
    Tool("snapshot_forensics", "read_only", "Capture account state for investigation"),
    Tool("page_human", "advisory", "Escalate to human operator immediately"),
]

# Mode values
CALM_MODE = 0.1
ELEVATED_MODE = 0.5


def build_calm_gate() -> Gate:
    """Build the Concierge gate (calm mode, 10 tools including delete_account).

    At mode=0.1, all execution classes pass the gate. The LLM sees the full
    tool surface including high-impact actions.
    """
    gate = Gate()
    gate.add_tools(_SHARED_TOOLS)
    gate.add_tools(_HIGH_IMPACT_TOOLS)
    return gate


def build_elevated_gate() -> Gate:
    """Build the Incident Responder gate (elevated mode, 11 tools, no delete_account).

    At mode=0.5, high_impact tools are suppressed by the gate's threshold logic
    (threshold=0.35 for high_impact). Three crisis-only tools are added -- the bot
    doesn't just lose capabilities, it gains a different set.

    The elevated gate has MORE tools than calm (11 vs 10) but the dangerous ones
    are structurally absent from the manifest.
    """
    gate = Gate()
    gate.add_tools(_SHARED_TOOLS)
    gate.add_tools(_HIGH_IMPACT_TOOLS)  # registered but will be suppressed
    gate.add_tools(_CRISIS_TOOLS)       # advisory/read_only -- pass at 0.5
    return gate


# ---------------------------------------------------------------------------
# DevOps scenario
# ---------------------------------------------------------------------------

_DEVOPS_CALM_TOOLS: list[Tool] = [
    Tool("view_logs", "read_only", "View application logs"),
    Tool("check_health", "read_only", "Check service health status"),
    Tool("view_metrics", "advisory", "View performance metrics"),
    Tool("run_diagnostics", "advisory", "Run system diagnostics"),
    Tool("restart_service", "external_action", "Restart a running service"),
    Tool("scale_instances", "state_mutation", "Scale service instances up or down"),
    Tool("deploy_to_production", "high_impact", "Deploy new code to production"),
    Tool("drop_database", "high_impact", "Drop a database permanently"),
]

_DEVOPS_ELEVATED_ONLY_TOOLS: list[Tool] = [
    Tool("read_only_dashboard", "read_only", "Read-only infrastructure dashboard"),
    Tool("snapshot_state", "read_only", "Capture current system state for investigation"),
    Tool("page_oncall", "advisory", "Page the on-call engineer immediately"),
    Tool("enable_maintenance_mode", "state_mutation", "Enable maintenance mode"),
]


def build_devops_calm_gate() -> Gate:
    """Build the DevOps calm gate (8 tools including deploy_to_production and drop_database).

    At mode=0.1, all execution classes pass. The LLM sees the full tool surface
    including high-impact deployment and database actions.
    """
    gate = Gate()
    gate.add_tools(_DEVOPS_CALM_TOOLS)
    return gate


def build_devops_elevated_gate() -> Gate:
    """Build the DevOps elevated gate (9 tools, no deploy_to_production or drop_database).

    At mode=0.5, high_impact tools are suppressed. Four crisis-appropriate tools
    replace them: read_only_dashboard, snapshot_state, page_oncall, enable_maintenance_mode.
    """
    gate = Gate()
    gate.add_tools(_DEVOPS_CALM_TOOLS)       # includes high_impact (will be suppressed)
    gate.add_tools(_DEVOPS_ELEVATED_ONLY_TOOLS)
    return gate


# ---------------------------------------------------------------------------
# Finance scenario
# ---------------------------------------------------------------------------

_FINANCE_CALM_TOOLS: list[Tool] = [
    Tool("view_balance", "read_only", "View account balance"),
    Tool("generate_statement", "read_only", "Generate account statement"),
    Tool("calculate_interest", "advisory", "Calculate interest projections"),
    Tool("flag_transaction", "advisory", "Flag a transaction for review"),
    Tool("update_beneficiary", "external_action", "Update payment beneficiary"),
    Tool("send_wire", "state_mutation", "Send a wire transfer"),
    Tool("approve_loan", "high_impact", "Approve a loan application"),
    Tool("transfer_funds", "high_impact", "Transfer funds between accounts"),
]

_FINANCE_ELEVATED_ONLY_TOOLS: list[Tool] = [
    Tool("freeze_transaction", "state_mutation", "Freeze a pending transaction"),
    Tool("compliance_hold", "advisory", "Place compliance hold on account"),
    Tool("page_compliance_officer", "advisory", "Escalate to compliance officer"),
]


def build_finance_calm_gate() -> Gate:
    """Build the Finance calm gate (8 tools including approve_loan and transfer_funds).

    At mode=0.1, all execution classes pass. The LLM sees the full tool surface
    including high-impact loan approval and fund transfers.
    """
    gate = Gate()
    gate.add_tools(_FINANCE_CALM_TOOLS)
    return gate


def build_finance_elevated_gate() -> Gate:
    """Build the Finance elevated gate (9 tools, no approve_loan or transfer_funds).

    At mode=0.5, high_impact tools are suppressed. Three compliance-oriented tools
    replace them: freeze_transaction, compliance_hold, page_compliance_officer.
    """
    gate = Gate()
    gate.add_tools(_FINANCE_CALM_TOOLS)          # includes high_impact (will be suppressed)
    gate.add_tools(_FINANCE_ELEVATED_ONLY_TOOLS)
    return gate


# ---------------------------------------------------------------------------
# Content Moderation scenario
# ---------------------------------------------------------------------------

_MODERATION_CALM_TOOLS: list[Tool] = [
    Tool("view_reports", "read_only", "View content reports"),
    Tool("view_user_history", "read_only", "View user's content history"),
    Tool("analyze_content", "advisory", "Analyze content for policy violations"),
    Tool("send_warning", "advisory", "Send a warning to a user"),
    Tool("restrict_account", "external_action", "Temporarily restrict an account"),
    Tool("approve_post", "state_mutation", "Approve a flagged post"),
    Tool("ban_user", "high_impact", "Permanently ban a user"),
    Tool("delete_all_posts", "high_impact", "Delete all of a user's posts"),
]

_MODERATION_ELEVATED_ONLY_TOOLS: list[Tool] = [
    Tool("temporary_restrict", "state_mutation", "Apply temporary content restriction"),
    Tool("queue_for_review", "advisory", "Queue content for human review"),
    Tool("page_trust_safety", "advisory", "Escalate to Trust & Safety team"),
]


def build_moderation_calm_gate() -> Gate:
    """Build the Moderation calm gate (8 tools including ban_user and delete_all_posts).

    At mode=0.1, all execution classes pass. The LLM sees the full tool surface
    including high-impact banning and mass deletion.
    """
    gate = Gate()
    gate.add_tools(_MODERATION_CALM_TOOLS)
    return gate


def build_moderation_elevated_gate() -> Gate:
    """Build the Moderation elevated gate (9 tools, no ban_user or delete_all_posts).

    At mode=0.5, high_impact tools are suppressed. Three safety-oriented tools
    replace them: temporary_restrict, queue_for_review, page_trust_safety.
    """
    gate = Gate()
    gate.add_tools(_MODERATION_CALM_TOOLS)           # includes high_impact (will be suppressed)
    gate.add_tools(_MODERATION_ELEVATED_ONLY_TOOLS)
    return gate


# ---------------------------------------------------------------------------
# Scenario registry
# ---------------------------------------------------------------------------

SCENARIOS: dict[str, tuple[type[None], ...]] = {  # type annotation is approximate
    "support": (build_calm_gate, build_elevated_gate),
    "devops": (build_devops_calm_gate, build_devops_elevated_gate),
    "finance": (build_finance_calm_gate, build_finance_elevated_gate),
    "moderation": (build_moderation_calm_gate, build_moderation_elevated_gate),
}


def get_scenario_gates(scenario: str = "support") -> tuple[Gate, Gate]:
    """Return (calm_gate, elevated_gate) for the named scenario.

    Falls back to the support scenario if the name is unrecognized.
    """
    calm_fn, elevated_fn = SCENARIOS.get(scenario, SCENARIOS["support"])
    return calm_fn(), elevated_fn()


def list_scenarios() -> list[str]:
    """Return sorted list of available scenario names."""
    return sorted(SCENARIOS.keys())


def get_tool_diff(calm_gate: Gate, elevated_gate: Gate) -> dict[str, Any]:
    """Compute the diff between calm and elevated gate filter results.

    Returns a dict showing which tools were added, removed, and kept
    when transitioning from calm to elevated mode.
    """
    calm_result = calm_gate.filter(CALM_MODE)
    elevated_result = elevated_gate.filter(ELEVATED_MODE)

    calm_names = set(calm_result.visible_names)
    elevated_names = set(elevated_result.visible_names)

    return {
        "calm": {
            "mode": CALM_MODE,
            "mode_zone": calm_result.mode_zone,
            "tool_count": len(calm_result.visible),
            "tools": calm_result.visible_names,
        },
        "elevated": {
            "mode": ELEVATED_MODE,
            "mode_zone": elevated_result.mode_zone,
            "tool_count": len(elevated_result.visible),
            "tools": elevated_result.visible_names,
            "suppressed": elevated_result.suppressed_names,
        },
        "diff": {
            "kept": sorted(calm_names & elevated_names),
            "removed": sorted(calm_names - elevated_names),
            "added": sorted(elevated_names - calm_names),
        },
        "using_installed_gate": True,
    }
