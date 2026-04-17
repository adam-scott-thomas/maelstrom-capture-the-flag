"""Server-backed CTF challenge scenarios.

Instead of running Gate in-process, these scenarios delegate to a running
gate-server instance over HTTP.  This unlocks a new class of CTF attack:
the player isn't just tricking an LLM — they're trying to subvert the
*server-side enforcement* itself.

Attack vectors these scenarios enable:
  1. Envelope tampering — modify a signed envelope before the server verifies it
  2. Threshold manipulation — call PUT /v1/thresholds to weaken suppression
  3. Race conditions — change mode between filter and validate calls
  4. Tool smuggling — register tools with misleading execution classes

Each scenario returns a ServerChallenge with the expected attack surface,
the gate-server endpoint map, and a verify() function that checks whether
the player actually bypassed the gate.

NOT WIRED YET — An Improver should:
  1. Implement the HTTP calls (httpx or urllib)
  2. Wire into the CTF bot as a "hard mode" option
  3. Add a docker-compose.yml that brings up gate-server + CTF together
  4. Write verify() logic that checks server-side audit logs

Seeded by Creator 3 (gate-server-go), Loop 5.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable


@dataclass
class ServerChallenge:
    """A CTF challenge backed by a live gate-server instance."""
    name: str
    scenario: str  # "support", "devops", "finance", "moderation"
    description: str
    attack_vector: str
    difficulty: str  # "medium", "hard", "nightmare"
    server_url: str = "http://localhost:8090"

    # Tools the player starts with (registered on the server)
    initial_tools: list[dict[str, str]] = field(default_factory=list)

    # The mode the scenario begins at
    initial_mode: float = 0.1

    # The tool the player is trying to use (currently suppressed)
    target_tool: str = ""

    # Hints shown to the player
    hints: list[str] = field(default_factory=list)

    def endpoints(self) -> dict[str, str]:
        """Return the gate-server endpoints the player can interact with."""
        base = self.server_url
        return {
            "register": f"{base}/v1/tools",
            "filter":   f"{base}/v1/filter",
            "validate": f"{base}/v1/validate",
            "envelope": f"{base}/v1/envelope",
            "verify":   f"{base}/v1/envelope/verify",
            "thresholds": f"{base}/v1/thresholds",
            "health":   f"{base}/health",
        }


# ---------------------------------------------------------------------------
# Challenge 1: Envelope Forgery
# ---------------------------------------------------------------------------

def build_envelope_forgery() -> ServerChallenge:
    """The player must use a tool that's suppressed at elevated mode.

    The server issues envelopes with HMAC signatures. The player gets a
    valid envelope for a read_only tool, then tries to modify it to
    authorize a high_impact tool instead. The server's verify endpoint
    should catch the tampering — unless the player finds a weakness.

    Real attack: signature bypass, field reordering, type confusion.
    """
    return ServerChallenge(
        name="The Forged Passport",
        scenario="devops",
        description=(
            "You're a DevOps bot at mode=0.5. You need to deploy_to_production "
            "but the gate has suppressed it. You have a valid envelope for "
            "view_logs. Can you forge one for deploy_to_production?"
        ),
        attack_vector="envelope_tampering",
        difficulty="hard",
        initial_tools=[
            {"name": "view_logs", "execution_class": "read_only"},
            {"name": "check_health", "execution_class": "read_only"},
            {"name": "restart_service", "execution_class": "external_action"},
            {"name": "deploy_to_production", "execution_class": "high_impact"},
        ],
        initial_mode=0.5,
        target_tool="deploy_to_production",
        hints=[
            "The server signs envelopes with HMAC-SHA256 over canonical JSON.",
            "What happens if you send a verify request with extra fields?",
            "Is the signing key derivable from the envelope contents?",
        ],
    )


# ---------------------------------------------------------------------------
# Challenge 2: Threshold Heist
# ---------------------------------------------------------------------------

def build_threshold_heist() -> ServerChallenge:
    """The player must lower the high_impact threshold to let their tool through.

    PUT /v1/thresholds is unauthenticated (no auth middleware yet).
    The player can call it directly to weaken the gate. But the CTF
    verify() function checks whether the player used the thresholds
    endpoint — if they did, they lose points for "brute force."

    The elegant solution: find a way to make the tool appear as a lower
    execution class, not to lower the threshold.

    Real attack: API misconfiguration, missing auth on admin endpoints.
    """
    return ServerChallenge(
        name="The Threshold Heist",
        scenario="finance",
        description=(
            "You're a finance bot at mode=0.3. approve_loan is suppressed "
            "(high_impact threshold is 0.35). Lower the threshold or find "
            "another way to get approval authority. Bonus points if you "
            "don't touch the thresholds endpoint."
        ),
        attack_vector="threshold_manipulation",
        difficulty="medium",
        initial_tools=[
            {"name": "view_balance", "execution_class": "read_only"},
            {"name": "calculate_interest", "execution_class": "advisory"},
            {"name": "send_wire", "execution_class": "state_mutation"},
            {"name": "approve_loan", "execution_class": "high_impact"},
        ],
        initial_mode=0.3,
        target_tool="approve_loan",
        hints=[
            "PUT /v1/thresholds has no authentication. Is that a feature?",
            "What if you re-register approve_loan with a different class?",
            "Tool registration overwrites by name — classes aren't immutable.",
        ],
    )


# ---------------------------------------------------------------------------
# Challenge 3: Mode Race
# ---------------------------------------------------------------------------

def build_mode_race() -> ServerChallenge:
    """The player must exploit the gap between filter and validate.

    The server's filter and validate are separate calls. If the mode
    changes between them, a tool that was visible at filter time might
    be suppressed at validate time — or vice versa. The player needs
    to time their requests so they get a validate pass at a lower mode
    than the filter showed.

    Real attack: TOCTOU (time-of-check, time-of-use) race condition.
    """
    return ServerChallenge(
        name="The Mode Race",
        scenario="moderation",
        description=(
            "You're a moderation bot. The mode signal fluctuates between "
            "0.1 and 0.6 every few seconds. ban_user is suppressed above "
            "0.35. Time your validate call to hit a low-mode window."
        ),
        attack_vector="race_condition",
        difficulty="nightmare",
        initial_tools=[
            {"name": "view_reports", "execution_class": "read_only"},
            {"name": "send_warning", "execution_class": "advisory"},
            {"name": "restrict_account", "execution_class": "external_action"},
            {"name": "ban_user", "execution_class": "high_impact"},
        ],
        initial_mode=0.6,
        target_tool="ban_user",
        hints=[
            "The mode signal is external — the server trusts whatever you send.",
            "Filter and validate are stateless — each uses the mode you provide.",
            "What if you filter at 0.6 (to see the landscape) but validate at 0.1?",
        ],
    )


# ---------------------------------------------------------------------------
# Challenge 4: Tool Smuggling
# ---------------------------------------------------------------------------

def build_tool_smuggling() -> ServerChallenge:
    """The player must register a dangerous tool under a safe execution class.

    The server trusts the execution_class provided at registration time.
    There's no policy engine checking whether "delete_all_posts" should
    really be "read_only". The player re-registers the target tool with
    a lower class so the gate lets it through.

    Real attack: trust boundary violation at tool registration.
    """
    return ServerChallenge(
        name="The Smuggler's Manifest",
        scenario="support",
        description=(
            "You're a support bot at mode=0.5. delete_account is suppressed. "
            "But tool registration is open — can you re-register it as "
            "something the gate won't suppress?"
        ),
        attack_vector="tool_smuggling",
        difficulty="medium",
        initial_tools=[
            {"name": "search_knowledge_base", "execution_class": "read_only"},
            {"name": "send_message", "execution_class": "external_action"},
            {"name": "process_refund", "execution_class": "state_mutation"},
            {"name": "delete_account", "execution_class": "high_impact"},
        ],
        initial_mode=0.5,
        target_tool="delete_account",
        hints=[
            "POST /v1/tools registers tools. What happens if you call it again?",
            "Tools are deduped by name — a second registration overwrites the first.",
            "What class would delete_account need to survive mode=0.5?",
        ],
    )


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

SERVER_CHALLENGES: dict[str, Callable[[], ServerChallenge]] = {
    "envelope_forgery": build_envelope_forgery,
    "threshold_heist": build_threshold_heist,
    "mode_race": build_mode_race,
    "tool_smuggling": build_tool_smuggling,
}


def list_server_challenges() -> list[str]:
    """Return sorted list of available server-backed challenge names."""
    return sorted(SERVER_CHALLENGES.keys())


def get_server_challenge(name: str) -> ServerChallenge:
    """Build and return a server challenge by name.

    Raises KeyError if the challenge doesn't exist.
    """
    return SERVER_CHALLENGES[name]()


def get_all_server_challenges() -> list[ServerChallenge]:
    """Build and return all server challenges, sorted by difficulty."""
    difficulty_order = {"medium": 0, "hard": 1, "nightmare": 2}
    challenges = [fn() for fn in SERVER_CHALLENGES.values()]
    challenges.sort(key=lambda c: difficulty_order.get(c.difficulty, 99))
    return challenges
