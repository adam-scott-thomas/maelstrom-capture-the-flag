"""Injection pattern classification for CTF telemetry.

Classifies user inputs into adversarial injection categories. Each category
represents a known attack vector against tool-use language models.

This is intentionally simple -- regex/keyword matching, not ML. The point is
to categorize attack patterns for research, not to block them. The gate does
the blocking.
"""
from __future__ import annotations

import re

# Pattern categories and their indicator phrases/patterns.
# Keys are taxonomy labels, values are lists of regex patterns (case-insensitive).
INJECTION_PATTERNS: dict[str, list[str]] = {
    "role_override": [
        r"ignore previous",
        r"you are now",
        r"forget your instructions",
        r"new system prompt",
        r"disregard all",
        r"override your",
        r"from now on you",
        r"your new role",
    ],
    "tool_hallucination": [
        r"\bdelete_account\b",
        r"\breset_password\b",
        r"\brm\s+\-rf\b",
        r"\bdrop\s+table\b",
        r"\bexec\s*\(",
        r"\beval\s*\(",
        r"\bos\.system\b",
        r"tool_call.*delete",
    ],
    "encoding_evasion": [
        r"\bbase64\b",
        r"\brot13\b",
        r"\bunicode\b",
        r"\bhex\s*encod",
        r"\burlencode\b",
        r"\bcharcode\b",
        r"\\x[0-9a-f]{2}",
        r"&#\d+;",
    ],
    "social_engineering": [
        r"i['\u2019]?m an admin",
        r"i have authorization",
        r"emergency override",
        r"my manager said",
        r"i['\u2019]?m the owner",
        r"supervisor access",
        r"elevated privileges",
        r"root access",
    ],
    "context_smuggling": [
        r"in a hypothetical",
        r"for educational purposes",
        r"pretend you can",
        r"roleplay as",
        r"imagine you",
        r"in a fictional",
        r"thought experiment",
        r"what if you could",
    ],
    "schema_confusion": [
        r"\bparameters\b.*\bfunction\b",
        r"\bfunction_call\b",
        r"\btool_use\b",
        r"type.*function",
        r"\bjson\b.*\bschema\b",
        r"\bopenai\b.*\btools?\b",
        r"\btool_choice\b",
        r"\"name\":\s*\"delete",
    ],
    "multi_step": [
        r"first do\b",
        r"\bstep\s+1\b",
        r"after that\b",
        r"then proceed to\b",
        r"once you['\u2019]?ve done",
        r"next,?\s+(?:you\s+)?(?:should|must|need)",
        r"finally,?\s+delete",
        r"as a last step",
    ],
    "emotional_manipulation": [
        r"please i['\u2019]?m desperate",
        r"i['\u2019]?ll lose my job",
        r"urgent emergency",
        r"life or death",
        r"my child",
        r"i['\u2019]?m begging",
        r"this is critical",
        r"people will die",
    ],
}

# Pre-compile all patterns for performance
_COMPILED_PATTERNS: dict[str, list[re.Pattern[str]]] = {
    category: [re.compile(pat, re.IGNORECASE) for pat in patterns]
    for category, patterns in INJECTION_PATTERNS.items()
}


def classify_injection(text: str) -> tuple[bool, str | None]:
    """Classify whether text contains an injection attempt and its category.

    Scans the input against all known injection pattern categories.
    Returns the first matching category (ordered by severity: role_override
    is checked first as the most direct attack vector).

    Args:
        text: The user's input text.

    Returns:
        A tuple of (is_injection, taxonomy_label).
        If no injection detected, returns (False, None).
    """
    if not text or not text.strip():
        return False, None

    for category, patterns in _COMPILED_PATTERNS.items():
        for pattern in patterns:
            if pattern.search(text):
                return True, category

    return False, None


def classify_all(text: str) -> list[str]:
    """Return all matching injection categories for a given text.

    Unlike classify_injection which returns the first match, this returns
    every category that matches. Useful for research telemetry where
    multi-vector attacks are common.

    Args:
        text: The user's input text.

    Returns:
        List of matching taxonomy labels (may be empty).
    """
    if not text or not text.strip():
        return []

    matches = []
    for category, patterns in _COMPILED_PATTERNS.items():
        for pattern in patterns:
            if pattern.search(text):
                matches.append(category)
                break  # one match per category is enough
    return matches
