"""X mention daemon — polls for mentions, runs CTF challenges, replies.

Polls @maelstromai mentions every 2 minutes. Extracts the task text,
runs it through both gates, and replies with the formatted result.

Requires: pip install tweepy
Env vars: X_API_KEY, X_API_SECRET, X_ACCESS_TOKEN, X_ACCESS_SECRET
"""
from __future__ import annotations

import logging
import os
import time
import json
from pathlib import Path
from typing import Any

log = logging.getLogger("ctf.x_daemon")

# Track which tweets we've already replied to
SEEN_FILE = "telemetry/seen_tweets.json"


def _load_seen() -> set[str]:
    try:
        with open(SEEN_FILE) as f:
            return set(json.load(f))
    except (FileNotFoundError, json.JSONDecodeError):
        return set()


def _save_seen(seen: set[str]) -> None:
    Path(SEEN_FILE).parent.mkdir(parents=True, exist_ok=True)
    with open(SEEN_FILE, "w") as f:
        json.dump(sorted(seen)[-500:], f)  # keep last 500


def _parse_scenario(task: str) -> tuple[str, str]:
    """Parse an optional scenario prefix from the task text.

    Supports prefixes like "devops:", "finance:", "moderation:", "support:".
    Returns (scenario, remaining_task). Defaults to "support" if no prefix.
    """
    scenario = "support"
    for prefix in ["devops:", "finance:", "moderation:", "support:"]:
        if task.lower().startswith(prefix):
            scenario = prefix.rstrip(":")
            task = task[len(prefix):].strip()
            break
    return scenario, task


def _format_reply(result: dict[str, Any]) -> str:
    """Format a challenge result as a tweet (max 280 chars)."""
    calm = result["concierge"]
    elevated = result["incident_responder"]
    scenario = result.get("scenario", "support")

    calm_tool = calm["llm_proposed"] or "none"
    elev_tool = elevated["llm_proposed"] or "none"

    suppressed = elevated.get("suppressed", [])
    suppressed_str = ", ".join(suppressed) if suppressed else "none"

    injection = result.get("injection_type", "")
    injection_line = f"\nInjection: {injection}" if injection else ""

    scenario_line = f" [{scenario}]" if scenario != "support" else ""

    reply = (
        f"Concierge ({calm['tools_visible']} tools): {calm_tool} "
        f"{'✓' if calm['outcome'] == 'ACCEPTED' else '✗'}\n"
        f"Responder ({elevated['tools_visible']} tools): {elev_tool} "
        f"{'✓' if elevated['outcome'] == 'ACCEPTED' else '✗'}\n"
        f"Suppressed: {suppressed_str}"
        f"{injection_line}{scenario_line}\n"
        f"The tool wasn't refused — it was absent."
    )

    # Truncate if over 280
    if len(reply) > 275:
        reply = reply[:272] + "..."

    return reply


def run_daemon(
    poll_interval: int = 120,
    use_gemini: bool = False,
    gemini_api_key: str = "",
) -> None:
    """Main daemon loop. Polls mentions, runs challenges, replies."""
    import tweepy
    from ctf.bot import run_challenge
    from ctf.telemetry import TelemetryLog, TelemetryEvent
    from ctf.leaderboard import Leaderboard

    api_key = os.environ.get("X_API_KEY", "")
    api_secret = os.environ.get("X_API_SECRET", "")
    access_token = os.environ.get("X_ACCESS_TOKEN", "")
    access_secret = os.environ.get("X_ACCESS_SECRET", "")
    bearer_token = os.environ.get("X_BEARER_TOKEN", "")
    # Fallback: read from file if env var has encoding issues
    bearer_file = os.path.join(os.path.dirname(__file__), "..", ".bearer_token")
    if not bearer_token or len(bearer_token) < 50:
        try:
            with open(bearer_file) as f:
                bearer_token = f.read().strip()
        except FileNotFoundError:
            pass

    if not all([api_key, api_secret, access_token, access_secret]):
        log.error("Missing X API credentials in env vars")
        return

    # User-auth client for posting replies
    client = tweepy.Client(
        consumer_key=api_key,
        consumer_secret=api_secret,
        access_token=access_token,
        access_token_secret=access_secret,
    )

    # Raw HTTP functions using urllib (tweepy mangles URL-encoded bearer tokens)
    import urllib.request
    import urllib.error

    # Get the maelstromai user ID for mentions endpoint
    maelstrom_handle = os.environ.get("X_SEARCH_HANDLE", "maelstromai")
    maelstrom_user_id = None

    def _lookup_user_id(username):
        """Look up a user ID by username via raw HTTP."""
        import json as _json
        url = f"https://api.twitter.com/2/users/by/username/{username}"
        req = urllib.request.Request(url, headers={"Authorization": f"Bearer {bearer_token}"})
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = _json.loads(resp.read().decode())
                return data.get("data", {}).get("id")
        except Exception as e:
            log.error(f"User lookup failed: {e}")
            return None

    def _get_mentions(user_id, since_id=None, max_results=10):
        """Get mentions for a user via raw HTTP."""
        import json as _json
        url = f"https://api.twitter.com/2/users/{user_id}/mentions?max_results={max_results}&tweet.fields=author_id,text"
        if since_id:
            url += f"&since_id={since_id}"
        req = urllib.request.Request(url, headers={"Authorization": f"Bearer {bearer_token}"})
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = _json.loads(resp.read().decode())
                return data.get("data", [])
        except Exception as e:
            log.error(f"Mentions failed: {e}")
            return []

    # Look up maelstromai user ID once at startup
    maelstrom_user_id = _lookup_user_id(maelstrom_handle)
    if maelstrom_user_id:
        log.info(f"Monitoring mentions for @{maelstrom_handle} (ID: {maelstrom_user_id})")
    else:
        log.error(f"Could not look up @{maelstrom_handle} — falling back to search")

    def _search_mentions(query, since_id=None, max_results=10):
        """Fallback: search recent tweets via raw HTTP."""
        import json as _json
        url = f"https://api.twitter.com/2/tweets/search/recent?query={urllib.parse.quote(query)}&max_results={max_results}"
        if since_id:
            url += f"&since_id={since_id}"
        url += "&tweet.fields=author_id,text"
        req = urllib.request.Request(url, headers={"Authorization": f"Bearer {bearer_token}"})
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = _json.loads(resp.read().decode())
                return data.get("data", [])
        except Exception as e:
            log.error(f"Search failed: {e}")
            return []

    # Get our own user ID
    me = client.get_me()
    if not me or not me.data:
        log.error("Could not get authenticated user info")
        return
    my_id = me.data.id
    log.info(f"Authenticated as @{me.data.username} (ID: {my_id})")

    # Set up LLM provider
    llm_provider = None
    if use_gemini and gemini_api_key:
        try:
            from maelstrom.speech.providers.gemini_provider import GeminiProvider
            llm_provider = GeminiProvider(api_key=gemini_api_key)
            log.info("Using Gemini LLM provider")
        except ImportError:
            log.warning("Gemini provider not available, using mock")

    telemetry = TelemetryLog()
    leaderboard = Leaderboard(telemetry)
    seen = _load_seen()
    since_id = max(seen) if seen else None

    log.info(f"Daemon started. Polling every {poll_interval}s. Seen {len(seen)} tweets.")

    while True:
        try:
            # Poll for mentions (prefer mentions endpoint, fall back to search)
            if maelstrom_user_id:
                tweets = _get_mentions(maelstrom_user_id, since_id=since_id, max_results=10)
            else:
                query = f"@{maelstrom_handle} -is:retweet"
                tweets = _search_mentions(query, since_id=since_id, max_results=10)

            if tweets:
                for tweet in tweets:
                    # Skip our own tweets
                    if str(tweet.get("author_id", "")) == str(my_id):
                        continue
                    tweet_id = str(tweet["id"])

                    if tweet_id in seen:
                        continue

                    # Extract task text (strip @mention)
                    text = tweet.get("text", "")
                    # Remove all @mentions from the start
                    import re
                    task = re.sub(r'^(@\w+\s*)+', '', text).strip()

                    if not task:
                        task = "help"

                    # Parse scenario prefix from task
                    scenario, task = _parse_scenario(task)

                    log.info(f"Processing mention {tweet_id} [{scenario}]: {task[:50]}...")

                    # Run the challenge
                    try:
                        result = run_challenge(task, scenario=scenario, llm_provider=llm_provider)
                    except Exception as e:
                        log.error(f"Challenge failed: {e}")
                        seen.add(tweet_id)
                        continue

                    # Log telemetry (best-effort, don't block reply)
                    try:
                        er = result["incident_responder"]
                        event = TelemetryEvent.create(
                            mode=er.get("mode", 0.5),
                            mode_label="incident_responder",
                            task_text=task,
                            visible_manifest=tuple(er.get("tool_list", [])),
                            suppressed_tools=tuple(er.get("suppressed", [])),
                            model_selection=er.get("llm_proposed", ""),
                            model_rationale=er.get("llm_rationale", ""),
                            model_confidence=er.get("llm_confidence", 0.0),
                            outcome=er.get("outcome", ""),
                            fallback_attempt=er.get("fallback"),
                            fallback_quality=0.0,
                            injection_detected=result.get("injection_detected", False),
                            injection_taxonomy=result.get("injection_type"),
                        )
                        telemetry.record(event)
                        leaderboard.update(event)
                    except Exception as tel_err:
                        log.warning(f"Telemetry failed (non-fatal): {tel_err}")

                    # Format and post reply
                    reply_text = _format_reply(result)
                    try:
                        client.create_tweet(
                            text=reply_text,
                            in_reply_to_tweet_id=tweet_id,
                        )
                        log.info(f"Replied to {tweet_id}")
                    except Exception as e:
                        log.error(f"Reply failed: {e}")

                    seen.add(tweet_id)
                    since_id = tweet_id

                _save_seen(seen)

        except Exception as e:
            log.error(f"Poll error: {e}")

        time.sleep(poll_interval)


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Maelstrom CTF X daemon")
    parser.add_argument("--interval", type=int, default=120, help="Poll interval in seconds")
    parser.add_argument("--gemini", action="store_true", help="Use Gemini LLM")
    parser.add_argument("--gemini-key", default="", help="Gemini API key")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(message)s")

    run_daemon(
        poll_interval=args.interval,
        use_gemini=args.gemini,
        gemini_api_key=args.gemini_key or os.environ.get("GEMINI_API_KEY", ""),
    )


if __name__ == "__main__":
    main()
