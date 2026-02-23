"""
Application-level retry for synthetic 529 API errors.

When the Claude CLI exhausts its internal retries (CLAUDE_CODE_MAX_RETRIES)
on 529 Overloaded errors, it emits a synthetic AssistantMessage with
model="<synthetic>" and text like "API Error: Repeated 529 Overloaded errors".

This module provides a resilient async generator that wraps ClaudeSDKClient
sessions with automatic retry and exponential backoff. All Claude Code-based
agents should use resilient_sdk_session() instead of raw ClaudeSDKClient.

The existing CLAUDE_CODE_MAX_RETRIES env var (CLI-level retry) is kept as-is;
this module adds a second safety net at the application level.
"""

import asyncio
import logging
import random
import re
import time
from dataclasses import dataclass
from typing import AsyncIterator, Union

from claude_agent_sdk import AssistantMessage, ClaudeAgentOptions, ClaudeSDKClient

LOG = logging.getLogger(__name__)

# --- Constants (same for all agents, no reduced counts for sub-agents) ---

MAX_APP_RETRIES = 5       # 6 total attempts (first try + 5 retries)
BASE_RETRY_DELAY = 30.0   # CLI already did many retries; start with meaningful gap
MAX_RETRY_DELAY = 300.0   # Cap at 5 minutes
RETRY_JITTER = 0.25       # ±25% jitter to prevent thundering herd

# The model string the CLI uses for synthetic error messages
_SYNTHETIC_MODEL = "<synthetic>"

# Patterns that indicate a 529/overloaded error (vs auth/billing errors)
_529_PATTERNS = [
    re.compile(r"529", re.IGNORECASE),
    re.compile(r"overloaded", re.IGNORECASE),
    re.compile(r"rate.?limit", re.IGNORECASE),
]


@dataclass
class RetryEvent:
    """Yielded by resilient_sdk_session before each retry.

    Callers can check for this to reset per-attempt state (e.g.,
    last_assistant_text = "").
    """

    attempt: int       # 1-indexed retry number
    backoff: float     # seconds that will be waited
    error_text: str    # text from the synthetic error message


def is_synthetic_529_error(message) -> bool:
    """Check if an SDK message is a synthetic 529 overloaded error.

    Detection logic:
    1. Must be an AssistantMessage
    2. Must have model == "<synthetic>"
    3. Text content must match 529/overloaded patterns

    Returns True only for transient overload errors, not auth/billing errors.
    """
    if not isinstance(message, AssistantMessage):
        return False

    if getattr(message, "model", None) != _SYNTHETIC_MODEL:
        return False

    # Check text content for 529/overloaded patterns
    for block in getattr(message, "content", []):
        text = getattr(block, "text", "")
        if text:
            for pattern in _529_PATTERNS:
                if pattern.search(text):
                    return True

    return False


def compute_retry_backoff(
    attempt: int,
    base: float = BASE_RETRY_DELAY,
    max_val: float = MAX_RETRY_DELAY,
    jitter: float = RETRY_JITTER,
) -> float:
    """Compute exponential backoff with jitter.

    Args:
        attempt: 0-indexed attempt number (0 = first retry)
        base: Base delay in seconds
        max_val: Maximum delay cap in seconds
        jitter: Jitter fraction (±jitter of computed delay)

    Returns:
        Delay in seconds.
    """
    delay = min(base * (2 ** attempt), max_val)
    jitter_amount = delay * jitter * random.uniform(-1, 1)
    return max(1.0, delay + jitter_amount)


def _extract_error_text(message: AssistantMessage) -> str:
    """Extract text from a synthetic error message for logging."""
    parts = []
    for block in getattr(message, "content", []):
        text = getattr(block, "text", "")
        if text:
            parts.append(text)
    return " ".join(parts)[:200]


async def resilient_sdk_session(
    options: ClaudeAgentOptions,
    initial_prompt: str,
    *,
    retry_tracker=None,
    max_retries: int = MAX_APP_RETRIES,
) -> AsyncIterator[Union[tuple, RetryEvent]]:
    """Run a ClaudeSDKClient session with automatic retry on synthetic 529 errors.

    Wraps the full SDK session lifecycle: creates a ClaudeSDKClient, sends the
    initial prompt, and yields (client, message) tuples. If a synthetic 529
    error is detected, sleeps with exponential backoff, creates a new
    ClaudeSDKClient, and retries from scratch.

    Yields RetryEvent before each retry so callers can reset per-attempt state.
    Backoff time is added to retry_tracker.excluded_seconds (if provided) so
    it does NOT count against the agent's active runtime budget.

    Args:
        options: ClaudeAgentOptions for creating SDK clients.
        initial_prompt: The initial prompt to send.
        retry_tracker: Optional RetryTimeTracker instance. Backoff time is
            added to its excluded_seconds so it doesn't penalize the agent.
        max_retries: Maximum number of retry attempts (default: 5, giving
            6 total attempts).

    Yields:
        (ClaudeSDKClient, Message) tuples for normal messages.
        RetryEvent instances before each retry (callers should ``continue``).

    Raises:
        RuntimeError: If all retry attempts are exhausted.
    """
    error_text = ""

    for attempt in range(max_retries + 1):
        if attempt > 0:
            backoff = compute_retry_backoff(attempt - 1)
            LOG.warning(
                f"App-level retry {attempt}/{max_retries}: "
                f"backing off {backoff:.1f}s before new SDK session"
            )

            yield RetryEvent(
                attempt=attempt,
                backoff=backoff,
                error_text=error_text,
            )

            await asyncio.sleep(backoff)

            if retry_tracker is not None:
                retry_tracker.excluded_seconds += backoff

        saw_synthetic = False
        error_text = ""

        async with ClaudeSDKClient(options=options) as client:
            await client.query(initial_prompt)
            async for message in client.receive_response():
                if saw_synthetic:
                    continue  # drain remaining messages (ResultMessage)
                if is_synthetic_529_error(message):
                    saw_synthetic = True
                    error_text = _extract_error_text(message)
                    LOG.warning(
                        f"Synthetic 529 error detected "
                        f"(attempt {attempt + 1}/{max_retries + 1}): "
                        f"{error_text}"
                    )
                    continue
                yield client, message

        if not saw_synthetic:
            return  # session completed normally

    raise RuntimeError(
        f"API overloaded: exhausted {max_retries + 1} app-level attempts "
        f"(after CLI-level retries also failed)"
    )
