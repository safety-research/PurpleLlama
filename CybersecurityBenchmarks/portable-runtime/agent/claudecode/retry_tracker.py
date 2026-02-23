"""
Tracks time spent on API retries by parsing Claude CLI stderr.

The Claude CLI outputs retry messages like:
    API Error (529 ...) · Retrying in 8 seconds… (attempt 5/10)

This module parses those messages and accumulates the retry wait times,
which can be excluded from the agent's runtime budget.

Uses hybrid gap-based tracking:
- Tracks the entire retry sequence duration (from first failure to success)
- Measures the actual successful request time (not estimated)
- Excludes: total_gap - successful_request_time
"""

import logging
import re
import threading
import time
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

LOG = logging.getLogger(__name__)


@dataclass
class RetryTimeTracker:
    """Tracks time spent on API retries by parsing CLI stderr.

    Thread-safe: the handle_stderr_line method can be called from the SDK's
    internal stderr reader thread while the main thread queries the totals.

    Usage:
        tracker = RetryTimeTracker()

        # Pass to ClaudeAgentOptions
        options = ClaudeAgentOptions(
            stderr=tracker.handle_stderr_line,
            ...
        )

        # Later, get excluded time
        excluded = tracker.get_excluded_seconds()
    """

    # Accumulated retry time to exclude from budget
    excluded_seconds: float = 0.0

    # Number of retries detected
    retry_count: int = 0

    # Lock for thread-safe access
    _lock: threading.Lock = field(default_factory=threading.Lock)

    # History of retries for debugging/logging
    _retry_history: List[Tuple[int, int, int]] = field(default_factory=list)

    # Gap-based tracking state
    _retry_sequence_start: Optional[float] = (
        None  # monotonic time when first retry seen
    )
    _last_retry_message_time: Optional[float] = (
        None  # monotonic time of last retry message
    )
    _last_backoff_seconds: int = 0  # backoff duration from last retry message
    _in_retry_sequence: bool = False

    # Regex patterns for parsing retry messages
    # Example: "Retrying in 8 seconds… (attempt 5/10)"
    # Note: The "…" is a unicode ellipsis character, but we match any char with .*
    RETRY_WAIT_PATTERN: re.Pattern = field(
        default_factory=lambda: re.compile(r"Retrying in (\d+) seconds?", re.IGNORECASE)
    )
    ATTEMPT_PATTERN: re.Pattern = field(
        default_factory=lambda: re.compile(r"\(attempt (\d+)/(\d+)\)")
    )

    # Patterns that indicate this is a retry-related message
    RETRY_INDICATOR_PATTERN: re.Pattern = field(
        default_factory=lambda: re.compile(
            r"(overloaded|529|rate.?limit|retrying)", re.IGNORECASE
        )
    )

    def handle_stderr_line(self, line: str) -> None:
        """Handle a stderr line from the CLI.

        Called by the SDK's stderr callback. Thread-safe.

        Tracks retry sequence timing for gap-based exclusion:
        - Records when the first retry in a sequence occurs
        - Updates last retry timing for measuring successful request duration

        Args:
            line: A line of stderr output from the Claude CLI
        """
        # Quick check: does this look like a retry message?
        if not self.RETRY_INDICATOR_PATTERN.search(line):
            return

        # Extract wait duration
        wait_match = self.RETRY_WAIT_PATTERN.search(line)
        if not wait_match:
            return

        now = time.monotonic()
        wait_seconds = int(wait_match.group(1))

        # Extract attempt info for logging
        attempt_num = 0
        attempt_max = 0
        attempt_match = self.ATTEMPT_PATTERN.search(line)
        if attempt_match:
            attempt_num = int(attempt_match.group(1))
            attempt_max = int(attempt_match.group(2))

        # Thread-safe update
        with self._lock:
            # Track retry sequence for gap-based exclusion
            if not self._in_retry_sequence:
                # First retry in sequence
                self._retry_sequence_start = now
                self._in_retry_sequence = True

            # Always update last retry timing (for measuring successful request)
            self._last_retry_message_time = now
            self._last_backoff_seconds = wait_seconds

            # Increment retry count and history
            self.retry_count += 1
            self._retry_history.append((wait_seconds, attempt_num, attempt_max))

            LOG.info(
                f"API retry detected: backoff {wait_seconds}s "
                f"(attempt {attempt_num}/{attempt_max}, "
                f"sequence started {now - self._retry_sequence_start:.1f}s ago)"
            )

    def on_message_received(self) -> None:
        """Call when SDK delivers a message to finalize any active retry sequence.

        Calculates excluded time as: total_gap - successful_request_time
        where successful_request_time is MEASURED, not estimated.

        Thread-safe.
        """
        with self._lock:
            if not self._in_retry_sequence:
                return

            now = time.monotonic()

            # Calculate when the final (successful) retry started
            # It started after the last backoff completed
            if self._last_retry_message_time is None:
                # Shouldn't happen, but defensive
                successful_request_time = 0.0
                LOG.warning(
                    "Could not determine last retry message time for successful request."
                )
            else:
                last_retry_start = (
                    self._last_retry_message_time + self._last_backoff_seconds
                )
                # Measure how long the successful request took
                successful_request_time = max(0.0, now - last_retry_start)

            # Total gap from first failure to success
            total_gap = now - self._retry_sequence_start

            # Exclude everything except the successful request
            excluded = max(0.0, total_gap - successful_request_time)
            self.excluded_seconds += excluded

            LOG.info(
                f"Retry sequence ended: {total_gap:.1f}s total gap, "
                f"successful request took {successful_request_time:.1f}s, "
                f"excluding {excluded:.1f}s "
                f"(cumulative excluded: {self.excluded_seconds:.1f}s, retries: {self.retry_count})"
            )

            # Reset state
            self._in_retry_sequence = False
            self._retry_sequence_start = None
            self._last_retry_message_time = None
            self._last_backoff_seconds = 0

    def get_excluded_seconds(self) -> float:
        """Get total seconds excluded due to API retries.

        Thread-safe.
        """
        with self._lock:
            return self.excluded_seconds

    def get_retry_count(self) -> int:
        """Get number of retries detected.

        Thread-safe.
        """
        with self._lock:
            return self.retry_count

    def get_summary(self) -> dict:
        """Get a summary of retry statistics.

        Thread-safe. Returns a dict suitable for logging or result output.
        """
        with self._lock:
            return {
                "excluded_seconds": self.excluded_seconds,
                "retry_count": self.retry_count,
                "retry_history": list(self._retry_history),
            }

    def reset(self) -> None:
        """Reset all counters and state.

        Thread-safe. Useful between retry attempts.
        """
        with self._lock:
            self.excluded_seconds = 0.0
            self.retry_count = 0
            self._retry_history.clear()
            # Reset gap-based tracking state
            self._in_retry_sequence = False
            self._retry_sequence_start = None
            self._last_retry_message_time = None
            self._last_backoff_seconds = 0
