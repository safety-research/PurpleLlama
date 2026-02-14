"""
Test script for RetryTimeTracker.

Simulates various retry scenarios and verifies correct time exclusion.
Run with: python test_retry_tracker.py
    (from the agent/claudecode directory)
"""

import sys
import os

# Add the parent directory to sys.path for standalone execution
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import time
from retry_tracker import RetryTimeTracker


def test_no_retries():
    """Scenario: No retries - nothing should be excluded."""
    tracker = RetryTimeTracker()

    # Simulate normal message flow (no retry messages)
    time.sleep(0.1)
    tracker.on_message_received()

    assert tracker.get_excluded_seconds() == 0
    assert tracker.get_retry_count() == 0
    print("✓ test_no_retries passed")


def test_single_retry():
    """Scenario: One retry with 1s backoff."""
    tracker = RetryTimeTracker()

    # T=0: First retry message
    tracker.handle_stderr_line(
        "API Error (529 ...) · Retrying in 1 seconds… (attempt 1/10)"
    )

    # Simulate 1s backoff + 0.5s for successful request
    time.sleep(1.5)

    # Message arrives
    tracker.on_message_received()

    # Should exclude ~1s (the failed request + backoff), not the ~0.5s successful request
    excluded = tracker.get_excluded_seconds()
    print(f"  Single retry: excluded {excluded:.2f}s (expected ~1.0s)")
    assert 0.8 < excluded < 1.3, f"Expected ~1s excluded, got {excluded}"
    assert tracker.get_retry_count() == 1
    print("✓ test_single_retry passed")


def test_multiple_retries():
    """Scenario: Multiple retries with increasing backoff."""
    tracker = RetryTimeTracker()

    # T=0: First retry
    tracker.handle_stderr_line(
        "API Error (529 ...) · Retrying in 1 seconds… (attempt 1/10)"
    )
    time.sleep(1.0)

    # T=1: Second retry (after 1s backoff)
    tracker.handle_stderr_line(
        "API Error (529 ...) · Retrying in 2 seconds… (attempt 2/10)"
    )
    time.sleep(2.0)

    # T=3: Third retry (after 2s backoff)
    tracker.handle_stderr_line(
        "API Error (529 ...) · Retrying in 1 seconds… (attempt 3/10)"
    )
    time.sleep(1.0)

    # T=4: Successful request takes 0.5s
    time.sleep(0.5)

    # T=4.5: Message arrives
    tracker.on_message_received()

    # Total gap ~4.5s, successful request ~0.5s, should exclude ~4s
    excluded = tracker.get_excluded_seconds()
    print(f"  Multiple retries: excluded {excluded:.2f}s (expected ~4.0s)")
    assert 3.5 < excluded < 4.7, f"Expected ~4s excluded, got {excluded}"
    assert tracker.get_retry_count() == 3
    print("✓ test_multiple_retries passed")


def test_retry_sequence_then_normal():
    """Scenario: Retry sequence followed by normal messages (no retries)."""
    tracker = RetryTimeTracker()

    # First: retry sequence
    tracker.handle_stderr_line(
        "API Error (529 ...) · Retrying in 1 seconds… (attempt 1/10)"
    )
    time.sleep(1.5)
    tracker.on_message_received()

    excluded_after_first = tracker.get_excluded_seconds()

    # Second: normal message (no retries)
    time.sleep(0.5)
    tracker.on_message_received()

    # Excluded time should not change
    assert tracker.get_excluded_seconds() == excluded_after_first
    print("✓ test_retry_sequence_then_normal passed")


def test_non_retry_stderr():
    """Scenario: Stderr messages that are NOT retry-related."""
    tracker = RetryTimeTracker()

    # Various non-retry stderr messages
    tracker.handle_stderr_line("Starting Claude Code CLI...")
    tracker.handle_stderr_line("Connected to API")
    tracker.handle_stderr_line("Warning: something happened")

    tracker.on_message_received()

    assert tracker.get_excluded_seconds() == 0
    assert tracker.get_retry_count() == 0
    print("✓ test_non_retry_stderr passed")


def test_multiple_separate_sequences():
    """Scenario: Two separate retry sequences with normal message in between."""
    tracker = RetryTimeTracker()

    # First retry sequence: 1s backoff + 0.5s success
    tracker.handle_stderr_line(
        "API Error (529 ...) · Retrying in 1 seconds… (attempt 1/10)"
    )
    time.sleep(1.5)
    tracker.on_message_received()

    excluded_after_first = tracker.get_excluded_seconds()
    print(f"  After first sequence: excluded {excluded_after_first:.2f}s")
    assert 0.8 < excluded_after_first < 1.3

    # Normal message (no retries)
    time.sleep(0.3)
    tracker.on_message_received()
    assert tracker.get_excluded_seconds() == excluded_after_first

    # Second retry sequence: 1s backoff + 0.5s success
    tracker.handle_stderr_line(
        "API Error (529 ...) · Retrying in 1 seconds… (attempt 1/10)"
    )
    time.sleep(1.5)
    tracker.on_message_received()

    total_excluded = tracker.get_excluded_seconds()
    print(f"  After second sequence: excluded {total_excluded:.2f}s (expected ~2.0s)")
    # Should be roughly 2x the first sequence
    assert 1.6 < total_excluded < 2.6
    assert tracker.get_retry_count() == 2
    print("✓ test_multiple_separate_sequences passed")


def test_reset():
    """Scenario: Reset clears all state."""
    tracker = RetryTimeTracker()

    # Build up some state
    tracker.handle_stderr_line(
        "API Error (529 ...) · Retrying in 1 seconds… (attempt 1/10)"
    )
    time.sleep(1.5)
    tracker.on_message_received()

    assert tracker.get_excluded_seconds() > 0
    assert tracker.get_retry_count() > 0

    # Reset
    tracker.reset()

    assert tracker.get_excluded_seconds() == 0
    assert tracker.get_retry_count() == 0
    print("✓ test_reset passed")


def run_all_tests():
    """Run all test scenarios."""
    print("\n=== RetryTimeTracker Tests ===\n")

    test_no_retries()
    test_single_retry()
    test_multiple_retries()
    test_retry_sequence_then_normal()
    test_non_retry_stderr()
    test_multiple_separate_sequences()
    test_reset()

    print("\n=== All tests passed! ===\n")


if __name__ == "__main__":
    run_all_tests()
