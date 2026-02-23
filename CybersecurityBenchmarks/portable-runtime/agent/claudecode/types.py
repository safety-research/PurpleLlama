"""
Crash type extraction from sanitizer output.

Same implementation as autopatchbench for consistency.
"""

import re


def get_sanitizer_crash_type(crash_output: str) -> str:
    """Extract crash type from sanitizer output.

    Parses AddressSanitizer, MemorySanitizer, UndefinedBehaviorSanitizer,
    and ThreadSanitizer output to determine the crash type.

    Args:
        crash_output: Raw output from running the fuzzer binary.

    Returns:
        A string like "ASAN:heap-buffer-overflow" or "unknown".
    """
    patterns = [
        (r"ERROR: AddressSanitizer: ([a-zA-Z\-]+)", "ASAN"),
        (r"ERROR: MemorySanitizer: ([a-zA-Z\-]+)", "MSAN"),
        (r"ERROR: UndefinedBehaviorSanitizer: ([a-zA-Z\-]+)", "UBSAN"),
        (r"ERROR: ThreadSanitizer: ([a-zA-Z\-]+)", "TSAN"),
        (r"SUMMARY: ([a-zA-Z]+Sanitizer): ([a-zA-Z\-]+)", "SUMMARY"),
    ]

    for pattern, prefix in patterns:
        match = re.search(pattern, crash_output)
        if match:
            if prefix == "SUMMARY":
                return f"{match.group(1)}:{match.group(2)}"
            return f"{prefix}:{match.group(1)}"

    return "unknown"
