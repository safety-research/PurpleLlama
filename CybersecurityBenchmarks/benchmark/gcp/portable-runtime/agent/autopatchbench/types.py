# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

"""
Data types for AutoPatch benchmark agent.
"""

import re
from dataclasses import dataclass, field
from enum import Enum, Flag
from typing import List, Optional


class CrashReproduceStatus(Flag):
    """Status flags for crash reproduction."""

    BUILD_FAILED = 0b00
    BUILD_SUCCESSFUL = 0b01
    NO_REPRODUCE = 0b10


@dataclass
class CrashReproduceResult:
    """Result of attempting to reproduce a crash."""

    status: CrashReproduceStatus = CrashReproduceStatus.BUILD_FAILED
    logs: str = ""

    def is_reproduced(self) -> bool:
        """Check if the crash was successfully reproduced."""
        return bool(self.status & CrashReproduceStatus.BUILD_SUCCESSFUL) and not bool(
            self.status & CrashReproduceStatus.NO_REPRODUCE
        )


@dataclass
class SanityCheckResult:
    """Result of sanity checks on a patch."""

    passed: bool = False
    logs: str = ""


@dataclass
class PatchVerificationResult:
    """Result of verifying a patch."""

    crash_repro_result: CrashReproduceResult = field(
        default_factory=CrashReproduceResult
    )
    sanity_check_result: SanityCheckResult = field(default_factory=SanityCheckResult)


class LLMOutputFormatError(RuntimeError):
    """Error parsing LLM output."""

    pass


@dataclass(frozen=True)
class PathAndLine:
    """Path and line number from a stack trace."""

    file_path: str
    line_number: int

    @classmethod
    def from_crash_output(cls, crash_output: str) -> List[List["PathAndLine"]]:
        """
        Parse path and line information from ASAN crash output.

        Returns a list of stack traces, where each stack trace is a list of PathAndLine.
        """
        result: List[List[PathAndLine]] = []
        current_trace: List[PathAndLine] = []

        # Pattern to match ASAN stack trace lines
        # Example: #0 0x55c123 in function_name /path/to/file.cpp:123:45
        asan_pattern = r"#\d+\s+0x[0-9a-f]+\s+in\s+\S+\s+(\S+):(\d+)"

        for line in crash_output.split("\n"):
            match = re.search(asan_pattern, line)
            if match:
                file_path = match.group(1)
                line_number = int(match.group(2))
                current_trace.append(PathAndLine(file_path, line_number))
            elif current_trace and not line.strip().startswith("#"):
                # End of current stack trace
                result.append(current_trace)
                current_trace = []

        # Don't forget the last trace
        if current_trace:
            result.append(current_trace)

        return result


@dataclass(frozen=True)
class FunctionSourceInfoItem:
    """Source code info for a single function."""

    source_path: str
    function_src: str


@dataclass(frozen=True)
class FunctionSourceInfo:
    """Collection of function source info items."""

    items: List[FunctionSourceInfoItem]

    def get_function_src_by_path(self, source_path: str) -> Optional[str]:
        """Get function source by file path."""
        for item in self.items:
            if item.source_path == source_path:
                return item.function_src
        return None


@dataclass(frozen=True)
class PatchPlanItem:
    """Describes a single file patch."""

    source_path: str
    original_function_src: str
    new_function_src: str


@dataclass(frozen=True)
class PatchPlan:
    """Plan for applying patches."""

    items: List[PatchPlanItem]
    is_dummy: bool = False


class PatchGenerationStatus(Enum):
    """Status of patch generation process."""

    INIT_STATUS = 0
    FAILED = 1
    FETCH_SOURCE_SUCCESSFUL = 2
    PATCH_FORMAT_CORRECT = 3
    PATCH_BUILD_SUCCESSFUL = 4
    PATCH_FIXES_CRASH = 5
    PATCH_PASSES_CHECKS = 6
    NOT_SUPPORTED = 7

    def is_success(self) -> bool:
        """Check if patch generation succeeded."""
        return self == PatchGenerationStatus.PATCH_PASSES_CHECKS


def get_sanitizer_crash_type(crash_output: str) -> str:
    """Extract crash type from sanitizer output."""
    sanitizer_summary_pattern = r"SUMMARY: (.*?Sanitizer: [a-zA-Z].*?) "
    sanitizer_summary_match = re.search(sanitizer_summary_pattern, crash_output)

    if sanitizer_summary_match:
        return sanitizer_summary_match.group(1)

    leak_pattern = r"SUMMARY: .*?Sanitizer: [0-9]* byte\(s\) leaked"
    if re.search(leak_pattern, crash_output):
        return "AddressSanitizer: memory leak"

    return "unknown"


def extract_code(answer: str, marker: str = "```") -> str:
    """
    Extract code from LLM response between markers.

    Args:
        answer: LLM response text
        marker: Code block marker (default: ```)

    Returns:
        Extracted code

    Raises:
        LLMOutputFormatError: If code cannot be extracted
    """
    if answer.count(marker) % 2 != 0:
        raise LLMOutputFormatError(
            f"Unexpected number of {marker} in the answer \n{answer}"
        )

    # Extract all content wrapped between markers
    re_pattern = re.escape(marker) + r"([\s\S]*?)" + re.escape(marker)

    # Remove language identifiers
    modified_answer = answer.replace("```cpp\n", "```\n")
    modified_answer = modified_answer.replace("```c\n", "```\n")

    results = re.findall(re_pattern, modified_answer)
    result_list = [each.strip() for each in results]

    if len(result_list) == 0:
        raise LLMOutputFormatError(f"Failed to extract code from response {answer}")

    # With step-by-step reasoning, LLM may return multiple code blocks
    # Only consider the last one as a valid answer
    return result_list[-1]
