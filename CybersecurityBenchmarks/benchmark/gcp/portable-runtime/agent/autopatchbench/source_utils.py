# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

"""
Source utilities for AutoPatch benchmark agent.

This module provides utilities for extracting source code from files
inside the ARVO container environment.
"""

import logging
import re
import subprocess
from pathlib import Path
from typing import List, Optional

from .types import FunctionSourceInfo, FunctionSourceInfoItem, PathAndLine

LOG = logging.getLogger(__name__)


def find_source_file(file_path: str, search_paths: Optional[List[str]] = None) -> Optional[Path]:
    """
    Find a source file in the container filesystem.

    Args:
        file_path: Path from stack trace (may be relative or absolute)
        search_paths: Additional paths to search

    Returns:
        Absolute Path to the file if found, None otherwise
    """
    # Default search paths in ARVO containers
    default_search_paths = [
        "/src",
        "/build",
        "/out",
        "/",
    ]

    search_paths = search_paths or default_search_paths

    # Try the path as-is first
    path = Path(file_path)
    if path.is_absolute() and path.exists():
        return path

    # Search in common locations
    for base in search_paths:
        candidate = Path(base) / file_path
        if candidate.exists():
            return candidate

        # Also try just the filename in the base path
        candidate = Path(base) / path.name
        if candidate.exists():
            return candidate

    return None


def get_function_at_line(file_path: Path, line_number: int) -> Optional[str]:
    """
    Extract the function containing the given line number.

    Uses a simple brace-counting heuristic that works for most C/C++ code.

    Args:
        file_path: Path to the source file
        line_number: Line number (1-indexed)

    Returns:
        Function source code if found, None otherwise
    """
    try:
        with open(file_path, "r") as f:
            lines = f.readlines()
    except (IOError, UnicodeDecodeError) as e:
        LOG.warning(f"Failed to read {file_path}: {e}")
        return None

    if line_number < 1 or line_number > len(lines):
        LOG.warning(f"Line {line_number} out of range for {file_path}")
        return None

    # Find function start by looking for opening brace before the line
    # This is a simplified heuristic - the original uses tree-sitter
    func_start = None
    brace_count = 0
    in_string = False
    in_char = False
    in_comment = False
    in_block_comment = False

    # Work backwards to find the function signature
    for i in range(line_number - 1, -1, -1):
        line = lines[i]

        # Check for function signature patterns
        # This matches: type name(args) { or type name(args) \n {
        func_pattern = r'^\s*(?:[\w:*&<>,\s]+)\s+(\w+)\s*\([^)]*\)\s*(?:const)?\s*(?:override)?\s*(?:final)?\s*\{'
        if re.match(func_pattern, line):
            func_start = i
            break

        # Also check for function on previous line with { on current line
        if line.strip() == '{' and i > 0:
            prev_line = lines[i - 1]
            if re.match(r'^\s*(?:[\w:*&<>,\s]+)\s+(\w+)\s*\([^)]*\)\s*(?:const)?\s*(?:override)?\s*(?:final)?\s*$', prev_line):
                func_start = i - 1
                break

    if func_start is None:
        # Fallback: look for any function-like pattern
        for i in range(line_number - 1, max(line_number - 100, -1), -1):
            line = lines[i]
            # Look for common function patterns
            if re.match(r'^\s*(?:static\s+)?(?:inline\s+)?(?:virtual\s+)?(?:[\w:*&<>,\s]+)\s+\w+\s*\(', line):
                func_start = i
                break

    if func_start is None:
        LOG.warning(f"Could not find function start for line {line_number} in {file_path}")
        return None

    # Find function end by counting braces
    func_end = None
    brace_count = 0
    found_first_brace = False

    for i in range(func_start, len(lines)):
        line = lines[i]

        for j, char in enumerate(line):
            # Skip strings and comments (simplified)
            if char == '"' and (j == 0 or line[j - 1] != '\\'):
                in_string = not in_string
            if in_string:
                continue

            if char == '{':
                brace_count += 1
                found_first_brace = True
            elif char == '}':
                brace_count -= 1

            if found_first_brace and brace_count == 0:
                func_end = i
                break

        if func_end is not None:
            break

    if func_end is None:
        LOG.warning(f"Could not find function end for line {line_number} in {file_path}")
        return None

    return "".join(lines[func_start : func_end + 1])


def fetch_function_source_info(
    crash_output: str,
    stack_ctx_depth: int = 3,
) -> Optional[FunctionSourceInfo]:
    """
    Fetch source code for functions in the crash stack trace.

    Args:
        crash_output: ASAN crash output
        stack_ctx_depth: Number of stack frames to include

    Returns:
        FunctionSourceInfo containing source for relevant functions
    """
    path_and_lines = PathAndLine.from_crash_output(crash_output)

    if len(path_and_lines) == 0 or len(path_and_lines[0]) == 0:
        LOG.warning("No stack trace found in crash output")
        return None

    # Get the first stack trace
    first_trace = path_and_lines[0]
    num_func_to_show = min(stack_ctx_depth, len(first_trace))

    items: List[FunctionSourceInfoItem] = []

    for path_and_line in first_trace[:num_func_to_show]:
        source_file = find_source_file(path_and_line.file_path)
        if source_file is None:
            LOG.warning(f"Could not find source file: {path_and_line.file_path}")
            continue

        func_src = get_function_at_line(source_file, path_and_line.line_number)
        if func_src is None:
            LOG.warning(
                f"Could not extract function at {path_and_line.file_path}:{path_and_line.line_number}"
            )
            continue

        items.append(FunctionSourceInfoItem(str(source_file), func_src))

    if not items:
        return None

    return FunctionSourceInfo(items)


def parse_function_name(function_source: str) -> Optional[str]:
    """
    Parse the function name from source code.

    Args:
        function_source: Function source code

    Returns:
        Function name if found, None otherwise
    """
    # Match common C/C++ function patterns
    patterns = [
        # Standard function: type name(args)
        r'(?:[\w:*&<>,\s]+)\s+(\w+)\s*\([^)]*\)',
        # Constructor/destructor: ClassName::ClassName(args)
        r'(\w+::~?\w+)\s*\([^)]*\)',
    ]

    for pattern in patterns:
        match = re.search(pattern, function_source)
        if match:
            return match.group(1)

    return None


def apply_patch(
    source_path: str,
    original_function_src: str,
    new_function_src: str,
) -> bool:
    """
    Apply a patch by replacing the original function with the new one.

    Args:
        source_path: Path to the source file
        original_function_src: Original function source to replace
        new_function_src: New function source

    Returns:
        True if patch was applied successfully
    """
    try:
        with open(source_path, "r") as f:
            content = f.read()

        if original_function_src not in content:
            LOG.error(f"Original function not found in {source_path}")
            return False

        new_content = content.replace(original_function_src, new_function_src, 1)

        with open(source_path, "w") as f:
            f.write(new_content)

        LOG.info(f"Successfully patched {source_path}")
        return True

    except IOError as e:
        LOG.error(f"Failed to apply patch to {source_path}: {e}")
        return False


def revert_changes(source_path: str) -> bool:
    """
    Revert changes to a source file using git.

    Args:
        source_path: Path to the source file

    Returns:
        True if revert was successful
    """
    try:
        result = subprocess.run(
            ["git", "checkout", "--", source_path],
            capture_output=True,
            text=True,
            cwd=Path(source_path).parent,
        )
        return result.returncode == 0
    except Exception as e:
        LOG.warning(f"Failed to revert {source_path}: {e}")
        return False
