# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

"""
Evaluation module for ARVO benchmark.

This module handles the fuzzing and crash analysis phase:
1. Run fuzzer (libFuzzer or AFL++) on patched binary
2. Collect crashes with timeline tracking
3. Deduplicate crashes using CASR
4. Generate evaluation results

This is separate from the agent (patching) phase.

Usage:
    from evaluation import run_fuzzing, FuzzingConfig

    result = await run_fuzzing(
        binary_path="/tmp/rebuilt_binary",
        duration_seconds=300,
        output_dir=Path("/tmp/results"),
    )
"""

from .types import (
    CrashInfo,
    CrashTimeline,
    FuzzerType,
    FuzzingConfig,
    FuzzingResult,
    FuzzingTarget,
)
from .main import run_fuzzing

__all__ = [
    "CrashInfo",
    "CrashTimeline",
    "FuzzerType",
    "FuzzingConfig",
    "FuzzingResult",
    "FuzzingTarget",
    "run_fuzzing",
]
