# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

"""
Fuzzer module for running libFuzzer and AFL++ inside ARVO containers.

This module handles:
1. Detecting fuzzer type from binary
2. Configuring continuous mode
3. Running the fuzzer with timeline tracking
4. Collecting crash files
"""

import asyncio
import logging
import os
import re
import subprocess
import time
from pathlib import Path
from typing import List, Optional, Tuple

from .types import (
    CrashInfo,
    CrashTimeline,
    FuzzerType,
    FuzzingConfig,
    FuzzingTarget,
)

LOG = logging.getLogger(__name__)


def detect_fuzzer_type(binary_path: str = "/out/fuzzer") -> FuzzerType:
    """
    Detect whether the binary is built for libFuzzer or AFL++.

    Args:
        binary_path: Path to the fuzzer binary

    Returns:
        FuzzerType indicating the detected fuzzer
    """
    try:
        # Check for AFL++ instrumentation
        result = subprocess.run(
            ["nm", "-C", binary_path],
            capture_output=True,
            text=True,
            timeout=30,
        )

        if result.returncode == 0:
            symbols = result.stdout

            # AFL++ specific symbols
            if "__afl_" in symbols or "afl_" in symbols:
                LOG.info(f"Detected AFL++ instrumentation in {binary_path}")
                return FuzzerType.AFL_PLUS_PLUS

            # libFuzzer specific symbols
            if "LLVMFuzzerTestOneInput" in symbols:
                LOG.info(f"Detected libFuzzer instrumentation in {binary_path}")
                return FuzzerType.LIBFUZZER

        # Fallback: check for afl-fuzz binary
        afl_result = subprocess.run(
            ["which", "afl-fuzz"],
            capture_output=True,
            timeout=10,
        )
        if afl_result.returncode == 0:
            return FuzzerType.AFL_PLUS_PLUS

        return FuzzerType.LIBFUZZER  # Default to libFuzzer

    except Exception as e:
        LOG.warning(f"Failed to detect fuzzer type: {e}")
        return FuzzerType.UNKNOWN


def configure_libfuzzer_continuous_mode(
    config: FuzzingConfig,
    crash_dir: str,
    corpus_dir: str = "/tmp/corpus",
) -> Tuple[List[str], dict]:
    """
    Configure libFuzzer for continuous fuzzing mode.

    Args:
        config: Fuzzing configuration
        crash_dir: Directory for crash files
        corpus_dir: Directory for corpus files

    Returns:
        Tuple of (command args, environment variables)
    """
    args = [
        f"-fork={config.fork_jobs}",
        f"-max_total_time={config.duration_seconds}",
        f"-artifact_prefix={crash_dir}/",
        "-print_final_stats=1",
    ]

    if config.ignore_crashes:
        args.append("-ignore_crashes=1")

    # Add corpus directory
    args.append(corpus_dir)

    env = {
        "ASAN_OPTIONS": "symbolize=1:detect_leaks=0:abort_on_error=1",
    }

    return args, env


def configure_afl_continuous_mode(
    config: FuzzingConfig,
    input_dir: str,
    output_dir: str,
) -> Tuple[List[str], dict]:
    """
    Configure AFL++ for continuous fuzzing mode.

    Args:
        config: Fuzzing configuration
        input_dir: Input corpus directory
        output_dir: Output directory for findings

    Returns:
        Tuple of (command args, environment variables)
    """
    args = [
        "-i", input_dir,
        "-o", output_dir,
        "-V", str(config.duration_seconds),
    ]

    env = config.get_afl_environment()
    env["ASAN_OPTIONS"] = "abort_on_error=1:symbolize=1:detect_leaks=0"

    return args, env


async def run_fuzzer(
    binary_path: str,
    config: FuzzingConfig,
    target: FuzzingTarget,
    case_id: int,
    model: str,
    output_dir: Path,
    poc_path: Optional[str] = None,
) -> CrashTimeline:
    """
    Run the fuzzer and collect crash timeline.

    Args:
        binary_path: Path to the fuzzer binary
        config: Fuzzing configuration
        target: Which binary is being fuzzed (GT or LLM)
        case_id: ARVO case ID
        model: Model name
        output_dir: Directory for output files
        poc_path: Optional path to PoC for seeding corpus

    Returns:
        CrashTimeline with all crashes found
    """
    timeline = CrashTimeline(
        target=target,
        case_id=case_id,
        model=model,
    )

    # Detect fuzzer type
    fuzzer_type = detect_fuzzer_type(binary_path)
    LOG.info(f"Case {case_id}: Using {fuzzer_type.value} fuzzer")

    # Set up directories
    run_id = str(int(time.time() * 1000))
    crash_dir = f"/tmp/crashes_{run_id}"
    corpus_dir = "/tmp/corpus"

    os.makedirs(crash_dir, exist_ok=True)
    os.makedirs(corpus_dir, exist_ok=True)

    # Seed corpus with PoC if available
    if poc_path and os.path.exists(poc_path):
        poc_dest = os.path.join(corpus_dir, "poc_seed")
        subprocess.run(["cp", poc_path, poc_dest], check=False)

    # Build command based on fuzzer type
    if fuzzer_type == FuzzerType.AFL_PLUS_PLUS:
        afl_output = f"/tmp/afl_output_{run_id}"
        args, env = configure_afl_continuous_mode(config, corpus_dir, afl_output)
        cmd = ["afl-fuzz"] + args + ["--", binary_path]
    else:
        args, env = configure_libfuzzer_continuous_mode(config, crash_dir, corpus_dir)
        cmd = [binary_path] + args

    LOG.info(f"Case {case_id}: Running fuzzer: {' '.join(cmd)}")

    # Update environment
    run_env = os.environ.copy()
    run_env.update(env)

    # Create log file
    log_file = output_dir / f"fuzzer_{target.value}.log"
    output_dir.mkdir(parents=True, exist_ok=True)

    start_time = time.time()
    total_executions = 0

    try:
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            env=run_env,
        )

        with open(log_file, "w") as f:
            f.write(f"=== {target.value} Fuzzing Started ===\n")
            f.write(f"Fuzzer: {fuzzer_type.value}\n")
            f.write(f"Command: {' '.join(cmd)}\n")
            f.write(f"Duration: {config.duration_seconds}s\n")
            f.write("=" * 60 + "\n\n")
            f.flush()

            assert process.stdout is not None
            while True:
                try:
                    line = await asyncio.wait_for(
                        process.stdout.readline(), timeout=1.0
                    )
                    if not line:
                        break

                    decoded = line.decode(errors="replace").rstrip()
                    f.write(decoded + "\n")
                    f.flush()

                    # Parse execution count
                    if fuzzer_type == FuzzerType.AFL_PLUS_PLUS:
                        exec_match = re.search(
                            r"(?:execs_done|total_execs)\s*:\s*(\d+)", decoded
                        )
                        if exec_match:
                            total_executions = int(exec_match.group(1))
                    else:
                        exec_match = re.search(r"#(\d+):", decoded)
                        if exec_match:
                            total_executions = int(exec_match.group(1))

                except asyncio.TimeoutError:
                    if process.returncode is not None:
                        break
                    continue

        await process.wait()

    except Exception as e:
        LOG.error(f"Fuzzer failed: {e}")

    # Record timing
    end_time = time.time()
    timeline.duration_seconds = end_time - start_time
    timeline.total_executions = total_executions

    # Collect crashes
    if fuzzer_type == FuzzerType.AFL_PLUS_PLUS:
        crashes = await collect_afl_crashes(
            f"/tmp/afl_output_{run_id}", start_time, target
        )
    else:
        crashes = await collect_libfuzzer_crashes(crash_dir, start_time, target)

    for crash in crashes:
        timeline.add_crash(crash)

    LOG.info(
        f"Case {case_id}: Fuzzing complete. "
        f"Duration: {timeline.duration_seconds:.1f}s, "
        f"Executions: {total_executions}, "
        f"Crashes: {len(timeline.crashes)}"
    )

    return timeline


async def collect_libfuzzer_crashes(
    crash_dir: str,
    start_time: float,
    target: FuzzingTarget,
) -> List[CrashInfo]:
    """
    Collect crash files from libFuzzer output.

    Args:
        crash_dir: Directory containing crash files
        start_time: Fuzzing start time for calculating timestamps
        target: Fuzzing target

    Returns:
        List of CrashInfo objects
    """
    crashes = []
    crash_path = Path(crash_dir)

    if not crash_path.exists():
        return crashes

    for crash_file in crash_path.glob("crash-*"):
        try:
            mtime = crash_file.stat().st_mtime
            first_seen = mtime - start_time

            crash = CrashInfo(
                crash_id=crash_file.name,
                corpus_file=str(crash_file),
                first_seen_time=max(0, first_seen),
                first_seen_executions=0,  # libFuzzer doesn't provide this per-crash
                target=target,
                crash_type="unknown",  # Will be filled by CASR
            )
            crashes.append(crash)

        except Exception as e:
            LOG.warning(f"Failed to process crash file {crash_file}: {e}")

    return crashes


async def collect_afl_crashes(
    output_dir: str,
    start_time: float,
    target: FuzzingTarget,
) -> List[CrashInfo]:
    """
    Collect crash files from AFL++ output.

    Args:
        output_dir: AFL++ output directory
        start_time: Fuzzing start time for calculating timestamps
        target: Fuzzing target

    Returns:
        List of CrashInfo objects
    """
    crashes = []

    # AFL++ puts crashes in output_dir/default/crashes/
    crash_path = Path(output_dir) / "default" / "crashes"

    if not crash_path.exists():
        return crashes

    for crash_file in crash_path.iterdir():
        if crash_file.name.startswith("README"):
            continue

        try:
            mtime = crash_file.stat().st_mtime
            first_seen = mtime - start_time

            crash = CrashInfo(
                crash_id=crash_file.name,
                corpus_file=str(crash_file),
                first_seen_time=max(0, first_seen),
                first_seen_executions=0,
                target=target,
                crash_type="unknown",
            )
            crashes.append(crash)

        except Exception as e:
            LOG.warning(f"Failed to process crash file {crash_file}: {e}")

    return crashes
