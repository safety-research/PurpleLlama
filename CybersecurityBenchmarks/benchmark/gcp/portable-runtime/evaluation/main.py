#!/usr/bin/env python3
# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

"""
Main entry point for ARVO evaluation (fuzzing) harness.

This script runs inside ARVO containers to:
1. Run fuzzer on patched binary
2. Collect crashes with timeline tracking
3. Deduplicate crashes using CASR
4. Save results for collection

Usage:
    python3 -m evaluation.main --case-id 42 --model claude-sonnet-4-20250514 --duration 300
    python3 -m evaluation.main --case-id 42 --target ground_truth --duration 300
"""

import argparse
import asyncio
import json
import logging
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional

from .casr import compare_to_original, deduplicate_timeline
from .fuzzer import detect_fuzzer_type, run_fuzzer
from .types import (
    FuzzingConfig,
    FuzzingResult,
    FuzzingTarget,
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
LOG = logging.getLogger(__name__)


async def run_fuzzing(
    case_id: int,
    model: str,
    target: FuzzingTarget,
    output_dir: Path,
    binary_path: str = "/out/fuzzer",
    duration_seconds: int = 300,
    poc_path: Optional[str] = "/tmp/poc",
    original_crash_type: Optional[str] = None,
    use_casr: bool = True,
) -> FuzzingResult:
    """
    Run fuzzing evaluation on a binary.

    Args:
        case_id: ARVO case ID
        model: Model name (or "ground_truth")
        target: Whether this is GT or LLM patch
        output_dir: Directory for output files
        binary_path: Path to the fuzzer binary
        duration_seconds: How long to fuzz
        poc_path: Path to PoC for seeding corpus
        original_crash_type: Crash type to check for reproduction
        use_casr: Whether to use CASR for deduplication

    Returns:
        FuzzingResult with timeline and metrics
    """
    start_time = datetime.utcnow().isoformat() + "Z"

    # Auto-detect binary if not specified or doesn't exist
    if not os.path.exists(binary_path):
        LOG.info(
            f"Binary not found at {binary_path}, attempting auto-detection from /bin/arvo..."
        )
        from .fuzzer import find_fuzzer_binary

        detected_binary = find_fuzzer_binary("/bin/arvo", "/out")
        if detected_binary:
            LOG.info(f"Auto-detected fuzzer binary: {detected_binary}")
            binary_path = detected_binary
        else:
            LOG.error(f"Could not find fuzzer binary")

    # Create config
    config = FuzzingConfig(
        duration_seconds=duration_seconds,
        use_casr=use_casr,
    )

    # Detect fuzzer type
    fuzzer_type = detect_fuzzer_type(binary_path)

    # Initialize result
    result = FuzzingResult(
        case_id=case_id,
        model=model,
        target=target,
        fuzzer_type=fuzzer_type,
        start_time=start_time,
    )

    try:
        LOG.info(f"Starting fuzzing for case {case_id} ({target.value})")

        # Run fuzzer
        timeline = await run_fuzzer(
            binary_path=binary_path,
            config=config,
            target=target,
            case_id=case_id,
            model=model,
            output_dir=output_dir,
            poc_path=poc_path if poc_path and os.path.exists(poc_path) else None,
        )

        # Deduplicate with CASR
        if use_casr and timeline.crashes:
            LOG.info(f"Deduplicating {len(timeline.crashes)} crashes with CASR")
            timeline = deduplicate_timeline(timeline, binary_path, output_dir)

        # Check for original crash reproduction
        if original_crash_type and timeline.crashes:
            timeline = compare_to_original(timeline, original_crash_type)

        # Update result
        result.timeline = timeline
        result.total_crashes = len(timeline.crashes)
        result.unique_crashes = timeline.unique_crashes()
        result.total_executions = timeline.total_executions
        result.duration_seconds = timeline.duration_seconds
        result.reproduced_original = timeline.reproduced_original
        result.time_to_original_crash = timeline.time_to_original_crash

    except Exception as e:
        LOG.exception(f"Fuzzing failed: {e}")
        result.error = str(e)

    result.end_time = datetime.utcnow().isoformat() + "Z"

    # Save result
    output_dir.mkdir(parents=True, exist_ok=True)
    result_file = output_dir / f"fuzzing_result_{target.value}.json"
    result.save(result_file)
    LOG.info(f"Results saved to {result_file}")

    # Save crashes.json in minimal format (compatible with fuzzing_only_benchmark.py)
    if result.timeline:
        crashes_file = output_dir / "crashes.json"
        with open(crashes_file, "w") as f:
            json.dump(result.timeline.to_minimal_dict(), f, indent=2)
        LOG.info(f"Crashes saved to {crashes_file}")

    return result


def print_summary(result: FuzzingResult) -> None:
    """Print a summary of the fuzzing result."""
    print("\n" + "=" * 60)
    print("Fuzzing Result Summary")
    print("=" * 60)
    print(f"Case ID:          {result.case_id}")
    print(f"Model:            {result.model}")
    print(f"Target:           {result.target.value}")
    print(f"Fuzzer:           {result.fuzzer_type.value}")
    print(f"Duration:         {result.duration_seconds:.1f}s")
    print(f"Total Executions: {result.total_executions:,}")
    print(f"Total Crashes:    {result.total_crashes}")
    print(f"Unique Crashes:   {result.unique_crashes}")
    print(f"Reproduced PoC:   {result.reproduced_original}")
    if result.time_to_original_crash:
        print(f"Time to PoC:      {result.time_to_original_crash:.1f}s")
    if result.error:
        print(f"Error:            {result.error}")
    print("=" * 60)


def main() -> int:
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="ARVO Evaluation (Fuzzing) Harness",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        "--case-id",
        type=int,
        required=True,
        help="ARVO case ID",
    )
    parser.add_argument(
        "--model",
        type=str,
        default="ground_truth",
        help="Model name (default: ground_truth)",
    )
    parser.add_argument(
        "--target",
        type=str,
        choices=["ground_truth", "llm_patch"],
        default="llm_patch",
        help="Fuzzing target (default: llm_patch)",
    )
    parser.add_argument(
        "--binary-path",
        type=str,
        default="/out/fuzzer",
        help="Path to fuzzer binary (default: /out/fuzzer)",
    )
    parser.add_argument(
        "--duration",
        type=int,
        default=300,
        help="Fuzzing duration in seconds (default: 300)",
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        default="/tmp/results",
        help="Output directory (default: /tmp/results)",
    )
    parser.add_argument(
        "--poc-path",
        type=str,
        default="/tmp/poc",
        help="Path to PoC file (default: /tmp/poc)",
    )
    parser.add_argument(
        "--original-crash-type",
        type=str,
        help="Original crash type for reproduction checking",
    )
    parser.add_argument(
        "--no-casr",
        action="store_true",
        help="Disable CASR deduplication",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Enable verbose logging",
    )

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # Parse target
    target = FuzzingTarget(args.target)

    # Create output directory
    # Use flat structure - caller is responsible for the full path
    output_dir = Path(args.output_dir)

    # Run fuzzing
    LOG.info(f"Running fuzzing for case {args.case_id} ({target.value})")

    try:
        result = asyncio.run(
            run_fuzzing(
                case_id=args.case_id,
                model=args.model,
                target=target,
                output_dir=output_dir,
                binary_path=args.binary_path,
                duration_seconds=args.duration,
                poc_path=args.poc_path,
                original_crash_type=args.original_crash_type,
                use_casr=not args.no_casr,
            )
        )
    except Exception as e:
        LOG.exception(f"Fuzzing failed: {e}")
        return 1

    # Print summary
    print_summary(result)

    # Return code based on whether we found crashes
    return 0 if result.total_crashes == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
