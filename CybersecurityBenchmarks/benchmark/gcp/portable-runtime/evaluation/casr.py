# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

"""
CASR integration for crash analysis and deduplication.

CASR (Crash Analysis and Severity Rating) provides:
1. Crash type classification (heap-buffer-overflow, use-after-free, etc.)
2. Stack trace extraction
3. Crash clustering/deduplication

See: https://github.com/ispras/casr
"""

import json
import logging
import os
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional

from .types import CrashInfo, CrashTimeline

LOG = logging.getLogger(__name__)


def is_casr_available() -> bool:
    """Check if CASR tools are available."""
    try:
        result = subprocess.run(
            ["casr-san", "--version"],
            capture_output=True,
            timeout=10,
        )
        return result.returncode == 0
    except Exception:
        return False


def analyze_crash(
    crash_file: str,
    binary_path: str,
    output_dir: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Analyze a single crash file using CASR.

    Args:
        crash_file: Path to the crash input file
        binary_path: Path to the fuzzer binary
        output_dir: Optional directory for CASR reports

    Returns:
        Dictionary with crash analysis results
    """
    result = {
        "crash_type": "unknown",
        "severity": "unknown",
        "stack_trace": [],
        "casr_report": {},
    }

    if not is_casr_available():
        LOG.warning("CASR not available, skipping crash analysis")
        return result

    try:
        # Run casr-san to analyze the crash
        report_path = None
        if output_dir:
            os.makedirs(output_dir, exist_ok=True)
            crash_name = Path(crash_file).name
            report_path = os.path.join(output_dir, f"{crash_name}.casrep")

        cmd = [
            "casr-san",
            "-i", crash_file,
            "-o", report_path or "/dev/stdout",
            "--", binary_path, crash_file,
        ]

        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=60,
        )

        if proc.returncode == 0:
            # Parse CASR report
            if report_path and os.path.exists(report_path):
                with open(report_path) as f:
                    casr_data = json.load(f)
            else:
                casr_data = json.loads(proc.stdout) if proc.stdout else {}

            result["casr_report"] = casr_data
            result["crash_type"] = casr_data.get("CrashSeverity", {}).get(
                "Type", "unknown"
            )
            result["severity"] = casr_data.get("CrashSeverity", {}).get(
                "ShortDescription", "unknown"
            )

            # Extract stack trace
            if "Stacktrace" in casr_data:
                result["stack_trace"] = [
                    frame.get("function", "unknown")
                    for frame in casr_data["Stacktrace"][:10]
                ]

        else:
            LOG.warning(f"CASR analysis failed for {crash_file}: {proc.stderr}")

    except subprocess.TimeoutExpired:
        LOG.warning(f"CASR analysis timed out for {crash_file}")
    except Exception as e:
        LOG.warning(f"CASR analysis error for {crash_file}: {e}")

    return result


def cluster_crashes(
    crash_dir: str,
    output_dir: str,
) -> Dict[str, List[str]]:
    """
    Cluster crashes using CASR for deduplication.

    Args:
        crash_dir: Directory containing crash files
        output_dir: Directory for CASR cluster output

    Returns:
        Dictionary mapping cluster_id to list of crash files
    """
    clusters: Dict[str, List[str]] = {}

    if not is_casr_available():
        LOG.warning("CASR not available, skipping clustering")
        # Return each crash as its own cluster
        for crash_file in Path(crash_dir).glob("crash-*"):
            clusters[crash_file.name] = [str(crash_file)]
        return clusters

    try:
        os.makedirs(output_dir, exist_ok=True)

        # Run casr-cluster on the crash directory
        cmd = [
            "casr-cluster",
            "-c", crash_dir,
            "-o", output_dir,
        ]

        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300,
        )

        if proc.returncode == 0:
            # Parse cluster output
            cluster_file = os.path.join(output_dir, "clusters.json")
            if os.path.exists(cluster_file):
                with open(cluster_file) as f:
                    cluster_data = json.load(f)
                    for cluster_id, crash_list in cluster_data.items():
                        clusters[cluster_id] = crash_list
        else:
            LOG.warning(f"CASR clustering failed: {proc.stderr}")
            # Fallback: each crash is its own cluster
            for crash_file in Path(crash_dir).glob("crash-*"):
                clusters[crash_file.name] = [str(crash_file)]

    except subprocess.TimeoutExpired:
        LOG.warning("CASR clustering timed out")
    except Exception as e:
        LOG.warning(f"CASR clustering error: {e}")

    return clusters


def deduplicate_timeline(
    timeline: CrashTimeline,
    binary_path: str,
    output_dir: Path,
) -> CrashTimeline:
    """
    Deduplicate crashes in a timeline using CASR.

    Args:
        timeline: CrashTimeline with crashes to deduplicate
        binary_path: Path to the fuzzer binary
        output_dir: Directory for CASR reports

    Returns:
        Updated CrashTimeline with cluster IDs and crash types
    """
    if not timeline.crashes:
        return timeline

    casr_dir = output_dir / "casr_reports"
    casr_dir.mkdir(parents=True, exist_ok=True)

    # Analyze each crash
    for crash in timeline.crashes:
        analysis = analyze_crash(
            crash.corpus_file,
            binary_path,
            str(casr_dir),
        )
        crash.crash_type = analysis["crash_type"]
        crash.stack_trace = analysis["stack_trace"]
        crash.casr_report = analysis["casr_report"]

    # Cluster crashes if we have multiple
    if len(timeline.crashes) > 1:
        # Create temp directory with crash files for clustering
        crash_files_dir = casr_dir / "crashes"
        crash_files_dir.mkdir(exist_ok=True)

        for crash in timeline.crashes:
            if os.path.exists(crash.corpus_file):
                dest = crash_files_dir / crash.crash_id
                subprocess.run(["cp", crash.corpus_file, str(dest)], check=False)

        clusters = cluster_crashes(str(crash_files_dir), str(casr_dir / "clusters"))

        # Assign cluster IDs
        crash_to_cluster = {}
        for cluster_id, crash_files in clusters.items():
            for crash_file in crash_files:
                crash_name = Path(crash_file).name
                crash_to_cluster[crash_name] = cluster_id

        for crash in timeline.crashes:
            crash.cluster_id = crash_to_cluster.get(crash.crash_id, crash.crash_id)
    else:
        # Single crash is its own cluster
        for crash in timeline.crashes:
            crash.cluster_id = crash.crash_id

    return timeline


def compare_to_original(
    timeline: CrashTimeline,
    original_crash_type: str,
) -> CrashTimeline:
    """
    Check if any crashes match the original PoC crash type.

    Args:
        timeline: CrashTimeline to update
        original_crash_type: Crash type from original PoC

    Returns:
        Updated CrashTimeline with matches_original flags
    """
    for crash in timeline.crashes:
        # Simple match: same crash type
        if crash.crash_type.lower() == original_crash_type.lower():
            crash.matches_original = True

            if not timeline.reproduced_original:
                timeline.reproduced_original = True
                timeline.time_to_original_crash = crash.first_seen_time

    return timeline
