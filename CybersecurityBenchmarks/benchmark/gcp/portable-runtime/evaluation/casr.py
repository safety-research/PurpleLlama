# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

"""
CASR integration for crash analysis and deduplication.

Uses casr-cluster-map to generate reports and cluster crashes in a single call.
This matches the implementation in fuzzing_only_benchmark.py.

CASR (Crash Analysis and Severity Rating) provides:
1. Crash type classification (heap-buffer-overflow, use-after-free, etc.)
2. Stack trace extraction
3. Crash clustering/deduplication

See: https://github.com/ispras/casr
"""

import json
import logging
import os
import shutil
import subprocess
from pathlib import Path
from typing import Dict, List, Optional

from .types import CrashInfo, CrashTimeline

LOG = logging.getLogger(__name__)


def is_casr_available() -> bool:
    """Check if CASR tools are available."""
    try:
        result = subprocess.run(
            ["casr-cluster-map", "--version"],
            capture_output=True,
            timeout=10,
        )
        return result.returncode == 0
    except Exception:
        return False


def get_all_crash_files(crash_dir: str) -> List[Path]:
    """
    Get all crash files from a directory.

    Includes crash-*, oom-*, timeout-*, leak-* files but excludes .log files.

    Args:
        crash_dir: Directory containing crash files

    Returns:
        List of Path objects for crash files
    """
    crash_path = Path(crash_dir)
    if not crash_path.exists():
        return []

    crash_prefixes = ["crash-", "oom-", "timeout-", "leak-"]
    crash_files = []

    for f in crash_path.iterdir():
        if f.is_file() and any(f.name.startswith(p) for p in crash_prefixes):
            # Skip log files
            if not f.name.endswith(".log"):
                crash_files.append(f)

    return crash_files


def run_casr_cluster_map(
    crashes_dir: str,
    output_dir: str,
    binary_path: str,
    timeout_per_crash: int = 120,
    jobs: int = 4,
) -> Dict[str, str]:
    """
    Run casr-cluster-map to generate reports and cluster crashes.

    This matches fuzzing_only_benchmark.py lines 1228-1375.

    Args:
        crashes_dir: Directory containing crash files
        output_dir: Directory for CASR reports and clusters
        binary_path: Path to the fuzzer binary
        timeout_per_crash: Timeout in seconds per crash (default: 120)
        jobs: Number of parallel jobs (default: 4)

    Returns:
        Dict mapping crash filename to cluster ID (e.g., "crash-abc123" -> "cl1")
    """
    crash_to_cluster: Dict[str, str] = {}

    # Check for crash files
    crash_files = get_all_crash_files(crashes_dir)
    if not crash_files:
        LOG.info("No crash files to cluster")
        return crash_to_cluster

    # Count crash types for logging
    oom_count = sum(1 for f in crash_files if f.name.startswith("oom-"))
    timeout_count = sum(1 for f in crash_files if f.name.startswith("timeout-"))
    leak_count = sum(1 for f in crash_files if f.name.startswith("leak-"))
    regular_count = len(crash_files) - oom_count - timeout_count - leak_count

    LOG.info(
        f"Processing {len(crash_files)} crashes with CASR "
        f"({regular_count} regular, {oom_count} OOM, {timeout_count} timeout, {leak_count} leak)"
    )

    if not is_casr_available():
        LOG.warning("casr-cluster-map not available, skipping clustering")
        # Return each crash as its own cluster
        for i, crash_file in enumerate(crash_files, 1):
            crash_to_cluster[crash_file.name] = f"cl{i}"
        return crash_to_cluster

    # Create output directory
    os.makedirs(output_dir, exist_ok=True)
    mapping_file = os.path.join(output_dir, "crash_mapping.json")

    # Build casr-cluster-map command
    # Matching fuzzing_only_benchmark.py lines 1228-1258
    cmd = [
        "casr-cluster-map",
        "-i",
        crashes_dir,
        "-o",
        output_dir,
        "-t",
        str(timeout_per_crash),
        "-j",
        str(jobs),
        "--mapping",
        mapping_file,
        "--use-logs",  # For libFuzzer log-based clustering
        "--",
        binary_path,
        "@@",  # Placeholder for crash input file
    ]

    LOG.info(f"Running CASR clustering: {' '.join(cmd)}")

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300,  # 5 minutes total timeout
        )

        stdout = result.stdout or ""
        stderr = result.stderr or ""

        # Save CASR output to log file
        casr_log_file = os.path.join(output_dir, "casr_output.log")
        with open(casr_log_file, "w") as f:
            f.write(f"=== CASR Clustering (casr-cluster-map) ===\n")
            f.write(f"Command: {' '.join(cmd)}\n")
            f.write(f"Return code: {result.returncode}\n\n")
            f.write("=== STDOUT ===\n")
            f.write(stdout)
            f.write("\n\n=== STDERR ===\n")
            f.write(stderr)
        LOG.info(f"CASR output saved to {casr_log_file}")

        if result.returncode != 0:
            LOG.warning(
                f"CASR clustering returned non-zero exit code {result.returncode}"
            )

            # Case 1: Only 1 unique crash type - this is OK
            if "Not enough valid reports" in stderr or "Less than 2" in stderr:
                LOG.info("CASR found only 1 unique stacktrace type")
                # Continue - CASR may still produce a valid mapping

            # Case 2: CASR couldn't reproduce crashes
            elif (
                "No reports generated" in stderr
                or "Program terminated (no crash)" in stderr
            ):
                LOG.warning(f"CASR failed to reproduce crashes: {stderr}")

            # Case 3: Unknown error
            else:
                LOG.warning(f"CASR clustering failed: {stderr}")

        # Parse JSON mapping file
        crash_to_cluster = parse_casr_json_mapping(mapping_file)

        if crash_to_cluster:
            num_clusters = len(set(crash_to_cluster.values()))
            LOG.info(
                f"CASR mapped {len(crash_to_cluster)} crashes to {num_clusters} clusters"
            )
        else:
            # Fallback: each crash is its own cluster
            LOG.warning(
                "CASR produced no mapping, using fallback (each crash = own cluster)"
            )
            for i, crash_file in enumerate(crash_files, 1):
                crash_to_cluster[crash_file.name] = f"cl{i}"

    except subprocess.TimeoutExpired:
        LOG.warning("CASR clustering timed out after 300s")
        # Fallback
        for i, crash_file in enumerate(crash_files, 1):
            crash_to_cluster[crash_file.name] = f"cl{i}"

    except Exception as e:
        LOG.warning(f"CASR clustering error: {e}")
        # Fallback
        for i, crash_file in enumerate(crash_files, 1):
            crash_to_cluster[crash_file.name] = f"cl{i}"

    return crash_to_cluster


def parse_casr_json_mapping(mapping_file: str) -> Dict[str, str]:
    """
    Parse JSON mapping file from casr-cluster-map tool.

    Matching fuzzing_only_benchmark.py lines 1559-1638.

    JSON format from casr-cluster-map:
    {
        "mappings": [{"crash": "crash-abc123", "cluster_id": 2}, ...],
        "clusters": {"1": [...], "2": [...]},
        "num_clusters": N
    }

    Args:
        mapping_file: Path to crash_mapping.json file

    Returns:
        Dict mapping crash filename to cluster ID (e.g., "crash-abc123" -> "cl1")
    """
    crash_to_cluster: Dict[str, str] = {}

    if not os.path.exists(mapping_file):
        LOG.warning(f"CASR mapping file not found: {mapping_file}")
        return crash_to_cluster

    try:
        with open(mapping_file) as f:
            mapping_data = json.load(f)

        # Build crash-to-cluster mapping from the mappings array
        # Each mapping has: {"crash": "crash-abc123", "cluster_id": 2, "is_representative": bool}
        mappings = mapping_data.get("mappings", [])
        for mapping in mappings:
            crash_name = mapping.get("crash", "")
            cluster_int = mapping.get("cluster_id", 0)
            if crash_name and cluster_int > 0:
                crash_to_cluster[crash_name] = f"cl{cluster_int}"

        num_clusters = mapping_data.get("num_clusters", 0)
        LOG.info(
            f"Loaded mapping for {len(crash_to_cluster)} crashes across {num_clusters} clusters"
        )

        # Log cluster distribution
        clusters = mapping_data.get("clusters", {})
        for cluster_id, crash_list in sorted(
            clusters.items(), key=lambda x: int(x[0]) if x[0].isdigit() else 0
        ):
            LOG.debug(f"Cluster {cluster_id} has {len(crash_list)} crashes")

    except json.JSONDecodeError as e:
        LOG.warning(f"Failed to parse CASR mapping JSON: {e}")
    except Exception as e:
        LOG.warning(f"Error reading CASR mapping: {e}")

    return crash_to_cluster


def deduplicate_timeline(
    timeline: CrashTimeline,
    binary_path: str,
    output_dir: Path,
) -> CrashTimeline:
    """
    Deduplicate crashes in a timeline using CASR.

    Uses casr-cluster-map to analyze and cluster all crashes in one call.

    Args:
        timeline: CrashTimeline with crashes to deduplicate
        binary_path: Path to the fuzzer binary
        output_dir: Directory for CASR reports

    Returns:
        Updated CrashTimeline with cluster IDs
    """
    if not timeline.crashes:
        return timeline

    casr_dir = output_dir / "casr_reports"
    casr_dir.mkdir(parents=True, exist_ok=True)

    # Log crash type distribution
    oom_count = sum(1 for c in timeline.crashes if c.crash_type == "oom")
    timeout_count = sum(1 for c in timeline.crashes if c.crash_type == "timeout")
    leak_count = sum(1 for c in timeline.crashes if c.crash_type == "leak")
    regular_count = len(timeline.crashes) - oom_count - timeout_count - leak_count

    LOG.info(
        f"Deduplicating {len(timeline.crashes)} crashes "
        f"({regular_count} regular, {oom_count} OOM, {timeout_count} timeout, {leak_count} leak)"
    )

    # Create temp directory with crash files for clustering
    crash_files_dir = casr_dir / "crashes"
    crash_files_dir.mkdir(exist_ok=True)

    # Copy crash files to temp directory
    for crash in timeline.crashes:
        if os.path.exists(crash.corpus_file):
            # Use crash_id as filename to match back later
            dest = crash_files_dir / crash.crash_id
            shutil.copy2(crash.corpus_file, dest)

            # Also copy log file if it exists (for --use-logs)
            log_file = crash.corpus_file + ".log"
            if os.path.exists(log_file):
                logs_dir = crash_files_dir / "logs"
                logs_dir.mkdir(exist_ok=True)
                shutil.copy2(log_file, logs_dir / (crash.crash_id + ".log"))

    # Run casr-cluster-map
    crash_to_cluster = run_casr_cluster_map(
        crashes_dir=str(crash_files_dir),
        output_dir=str(casr_dir / "output"),
        binary_path=binary_path,
    )

    # Assign cluster IDs to crashes
    for crash in timeline.crashes:
        cluster_id = crash_to_cluster.get(crash.crash_id)
        if cluster_id:
            crash.cluster_id = cluster_id
        else:
            # Fallback: use crash_id as cluster_id
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
