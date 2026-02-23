#!/usr/bin/env python3
"""
casr_cluster.py - Cluster libfuzzer crashes without losing duplicates.
Similar to casr-libfuzzer but preserves full crash-to-cluster mapping.

This script generates individual CASR reports for all crashes and clusters them
WITHOUT deduplication, preserving the complete crash-to-cluster mapping.
"""
from __future__ import annotations

import os
import subprocess
import sys
import tempfile
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

# Ensure we're using Python 3
if sys.version_info < (3, 6):
    print("Error: Python 3.6 or higher required", file=sys.stderr)
    sys.exit(1)


@dataclass
class ClusterResult:
    """Result of clustering crashes."""
    crash_to_cluster: 'Dict[str, int]'  # crash filename -> cluster id
    cluster_to_crashes: 'Dict[int, List[str]]'  # cluster id -> list of crash filenames
    num_clusters: int


def detect_tool(binary_path: Path) -> str:
    """Auto-detect which casr tool to use based on binary."""
    binary_str = str(binary_path)

    # Check file extension / type hints
    if binary_str.endswith('.py'):
        return 'casr-python'
    if binary_str.endswith('.js') or binary_str.endswith('node'):
        return 'casr-js'
    if binary_str.endswith('java') or binary_str.endswith('jazzer'):
        return 'casr-java'
    if binary_str.endswith('.lua') or 'lua' in binary_str:
        return 'casr-lua'

    # Check for sanitizer symbols in binary
    try:
        result = subprocess.run(
            ['nm', binary_str],
            capture_output=True,
            text=True,
            timeout=10
        )
        symbols = result.stdout
        if '__asan' in symbols or '__msan' in symbols or '__tsan' in symbols:
            return 'casr-san'
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass

    # Default to gdb for uninstrumented binaries
    return 'casr-gdb'


def generate_report(
    tool: str,
    crash_path: Path,
    output_path: Path,
    binary_args: List[str],
    timeout: int = 30,
    use_stdin: bool = True,
) -> Tuple[str, bool, str]:
    """
    Generate a single CASR report.
    Returns: (crash_filename, success, error_message)
    """
    crash_name = crash_path.name
    report_path = output_path / f"{crash_name}.casrep"

    # Build command
    cmd = [tool, '-o', str(report_path)]

    if timeout > 0:
        cmd.extend(['-t', str(timeout)])

    # Handle input: stdin or argument
    if use_stdin:
        cmd.extend(['--stdin', str(crash_path)])

    cmd.append('--')

    # Add binary and arguments
    args = binary_args.copy()
    if not use_stdin:
        # Replace @@ with crash path or append it
        replaced = False
        for i, arg in enumerate(args):
            if '@@' in arg:
                args[i] = arg.replace('@@', str(crash_path))
                replaced = True
        if not replaced:
            args.append(str(crash_path))

    cmd.extend(args)

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout + 10 if timeout > 0 else 120
        )
        if result.returncode == 0 and report_path.exists():
            return (crash_name, True, "")
        else:
            error_msg = result.stderr.strip() if result.stderr else f"Exit code {result.returncode}"
            return (crash_name, False, error_msg)
    except subprocess.TimeoutExpired:
        return (crash_name, False, f"Timeout after {timeout + 10}s (CASR timeout: {timeout}s)")
    except Exception as e:
        return (crash_name, False, str(e))


def cluster_reports(
    reports_dir: Path,
    clusters_dir: Path,
) -> Dict[str, int]:
    """
    Run casr-cluster on reports directory.
    Returns mapping of report filename -> cluster id.
    """
    # Run casr-cluster -c (no dedup!)
    cmd = ['casr-cluster', '-c', str(reports_dir), str(clusters_dir)]
    result = subprocess.run(cmd, capture_output=True, text=True)

    if result.returncode != 0:
        raise RuntimeError(f"casr-cluster failed: {result.stderr}")

    # Parse cluster directories to build mapping
    crash_to_cluster = {}
    for cluster_dir in clusters_dir.iterdir():
        if cluster_dir.is_dir() and cluster_dir.name.startswith('cl'):
            cluster_name = cluster_dir.name
            if cluster_name == 'clerr':
                continue
            # Extract cluster number from "cl1", "cl2", etc.
            try:
                cluster_id = int(cluster_name[2:])
            except ValueError:
                continue

            for report_file in cluster_dir.glob('*.casrep'):
                # Remove .casrep extension to get crash name
                crash_name = report_file.stem
                crash_to_cluster[crash_name] = cluster_id

    return crash_to_cluster


def cluster_crashes(
    crashes_dir: Path,
    binary_args: List[str],
    output_dir: Optional[Path] = None,
    tool: Optional[str] = None,
    timeout: int = 30,
    jobs: Optional[int] = None,
    use_stdin: bool = True,
) -> ClusterResult:
    """
    Main function: generate reports for all crashes and cluster them.

    Args:
        crashes_dir: Directory containing crash inputs
        binary_args: Command line for the target binary (e.g., ['./binary', '@@'])
        output_dir: Output directory for reports and clusters (default: temp dir)
        tool: CASR tool to use (default: auto-detect)
        timeout: Timeout in seconds for each crash (default: 30)
        jobs: Number of parallel jobs (default: CPU count / 2)
        use_stdin: Use --stdin for crash input (default: True for libFuzzer)

    Returns:
        ClusterResult with crash-to-cluster mapping
    """
    crashes_dir = Path(crashes_dir)

    if output_dir is None:
        output_dir = Path(tempfile.mkdtemp(prefix='casr_'))
    else:
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

    reports_dir = output_dir / 'reports'
    clusters_dir = output_dir / 'clusters'
    reports_dir.mkdir(exist_ok=True)
    clusters_dir.mkdir(exist_ok=True)

    # Auto-detect tool if not specified
    if tool is None:
        binary_path = Path(binary_args[0])
        tool = detect_tool(binary_path)
    print(f"Using tool: {tool}")

    # Get all crash files
    crash_files = [
        f for f in crashes_dir.iterdir()
        if f.is_file() and not f.name.startswith('.')
    ]
    print(f"Found {len(crash_files)} crash files")

    # Generate reports in parallel
    if jobs is None:
        jobs = max(1, os.cpu_count() // 2)

    print(f"Generating reports with {jobs} parallel jobs...")
    successful = []
    failed = []

    with ThreadPoolExecutor(max_workers=jobs) as executor:
        futures = {
            executor.submit(
                generate_report,
                tool,
                crash_path,
                reports_dir,
                binary_args,
                timeout,
                use_stdin,
            ): crash_path
            for crash_path in crash_files
        }

        for future in as_completed(futures):
            crash_name, success, error = future.result()
            if success:
                successful.append(crash_name)
            else:
                failed.append((crash_name, error))

    print(f"Generated {len(successful)} reports, {len(failed)} failed")

    if failed:
        print("Failed crashes:")
        for name, err in failed[:5]:  # Show first 5
            print(f"  {name}: {err}")
        if len(failed) > 5:
            print(f"  ... and {len(failed) - 5} more")

    # Check we have enough reports to cluster
    report_count = len(list(reports_dir.glob('*.casrep')))
    if report_count < 2:
        print(f"Only {report_count} reports, cannot cluster")
        # Return single cluster with all crashes
        return ClusterResult(
            crash_to_cluster={name: 1 for name in successful},
            cluster_to_crashes={1: successful},
            num_clusters=1 if successful else 0,
        )

    # Cluster reports (no dedup!)
    print("Clustering reports...")
    crash_to_cluster = cluster_reports(reports_dir, clusters_dir)

    # Build reverse mapping
    cluster_to_crashes = {}  # type: Dict[int, List[str]]
    for crash, cluster_id in crash_to_cluster.items():
        if cluster_id not in cluster_to_crashes:
            cluster_to_crashes[cluster_id] = []
        cluster_to_crashes[cluster_id].append(crash)

    num_clusters = len(cluster_to_crashes)
    print(f"Created {num_clusters} clusters")
    for cluster_id, crashes in sorted(cluster_to_crashes.items()):
        print(f"  Cluster {cluster_id}: {len(crashes)} crashes")

    return ClusterResult(
        crash_to_cluster=crash_to_cluster,
        cluster_to_crashes=cluster_to_crashes,
        num_clusters=num_clusters,
    )


# Example usage
if __name__ == '__main__':
    import argparse
    import json

    parser = argparse.ArgumentParser(description='Cluster crashes without deduplication')
    parser.add_argument('-i', '--input', required=True, help='Crashes directory')
    parser.add_argument('-o', '--output', required=True, help='Output directory')
    parser.add_argument('-t', '--timeout', type=int, default=30, help='Timeout per crash')
    parser.add_argument('-j', '--jobs', type=int, help='Parallel jobs')
    parser.add_argument('--tool', help='CASR tool (auto-detect if not specified)')
    parser.add_argument('--no-stdin', action='store_true', help='Use @@ instead of stdin')
    parser.add_argument('--json', help='Write JSON mapping to file')
    parser.add_argument('binary_args', nargs='+', help='Binary and arguments (use @@ for crash input)')

    args = parser.parse_args()

    result = cluster_crashes(
        crashes_dir=args.input,
        binary_args=args.binary_args,
        output_dir=args.output,
        tool=args.tool,
        timeout=args.timeout,
        jobs=args.jobs,
        use_stdin=not args.no_stdin,
    )

    # Write JSON mapping if requested
    if args.json:
        with open(args.json, 'w') as f:
            json.dump({
                'crash_to_cluster': result.crash_to_cluster,
                'cluster_to_crashes': result.cluster_to_crashes,
                'num_clusters': result.num_clusters,
            }, f, indent=2)

    # Print CSV mapping
    print("\n=== Crash to Cluster Mapping ===")
    for crash, cluster_id in sorted(result.crash_to_cluster.items()):
        print(f"{crash},cl{cluster_id}")
