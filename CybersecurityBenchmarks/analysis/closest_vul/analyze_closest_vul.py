#!/usr/bin/env python3
"""
Analyze closest-vul results: collect per-case result.json files from GCS
and produce an aggregate report.

Usage:
    python analyze_closest_vul.py --config ../../benchmark/gcp/.gke-config.json
    python analyze_closest_vul.py --local-dir /tmp/closest_vul  # skip GCS download
"""

import argparse
import json
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

# Resolve paths relative to this script
SCRIPT_DIR = Path(__file__).parent.resolve()
REPO_ROOT = SCRIPT_DIR.parent.parent
APB_CONFIG = REPO_ROOT / "benchmark" / "gcp" / "configs" / "autopatchbench_all.json"
DEFAULT_GKE_CONFIG = REPO_ROOT / "benchmark" / "gcp" / ".gke-config.json"


def load_gke_config(path: Path) -> dict:
    with open(path) as f:
        return json.load(f)


def load_case_ids() -> list[int]:
    with open(APB_CONFIG) as f:
        return json.load(f)["cases"]


def download_from_gcs(bucket: str, case_ids: list[int], dest_dir: Path) -> int:
    """Download result.json for each case from GCS. Returns number downloaded."""
    dest_dir.mkdir(parents=True, exist_ok=True)
    downloaded = 0

    for cid in case_ids:
        gcs_path = f"gs://{bucket}/analysis/closest_vul/{cid}/result.json"
        local_file = dest_dir / str(cid) / "result.json"
        local_file.parent.mkdir(exist_ok=True)

        result = subprocess.run(
            ["gsutil", "cp", gcs_path, str(local_file)],
            capture_output=True,
            text=True,
        )
        if result.returncode == 0:
            downloaded += 1
        # Silently skip missing cases (not yet processed)

    return downloaded


def load_result(case_dir: Path) -> dict[str, Any] | None:
    """Load result.json for a single case."""
    result_file = case_dir / "result.json"
    if not result_file.exists():
        return None
    try:
        with open(result_file) as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return None


def analyze(case_ids: list[int], data_dir: Path) -> dict[str, Any]:
    """Collect all results and produce aggregate report."""

    details = []
    found = 0
    failed_no_crash = 0
    failed_no_compile = 0
    errors = 0
    no_data = 0

    distances_c_to_b = []
    distances_c_to_k = []

    for cid in case_ids:
        case_dir = data_dir / str(cid)
        result = load_result(case_dir)

        if not result:
            no_data += 1
            details.append({"case_id": cid, "status": "no_data"})
            continue

        status = result.get("status", "unknown")
        details.append(result)

        if status == "found":
            found += 1
            c_to_b = result.get("distance_c_to_b", -1)
            c_to_k = result.get("distance_c_to_k", -1)
            if c_to_b >= 0:
                distances_c_to_b.append(c_to_b)
            if c_to_k >= 0:
                distances_c_to_k.append(c_to_k)
        elif status == "failed_no_crash":
            failed_no_crash += 1
        elif status == "failed_no_compile":
            failed_no_compile += 1
        elif status == "error":
            errors += 1
        else:
            errors += 1

    # Compute distance stats
    distance_stats = {}
    if distances_c_to_b:
        distance_stats["c_to_b"] = {
            "min": min(distances_c_to_b),
            "max": max(distances_c_to_b),
            "avg": sum(distances_c_to_b) / len(distances_c_to_b),
            "median": sorted(distances_c_to_b)[len(distances_c_to_b) // 2],
        }
    if distances_c_to_k:
        distance_stats["c_to_k"] = {
            "min": min(distances_c_to_k),
            "max": max(distances_c_to_k),
            "avg": sum(distances_c_to_k) / len(distances_c_to_k),
            "median": sorted(distances_c_to_k)[len(distances_c_to_k) // 2],
        }

    return {
        "total_cases": len(case_ids),
        "found": found,
        "failed_no_crash": failed_no_crash,
        "failed_no_compile": failed_no_compile,
        "errors": errors,
        "no_data": no_data,
        "distance_stats": distance_stats,
        "details": details,
    }


def print_summary(report: dict) -> None:
    """Print a human-readable summary."""
    print("\n" + "=" * 80)
    print("Closest Vulnerable Commit Report")
    print("=" * 80)
    total = report["total_cases"]
    print(f"Total APB cases:       {total}")
    print(f"  Found (C):           {report['found']}")
    print(f"  Failed (no crash):   {report['failed_no_crash']}")
    print(f"  Failed (no compile): {report['failed_no_compile']}")
    print(f"  Errors:              {report['errors']}")
    print(f"  No data:             {report['no_data']}")
    print()

    # Distance stats
    ds = report.get("distance_stats", {})
    if "c_to_b" in ds:
        s = ds["c_to_b"]
        print("Distance C -> B (commits):")
        print(
            f"  min={s['min']}  max={s['max']}  "
            f"avg={s['avg']:.1f}  median={s['median']}"
        )
    if "c_to_k" in ds:
        s = ds["c_to_k"]
        print("Distance C -> K (commits):")
        print(
            f"  min={s['min']}  max={s['max']}  "
            f"avg={s['avg']:.1f}  median={s['median']}"
        )
    print()

    # Per-case table for found cases
    found_cases = [d for d in report["details"] if d.get("status") == "found"]
    if found_cases:
        print(f"--- Found Cases ({len(found_cases)}) ---")
        print(
            f"{'Case':<8} {'C->B':<6} {'C->K':<6} {'Attempts':<9} "
            f"{'Candidates':<11} {'Commit C'}"
        )
        print("-" * 80)
        for case in sorted(found_cases, key=lambda c: c.get("distance_c_to_b", 0)):
            cid = case.get("case_id", "?")
            c_to_b = case.get("distance_c_to_b", "?")
            c_to_k = case.get("distance_c_to_k", "?")
            attempts = case.get("attempts", "?")
            candidates = case.get("total_candidates", "?")
            c_commit = case.get("closest_vul_commit", "?")[:12]
            print(
                f"{cid:<8} {c_to_b:<6} {c_to_k:<6} {attempts:<9} "
                f"{candidates:<11} {c_commit}"
            )
        print()

    # Per-case table for failed cases
    failed_cases = [
        d
        for d in report["details"]
        if d.get("status") in ("failed_no_crash", "failed_no_compile", "error")
    ]
    if failed_cases:
        print(f"--- Failed Cases ({len(failed_cases)}) ---")
        print(f"{'Case':<8} {'Status':<20} {'Attempts':<9} {'Reason'}")
        print("-" * 80)
        for case in failed_cases:
            cid = case.get("case_id", "?")
            status = case.get("status", "?")
            attempts = case.get("attempts", "?")
            reason = case.get("reason", "")
            print(f"{cid:<8} {status:<20} {attempts:<9} {reason}")
        print()


def main():
    parser = argparse.ArgumentParser(
        description="Analyze closest-vul search results"
    )
    parser.add_argument(
        "--config", type=Path, default=DEFAULT_GKE_CONFIG, help="GKE config file"
    )
    parser.add_argument(
        "--local-dir",
        type=Path,
        default=None,
        help="Use local directory instead of downloading from GCS",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=SCRIPT_DIR / "report.json",
        help="Output report file",
    )
    args = parser.parse_args()

    # Load case IDs
    case_ids = load_case_ids()
    print(f"APB cases: {len(case_ids)}")

    # Get data directory
    gke_config = load_gke_config(args.config)
    bucket = gke_config["bucket_name"]

    if args.local_dir:
        data_dir = args.local_dir
        print(f"Using local data from {data_dir}")
    else:
        data_dir = Path(tempfile.mkdtemp(prefix="closest-vul-"))
        print(f"Downloading from GCS to {data_dir}...")
        downloaded = download_from_gcs(bucket, case_ids, data_dir)
        print(f"  Downloaded data for {downloaded} cases")

    # Run analysis
    print("\nAnalyzing...")
    report = analyze(case_ids, data_dir)

    # Save report
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with open(args.output, "w") as f:
        json.dump(report, f, indent=2)
    print(f"\nReport saved to {args.output}")

    # Print summary
    print_summary(report)

    return 0


if __name__ == "__main__":
    sys.exit(main())
