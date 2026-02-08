#!/usr/bin/env python3
"""
Check ARVO benchmark results for a given experiment ID.

Downloads fuzzing results and patch results from GCS, parses Argo artifacts
(tar-compressed JSON), and prints a summary table.

Usage:
    python check_results.py <experiment_id> [--bucket BUCKET] [--details]

Example:
    python check_results.py fuzz1800
    python check_results.py fuzz1800 --details
    python check_results.py fuzz1800 --bucket my-custom-bucket
"""

import argparse
import gzip
import io
import json
import subprocess
import sys
import tarfile
import tempfile
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Optional


def get_default_bucket() -> str:
    """Read bucket from .gke-config.json."""
    # Script is at .cursor/skills/check-results/scripts/check_results.py
    # Need 5 parents to reach CybersecurityBenchmarks/
    config_path = (
        Path(__file__).resolve().parent.parent.parent.parent.parent
        / "benchmark"
        / "gcp"
        / ".gke-config.json"
    )
    if config_path.exists():
        with open(config_path) as f:
            return json.load(f).get("bucket_name", "")
    return ""


def gsutil_ls(gcs_path: str) -> list[str]:
    """List GCS path, return list of paths."""
    result = subprocess.run(
        ["gsutil", "ls", gcs_path],
        capture_output=True,
        text=True,
        timeout=30,
    )
    if result.returncode != 0:
        return []
    return [
        line.strip().rstrip("/")
        for line in result.stdout.strip().split("\n")
        if line.strip()
    ]


def gsutil_rsync(gcs_path: str, local_path: str) -> bool:
    """Sync GCS directory to local path."""
    result = subprocess.run(
        ["gsutil", "-m", "-q", "rsync", "-r", gcs_path, local_path],
        capture_output=True,
        text=True,
        timeout=600,
    )
    return result.returncode == 0


def read_argo_artifact(path: Path) -> Optional[dict]:
    """Read a JSON file that may be wrapped in a tar archive by Argo."""
    if not path.exists():
        return None
    content = path.read_bytes()
    if not content:
        return None

    # Try plain JSON first
    try:
        return json.loads(content)
    except (json.JSONDecodeError, UnicodeDecodeError):
        pass

    # Try gzip -> tar -> JSON
    try:
        content = gzip.decompress(content)
    except (gzip.BadGzipFile, OSError):
        pass

    # Try tar -> JSON
    try:
        with tarfile.open(fileobj=io.BytesIO(content)) as tar:
            for member in tar.getmembers():
                if member.name.endswith(".json") or not member.name.startswith("."):
                    f = tar.extractfile(member)
                    if f:
                        return json.loads(f.read())
    except (tarfile.TarError, json.JSONDecodeError):
        pass

    return None


def collect_results(results_dir: Path) -> dict[str, dict]:
    """
    Walk the results directory and collect fuzzing + patch results.

    Returns:
        Dict keyed by case_id, each containing:
            {model: {fuzzing_result: ..., patch_result: ..., crashes: ...}}
    """
    data: dict[str, dict] = {}

    for case_dir in sorted(results_dir.iterdir()):
        if not case_dir.is_dir():
            continue
        case_id = case_dir.name
        data[case_id] = {}

        for model_dir in sorted(case_dir.iterdir()):
            if not model_dir.is_dir():
                continue
            model = model_dir.name
            entry: dict[str, Any] = {}

            fuzz_result = read_argo_artifact(model_dir / "fuzzing_result.json")
            if fuzz_result:
                entry["fuzzing_result"] = fuzz_result

            patch_result = read_argo_artifact(model_dir / "result.json")
            if patch_result:
                entry["patch_result"] = patch_result

            crashes = read_argo_artifact(model_dir / "crashes.json")
            if crashes:
                entry["crashes"] = crashes

            regression = read_argo_artifact(model_dir / "regression_analysis.json")
            if regression:
                entry["regression"] = regression

            if entry:
                data[case_id][model] = entry

    return data


def shorten_model(name: str) -> str:
    """Shorten model name for display."""
    replacements = [
        ("claude-", ""),
        ("autopatchbench-claude-", ""),
        ("autopatchbench-", "apb-"),
        ("-2025", "-25"),
        ("-2024", "-24"),
        ("-2026", "-26"),
        ("0514", "05"),
        ("0929", "09"),
        ("1001", "10"),
        ("1101", "11"),
    ]
    short = name
    for old, new in replacements:
        short = short.replace(old, new)
    return short


def print_crash_table(data: dict[str, dict], details: bool = False) -> None:
    """Print crash table: cases x models."""
    # Collect all models (sorted, gt first)
    all_models = set()
    for case_data in data.values():
        all_models.update(case_data.keys())
    models = sorted(all_models - {"gt"})
    if "gt" in all_models:
        models.append("gt")

    if not models:
        print("No results found.")
        return

    # Column widths
    case_col = 8
    col_w = max(14, max(len(shorten_model(m)) + 2 for m in models))

    # Header
    header = f"{'Case':<{case_col}}"
    for m in models:
        header += f"{shorten_model(m):>{col_w}}"
    print(header)
    print("-" * len(header))

    # Totals
    total_crashes = defaultdict(int)
    total_unique = defaultdict(int)
    total_regressions = defaultdict(int)
    total_pre_existing = defaultdict(int)
    total_different_crash = defaultdict(int)
    has_regression_data = defaultdict(bool)
    patch_ok = defaultdict(int)
    patch_fail = defaultdict(int)
    zero_crashes = defaultdict(int)
    case_count = 0

    cases = sorted(data.keys(), key=lambda x: int(x) if x.isdigit() else 0)
    for case_id in cases:
        case_data = data[case_id]
        if not any(m in case_data for m in models):
            continue
        case_count += 1

        row = f"{case_id:<{case_col}}"
        for m in models:
            if m not in case_data:
                row += f"{'--':>{col_w}}"
                continue

            entry = case_data[m]
            fr = entry.get("fuzzing_result", {})
            total = fr.get("total_crashes", 0)
            unique = fr.get("unique_crashes", 0)
            repro = fr.get("reproduced_original", False)

            total_crashes[m] += total
            total_unique[m] += unique

            # Track regression data
            reg = entry.get("regression", {})
            if reg:
                has_regression_data[m] = True
                total_regressions[m] += reg.get("regressions", 0)
                total_pre_existing[m] += reg.get("pre_existing", 0)
                total_different_crash[m] += reg.get("different_crash", 0)

            # Track zero crashes
            if total == 0:
                zero_crashes[m] += 1

            # Track patch status
            pr = entry.get("patch_result", {})
            if pr:
                if pr.get("patch_successful") or pr.get("crash_fixed"):
                    patch_ok[m] += 1
                else:
                    patch_fail[m] += 1

            # Format cell: unique(total) with regression marker
            # e.g. "3(511)" or "1r/3(511)" if regression data available
            repro_marker = " R" if repro else ""
            regressions = reg.get("regressions", 0) if reg else 0
            if reg and unique > 0:
                # Show regressions: "1r/3(511)" or "1r/3" if total==unique
                if total == unique:
                    cell = f"{regressions}r/{total}{repro_marker}"
                else:
                    cell = f"{regressions}r/{unique}({total}){repro_marker}"
            elif total == unique:
                cell = f"{total}{repro_marker}"
            else:
                cell = f"{unique}({total}){repro_marker}"
            row += f"{cell:>{col_w}}"

        print(row)

    # Summary
    print("-" * (case_col + col_w * len(models)))

    # Total crashes row
    row = f"{'TOTAL':<{case_col}}"
    for m in models:
        if total_crashes[m] == total_unique[m]:
            row += f"{total_crashes[m]:>{col_w}}"
        else:
            cell = f"{total_unique[m]}({total_crashes[m]})"
            row += f"{cell:>{col_w}}"
    print(row)

    # Unique crashes row (if different from total)
    if any(total_crashes[m] != total_unique[m] for m in models):
        row = f"{'UNIQUE':<{case_col}}"
        for m in models:
            row += f"{total_unique[m]:>{col_w}}"
        print(row)

    # Regression analysis rows (only shown when data exists)
    if any(has_regression_data[m] for m in models):
        # REGR: LLM-introduced regressions (crash does NOT reproduce on vul binary)
        row = f"{'REGR':<{case_col}}"
        for m in models:
            if has_regression_data[m]:
                row += f"{total_regressions[m]:>{col_w}}"
            else:
                row += f"{'--':>{col_w}}"
        print(row)

        # PRE-EXIST: crashes that also reproduce on vul binary (pre-existing bugs)
        row = f"{'PRE-EXIST':<{case_col}}"
        for m in models:
            if has_regression_data[m]:
                row += f"{total_pre_existing[m]:>{col_w}}"
            else:
                row += f"{'--':>{col_w}}"
        print(row)

        # DIFF CRASH: crashes vul binary too, but with different stack trace
        if any(total_different_crash[m] > 0 for m in models):
            row = f"{'DIFF CRSH':<{case_col}}"
            for m in models:
                if has_regression_data[m]:
                    row += f"{total_different_crash[m]:>{col_w}}"
                else:
                    row += f"{'--':>{col_w}}"
            print(row)

    # Zero crashes row
    row = f"{'NO CRASH':<{case_col}}"
    for m in models:
        row += f"{zero_crashes[m]:>{col_w}}"
    print(row)

    # Patch status row (only for non-gt models)
    if any(patch_ok[m] + patch_fail[m] > 0 for m in models):
        row = f"{'PATCH OK':<{case_col}}"
        for m in models:
            n_ok = patch_ok[m]
            n_total = patch_ok[m] + patch_fail[m]
            if n_total > 0:
                cell = f"{n_ok}/{n_total}"
                row += f"{cell:>{col_w}}"
            else:
                row += f"{'--':>{col_w}}"
        print(row)

    print(f"\nCases with results: {case_count}")

    if details:
        print_details(data, models)


def print_details(data: dict[str, dict], models: list[str]) -> None:
    """Print detailed per-case breakdown."""
    cases = sorted(data.keys(), key=lambda x: int(x) if x.isdigit() else 0)

    for case_id in cases:
        case_data = data[case_id]
        # Only show cases with interesting data
        has_crashes = any(
            case_data.get(m, {}).get("fuzzing_result", {}).get("total_crashes", 0) > 0
            for m in models
        )
        if not has_crashes:
            continue

        print(f"\n{'=' * 60}")
        print(f"Case {case_id}")
        print(f"{'=' * 60}")

        for m in models:
            if m not in case_data:
                continue
            entry = case_data[m]
            fr = entry.get("fuzzing_result", {})
            pr = entry.get("patch_result", {})
            crashes_data = entry.get("crashes", {})

            reg = entry.get("regression", {})

            print(f"\n  --- {shorten_model(m)} ---")
            print(f"  Total crashes:  {fr.get('total_crashes', 0)}")
            print(f"  Unique crashes: {fr.get('unique_crashes', 0)}")
            print(f"  Duration:       {fr.get('duration_seconds', 0):.0f}s")

            if pr:
                print(f"  Patch status:   {pr.get('status', 'N/A')}")
                print(f"  Patch applied:  {pr.get('patch_generated', False)}")
                print(f"  Build success:  {pr.get('build_success', False)}")
                print(f"  Crash fixed:    {pr.get('crash_fixed', False)}")
                if pr.get("error"):
                    print(f"  Error:          {pr.get('error')[:80]}")

            # Regression analysis
            if reg:
                print(f"  Regression analysis:")
                print(
                    f"    Regressions:    {reg.get('regressions', 0)} (LLM-introduced)"
                )
                print(
                    f"    Pre-existing:   {reg.get('pre_existing', 0)} (also crash on vul)"
                )
                print(f"    Different crash: {reg.get('different_crash', 0)}")
                print(f"    Replay errors:  {reg.get('replay_errors', 0)}")
                # Show per-crash classification details
                details_list = reg.get("details", [])
                if details_list:
                    for d in details_list:
                        cls = d.get("classification", "?")
                        crash_id = d.get("llm_report", "?")
                        cluster = d.get("cluster_id", "")
                        tag = (
                            "REGR"
                            if cls == "regression"
                            else "pre-exist"
                            if cls == "pre_existing"
                            else cls
                        )
                        print(f"      {crash_id}: {tag} (cluster: {cluster})")

            # Show crash cluster distribution
            if crashes_data and crashes_data.get("crashes"):
                crash_list = crashes_data["crashes"]
                clusters = Counter(c.get("cluster_id", "unknown") for c in crash_list)
                with_traces = sum(1 for c in crash_list if c.get("stack_trace"))
                print(f"  Clusters:       {len(clusters)}")
                print(f"  With traces:    {with_traces}/{len(crash_list)}")
                if len(clusters) <= 10:
                    for cl, count in clusters.most_common():
                        print(f"    {cl}: {count} crashes")


def main():
    parser = argparse.ArgumentParser(description="Check ARVO benchmark results")
    parser.add_argument("experiment_id", help="Experiment ID to check")
    parser.add_argument(
        "--bucket", help="GCS bucket name (default: from .gke-config.json)"
    )
    parser.add_argument(
        "--details", "-d", action="store_true", help="Show detailed per-case breakdown"
    )
    parser.add_argument(
        "--local", "-l", help="Read from local directory instead of downloading"
    )
    args = parser.parse_args()

    bucket = args.bucket or get_default_bucket()
    if not bucket and not args.local:
        print(
            "Error: No bucket configured. Pass --bucket or configure .gke-config.json",
            file=sys.stderr,
        )
        sys.exit(1)

    if args.local:
        results_dir = Path(args.local)
    else:
        gcs_path = f"gs://{bucket}/results/{args.experiment_id}/"
        print(f"Fetching results from {gcs_path} ...", file=sys.stderr)

        # Check if results exist
        case_dirs = gsutil_ls(gcs_path)
        if not case_dirs:
            print(
                f"No results found for experiment '{args.experiment_id}'",
                file=sys.stderr,
            )
            sys.exit(1)
        print(f"Found {len(case_dirs)} cases", file=sys.stderr)

        # Sync to temp directory (only JSON files, skip binaries)
        tmpdir = Path(tempfile.mkdtemp(prefix=f"arvo-results-{args.experiment_id}-"))
        print(f"Downloading to {tmpdir} ...", file=sys.stderr)

        # Download only JSON files (skip rebuilt_binary which is huge)
        result = subprocess.run(
            [
                "gsutil",
                "-m",
                "-q",
                "rsync",
                "-r",
                "-x",
                ".*rebuilt_binary.*|.*original_binary.*|.*\\.tar\\.gz$",
                gcs_path,
                str(tmpdir),
            ],
            capture_output=True,
            text=True,
            timeout=600,
        )
        if result.returncode != 0:
            print(
                f"Warning: gsutil rsync had issues: {result.stderr[:200]}",
                file=sys.stderr,
            )

        results_dir = tmpdir

    print("Parsing results ...", file=sys.stderr)
    data = collect_results(results_dir)

    if not data:
        print("No results found.", file=sys.stderr)
        sys.exit(1)

    print(file=sys.stderr)  # blank line before table
    print_crash_table(data, details=args.details)


if __name__ == "__main__":
    main()
