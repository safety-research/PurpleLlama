#!/usr/bin/env python3
"""
Analyze crash timelines from ARVO benchmark results.

Loads crashes.json data for all cases/models, filters for completeness
and validity, then plots an aggregate "unique crashes vs time" chart
with one line per model (mean across cases, shaded std band).

Usage:
    # From GCS (run from the gcp/ directory)
    python -m analysis.analyze_crashes fuzz1800

    # From a local directory (previously downloaded by check_results.py)
    python -m analysis.analyze_crashes fuzz1800 --local /tmp/arvo-results-fuzz1800-xxxxx

    # Save plot to file
    python -m analysis.analyze_crashes fuzz1800 --local /tmp/results --output my_plot.png

    # Show interactive plot
    python -m analysis.analyze_crashes fuzz1800 --local /tmp/results --show
"""

import argparse
import gzip
import io
import json
import subprocess
import sys
import tarfile
import tempfile
from collections import defaultdict
from pathlib import Path
from typing import Any, Optional

import numpy as np

try:
    import matplotlib.pyplot as plt

    MATPLOTLIB_AVAILABLE = True
except ImportError:
    MATPLOTLIB_AVAILABLE = False


# ---------------------------------------------------------------------------
# Data loading (reused from check_results.py)
# ---------------------------------------------------------------------------


def get_default_bucket() -> str:
    """Read bucket from .gke-config.json."""
    config_path = (
        Path(__file__).resolve().parent.parent
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
    """Walk results directory and collect fuzzing + crash data per case/model."""
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

            crashes = read_argo_artifact(model_dir / "crashes.json")
            if crashes:
                entry["crashes"] = crashes

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


def download_results(experiment_id: str, bucket: str) -> Path:
    """Download results from GCS to a temp directory."""
    gcs_path = f"gs://{bucket}/results/{experiment_id}/"
    print(f"Fetching results from {gcs_path} ...", file=sys.stderr)

    case_dirs = gsutil_ls(gcs_path)
    if not case_dirs:
        print(
            f"No results found for experiment '{experiment_id}'", file=sys.stderr
        )
        sys.exit(1)
    print(f"Found {len(case_dirs)} cases", file=sys.stderr)

    tmpdir = Path(tempfile.mkdtemp(prefix=f"arvo-results-{experiment_id}-"))
    print(f"Downloading to {tmpdir} ...", file=sys.stderr)

    result = subprocess.run(
        [
            "gsutil", "-m", "-q", "rsync", "-r",
            "-x", ".*rebuilt_binary.*|.*\\.tar\\.gz$",
            gcs_path, str(tmpdir),
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

    return tmpdir


# ---------------------------------------------------------------------------
# Unique-crash time-series computation
# ---------------------------------------------------------------------------


def compute_unique_crash_timeseries(
    crashes_data: dict,
    resolution: float = 5.0,
    max_time: Optional[float] = None,
) -> tuple[np.ndarray, np.ndarray]:
    """Compute cumulative unique crash count over time for one (case, model).

    Args:
        crashes_data: The crashes.json dict (minimal format).
        resolution: Time step in seconds.
        max_time: End of time axis.  If None, uses duration_seconds from data.

    Returns:
        (times, unique_counts) numpy arrays.
    """
    duration = crashes_data.get("duration_seconds", 0.0)
    if max_time is None:
        max_time = duration
    if max_time <= 0:
        return np.array([0.0]), np.array([0])

    crash_list = crashes_data.get("crashes", [])

    # Pre-sort crashes by first_seen_time
    sorted_crashes = sorted(crash_list, key=lambda c: c.get("first_seen_time", 0))

    times = np.arange(0, max_time + resolution, resolution)
    unique_counts = np.zeros(len(times), dtype=int)

    for i, t in enumerate(times):
        seen_clusters: set[str] = set()
        for c in sorted_crashes:
            if c.get("first_seen_time", 0) <= t:
                cluster = c.get("cluster_id") or c.get("crash_id", "")
                seen_clusters.add(cluster)
            else:
                break  # sorted, so no more crashes at this time
        unique_counts[i] = len(seen_clusters)

    return times, unique_counts


# ---------------------------------------------------------------------------
# Filtering
# ---------------------------------------------------------------------------


def get_unique_crash_count(entry: dict) -> int:
    """Get the unique crash count from a case/model entry.

    Tries the summary field in crashes.json first, then fuzzing_result.json.
    """
    crashes_data = entry.get("crashes", {})
    summary = crashes_data.get("summary", {})
    if "unique_crashes" in summary:
        return summary["unique_crashes"]

    fr = entry.get("fuzzing_result", {})
    return fr.get("unique_crashes", 0)


def filter_data(
    data: dict[str, dict],
    max_crashes: int = 20,
) -> tuple[dict[str, dict], list[str], list[str]]:
    """Filter for complete cases and remove faulty runs.

    Args:
        data: Raw collected results {case_id: {model: entry}}.
        max_crashes: Unique crash threshold for faulty-run detection.

    Returns:
        (filtered_data, incomplete_cases, faulty_cases)
    """
    # Step 1: Determine the full set of models across all cases
    all_models: set[str] = set()
    for case_data in data.values():
        all_models.update(case_data.keys())

    if not all_models:
        return {}, [], []

    print(f"Models found: {sorted(all_models)}", file=sys.stderr)

    # Step 2: Keep only cases that have crashes data for ALL models
    incomplete_cases: list[str] = []
    complete: dict[str, dict] = {}

    for case_id in sorted(data.keys(), key=lambda x: int(x) if x.isdigit() else 0):
        case_data = data[case_id]
        missing = [
            m for m in all_models
            if m not in case_data or not case_data[m].get("crashes")
        ]
        if missing:
            incomplete_cases.append(case_id)
        else:
            complete[case_id] = case_data

    # Step 3: Remove faulty runs (any model in case has unique crashes > threshold)
    faulty_cases: list[str] = []
    filtered: dict[str, dict] = {}

    for case_id, case_data in complete.items():
        faulty = False
        for model, entry in case_data.items():
            uc = get_unique_crash_count(entry)
            if uc > max_crashes:
                faulty = True
                break
        if faulty:
            faulty_cases.append(case_id)
        else:
            filtered[case_id] = case_data

    return filtered, incomplete_cases, faulty_cases


# ---------------------------------------------------------------------------
# Aggregation & plotting
# ---------------------------------------------------------------------------

# Colour palette: distinct, colour-blind-friendly colours
MODEL_COLORS = [
    "#1f77b4",  # blue
    "#ff7f0e",  # orange
    "#2ca02c",  # green
    "#d62728",  # red
    "#9467bd",  # purple
    "#8c564b",  # brown
    "#e377c2",  # pink
    "#7f7f7f",  # grey
    "#bcbd22",  # olive
    "#17becf",  # cyan
]


def plot_aggregate(
    data: dict[str, dict],
    output_path: Optional[str] = None,
    show: bool = False,
    resolution: float = 5.0,
) -> None:
    """Plot aggregate unique crashes vs time, one line per model.

    For each model the line is the mean across all valid cases, and the
    shaded band is +/- 1 standard deviation.
    """
    if not MATPLOTLIB_AVAILABLE:
        print(
            "Error: matplotlib is required.  Install with: pip install matplotlib",
            file=sys.stderr,
        )
        sys.exit(1)

    # Determine models (sorted, gt last)
    all_models: set[str] = set()
    for case_data in data.values():
        all_models.update(case_data.keys())
    models = sorted(all_models - {"gt"})
    if "gt" in all_models:
        models.append("gt")

    if not models:
        print("No models to plot.", file=sys.stderr)
        return

    # Determine common max_time from the data (use median duration)
    durations: list[float] = []
    for case_data in data.values():
        for entry in case_data.values():
            cd = entry.get("crashes", {})
            d = cd.get("duration_seconds", 0)
            if d > 0:
                durations.append(d)
    if not durations:
        print("No duration data available.", file=sys.stderr)
        return
    max_time = float(np.median(durations))
    times = np.arange(0, max_time + resolution, resolution)

    # Compute per-model arrays: shape (n_cases, n_times)
    model_series: dict[str, list[np.ndarray]] = defaultdict(list)

    case_ids = sorted(data.keys(), key=lambda x: int(x) if x.isdigit() else 0)
    for case_id in case_ids:
        case_data = data[case_id]
        for model in models:
            entry = case_data.get(model, {})
            crashes_data = entry.get("crashes", {})
            if not crashes_data:
                continue
            _, counts = compute_unique_crash_timeseries(
                crashes_data, resolution=resolution, max_time=max_time
            )
            # Ensure same length as times (trim or pad)
            if len(counts) > len(times):
                counts = counts[: len(times)]
            elif len(counts) < len(times):
                counts = np.pad(
                    counts, (0, len(times) - len(counts)), constant_values=counts[-1]
                )
            model_series[model].append(counts)

    # --- Plot ---
    fig, ax = plt.subplots(figsize=(10, 6))

    for idx, model in enumerate(models):
        series = model_series.get(model, [])
        if not series:
            continue

        arr = np.array(series)  # (n_cases, n_times)
        mean = arr.mean(axis=0)
        std = arr.std(axis=0)

        color = MODEL_COLORS[idx % len(MODEL_COLORS)]
        label = shorten_model(model)

        # Use dashed line for gt
        linestyle = "--" if model == "gt" else "-"
        linewidth = 2.5 if model == "gt" else 2

        ax.plot(times, mean, color=color, linestyle=linestyle,
                linewidth=linewidth, label=label)
        ax.fill_between(
            times,
            np.maximum(mean - std, 0),
            mean + std,
            color=color,
            alpha=0.15,
        )

    ax.set_xlabel("time fuzzing (s)", fontsize=12)
    ax.set_ylabel("# uniq crashes", fontsize=12)
    ax.set_title(
        f"Unique Crashes Over Time  (n={len(case_ids)} cases)",
        fontsize=14,
        fontweight="bold",
    )
    ax.legend(fontsize=10)
    ax.grid(True, alpha=0.3)
    fig.tight_layout()

    if output_path:
        fig.savefig(output_path, dpi=150, bbox_inches="tight")
        print(f"Plot saved to {output_path}", file=sys.stderr)

    if show:
        plt.show()

    if not output_path and not show:
        # Default: save next to script
        default_path = "crash_timeline.png"
        fig.savefig(default_path, dpi=150, bbox_inches="tight")
        print(f"Plot saved to {default_path}", file=sys.stderr)


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------


def report_filtered(
    data: dict[str, dict],
    incomplete_cases: list[str],
    faulty_cases: list[str],
    all_data: dict[str, dict],
) -> None:
    """Print a report of which cases were kept and which were filtered."""
    total_cases = len(all_data)
    kept = len(data)

    print(f"\n{'='*60}", file=sys.stderr)
    print("Filtering Report", file=sys.stderr)
    print(f"{'='*60}", file=sys.stderr)
    print(f"Total cases found:     {total_cases}", file=sys.stderr)
    print(f"Incomplete (dropped):  {len(incomplete_cases)}", file=sys.stderr)
    print(f"Faulty >20 (dropped):  {len(faulty_cases)}", file=sys.stderr)
    print(f"Cases used in plot:    {kept}", file=sys.stderr)

    if incomplete_cases:
        print(f"\nIncomplete cases (missing models):", file=sys.stderr)
        all_models: set[str] = set()
        for cd in all_data.values():
            all_models.update(cd.keys())
        for cid in incomplete_cases:
            present = set(all_data.get(cid, {}).keys())
            has_crashes = {
                m for m in present
                if all_data[cid][m].get("crashes")
            }
            missing = sorted(all_models - has_crashes)
            print(f"  case {cid}: missing crashes for {missing}", file=sys.stderr)

    if faulty_cases:
        print(f"\nFaulty cases (unique crashes > 20):", file=sys.stderr)
        for cid in faulty_cases:
            parts = []
            for model, entry in sorted(all_data[cid].items()):
                uc = get_unique_crash_count(entry)
                if uc > 20:
                    parts.append(f"{shorten_model(model)}={uc}")
            print(f"  case {cid}: {', '.join(parts)}", file=sys.stderr)

    print(f"{'='*60}\n", file=sys.stderr)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Analyze unique crash timelines from ARVO benchmark results."
    )
    parser.add_argument("experiment_id", help="Experiment ID to analyze")
    parser.add_argument(
        "--bucket", help="GCS bucket name (default: from .gke-config.json)"
    )
    parser.add_argument(
        "--local", "-l",
        help="Read from a local directory instead of downloading from GCS",
    )
    parser.add_argument(
        "--output", "-o",
        help="Output path for the plot image (default: crash_timeline.png)",
    )
    parser.add_argument(
        "--show", action="store_true",
        help="Show plot interactively (in addition to saving)",
    )
    parser.add_argument(
        "--max-crashes", type=int, default=20,
        help="Filter threshold: drop cases where any model has more unique "
             "crashes than this value (default: 20)",
    )
    parser.add_argument(
        "--resolution", type=float, default=5.0,
        help="Time-series resolution in seconds (default: 5.0)",
    )
    args = parser.parse_args()

    if not MATPLOTLIB_AVAILABLE:
        print(
            "Error: matplotlib is required. Install with: pip install matplotlib",
            file=sys.stderr,
        )
        return 1

    # --- Load data ---
    if args.local:
        results_dir = Path(args.local)
    else:
        bucket = args.bucket or get_default_bucket()
        if not bucket:
            print(
                "Error: No bucket configured. "
                "Pass --bucket or configure .gke-config.json",
                file=sys.stderr,
            )
            return 1
        results_dir = download_results(args.experiment_id, bucket)

    print("Parsing results ...", file=sys.stderr)
    all_data = collect_results(results_dir)
    if not all_data:
        print("No results found.", file=sys.stderr)
        return 1

    print(f"Loaded {len(all_data)} cases", file=sys.stderr)

    # --- Filter ---
    filtered, incomplete, faulty = filter_data(all_data, max_crashes=args.max_crashes)

    if not filtered:
        print("No complete, non-faulty cases remain after filtering.", file=sys.stderr)
        report_filtered(filtered, incomplete, faulty, all_data)
        return 1

    # --- Plot ---
    plot_aggregate(
        filtered,
        output_path=args.output,
        show=args.show,
        resolution=args.resolution,
    )

    # --- Report ---
    report_filtered(filtered, incomplete, faulty, all_data)

    return 0


if __name__ == "__main__":
    sys.exit(main())
