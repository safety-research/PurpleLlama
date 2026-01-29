# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

"""
Plot crash timelines from FuzzingOnlyBenchmark results.

Creates matplotlib charts showing crashes over time or executions
for both ground truth and LLM patches.

Usage:
    # Plot all cases in a directory
    python analysis/plot_crash_timeline.py /path/to/output_dir --output plots/

    # Plot a specific case
    python analysis/plot_crash_timeline.py /path/to/output_dir --case 35172 --output case_plot.png

    # Plot with execution count on X-axis
    python analysis/plot_crash_timeline.py /path/to/output_dir --x-axis executions --output exec_plot.png

    # Compare GT vs LLM for all cases
    python analysis/plot_crash_timeline.py /path/to/output_dir --compare --output comparison.png
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

try:
    import matplotlib.pyplot as plt
    import matplotlib.patches as mpatches
    from matplotlib.figure import Figure

    MATPLOTLIB_AVAILABLE = True
except ImportError:
    MATPLOTLIB_AVAILABLE = False


def load_fuzzing_results(results_path: Path) -> List[Dict[str, Any]]:
    """Load fuzzing results from a JSON file or directory."""
    results = []

    if results_path.is_file() and results_path.name == "fuzzing_results.json":
        with open(results_path) as f:
            data = json.load(f)
            if isinstance(data, list):
                results.extend(data)
            else:
                results.append(data)
    elif results_path.is_dir():
        # Look for fuzzing_results.json in the directory
        main_results = results_path / "fuzzing_results.json"
        if main_results.exists():
            with open(main_results) as f:
                data = json.load(f)
                if isinstance(data, list):
                    results.extend(data)
                else:
                    results.append(data)

        # Also look in case subdirectories
        for case_dir in results_path.glob("files/case_*/*/"):
            case_results = case_dir / "fuzzing_results.json"
            if case_results.exists():
                with open(case_results) as f:
                    results.append(json.load(f))

    return results


def extract_timeline_data(
    timeline: Dict[str, Any], x_axis: str = "time"
) -> Tuple[List[float], List[int], List[int]]:
    """Extract x values and crash counts from a timeline.

    Returns:
        (x_values, crash_counts, unique_crash_counts)
    """
    if not timeline:
        return [], [], []

    timestamps = timeline.get("timestamps", [])
    executions = timeline.get("executions", [])
    duration = timeline.get("duration_seconds", 0)
    total_execs = timeline.get("total_executions", 0)

    if x_axis == "time":
        # Generate time-based data points
        max_time = duration if duration > 0 else (max(timestamps) if timestamps else 0)
        if max_time == 0:
            return [], [], []

        resolution = max(1.0, max_time / 100)  # Up to 100 data points
        x_values = []
        crash_counts = []
        unique_counts = []

        t = 0.0
        while t <= max_time:
            x_values.append(t)
            count = sum(1 for ts in timestamps if ts <= t)
            crash_counts.append(count)
            # For unique counts, we'd need cluster info - use raw count as approximation
            unique_counts.append(count)
            t += resolution

        return x_values, crash_counts, unique_counts

    else:  # executions
        max_execs = total_execs if total_execs > 0 else (max(executions) if executions else 0)
        if max_execs == 0:
            return [], [], []

        resolution = max(1000, max_execs // 100)  # Up to 100 data points
        x_values = []
        crash_counts = []
        unique_counts = []

        e = 0
        while e <= max_execs:
            x_values.append(e)
            count = sum(1 for ex in executions if ex <= e)
            crash_counts.append(count)
            unique_counts.append(count)
            e += resolution

        return x_values, crash_counts, unique_counts


def plot_single_case(
    result: Dict[str, Any],
    x_axis: str = "time",
    ax: Optional[plt.Axes] = None,
) -> plt.Axes:
    """Plot crash timeline for a single case."""
    if ax is None:
        _, ax = plt.subplots(figsize=(10, 6))

    case_id = result.get("arvo_challenge_number", "unknown")
    model = result.get("model", "unknown")

    gt_timeline = result.get("gt_crash_timeline", {})
    llm_timeline = result.get("llm_crash_timeline", {})

    # Plot GT timeline
    if gt_timeline:
        x_gt, y_gt, _ = extract_timeline_data(gt_timeline, x_axis)
        if x_gt:
            ax.plot(x_gt, y_gt, "b-", label="Ground Truth", linewidth=2)
            # Mark original crash reproduction
            gt_time_to_orig = result.get("gt_time_to_original_crash")
            if gt_time_to_orig and x_axis == "time":
                ax.axvline(x=gt_time_to_orig, color="b", linestyle="--", alpha=0.5)
                ax.annotate(
                    "GT: Original Crash",
                    xy=(gt_time_to_orig, max(y_gt) * 0.9),
                    fontsize=8,
                    color="blue",
                )

    # Plot LLM timeline
    if llm_timeline:
        x_llm, y_llm, _ = extract_timeline_data(llm_timeline, x_axis)
        if x_llm:
            ax.plot(x_llm, y_llm, "r-", label="LLM Patch", linewidth=2)
            # Mark original crash reproduction
            llm_time_to_orig = result.get("llm_time_to_original_crash")
            if llm_time_to_orig and x_axis == "time":
                ax.axvline(x=llm_time_to_orig, color="r", linestyle="--", alpha=0.5)
                ax.annotate(
                    "LLM: Original Crash",
                    xy=(llm_time_to_orig, max(y_llm) * 0.8),
                    fontsize=8,
                    color="red",
                )

    x_label = "Time (seconds)" if x_axis == "time" else "Executions"
    ax.set_xlabel(x_label)
    ax.set_ylabel("Cumulative Crashes")
    ax.set_title(f"Case {case_id} - {model[:30]}")
    ax.legend()
    ax.grid(True, alpha=0.3)

    return ax


def plot_comparison(
    results: List[Dict[str, Any]],
    x_axis: str = "time",
    output_path: Optional[Path] = None,
) -> Figure:
    """Create a comparison plot of GT vs LLM across all cases."""
    fig, axes = plt.subplots(2, 2, figsize=(14, 10))

    # Aggregate data
    gt_reproduced = sum(1 for r in results if r.get("gt_reproduced_original", False))
    llm_reproduced = sum(1 for r in results if r.get("llm_reproduced_original", False))
    total = len(results)

    # Plot 1: Bar chart of reproduction rates
    ax1 = axes[0, 0]
    categories = ["Ground Truth", "LLM Patch"]
    reproduced = [gt_reproduced, llm_reproduced]
    colors = ["blue", "red"]
    bars = ax1.bar(categories, reproduced, color=colors, alpha=0.7)
    ax1.set_ylabel("Cases Reproduced Original Crash")
    ax1.set_title(f"Original Crash Reproduction (n={total})")
    for bar, count in zip(bars, reproduced):
        ax1.annotate(
            f"{count} ({count/total*100:.1f}%)",
            xy=(bar.get_x() + bar.get_width() / 2, bar.get_height()),
            ha="center",
            va="bottom",
        )

    # Plot 2: Time to original crash distribution
    ax2 = axes[0, 1]
    gt_times = [
        r["gt_time_to_original_crash"]
        for r in results
        if r.get("gt_time_to_original_crash") is not None
    ]
    llm_times = [
        r["llm_time_to_original_crash"]
        for r in results
        if r.get("llm_time_to_original_crash") is not None
    ]

    if gt_times or llm_times:
        data_to_plot = []
        labels = []
        if gt_times:
            data_to_plot.append(gt_times)
            labels.append("GT")
        if llm_times:
            data_to_plot.append(llm_times)
            labels.append("LLM")

        bp = ax2.boxplot(data_to_plot, labels=labels, patch_artist=True)
        colors_box = ["blue", "red"][: len(data_to_plot)]
        for patch, color in zip(bp["boxes"], colors_box):
            patch.set_facecolor(color)
            patch.set_alpha(0.5)
        ax2.set_ylabel("Time (seconds)")
        ax2.set_title("Time to Reproduce Original Crash")

    # Plot 3: Total crashes comparison
    ax3 = axes[1, 0]
    gt_crashes = [r.get("gt_total_crashes", 0) for r in results]
    llm_crashes = [r.get("llm_total_crashes", 0) for r in results]
    case_ids = [str(r.get("arvo_challenge_number", i)) for i, r in enumerate(results)]

    x = range(len(results))
    width = 0.35
    ax3.bar([i - width / 2 for i in x], gt_crashes, width, label="GT", color="blue", alpha=0.7)
    ax3.bar([i + width / 2 for i in x], llm_crashes, width, label="LLM", color="red", alpha=0.7)
    ax3.set_xlabel("Case")
    ax3.set_ylabel("Total Crashes")
    ax3.set_title("Total Crashes by Case")
    ax3.legend()
    if len(case_ids) <= 20:
        ax3.set_xticks(list(x))
        ax3.set_xticklabels(case_ids, rotation=45, ha="right", fontsize=8)

    # Plot 4: Unique crashes comparison
    ax4 = axes[1, 1]
    gt_unique = [r.get("gt_unique_crashes", 0) for r in results]
    llm_unique = [r.get("llm_unique_crashes", 0) for r in results]

    ax4.bar([i - width / 2 for i in x], gt_unique, width, label="GT", color="blue", alpha=0.7)
    ax4.bar([i + width / 2 for i in x], llm_unique, width, label="LLM", color="red", alpha=0.7)
    ax4.set_xlabel("Case")
    ax4.set_ylabel("Unique Crashes")
    ax4.set_title("Unique Crashes by Case (CASR Deduplicated)")
    ax4.legend()
    if len(case_ids) <= 20:
        ax4.set_xticks(list(x))
        ax4.set_xticklabels(case_ids, rotation=45, ha="right", fontsize=8)

    plt.tight_layout()

    if output_path:
        plt.savefig(output_path, dpi=150, bbox_inches="tight")
        print(f"Saved comparison plot to {output_path}")

    return fig


def plot_all_cases(
    results: List[Dict[str, Any]],
    x_axis: str = "time",
    output_dir: Optional[Path] = None,
) -> List[Figure]:
    """Plot each case individually."""
    figures = []

    for result in results:
        case_id = result.get("arvo_challenge_number", "unknown")
        model = result.get("model", "unknown")

        fig, ax = plt.subplots(figsize=(10, 6))
        plot_single_case(result, x_axis, ax)

        if output_dir:
            output_dir.mkdir(parents=True, exist_ok=True)
            model_safe = model.replace("/", "_").replace(":", "_")[:30]
            output_path = output_dir / f"case_{case_id}_{model_safe}_{x_axis}.png"
            plt.savefig(output_path, dpi=150, bbox_inches="tight")
            print(f"Saved {output_path}")

        figures.append(fig)

    return figures


def plot_aggregate_timeline(
    results: List[Dict[str, Any]],
    x_axis: str = "time",
    output_path: Optional[Path] = None,
) -> Figure:
    """Create an aggregate timeline plot showing all cases overlaid."""
    fig, ax = plt.subplots(figsize=(12, 8))

    gt_color = plt.cm.Blues
    llm_color = plt.cm.Reds

    for i, result in enumerate(results):
        case_id = result.get("arvo_challenge_number", i)
        alpha = 0.3 + (i % 5) * 0.1  # Vary alpha for visibility

        gt_timeline = result.get("gt_crash_timeline", {})
        llm_timeline = result.get("llm_crash_timeline", {})

        if gt_timeline:
            x_gt, y_gt, _ = extract_timeline_data(gt_timeline, x_axis)
            if x_gt:
                ax.plot(
                    x_gt,
                    y_gt,
                    color=gt_color(0.5 + i * 0.03),
                    alpha=alpha,
                    linewidth=1,
                )

        if llm_timeline:
            x_llm, y_llm, _ = extract_timeline_data(llm_timeline, x_axis)
            if x_llm:
                ax.plot(
                    x_llm,
                    y_llm,
                    color=llm_color(0.5 + i * 0.03),
                    alpha=alpha,
                    linewidth=1,
                )

    # Add legend
    gt_patch = mpatches.Patch(color="blue", alpha=0.5, label="Ground Truth")
    llm_patch = mpatches.Patch(color="red", alpha=0.5, label="LLM Patch")
    ax.legend(handles=[gt_patch, llm_patch])

    x_label = "Time (seconds)" if x_axis == "time" else "Executions"
    ax.set_xlabel(x_label)
    ax.set_ylabel("Cumulative Crashes")
    ax.set_title(f"Aggregate Crash Timeline ({len(results)} cases)")
    ax.grid(True, alpha=0.3)

    if output_path:
        plt.savefig(output_path, dpi=150, bbox_inches="tight")
        print(f"Saved aggregate plot to {output_path}")

    return fig


def main() -> int:
    if not MATPLOTLIB_AVAILABLE:
        print("Error: matplotlib is required for plotting.", file=sys.stderr)
        print("Install with: pip install matplotlib", file=sys.stderr)
        return 1

    parser = argparse.ArgumentParser(
        description="Plot crash timelines from FuzzingOnlyBenchmark results."
    )
    parser.add_argument(
        "input_path",
        type=Path,
        help="Path to fuzzing_results.json or output directory",
    )
    parser.add_argument(
        "--output",
        "-o",
        type=Path,
        help="Output path for plot (file or directory)",
    )
    parser.add_argument(
        "--case",
        type=int,
        help="Plot only a specific case by ARVO ID",
    )
    parser.add_argument(
        "--x-axis",
        choices=["time", "executions"],
        default="time",
        help="X-axis type (default: time)",
    )
    parser.add_argument(
        "--compare",
        action="store_true",
        help="Create comparison summary plot",
    )
    parser.add_argument(
        "--aggregate",
        action="store_true",
        help="Create aggregate timeline plot with all cases overlaid",
    )
    parser.add_argument(
        "--show",
        action="store_true",
        help="Show plots interactively (in addition to saving)",
    )

    args = parser.parse_args()

    # Load results
    results = load_fuzzing_results(args.input_path)
    if not results:
        print(f"No fuzzing results found at {args.input_path}", file=sys.stderr)
        return 1

    print(f"Loaded {len(results)} fuzzing result(s)")

    # Filter to specific case if requested
    if args.case is not None:
        results = [r for r in results if r.get("arvo_challenge_number") == args.case]
        if not results:
            print(f"No results found for case {args.case}", file=sys.stderr)
            return 1

    # Generate plots
    if args.compare:
        output_path = args.output if args.output else Path("comparison.png")
        plot_comparison(results, args.x_axis, output_path)
    elif args.aggregate:
        output_path = args.output if args.output else Path("aggregate.png")
        plot_aggregate_timeline(results, args.x_axis, output_path)
    elif len(results) == 1:
        # Single case
        fig, ax = plt.subplots(figsize=(10, 6))
        plot_single_case(results[0], args.x_axis, ax)
        if args.output:
            plt.savefig(args.output, dpi=150, bbox_inches="tight")
            print(f"Saved plot to {args.output}")
    else:
        # Multiple cases - plot each
        output_dir = args.output if args.output else Path("plots")
        plot_all_cases(results, args.x_axis, output_dir)

    if args.show:
        plt.show()

    return 0


if __name__ == "__main__":
    sys.exit(main())
