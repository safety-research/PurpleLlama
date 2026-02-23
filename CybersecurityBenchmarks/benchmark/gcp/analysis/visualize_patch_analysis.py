#!/usr/bin/env python3
"""
Visualize blinded pairwise patch comparison analysis results.

Loads report.json + blinding_key.json for each case, unblinds the results,
and produces summary statistics and charts.

Usage:
    python visualize_patch_analysis.py /tmp/analysis-results/analysis-YYYYMMDD-HHMMSS
    python visualize_patch_analysis.py /tmp/analysis-results/analysis-YYYYMMDD-HHMMSS --output report.png
"""

import argparse
import json
import os
import sys
from collections import Counter
from pathlib import Path

import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import numpy as np


def load_results(results_dir: str) -> list[dict]:
    """Load and unblind all analysis reports."""
    results = []
    results_path = Path(results_dir)

    for case_dir in sorted(results_path.iterdir()):
        if not case_dir.is_dir():
            continue
        case_id = case_dir.name

        for pair_dir in case_dir.iterdir():
            if not pair_dir.is_dir():
                continue

            report_path = pair_dir / "report.json"
            blinding_key_path = pair_dir / "blinding_key.json"

            if not report_path.exists():
                continue

            with open(report_path) as f:
                report = json.load(f)

            # Load blinding key to unblind
            blinding_key = {}
            if blinding_key_path.exists():
                with open(blinding_key_path) as f:
                    blinding_key = json.load(f)

            # Unblind: map patch_a/patch_b back to actual patcher names
            patch_a_patcher = blinding_key.get("patch_a_patcher", "unknown_a")
            patch_b_patcher = blinding_key.get("patch_b_patcher", "unknown_b")

            # Build unblinded result
            result = {
                "case_id": case_id,
                "status": report.get("status", "unknown"),
                "duration_seconds": report.get("duration_seconds", 0),
                # Vulnerability info
                "crash_type": report.get("vulnerability", {}).get("type", ""),
                "root_cause": report.get("vulnerability", {}).get(
                    "root_cause_description", ""
                ),
                # Unblinded patch analysis
                "patchers": {
                    patch_a_patcher: report.get("patch_a", {}),
                    patch_b_patcher: report.get("patch_b", {}),
                },
                # Comparison (unblinded)
                "similarity": report.get("comparison", {}).get("similarity", "unknown"),
                "which_is_better_blinded": report.get("comparison", {}).get(
                    "which_is_better", "equivalent"
                ),
                "simpler_patch_blinded": report.get("comparison", {}).get(
                    "simpler_patch", "equivalent"
                ),
                "key_differences": report.get("comparison", {}).get(
                    "key_differences", []
                ),
                "reasoning": report.get("comparison", {}).get("reasoning", ""),
                # Blinding key for unblinding "better"/"simpler"
                "patch_a_patcher": patch_a_patcher,
                "patch_b_patcher": patch_b_patcher,
            }

            # Unblind "which_is_better" and "simpler_patch"
            better = result["which_is_better_blinded"]
            if better == "a":
                result["which_is_better"] = patch_a_patcher
            elif better == "b":
                result["which_is_better"] = patch_b_patcher
            else:
                result["which_is_better"] = "equivalent"

            simpler = result["simpler_patch_blinded"]
            if simpler == "a":
                result["simpler_patch"] = patch_a_patcher
            elif simpler == "b":
                result["simpler_patch"] = patch_b_patcher
            else:
                result["simpler_patch"] = "equivalent"

            results.append(result)

    return results


def print_summary(results: list[dict]) -> None:
    """Print text summary of analysis results."""
    n = len(results)
    completed = [r for r in results if r["status"] == "completed"]
    print(f"Total cases: {n}")
    print(f"Completed: {len(completed)}")
    print(f"Failed/timeout: {n - len(completed)}")
    print()

    # Use only completed results for stats
    results = completed

    # --- Similarity distribution ---
    sim_counts = Counter(r["similarity"] for r in results)
    print("=== Patch Similarity (claude-opus-4-6 vs GT) ===")
    for sim in [
        "identical",
        "similar_approach",
        "different_approach",
        "fundamentally_different",
    ]:
        count = sim_counts.get(sim, 0)
        pct = count / len(results) * 100 if results else 0
        bar = "#" * int(pct / 2)
        print(f"  {sim:30s}  {count:3d} ({pct:5.1f}%)  {bar}")
    print()

    # --- Which is better ---
    better_counts = Counter(r["which_is_better"] for r in results)
    print("=== Which Patch is Better? ===")
    for patcher in sorted(better_counts.keys()):
        count = better_counts[patcher]
        pct = count / len(results) * 100 if results else 0
        print(f"  {patcher:40s}  {count:3d} ({pct:5.1f}%)")
    print()

    # --- Which is simpler ---
    simpler_counts = Counter(r["simpler_patch"] for r in results)
    print("=== Which Patch is Simpler? ===")
    for patcher in sorted(simpler_counts.keys()):
        count = simpler_counts[patcher]
        pct = count / len(results) * 100 if results else 0
        print(f"  {patcher:40s}  {count:3d} ({pct:5.1f}%)")
    print()

    # --- Approach type distribution ---
    print("=== Approach Types ===")
    for patcher_name in ["claudecode-claude-opus-4-6", "gt"]:
        approaches = Counter()
        for r in results:
            info = r["patchers"].get(patcher_name, {})
            approaches[info.get("approach_type", "unknown")] += 1
        print(f"  {patcher_name}:")
        for approach in [
            "root_cause_fix",
            "symptom_masking",
            "incomplete_fix",
            "overly_broad",
            "no_op",
            "unknown",
        ]:
            count = approaches.get(approach, 0)
            if count > 0:
                pct = count / len(results) * 100
                print(f"    {approach:25s}  {count:3d} ({pct:5.1f}%)")
    print()

    # --- Correctness distribution ---
    print("=== Correctness ===")
    for patcher_name in ["claudecode-claude-opus-4-6", "gt"]:
        correctness = Counter()
        for r in results:
            info = r["patchers"].get(patcher_name, {})
            correctness[info.get("correctness", "unknown")] += 1
        print(f"  {patcher_name}:")
        for level in ["correct", "partial", "incorrect", "unknown"]:
            count = correctness.get(level, 0)
            if count > 0:
                pct = count / len(results) * 100
                print(f"    {level:25s}  {count:3d} ({pct:5.1f}%)")
    print()

    # --- Duration stats ---
    durations = [r["duration_seconds"] for r in results if r["duration_seconds"] > 0]
    if durations:
        print("=== Analysis Duration ===")
        print(f"  Mean:   {np.mean(durations):7.1f}s")
        print(f"  Median: {np.median(durations):7.1f}s")
        print(f"  Min:    {np.min(durations):7.1f}s")
        print(f"  Max:    {np.max(durations):7.1f}s")
        print()


def plot_results(results: list[dict], output_path: str | None = None) -> None:
    """Create visualization of analysis results."""
    completed = [r for r in results if r["status"] == "completed"]
    if not completed:
        print("No completed results to plot.")
        return

    fig, axes = plt.subplots(2, 2, figsize=(16, 12))
    fig.suptitle(
        f"Patch Comparison Analysis: claude-opus-4-6 vs Ground Truth\n"
        f"({len(completed)} cases)",
        fontsize=14,
        fontweight="bold",
    )

    # Color palette
    colors = {
        "identical": "#2ecc71",
        "similar_approach": "#3498db",
        "different_approach": "#f39c12",
        "fundamentally_different": "#e74c3c",
    }
    patcher_colors = {
        "claudecode-claude-opus-4-6": "#8e44ad",
        "gt": "#27ae60",
        "equivalent": "#95a5a6",
    }
    correctness_colors = {
        "correct": "#2ecc71",
        "partial": "#f39c12",
        "incorrect": "#e74c3c",
        "unknown": "#95a5a6",
    }

    # --- Plot 1: Similarity distribution (pie) ---
    ax = axes[0, 0]
    sim_counts = Counter(r["similarity"] for r in completed)
    labels_order = [
        "identical",
        "similar_approach",
        "different_approach",
        "fundamentally_different",
    ]
    sizes = [sim_counts.get(s, 0) for s in labels_order]
    display_labels = [s.replace("_", " ").title() for s in labels_order]
    pie_colors = [colors[s] for s in labels_order]

    # Filter out zero slices
    non_zero = [(l, s, c) for l, s, c in zip(display_labels, sizes, pie_colors) if s > 0]
    if non_zero:
        nl, ns, nc = zip(*non_zero)
        wedges, texts, autotexts = ax.pie(
            ns,
            labels=nl,
            colors=nc,
            autopct=lambda pct: f"{pct:.0f}%\n({int(round(pct/100*sum(ns)))})"
            if pct > 3
            else "",
            startangle=90,
            textprops={"fontsize": 10},
        )
    ax.set_title("Patch Similarity", fontsize=12, fontweight="bold")

    # --- Plot 2: Which is better (bar) ---
    ax = axes[0, 1]
    better_counts = Counter(r["which_is_better"] for r in completed)
    bar_labels = ["claudecode-claude-opus-4-6", "equivalent", "gt"]
    bar_display = ["Claude Opus 4.6", "Equivalent", "Ground Truth"]
    bar_values = [better_counts.get(l, 0) for l in bar_labels]
    bar_colors = [patcher_colors.get(l, "#bdc3c7") for l in bar_labels]

    bars = ax.bar(bar_display, bar_values, color=bar_colors, edgecolor="white", width=0.6)
    for bar, val in zip(bars, bar_values):
        if val > 0:
            ax.text(
                bar.get_x() + bar.get_width() / 2,
                bar.get_height() + 0.5,
                f"{val} ({val/len(completed)*100:.0f}%)",
                ha="center",
                va="bottom",
                fontweight="bold",
                fontsize=11,
            )
    ax.set_title("Which Patch is Better?", fontsize=12, fontweight="bold")
    ax.set_ylabel("Number of Cases")
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)

    # --- Plot 3: Correctness comparison (grouped bar) ---
    ax = axes[1, 0]
    correctness_levels = ["correct", "partial", "incorrect", "unknown"]
    x = np.arange(len(correctness_levels))
    width = 0.35

    opus_correctness = Counter()
    gt_correctness = Counter()
    for r in completed:
        opus_info = r["patchers"].get("claudecode-claude-opus-4-6", {})
        gt_info = r["patchers"].get("gt", {})
        opus_correctness[opus_info.get("correctness", "unknown")] += 1
        gt_correctness[gt_info.get("correctness", "unknown")] += 1

    opus_vals = [opus_correctness.get(c, 0) for c in correctness_levels]
    gt_vals = [gt_correctness.get(c, 0) for c in correctness_levels]

    bars1 = ax.bar(
        x - width / 2, opus_vals, width, label="Claude Opus 4.6", color="#8e44ad", alpha=0.85
    )
    bars2 = ax.bar(
        x + width / 2, gt_vals, width, label="Ground Truth", color="#27ae60", alpha=0.85
    )

    for bars in [bars1, bars2]:
        for bar in bars:
            h = bar.get_height()
            if h > 0:
                ax.text(
                    bar.get_x() + bar.get_width() / 2,
                    h + 0.3,
                    str(int(h)),
                    ha="center",
                    va="bottom",
                    fontsize=10,
                )

    ax.set_xticks(x)
    ax.set_xticklabels([c.title() for c in correctness_levels])
    ax.set_title("Patch Correctness", fontsize=12, fontweight="bold")
    ax.set_ylabel("Number of Cases")
    ax.legend()
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)

    # --- Plot 4: Approach type comparison (grouped bar) ---
    ax = axes[1, 1]
    approach_types = [
        "root_cause_fix",
        "symptom_masking",
        "incomplete_fix",
        "overly_broad",
        "no_op",
    ]
    x = np.arange(len(approach_types))

    opus_approaches = Counter()
    gt_approaches = Counter()
    for r in completed:
        opus_info = r["patchers"].get("claudecode-claude-opus-4-6", {})
        gt_info = r["patchers"].get("gt", {})
        opus_approaches[opus_info.get("approach_type", "unknown")] += 1
        gt_approaches[gt_info.get("approach_type", "unknown")] += 1

    opus_vals = [opus_approaches.get(a, 0) for a in approach_types]
    gt_vals = [gt_approaches.get(a, 0) for a in approach_types]

    bars1 = ax.bar(
        x - width / 2, opus_vals, width, label="Claude Opus 4.6", color="#8e44ad", alpha=0.85
    )
    bars2 = ax.bar(
        x + width / 2, gt_vals, width, label="Ground Truth", color="#27ae60", alpha=0.85
    )

    for bars in [bars1, bars2]:
        for bar in bars:
            h = bar.get_height()
            if h > 0:
                ax.text(
                    bar.get_x() + bar.get_width() / 2,
                    h + 0.3,
                    str(int(h)),
                    ha="center",
                    va="bottom",
                    fontsize=10,
                )

    ax.set_xticks(x)
    ax.set_xticklabels([a.replace("_", "\n") for a in approach_types], fontsize=9)
    ax.set_title("Patch Approach Type", fontsize=12, fontweight="bold")
    ax.set_ylabel("Number of Cases")
    ax.legend()
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)

    plt.tight_layout()

    if output_path:
        plt.savefig(output_path, dpi=150, bbox_inches="tight")
        print(f"Saved plot to {output_path}")
    else:
        plt.show()


def main():
    parser = argparse.ArgumentParser(
        description="Visualize patch comparison analysis results"
    )
    parser.add_argument("results_dir", help="Path to analysis results directory")
    parser.add_argument("--output", "-o", help="Output path for plot image")
    parser.add_argument(
        "--no-plot", action="store_true", help="Skip plotting, only print summary"
    )
    args = parser.parse_args()

    results = load_results(args.results_dir)
    if not results:
        print(f"No results found in {args.results_dir}")
        sys.exit(1)

    print_summary(results)

    if not args.no_plot:
        output = args.output or os.path.join(args.results_dir, "analysis_summary.png")
        plot_results(results, output)


if __name__ == "__main__":
    main()
