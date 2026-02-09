# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

"""
Plot crash timelines from ARVO benchmark results (multi-agent).

Reads the same directory structure produced by check_results.py:
    case_id/model_name/fuzzing_result.json

Creates matplotlib charts showing cumulative unique crashes and
regressions over time for all agents (GT + LLM models).

Usage:
    # Download from GCS and show comparison in popup viewer
    python analysis/plot_crash_timeline.py fuzz1800_all --compare

    # Save to file instead of popup
    python analysis/plot_crash_timeline.py fuzz1800_all --compare -o plots/comparison.png

    # Use previously downloaded local data
    python analysis/plot_crash_timeline.py fuzz1800_all -l /tmp/arvo-results-xxx --compare

    # Plot individual case timelines (popup)
    python analysis/plot_crash_timeline.py fuzz1800_all -l /tmp/data --case 11429

    # Plot all cases with crashes (one PNG per case, always saves to dir)
    python analysis/plot_crash_timeline.py fuzz1800_all -l /tmp/data -o plots/

    # Aggregate crash curves across all cases
    python analysis/plot_crash_timeline.py fuzz1800_all -l /tmp/data --aggregate
"""

from __future__ import annotations

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

try:
    import matplotlib

    # Use a GUI backend when available; fall back to Agg for headless.
    try:
        matplotlib.use("TkAgg")
    except ImportError:
        pass

    import matplotlib.pyplot as plt
    import matplotlib.patches as mpatches
    import numpy as np
    from matplotlib.figure import Figure

    plt.style.use("seaborn-v0_8-paper")
    # plt.rcParams.update(
    #     {
    #         "font.family": "serif",
    #         "font.serif": ["Times New Roman", "DejaVu Serif", "Bitstream Vera Serif"],
    #         "mathtext.fontset": "dejavuserif",
    #         "font.size": 10,
    #         "axes.titlesize": 11,
    #         "axes.titleweight": "bold",
    #         "axes.labelsize": 10,
    #         "legend.fontsize": 8,
    #         "legend.frameon": True,
    #         "legend.framealpha": 0.9,
    #         "legend.edgecolor": "#cccccc",
    #         "figure.facecolor": "white",
    #         "axes.facecolor": "white",
    #         "axes.edgecolor": "black",
    #         "axes.linewidth": 0.8,
    #         "axes.grid": True,
    #         "grid.color": "#e0e0e0",
    #         "grid.linewidth": 0.5,
    #         "grid.linestyle": "--",
    #         "xtick.direction": "in",
    #         "ytick.direction": "in",
    #         "xtick.major.size": 4,
    #         "ytick.major.size": 4,
    #         "xtick.minor.visible": True,
    #         "ytick.minor.visible": True,
    #         "xtick.minor.size": 2,
    #         "ytick.minor.size": 2,
    #         "figure.dpi": 150,
    #         "savefig.dpi": 300,
    #         "savefig.bbox": "tight",
    #     }
    # )

    MATPLOTLIB_AVAILABLE = True
except ImportError:
    MATPLOTLIB_AVAILABLE = False


# ---------------------------------------------------------------------------
# Resolve paths relative to this script
# ---------------------------------------------------------------------------
SCRIPT_DIR = Path(__file__).parent.resolve()
REPO_ROOT = SCRIPT_DIR.parent
GKE_CONFIG = REPO_ROOT / "benchmark" / "gcp" / ".gke-config.json"


def get_default_bucket() -> str:
    if GKE_CONFIG.exists():
        with open(GKE_CONFIG) as f:
            return json.load(f).get("bucket_name", "")
    return ""


# ---------------------------------------------------------------------------
# Data loading (mirrors check_results.py)
# ---------------------------------------------------------------------------


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


def collect_results(results_dir: Path) -> dict[str, dict[str, dict]]:
    """
    Walk results directory and collect fuzzing results per case per model.

    Returns: {case_id: {model_name: {fuzzing_result, patch_result, ...}}}
    """
    data: dict[str, dict[str, dict]] = {}

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

            regression = read_argo_artifact(model_dir / "regression_analysis.json")
            if regression:
                entry["regression"] = regression

            if entry:
                data[case_id][model] = entry

    return data


def download_from_gcs(bucket: str, experiment_id: str) -> Path:
    """Download experiment results from GCS, return local directory."""
    gcs_path = f"gs://{bucket}/results/{experiment_id}/"
    print(f"Fetching results from {gcs_path} ...", file=sys.stderr)

    tmpdir = Path(tempfile.mkdtemp(prefix=f"arvo-results-{experiment_id}-"))
    print(f"Downloading to {tmpdir} ...", file=sys.stderr)

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
            f"Warning: gsutil rsync had issues: {result.stderr[:200]}", file=sys.stderr
        )

    return tmpdir


# ---------------------------------------------------------------------------
# Model display helpers
# ---------------------------------------------------------------------------

# Agent family -> (color, linestyle, marker, linewidth)
# Colors chosen for maximum contrast; linestyles vary so overlapping lines
# are still distinguishable in B&W or when colors are close.
AGENT_STYLES: dict[str, dict] = {
    "gt": {"color": "#2ca02c", "ls": "--", "marker": "", "lw": 2.5},
    "apb-haiku": {"color": "#1f77b4", "ls": "-", "marker": "o", "lw": 1.6},
    "apb-opus": {"color": "#ff7f0e", "ls": "-", "marker": "s", "lw": 1.6},
    "apb-sonnet": {"color": "#d62728", "ls": "-", "marker": "^", "lw": 1.6},
    "cc-haiku": {"color": "#0b8a8f", "ls": "-", "marker": "D", "lw": 1.6},  # dark teal
    "cc-opus": {"color": "#6a3d9a", "ls": "-", "marker": "P", "lw": 1.6},  # purple
    "cc-sonnet": {"color": "#c44e9e", "ls": "-", "marker": "v", "lw": 1.6},  # magenta
    "gtbp-opus": {"color": "#555555", "ls": "-", "marker": "X", "lw": 1.6},  # dark gray
}

# Backward-compat lookup
AGENT_PALETTE = {k: v["color"] for k, v in AGENT_STYLES.items()}


def shorten_model(name: str) -> str:
    """Shorten model name for plot labels."""
    replacements = [
        ("claude-", ""),
        ("autopatchbench-claude-", "apb-"),
        ("autopatchbench-", "apb-"),
        ("claudecode-claude-", "cc-"),
        ("claudecode-", "cc-"),
        ("gtbackporter-claude-", "gtbp-"),
        ("gtbackporter-", "gtbp-"),
        ("-20251001", ""),
        ("-20251101", ""),
        ("-20250929", ""),
        ("-20250514", ""),
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


def get_model_style(model: str) -> dict:
    """Return plot style dict (color, ls, marker, lw) for a model."""
    short = shorten_model(model).lower()
    for key, style in AGENT_STYLES.items():
        if key in short:
            return dict(style)
    # Fallback
    idx = hash(model) % 20
    cmap = plt.colormaps.get_cmap("tab20")
    rgba = cmap(idx)
    color = "#{:02x}{:02x}{:02x}".format(
        int(rgba[0] * 255), int(rgba[1] * 255), int(rgba[2] * 255)
    )
    return {"color": color, "ls": "-", "marker": "", "lw": 1.5}


def get_model_color(model: str) -> str:
    """Return a consistent color for a model."""
    return get_model_style(model)["color"]


def get_sorted_models(all_models: set[str]) -> list[str]:
    """Sort models: LLMs alphabetically, gt last."""
    models = sorted(all_models - {"gt"})
    if "gt" in all_models:
        models.append("gt")
    return models


def get_common_success_cases(
    data: dict[str, dict[str, dict]], models: list[str]
) -> set[str]:
    """Return case IDs where every LLM agent patched successfully.

    GT is excluded from the requirement (it has no patch concept).
    """
    llm_models = [m for m in models if m != "gt"]
    common = set(data.keys())
    for m in llm_models:
        ok: set[str] = set()
        for cid, case_data in data.items():
            pr = case_data.get(m, {}).get("patch_result", {})
            if pr.get("patch_successful") or pr.get("crash_fixed"):
                ok.add(cid)
        common &= ok
    return common


# ---------------------------------------------------------------------------
# Timeline extraction
# ---------------------------------------------------------------------------


def _get_timeline_crashes(entry: dict) -> tuple[list[dict], float]:
    """Return (sorted crash list, duration) from a fuzzing_result entry."""
    fr = entry.get("fuzzing_result", {})
    timeline = fr.get("timeline", {})
    duration = fr.get("duration_seconds") or timeline.get("duration_seconds") or 0
    crashes = timeline.get("crashes", [])
    sorted_crashes = sorted(crashes, key=lambda c: c.get("first_seen_time", 0))
    return sorted_crashes, duration


def extract_all_crash_times(entry: dict) -> tuple[list[float], float]:
    """
    Extract *all* crash timestamps (total, not deduplicated).

    Returns: (sorted crash times, duration_seconds)
    """
    crashes, duration = _get_timeline_crashes(entry)
    times = [c["first_seen_time"] for c in crashes if "first_seen_time" in c]
    return sorted(times), duration


def extract_unique_crash_times(entry: dict) -> tuple[list[float], float]:
    """
    Extract the *first-seen time of each unique cluster* and the duration.

    Returns: (sorted unique crash times, duration_seconds)
    """
    crashes, duration = _get_timeline_crashes(entry)
    seen_clusters: set[str] = set()
    times: list[float] = []
    for c in crashes:
        cluster = c.get("cluster_id", c.get("crash_id", ""))
        if cluster not in seen_clusters:
            seen_clusters.add(cluster)
            t = c.get("first_seen_time")
            if t is not None:
                times.append(t)
    return sorted(times), duration


def extract_regression_crash_times(entry: dict) -> tuple[list[float], float]:
    """
    Extract first-seen times of *regression* crashes (LLM-introduced only).

    Uses regression_analysis.json to classify each unique crash, then maps
    back to the timeline to get the first-seen time for each regression cluster.

    Returns: (sorted regression crash times, duration_seconds)
    """
    regression = entry.get("regression", {})
    if not regression:
        # No regression analysis — still return the fuzzing duration so this
        # case counts as 0 regressions in the average (not skipped).
        _, duration = _get_timeline_crashes(entry)
        return [], duration

    # Build set of crash_ids classified as regressions
    reg_crash_ids: set[str] = set()
    for d in regression.get("details", []):
        if d.get("classification") == "regression":
            cid = d.get("llm_crash")
            if cid:
                reg_crash_ids.add(cid)

    if not reg_crash_ids:
        crashes, duration = _get_timeline_crashes(entry)
        return [], duration

    crashes, duration = _get_timeline_crashes(entry)

    # Map regression crash_ids -> their cluster_ids
    reg_clusters: set[str] = set()
    for c in crashes:
        if c.get("crash_id") in reg_crash_ids:
            cluster = c.get("cluster_id", c.get("crash_id", ""))
            reg_clusters.add(cluster)

    # Find first-seen time for each regression cluster
    seen: set[str] = set()
    times: list[float] = []
    for c in crashes:
        cluster = c.get("cluster_id", c.get("crash_id", ""))
        if cluster in reg_clusters and cluster not in seen:
            seen.add(cluster)
            t = c.get("first_seen_time")
            if t is not None:
                times.append(t)

    return sorted(times), duration


def cumulative_curve(
    crash_times: list[float], duration: float, resolution: int = 200
) -> tuple[list[float], list[int]]:
    """
    Build a cumulative crash count curve.

    Returns (x_values, y_values) where x is time in seconds.
    """
    if not duration:
        return [], []

    step = max(duration / resolution, 0.5)
    xs: list[float] = []
    ys: list[int] = []

    t = 0.0
    idx = 0
    n = len(crash_times)
    while t <= duration:
        while idx < n and crash_times[idx] <= t:
            idx += 1
        xs.append(t)
        ys.append(idx)
        t += step

    # Make sure we include the endpoint
    if not xs or xs[-1] < duration:
        xs.append(duration)
        ys.append(n)

    return xs, ys


# ---------------------------------------------------------------------------
# Plotting functions
# ---------------------------------------------------------------------------


def _plot_timeline_on_ax(
    ax: plt.Axes,
    case_data: dict[str, dict],
    models: list[str],
    extractor,
    ylabel: str,
    title: str,
) -> None:
    """Plot cumulative curves for all agents on a single axes."""
    for model in models:
        if model not in case_data:
            continue
        entry = case_data[model]
        crash_times, duration = extractor(entry)

        if not duration:
            continue

        xs, ys = cumulative_curve(crash_times, duration)
        if not xs:
            continue

        label = shorten_model(model)
        sty = get_model_style(model)
        markevery = max(1, len(xs) // 8)  # ~8 markers per line

        ax.plot(
            xs,
            ys,
            color=sty["color"],
            linewidth=sty["lw"],
            linestyle=sty["ls"],
            marker=sty["marker"],
            markersize=6,
            markevery=markevery,
            markeredgecolor="black",
            markeredgewidth=0.5,
            alpha=0.9,
            label=f"{label} ({max(ys)})",
        )

    ax.set_xlabel("Time (seconds)")
    ax.set_ylabel(ylabel)
    ax.set_title(title)
    ax.legend(fontsize=7, loc="upper left", ncol=2)
    ax.grid(True, alpha=0.3)


def plot_single_case(
    case_id: str,
    data: dict[str, dict[str, dict]],
    models: list[str],
    output_path: Optional[Path] = None,
) -> Figure:
    """Plot a single case: unique crashes (left) and regressions (right)."""
    case_data = data[case_id]

    # Check if any agent has regression data for this case
    has_reg = any(case_data.get(m, {}).get("regression") for m in models)

    if has_reg:
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(20, 6))
    else:
        fig, ax1 = plt.subplots(figsize=(13, 6))
        ax2 = None

    _plot_timeline_on_ax(
        ax1,
        case_data,
        models,
        extract_unique_crash_times,
        "Cumulative Unique Crashes",
        f"Case {case_id} — Unique Crashes",
    )

    if ax2 is not None:
        _plot_timeline_on_ax(
            ax2,
            case_data,
            models,
            extract_regression_crash_times,
            "Cumulative Regressions",
            f"Case {case_id} — Regressions (LLM-Introduced)",
        )

    plt.tight_layout()
    if output_path:
        plt.savefig(output_path, dpi=150, bbox_inches="tight")
        print(f"Saved {output_path}")

    return fig


def plot_all_cases(
    data: dict[str, dict[str, dict]],
    models: list[str],
    output_dir: Path,
    min_crashes: int = 1,
) -> int:
    """Plot each case with crashes individually. Returns count of plots created."""
    output_dir.mkdir(parents=True, exist_ok=True)
    count = 0

    cases = sorted(data.keys(), key=lambda x: int(x) if x.isdigit() else 0)
    for case_id in cases:
        case_data = data[case_id]
        # Skip cases with zero crashes across all agents
        total = sum(
            case_data.get(m, {}).get("fuzzing_result", {}).get("total_crashes", 0)
            for m in models
        )
        if total < min_crashes:
            continue

        fig = plot_single_case(
            case_id,
            data,
            models,
            output_dir / f"case_{case_id}.png",
        )
        plt.close(fig)
        count += 1

    return count


def plot_comparison(
    data: dict[str, dict[str, dict]],
    models: list[str],
    output_path: Optional[Path] = None,
) -> Figure:
    """Create multi-panel comparison summary across all agents."""
    fig, axes = plt.subplots(2, 3, figsize=(20, 11))

    n_cases = len(data)
    labels = [shorten_model(m) for m in models]
    colors = [get_model_color(m) for m in models]

    # --- Collect per-model aggregates ---
    total_crashes = []
    unique_crashes = []
    regressions = []
    pre_existing = []
    no_crash_counts = []
    patch_ok = []
    patch_total = []

    for m in models:
        tc = uc = reg = pe = nc = pok = ptot = 0
        for case_data in data.values():
            if m not in case_data:
                continue
            fr = case_data[m].get("fuzzing_result", {})
            tc += fr.get("total_crashes", 0)
            uc += fr.get("unique_crashes", 0)
            if fr.get("total_crashes", 0) == 0:
                nc += 1

            ra = case_data[m].get("regression", {})
            if ra:
                reg += ra.get("regressions", 0)
                pe += ra.get("pre_existing", 0)

            pr = case_data[m].get("patch_result", {})
            if pr:
                ptot += 1
                if pr.get("patch_successful") or pr.get("crash_fixed"):
                    pok += 1

        total_crashes.append(tc)
        unique_crashes.append(uc)
        regressions.append(reg)
        pre_existing.append(pe)
        no_crash_counts.append(nc)
        patch_ok.append(pok)
        patch_total.append(ptot)

    x = np.arange(len(models))
    bar_kw = dict(edgecolor="white", linewidth=0.5)

    # Panel 1: Unique crashes per agent
    ax1 = axes[0, 0]
    bars = ax1.bar(x, unique_crashes, color=colors, **bar_kw)
    ax1.set_xticks(x)
    ax1.set_xticklabels(labels, rotation=35, ha="right", fontsize=8)
    ax1.set_ylabel("Unique Crashes (sum)")
    ax1.set_title(f"Total Unique Crashes ({n_cases} cases)")
    for bar, val in zip(bars, unique_crashes):
        ax1.annotate(
            str(val),
            xy=(bar.get_x() + bar.get_width() / 2, bar.get_height()),
            ha="center",
            va="bottom",
            fontsize=7,
        )

    # Panel 2: Regressions per agent
    ax2 = axes[0, 1]
    bars = ax2.bar(x, regressions, color=colors, **bar_kw)
    ax2.set_xticks(x)
    ax2.set_xticklabels(labels, rotation=35, ha="right", fontsize=8)
    ax2.set_ylabel("Regressions")
    ax2.set_title("LLM-Introduced Regressions")
    for bar, val in zip(bars, regressions):
        if val > 0:
            ax2.annotate(
                str(val),
                xy=(bar.get_x() + bar.get_width() / 2, bar.get_height()),
                ha="center",
                va="bottom",
                fontsize=7,
            )

    # Panel 3: No-crash cases per agent
    ax3 = axes[0, 2]
    bars = ax3.bar(x, no_crash_counts, color=colors, **bar_kw)
    ax3.set_xticks(x)
    ax3.set_xticklabels(labels, rotation=35, ha="right", fontsize=8)
    ax3.set_ylabel("Cases")
    ax3.set_title("Cases with Zero Crashes")
    for bar, val in zip(bars, no_crash_counts):
        ax3.annotate(
            str(val),
            xy=(bar.get_x() + bar.get_width() / 2, bar.get_height()),
            ha="center",
            va="bottom",
            fontsize=7,
        )

    # Panel 4: Patch success rate
    ax4 = axes[1, 0]
    rates = [
        pok / ptot * 100 if ptot > 0 else 0 for pok, ptot in zip(patch_ok, patch_total)
    ]
    bars = ax4.bar(x, rates, color=colors, **bar_kw)
    ax4.set_xticks(x)
    ax4.set_xticklabels(labels, rotation=35, ha="right", fontsize=8)
    ax4.set_ylabel("Success %")
    ax4.set_ylim(0, 105)
    ax4.set_title("Patch Success Rate")
    for bar, val, pok_v, ptot_v in zip(bars, rates, patch_ok, patch_total):
        lbl = f"{val:.0f}%\n({pok_v}/{ptot_v})" if ptot_v > 0 else "N/A"
        ax4.annotate(
            lbl,
            xy=(bar.get_x() + bar.get_width() / 2, bar.get_height()),
            ha="center",
            va="bottom",
            fontsize=6,
        )

    # Panel 5: Stacked bar — regressions vs pre-existing vs clean
    ax5 = axes[1, 1]
    clean = [
        uc - reg - pe for uc, reg, pe in zip(unique_crashes, regressions, pre_existing)
    ]
    # Clamp negatives (can happen if regression data is partial)
    clean = [max(0, c) for c in clean]
    ax5.bar(x, pre_existing, label="Pre-existing", color="#aec7e8", **bar_kw)
    ax5.bar(
        x,
        regressions,
        bottom=pre_existing,
        label="Regressions (LLM)",
        color="#ff9896",
        **bar_kw,
    )
    bottom2 = [p + r for p, r in zip(pre_existing, regressions)]
    ax5.bar(x, clean, bottom=bottom2, label="Other/Diff", color="#c7c7c7", **bar_kw)
    ax5.set_xticks(x)
    ax5.set_xticklabels(labels, rotation=35, ha="right", fontsize=8)
    ax5.set_ylabel("Unique Crashes")
    ax5.set_title("Crash Breakdown")
    ax5.legend(fontsize=7)

    # Panel 6: Per-case crash heatmap (top N crashiest cases)
    ax6 = axes[1, 2]
    # Gather per-case unique crash counts
    cases_sorted = sorted(data.keys(), key=lambda c: int(c) if c.isdigit() else 0)
    case_totals = []
    for cid in cases_sorted:
        tot = sum(
            data[cid].get(m, {}).get("fuzzing_result", {}).get("unique_crashes", 0)
            for m in models
        )
        case_totals.append((cid, tot))

    # Top 20 crashiest cases
    case_totals.sort(key=lambda t: t[1], reverse=True)
    top_cases = [c for c, _ in case_totals[:20] if _ > 0]

    if top_cases:
        matrix = []
        for cid in top_cases:
            row = []
            for m in models:
                uc = (
                    data[cid]
                    .get(m, {})
                    .get("fuzzing_result", {})
                    .get("unique_crashes", 0)
                )
                row.append(uc)
            matrix.append(row)

        matrix_arr = np.array(matrix, dtype=float)
        im = ax6.imshow(
            matrix_arr, aspect="auto", cmap="YlOrRd", interpolation="nearest"
        )
        ax6.set_xticks(range(len(models)))
        ax6.set_xticklabels(labels, rotation=35, ha="right", fontsize=7)
        ax6.set_yticks(range(len(top_cases)))
        ax6.set_yticklabels(top_cases, fontsize=7)
        ax6.set_title("Top 20 Crashiest Cases (unique)")
        fig.colorbar(im, ax=ax6, shrink=0.8)

    fig.suptitle(
        f"ARVO Benchmark Crash Comparison — {n_cases} cases", fontsize=14, y=1.01
    )
    plt.tight_layout()

    if output_path:
        plt.savefig(output_path, dpi=150, bbox_inches="tight")
        print(f"Saved comparison plot to {output_path}")

    return fig


class AggregateCurve:
    """Holds mean + percentile bands for one model's aggregate curve."""

    __slots__ = ("mean", "p25", "p75")

    def __init__(self, mean: np.ndarray, p25: np.ndarray, p75: np.ndarray):
        self.mean = mean
        self.p25 = p25
        self.p75 = p75


def _build_aggregate_curves(
    data: dict[str, dict[str, dict]],
    models: list[str],
    extractor,
    resolution: int = 200,
    max_seconds: Optional[float] = None,
) -> tuple[dict[str, AggregateCurve], float]:
    """Build aggregate cumulative curves for each model in absolute seconds.

    For each model, collects per-case curves and computes the mean and
    25th/75th percentile bands across cases.

    Returns ({model: AggregateCurve}, max_seconds).
    """
    # Determine the common time axis from the median observed duration
    if max_seconds is None:
        all_durations: list[float] = []
        for case_data in data.values():
            for model in models:
                if model not in case_data:
                    continue
                _, dur = extractor(case_data[model])
                if dur:
                    all_durations.append(dur)
        max_seconds = float(np.median(all_durations)) if all_durations else 1800.0

    curves: dict[str, AggregateCurve] = {}
    for model in models:
        per_case: list[np.ndarray] = []

        for case_data in data.values():
            if model not in case_data:
                continue
            crash_times, duration = extractor(case_data[model])
            if not duration:
                continue

            row = np.zeros(resolution + 1)
            for i in range(resolution + 1):
                t = (i / resolution) * max_seconds
                row[i] = sum(1 for ct in crash_times if ct <= t)
            per_case.append(row)

        if per_case:
            matrix = np.stack(per_case)  # shape (n_cases, resolution+1)
            curves[model] = AggregateCurve(
                mean=matrix.mean(axis=0),
                p25=np.percentile(matrix, 25, axis=0),
                p75=np.percentile(matrix, 75, axis=0),
            )

    return curves, max_seconds


def _plot_aggregate_panel(
    ax: plt.Axes,
    curves: dict[str, AggregateCurve],
    models: list[str],
    xs: list[float],
    xlabel: str,
    ylabel: str,
    title: str,
    fill: bool = True,
) -> None:
    """Plot aggregate cumulative curves with p25–p75 variation bands."""
    for model in models:
        if model not in curves:
            continue
        curve = curves[model]
        if curve.mean[-1] == 0 and model != "gt":
            continue
        label = shorten_model(model)
        sty = get_model_style(model)
        markevery = max(1, len(xs) // 8)

        final_val = curve.mean[-1]
        val_str = f"{final_val:.2f}" if final_val < 100 else f"{int(final_val)}"

        ax.plot(
            xs,
            curve.mean,
            color=sty["color"],
            linewidth=sty["lw"],
            linestyle=sty["ls"],
            marker=sty["marker"],
            markersize=6,
            markevery=markevery,
            markeredgecolor="black",
            markeredgewidth=0.5,
            alpha=0.9,
            label=f"{label} ({val_str})",
        )

    ax.set_xlabel(xlabel)
    ax.set_ylabel(ylabel)
    ax.set_title(title)
    ax.legend(fontsize=7, loc="upper left")
    ax.grid(True, alpha=0.3)


def get_common_success_cases(
    data: dict[str, dict[str, dict]], models: list[str]
) -> set[str]:
    """Cases where every LLM agent patched successfully."""
    llm_models = [m for m in models if m != "gt"]
    common = set(data.keys())
    for m in llm_models:
        ok = set()
        for cid, case_data in data.items():
            pr = case_data.get(m, {}).get("patch_result", {})
            if pr.get("patch_successful") or pr.get("crash_fixed"):
                ok.add(cid)
        common &= ok
    return common


def _plot_conditional_violin(
    ax: plt.Axes,
    data: dict[str, dict[str, dict]],
    models: list[str],
    value_fn,
    ylabel: str,
    title: str,
    include_gt: bool = True,
) -> None:
    """Plot conditional violins: violin of non-zero values + zero% annotation.

    Args:
        value_fn: callable(entry) -> int, extracts the count from a model entry.
        include_gt: whether to include the GT model.
    """
    plot_models = models if include_gt else [m for m in models if m != "gt"]

    all_counts: list[list[int]] = []
    labels: list[str] = []
    colors: list[str] = []

    for model in plot_models:
        counts = []
        for case_data in data.values():
            if model not in case_data:
                continue
            counts.append(value_fn(case_data[model]))
        if counts:
            all_counts.append(counts)
            labels.append(shorten_model(model))
            colors.append(get_model_color(model))

    if not all_counts:
        ax.set_title(title)
        return

    # For each agent: separate zero vs non-zero
    nonzero_data: list[list[int]] = []
    zero_pcts: list[float] = []
    has_any_nonzero = False

    for counts in all_counts:
        n_total = len(counts)
        n_zero = sum(1 for c in counts if c == 0)
        zero_pcts.append(n_zero / n_total * 100 if n_total > 0 else 100)
        nz = [c for c in counts if c > 0]
        nonzero_data.append(nz)
        if nz:
            has_any_nonzero = True

    # Plot violins for non-zero data only
    positions = list(range(1, len(labels) + 1))

    if has_any_nonzero:
        # Only plot violins for agents that have non-zero cases
        vp_positions = []
        vp_data = []
        vp_colors = []
        for i, nz in enumerate(nonzero_data):
            if nz:
                vp_positions.append(positions[i])
                vp_data.append(nz)
                vp_colors.append(colors[i])

        if vp_data:
            vp = ax.violinplot(
                vp_data, positions=vp_positions, showmedians=True, showextrema=True
            )
            for j, body in enumerate(vp["bodies"]):
                body.set_facecolor(vp_colors[j])
                body.set_alpha(0.5)
            for part in ("cbars", "cmins", "cmaxes", "cmedians"):
                if part in vp:
                    vp[part].set_color("black")
                    vp[part].set_linewidth(0.8)

    # Annotate zero percentages below x-axis
    ax.set_xticks(positions)
    tick_labels = []
    for i, label in enumerate(labels):
        zp = zero_pcts[i]
        tick_labels.append(f"{label}\n0-crash: {zp:.0f}%")
    ax.set_xticklabels(tick_labels, fontsize=7)

    ax.set_ylabel(ylabel)
    ax.set_title(title)
    ax.tick_params(axis="x", rotation=35)
    ax.grid(True, axis="y", alpha=0.3)


def _plot_regression_rate_bars(
    ax: plt.Axes,
    data: dict[str, dict[str, dict]],
    models: list[str],
    n_cases: int,
) -> None:
    """Bar chart: % of cases with at least 1 regression, per agent."""
    llm_models = [m for m in models if m != "gt"]
    labels = [shorten_model(m) for m in llm_models]
    colors = [get_model_color(m) for m in llm_models]

    rates = []
    counts = []
    for m in llm_models:
        n_with_reg = 0
        for case_data in data.values():
            if m not in case_data:
                continue
            ra = case_data[m].get("regression", {})
            if ra and ra.get("regressions", 0) > 0:
                n_with_reg += 1
        rates.append(n_with_reg / n_cases * 100 if n_cases > 0 else 0)
        counts.append(n_with_reg)

    x = np.arange(len(llm_models))
    bars = ax.bar(x, rates, color=colors, edgecolor="white", linewidth=0.5)
    ax.set_xticks(x)
    ax.set_xticklabels(labels, rotation=35, ha="right", fontsize=8)
    ax.set_ylabel("% Cases with >= 1 Regression")
    ax.set_title(f"P(Regression | all agents patched original PoC) N={n_cases}")
    ax.set_ylim(0, max(rates) * 1.3 if rates else 10)
    ax.grid(True, axis="y", alpha=0.3)

    for bar, rate, cnt in zip(bars, rates, counts):
        ax.annotate(
            f"{rate:.1f}%\n({cnt}/{n_cases})",
            xy=(bar.get_x() + bar.get_width() / 2, bar.get_height()),
            ha="center",
            va="bottom",
            fontsize=7,
        )


def plot_aggregate_timeline(
    data: dict[str, dict[str, dict]],
    models: list[str],
    output_path: Optional[Path] = None,
) -> Figure:
    """
    Aggregate crash timeline with four panels:
      Top-left:     unique crashes over time (avg per case, ALL cases)
      Top-right:    regressions over time (avg per case, INTERSECTION cases only)
      Bottom-left:  unique crash distribution (conditional violin, all cases)
      Bottom-right: regression distribution (conditional violin, intersection only)

    Regressions use the intersection of cases where every LLM agent patched
    successfully, so all agents are compared on the same vulnerabilities.
    """
    n_all = len(data)

    # --- Intersection: cases where every LLM agent patched successfully ---
    common_cases = get_common_success_cases(data, models)
    data_reg = {cid: data[cid] for cid in common_cases if cid in data}
    n_common = len(data_reg)

    fig, axes = plt.subplots(2, 2, figsize=(20, 12), layout="constrained")
    ax_uniq = axes[0, 0]
    ax_reg = axes[0, 1]
    ax_dist_u = axes[1, 0]
    ax_dist_r = axes[1, 1]

    resolution = 200

    # --- Build curves ---
    # Unique crashes: all cases
    unique_curves, max_sec = _build_aggregate_curves(
        data, models, extract_unique_crash_times, resolution
    )
    # Regressions: intersection cases only
    reg_curves, _ = _build_aggregate_curves(
        data_reg,
        models,
        extract_regression_crash_times,
        resolution,
        max_seconds=max_sec,
    )

    xs_sec = [i / resolution * max_sec for i in range(resolution + 1)]

    # --- Top-left: unique crashes (all cases) ---
    _plot_aggregate_panel(
        ax_uniq,
        unique_curves,
        models,
        xs_sec,
        "Time (seconds)",
        "Avg Unique Crashes per Case",
        f"Unique Crashes Over Time (avg, N={n_all})",
    )

    # --- Top-right: regressions (intersection cases) ---
    has_any_reg = any(
        model in reg_curves and reg_curves[model].mean[-1] > 0 for model in models
    )
    if has_any_reg:
        _plot_aggregate_panel(
            ax_reg,
            reg_curves,
            models,
            xs_sec,
            "Time (seconds)",
            "Avg Regressions per Case",
            f"E[#Regressions | all agents patched original PoC] (N={n_common})",
        )
    else:
        ax_reg.text(
            0.5,
            0.5,
            "No regression data",
            transform=ax_reg.transAxes,
            ha="center",
            va="center",
            fontsize=12,
            color="gray",
        )
        ax_reg.set_title("Regressions Over Time")
        ax_reg.grid(True, alpha=0.3)

    # --- Bottom-left: unique crash conditional violin (all cases) ---
    _plot_conditional_violin(
        ax_dist_u,
        data,
        models,
        value_fn=lambda entry: entry.get("fuzzing_result", {}).get("unique_crashes", 0),
        ylabel="Unique Crashes (non-zero cases)",
        title=f"Distribution of #Unique Crashes (N={n_all})",
        include_gt=True,
    )

    # --- Bottom-right: regression rate bar chart (intersection cases) ---
    _plot_regression_rate_bars(
        ax_dist_r,
        data_reg,
        models,
        n_common,
    )

    if output_path:
        plt.savefig(output_path, dpi=150, bbox_inches="tight")
        print(f"Saved aggregate plot to {output_path}")

    return fig


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> int:
    if not MATPLOTLIB_AVAILABLE:
        print(
            "Error: matplotlib is required. Install with: pip install matplotlib",
            file=sys.stderr,
        )
        return 1

    parser = argparse.ArgumentParser(
        description="Plot crash timelines from ARVO benchmark results (multi-agent).",
    )
    parser.add_argument(
        "experiment_id",
        help="Experiment ID (used for GCS path, e.g. fuzz1800_all)",
    )
    parser.add_argument(
        "--local",
        "-l",
        type=Path,
        help="Path to local results directory (skip GCS download)",
    )
    parser.add_argument(
        "--output",
        "-o",
        type=Path,
        help="Output path for saving to file. If omitted, opens a popup viewer instead.",
    )
    parser.add_argument(
        "--case",
        type=int,
        help="Plot only a specific case by ARVO ID",
    )
    parser.add_argument(
        "--compare",
        action="store_true",
        help="Create comparison summary dashboard",
    )
    parser.add_argument(
        "--aggregate",
        action="store_true",
        help="Create aggregate timeline plot",
    )
    parser.add_argument(
        "--bucket",
        help="Override GCS bucket name",
    )
    parser.add_argument(
        "--show",
        action="store_true",
        help="Force popup viewer even when -o is given (show + save)",
    )

    args = parser.parse_args()

    # Resolve data directory
    if args.local:
        results_dir = args.local
        if not results_dir.exists():
            print(f"Error: {results_dir} does not exist", file=sys.stderr)
            return 1
    else:
        bucket = args.bucket or get_default_bucket()
        if not bucket:
            print(
                "Error: No bucket configured. Pass --bucket or use --local.",
                file=sys.stderr,
            )
            return 1
        results_dir = download_from_gcs(bucket, args.experiment_id)

    # Load data
    print(f"Loading results from {results_dir} ...", file=sys.stderr)
    data = collect_results(results_dir)
    if not data:
        print("No results found.", file=sys.stderr)
        return 1

    all_models: set[str] = set()
    for case_data in data.values():
        all_models.update(case_data.keys())
    models = get_sorted_models(all_models)

    print(
        f"Loaded {len(data)} cases, {len(models)} agents: {', '.join(shorten_model(m) for m in models)}",
        file=sys.stderr,
    )

    # When no output path is given, default to popup viewer
    should_show = args.show or (args.output is None)

    # Generate plots
    if args.case is not None:
        case_key = str(args.case)
        if case_key not in data:
            print(f"Case {args.case} not found in results.", file=sys.stderr)
            return 1
        plot_single_case(case_key, data, models, args.output)

    elif args.compare:
        plot_comparison(data, models, args.output)

    elif args.aggregate:
        plot_aggregate_timeline(data, models, args.output)

    else:
        if args.output:
            # Save all cases to directory
            n = plot_all_cases(data, models, args.output)
            print(f"Generated {n} case plots in {args.output}/")
        else:
            # No output and no specific mode: default to compare popup
            print("No mode specified — showing comparison dashboard.", file=sys.stderr)
            plot_comparison(data, models)

    if should_show:
        plt.show()

    return 0


if __name__ == "__main__":
    sys.exit(main())
