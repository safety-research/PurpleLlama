#!/usr/bin/env python3
"""
Download analysis artifacts from GCS and stage them for build_explorer.py.

Downloads analysis reports, agent patches, conversations, and GT patches,
then organizes them into the per-agent layout expected by build_explorer.py.

Usage:
    # Auto-detect source experiment from analysis reports
    python analysis/download_analysis.py analysis-20260222-214329

    # Explicit source experiment
    python analysis/download_analysis.py analysis-20260222-214329 \
        --source-experiment fuzz1800_all_0218

    # Download + build explorers in one shot
    python analysis/download_analysis.py analysis-20260222-214329 --build

    # Custom output directory
    python analysis/download_analysis.py analysis-20260222-214329 \
        --output-dir /tmp/my-analysis --build

    # Reuse previously downloaded data (skip GCS download)
    python analysis/download_analysis.py analysis-20260222-214329 \
        --local /tmp/explorer-analysis-20260222-214329 --build
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

SCRIPT_DIR = Path(__file__).parent.resolve()
REPO_ROOT = SCRIPT_DIR.parent
GKE_CONFIG = REPO_ROOT / "benchmark" / "gcp" / ".gke-config.json"
BUILD_EXPLORER = SCRIPT_DIR / "build_explorer.py"


def get_default_bucket() -> str:
    if GKE_CONFIG.exists():
        with open(GKE_CONFIG) as f:
            return json.load(f).get("bucket_name", "")
    return ""


def run_gcs(args: list[str], desc: str = "") -> subprocess.CompletedProcess:
    """Run a gcloud storage command, preferring gcloud over gsutil."""
    if desc:
        print(f"  {desc}...", file=sys.stderr)
    result = subprocess.run(args, capture_output=True, text=True)
    if result.returncode != 0:
        err = result.stderr.strip()[-200:] if result.stderr else ""
        print(f"  Warning: {' '.join(args[:4])}... failed: {err}", file=sys.stderr)
    return result


def rsync_from_gcs(gcs_path: str, local_path: str, exclude: str = "") -> None:
    """Download a GCS prefix to a local directory using gcloud storage rsync."""
    Path(local_path).mkdir(parents=True, exist_ok=True)
    cmd = ["gcloud", "storage", "rsync", "--recursive"]
    if exclude:
        cmd.extend([f"--exclude={exclude}"])
    cmd.extend([gcs_path, local_path])
    subprocess.run(cmd, check=True)


def detect_source_experiment(analysis_dir: Path) -> str | None:
    """Read source_experiment from the first available report.json."""
    for case_dir in sorted(analysis_dir.iterdir()):
        if not case_dir.is_dir():
            continue
        for pair_dir in case_dir.iterdir():
            report = pair_dir / "report.json"
            if report.exists():
                try:
                    data = json.loads(report.read_text())
                    return data.get("source_experiment")
                except (json.JSONDecodeError, KeyError):
                    continue
    return None


def detect_agents(analysis_dir: Path) -> list[str]:
    """Detect agent IDs from the analysis directory structure."""
    agents: set[str] = set()
    for case_dir in analysis_dir.iterdir():
        if not case_dir.is_dir():
            continue
        for pair_dir in case_dir.iterdir():
            if not pair_dir.is_dir():
                continue
            name = pair_dir.name
            if "-vs-gt" in name:
                agent = name.replace("-vs-gt", "")
                agents.add(agent)
            elif "-vs-" in name:
                parts = name.split("-vs-")
                agents.update(parts)
    return sorted(agents - {"gt"})


def stage_per_agent(
    staging_dir: Path,
    analysis_dir: Path,
    results_dir: Path,
    patches_dir: Path,
    agents: list[str],
) -> dict[str, Path]:
    """Create per-agent artifact directories with symlinks.

    Returns {agent_id: artifacts_path} mapping.
    """
    cases = [d.name for d in sorted(analysis_dir.iterdir()) if d.is_dir()]
    agent_dirs: dict[str, Path] = {}

    for agent in agents:
        agent_dir = staging_dir / "per-agent" / agent
        agent_dirs[agent] = agent_dir

        for case_id in cases:
            case_dir = agent_dir / case_id
            case_dir.mkdir(parents=True, exist_ok=True)

            # Agent patch
            src = results_dir / case_id / agent / "patch.patch"
            dst = case_dir / "agent_patch.patch"
            if src.exists() and not dst.exists():
                dst.symlink_to(src)

            # Conversation
            src = results_dir / case_id / agent / "conversation.json"
            dst = case_dir / "conversation.json"
            if src.exists() and not dst.exists():
                dst.symlink_to(src)

            # GT patch
            src = patches_dir / f"{case_id}-patch.json"
            dst = case_dir / "gt_patch.json"
            if src.exists() and not dst.exists():
                dst.symlink_to(src)

    return agent_dirs


def build_explorers(
    analysis_dir: Path,
    agent_dirs: dict[str, Path],
    output_dir: Path,
    image_audit_dir: Path | None = None,
    extra_args: list[str] | None = None,
) -> list[Path]:
    """Run build_explorer.py for each agent. Returns list of output HTML paths."""
    output_dir.mkdir(parents=True, exist_ok=True)
    html_files: list[Path] = []

    for agent, artifacts_path in sorted(agent_dirs.items()):
        short = agent.replace("claudecode-claude-", "").replace("claudecode-", "")
        out = output_dir / f"explorer_{short}.html"
        cmd = [
            sys.executable,
            str(BUILD_EXPLORER),
            "--analysis-dir", str(analysis_dir),
            "--artifacts-dir", str(artifacts_path),
            "--agent-id", agent,
            "--output", str(out),
        ]
        if image_audit_dir and image_audit_dir.exists():
            cmd.extend(["--image-audit", str(image_audit_dir)])
        if extra_args:
            cmd.extend(extra_args)

        print(f"\nBuilding explorer for {agent}...", file=sys.stderr)
        result = subprocess.run(cmd)
        if result.returncode == 0:
            html_files.append(out)
        else:
            print(f"  Failed to build explorer for {agent}", file=sys.stderr)

    return html_files


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Download analysis artifacts from GCS and optionally build explorers.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "analysis_experiment",
        help="Analysis experiment ID (e.g. analysis-20260222-214329)",
    )
    parser.add_argument(
        "--source-experiment", "-s",
        help="Source patching experiment ID (auto-detected from reports if omitted)",
    )
    parser.add_argument(
        "--bucket", "-b",
        help="GCS bucket name (default: from .gke-config.json)",
    )
    parser.add_argument(
        "--output-dir", "-o",
        type=Path,
        help="Output directory (default: /tmp/explorer-<analysis_experiment>)",
    )
    parser.add_argument(
        "--local", "-l",
        type=Path,
        help="Use a previously downloaded staging directory (skip GCS download)",
    )
    parser.add_argument(
        "--build",
        action="store_true",
        help="Also run build_explorer.py for each agent after downloading",
    )
    parser.add_argument(
        "--open",
        action="store_true",
        help="Open generated HTML files in browser (implies --build)",
    )
    parser.add_argument(
        "--build-args",
        nargs=argparse.REMAINDER,
        help="Extra arguments to pass to build_explorer.py (e.g. --image-audit /path)",
    )

    args = parser.parse_args()

    if args.open:
        args.build = True

    bucket = args.bucket or get_default_bucket()
    if not bucket and not args.local:
        print("Error: No bucket configured. Pass --bucket or use --local.", file=sys.stderr)
        return 1

    analysis_exp = args.analysis_experiment
    staging = args.output_dir or Path(f"/tmp/explorer-{analysis_exp}")

    if args.local:
        staging = args.local
        if not staging.exists():
            print(f"Error: {staging} does not exist", file=sys.stderr)
            return 1
        print(f"Using local data from {staging}", file=sys.stderr)
    else:
        staging.mkdir(parents=True, exist_ok=True)
        print(f"Staging directory: {staging}", file=sys.stderr)

        # Step 1: Download analysis reports
        analysis_dir = staging / "analysis"
        print(f"\n[1/3] Downloading analysis reports...", file=sys.stderr)
        rsync_from_gcs(
            f"gs://{bucket}/analysis/patch-comparison/{analysis_exp}/",
            str(analysis_dir),
        )

        # Detect source experiment if not provided
        source_exp = args.source_experiment or detect_source_experiment(analysis_dir)
        if not source_exp:
            print("Error: Could not detect source experiment. Pass --source-experiment.", file=sys.stderr)
            return 1
        print(f"Source experiment: {source_exp}", file=sys.stderr)

        # Step 2: Download result artifacts (patches + conversations)
        results_dir = staging / "results"
        print(f"\n[2/3] Downloading result artifacts...", file=sys.stderr)
        rsync_from_gcs(
            f"gs://{bucket}/results/{source_exp}/",
            str(results_dir),
            exclude=".*rebuilt_binary.*|.*original_binary.*|.*\\.tar\\.gz$|.*fuzzing_result.*|.*regression_analysis.*|.*_SUCCESS.*|.*crash_output.*|.*chat\\.md$|.*result\\.json$",
        )

        # Step 3: Download GT patches
        patches_dir = staging / "patches"
        print(f"\n[3/4] Downloading GT patches...", file=sys.stderr)
        rsync_from_gcs(
            f"gs://{bucket}/patches/",
            str(patches_dir),
        )

        # Step 4: Download image-audit data (for dirty-repo filtering)
        image_audit_dir = staging / "image-audit"
        print(f"\n[4/4] Downloading image-audit data...", file=sys.stderr)
        rsync_from_gcs(
            f"gs://{bucket}/image-audit/",
            str(image_audit_dir),
        )

    # Detect agents and stage per-agent dirs
    analysis_dir = staging / "analysis"
    results_dir = staging / "results"
    patches_dir = staging / "patches"

    agents = detect_agents(analysis_dir)
    n_cases = sum(1 for d in analysis_dir.iterdir() if d.is_dir())
    print(f"\nDetected {len(agents)} agents across {n_cases} cases:", file=sys.stderr)
    for a in agents:
        print(f"  - {a}", file=sys.stderr)

    agent_dirs = stage_per_agent(staging, analysis_dir, results_dir, patches_dir, agents)

    # Verify artifact counts
    for agent, adir in sorted(agent_dirs.items()):
        patches = sum(1 for p in adir.rglob("agent_patch.patch") if p.is_symlink() and p.resolve().exists())
        convos = sum(1 for p in adir.rglob("conversation.json") if p.is_symlink() and p.resolve().exists())
        gt = sum(1 for p in adir.rglob("gt_patch.json") if p.is_symlink() and p.resolve().exists())
        short = agent.replace("claudecode-claude-", "")
        print(f"  {short}: {patches} patches, {convos} conversations, {gt} GT patches", file=sys.stderr)

    print(f"\nStaging complete: {staging}", file=sys.stderr)

    if args.build:
        html_dir = staging / "html"
        image_audit_dir = staging / "image-audit"
        html_files = build_explorers(
            analysis_dir, agent_dirs, html_dir,
            image_audit_dir=image_audit_dir if image_audit_dir.exists() else None,
            extra_args=args.build_args,
        )
        print(f"\nGenerated {len(html_files)} explorer(s) in {html_dir}/", file=sys.stderr)

        if args.open and html_files:
            import platform
            opener = "open" if platform.system() == "Darwin" else "xdg-open"
            for f in html_files:
                subprocess.Popen([opener, str(f)])

    return 0


if __name__ == "__main__":
    sys.exit(main())
