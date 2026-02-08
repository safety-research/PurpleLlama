#!/usr/bin/env python3
"""
Analyze intermediate commits between vul and fix for each APB case.

1. Match APB case IDs to the new ARVO database (arvo.db) via fix_commit hash
2. Load intermediate commits from GCS (produced by extract_commits_job.py)
3. Cross-reference intermediate commits against arvo.db to find known fixes
4. Generate a report identifying cases with "bonus fixes"

Usage:
    python analyze_between_commits.py --config ../../benchmark/gcp/.gke-config.json
    python analyze_between_commits.py --local-dir /tmp/between_commits  # skip GCS download
"""

import argparse
import json
import os
import sqlite3
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

# Resolve paths relative to this script
SCRIPT_DIR = Path(__file__).parent.resolve()
REPO_ROOT = SCRIPT_DIR.parent.parent
AUTOPATCH_META_DIR = REPO_ROOT / "datasets" / "autopatch" / "arvo_meta"
APB_CONFIG = REPO_ROOT / "benchmark" / "gcp" / "configs" / "autopatchbench_all.json"
ARVO_DB_PATH = REPO_ROOT / "datasets" / "arvo.db"
DEFAULT_GKE_CONFIG = REPO_ROOT / "benchmark" / "gcp" / ".gke-config.json"


def load_gke_config(path: Path) -> dict:
    with open(path) as f:
        return json.load(f)


def load_case_ids() -> list[int]:
    with open(APB_CONFIG) as f:
        return json.load(f)["cases"]


def load_case_metadata(case_id: int) -> dict | None:
    meta_file = AUTOPATCH_META_DIR / f"{case_id}-meta.json"
    if not meta_file.exists():
        return None
    with open(meta_file) as f:
        return json.load(f)


def get_fix_commits(meta: dict) -> list[str]:
    """Get fix commit(s) as a list. Handles both str and list formats."""
    fc = meta.get("arvo_metadata", {}).get("fix_commit")
    if isinstance(fc, list):
        return fc
    elif fc:
        return [fc]
    return []


def build_arvo_index(db_path: Path) -> dict[str, list[dict]]:
    """Build an index from fix_commit -> list of arvo.db entries."""
    db = sqlite3.connect(str(db_path))
    db.row_factory = sqlite3.Row
    rows = db.execute(
        "SELECT localId, project, fix_commit, crash_type, severity, repo_addr "
        "FROM arvo WHERE fix_commit IS NOT NULL AND fix_commit != ''"
    ).fetchall()
    db.close()

    index: dict[str, list[dict]] = {}
    for row in rows:
        fc = row["fix_commit"]
        entry = {
            "arvo_id": row["localId"],
            "project": row["project"],
            "crash_type": row["crash_type"],
            "severity": row["severity"],
            "repo_addr": row["repo_addr"],
        }
        index.setdefault(fc, []).append(entry)

    return index


def download_from_gcs(bucket: str, case_ids: list[int], dest_dir: Path) -> int:
    """Download extraction results from GCS. Returns number downloaded."""
    dest_dir.mkdir(parents=True, exist_ok=True)
    downloaded = 0

    for cid in case_ids:
        gcs_prefix = f"gs://{bucket}/analysis/between_commits/{cid}/"
        local_dir = dest_dir / str(cid)
        local_dir.mkdir(exist_ok=True)

        result = subprocess.run(
            ["gsutil", "-m", "cp", "-r", f"{gcs_prefix}*", str(local_dir)],
            capture_output=True,
            text=True,
        )
        if result.returncode == 0:
            downloaded += 1
        # Silently skip missing cases (not yet extracted)

    return downloaded


def load_commits_for_case(case_dir: Path) -> dict[str, Any] | None:
    """Load extracted commit data for a single case."""
    vul_file = case_dir / "vul_commit"
    fix_file = case_dir / "fix_commit"
    commits_file = case_dir / "commits.txt"

    if not commits_file.exists():
        return None

    vul_commit = vul_file.read_text().strip() if vul_file.exists() else ""
    fix_commit = fix_file.read_text().strip() if fix_file.exists() else ""

    # Parse commits: each line is "hash message"
    intermediate_commits = []
    for line in commits_file.read_text().strip().splitlines():
        if not line or line.startswith("ERROR"):
            continue
        parts = line.split(" ", 1)
        commit_hash = parts[0]
        message = parts[1] if len(parts) > 1 else ""
        intermediate_commits.append({"hash": commit_hash, "message": message})

    return {
        "vul_commit": vul_commit,
        "fix_commit": fix_commit,
        "intermediate_commits": intermediate_commits,
    }


def analyze(
    case_ids: list[int],
    data_dir: Path,
    arvo_index: dict[str, list[dict]],
    bucket: str,
) -> dict[str, Any]:
    """Run the full analysis and return the report."""

    details = []
    cases_clean = 0
    cases_confounded = 0
    cases_no_data = 0
    all_needed_arvo_ids = set()

    for cid in case_ids:
        meta = load_case_metadata(cid)
        if not meta:
            continue

        project = meta.get("arvo_metadata", {}).get("project", "")
        fix_commits = get_fix_commits(meta)
        fix_commit_set = set(fix_commits)

        # Load extracted commit data
        case_dir = data_dir / str(cid)
        commit_data = load_commits_for_case(case_dir)

        if not commit_data:
            cases_no_data += 1
            details.append(
                {
                    "apb_case_id": cid,
                    "project": project,
                    "fix_commit": fix_commits[-1] if fix_commits else "",
                    "status": "no_data",
                }
            )
            continue

        # Check each intermediate commit against arvo.db
        known_fixes = []
        for ic in commit_data["intermediate_commits"]:
            commit_hash = ic["hash"]
            # Skip the case's own fix commit(s)
            if commit_hash in fix_commit_set:
                continue
            # Look up in arvo.db
            if commit_hash in arvo_index:
                for arvo_entry in arvo_index[commit_hash]:
                    all_needed_arvo_ids.add(arvo_entry["arvo_id"])
                    known_fixes.append(
                        {
                            "commit": commit_hash,
                            "message": ic["message"],
                            "arvo_id": arvo_entry["arvo_id"],
                            "project": arvo_entry["project"],
                            "crash_type": arvo_entry["crash_type"],
                            "severity": arvo_entry["severity"],
                            "poc_path": f"gs://{bucket}/analysis/relevant_pocs/{arvo_entry['arvo_id']}/poc",
                        }
                    )

        if known_fixes:
            cases_confounded += 1
        else:
            cases_clean += 1

        details.append(
            {
                "apb_case_id": cid,
                "project": project,
                "vul_commit": commit_data["vul_commit"],
                "fix_commit": commit_data["fix_commit"],
                "total_intermediate_commits": len(commit_data["intermediate_commits"]),
                "known_arvo_fixes_in_range": known_fixes,
                "status": "confounded" if known_fixes else "clean",
            }
        )

    return {
        "total_cases": len(case_ids),
        "cases_analyzed": cases_clean + cases_confounded,
        "cases_clean": cases_clean,
        "cases_with_bonus_fixes": cases_confounded,
        "cases_no_data": cases_no_data,
        "all_needed_arvo_ids": sorted(all_needed_arvo_ids),
        "details": details,
    }


def print_summary(report: dict) -> None:
    """Print a human-readable summary."""
    print("\n" + "=" * 70)
    print("Between-Commits Analysis Report")
    print("=" * 70)
    print(f"Total APB cases:           {report['total_cases']}")
    print(f"Cases analyzed:            {report['cases_analyzed']}")
    print(f"  Clean (no bonus fixes):  {report['cases_clean']}")
    print(f"  Confounded (has bonus):  {report['cases_with_bonus_fixes']}")
    print(f"Cases without data:        {report['cases_no_data']}")
    print(f"Unique ARVO IDs for PoCs:  {len(report['all_needed_arvo_ids'])}")
    print()

    # Print confounded cases
    confounded = [d for d in report["details"] if d.get("status") == "confounded"]
    if confounded:
        print("--- Confounded Cases (bonus fixes between vul and fix) ---")
        print(f"{'Case':<8} {'Project':<20} {'Commits':<8} {'Bonus Fixes'}")
        print("-" * 70)
        for case in confounded:
            n_bonus = len(case["known_arvo_fixes_in_range"])
            n_commits = case["total_intermediate_commits"]
            print(
                f"{case['apb_case_id']:<8} {case['project']:<20} {n_commits:<8} {n_bonus}"
            )
            for fix in case["known_arvo_fixes_in_range"]:
                print(
                    f"         -> ARVO {fix['arvo_id']}: {fix['crash_type']} "
                    f"({fix['commit'][:12]})"
                )
        print()

    # Print clean cases summary
    clean = [d for d in report["details"] if d.get("status") == "clean"]
    if clean:
        zero_intermediate = [
            c for c in clean if c.get("total_intermediate_commits", 0) == 0
        ]
        with_intermediate = [
            c for c in clean if c.get("total_intermediate_commits", 0) > 0
        ]
        print(f"--- Clean Cases ---")
        print(f"  Zero intermediate commits (direct fix): {len(zero_intermediate)}")
        print(
            f"  With intermediate commits (no known ARVO fixes): {len(with_intermediate)}"
        )
        if with_intermediate:
            max_commits = max(
                c["total_intermediate_commits"] for c in with_intermediate
            )
            avg_commits = sum(
                c["total_intermediate_commits"] for c in with_intermediate
            ) / len(with_intermediate)
            print(f"  Max intermediate commits: {max_commits}")
            print(f"  Avg intermediate commits: {avg_commits:.1f}")
    print()


def main():
    parser = argparse.ArgumentParser(description="Analyze intermediate commits")
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
    parser.add_argument(
        "--arvo-db", type=Path, default=ARVO_DB_PATH, help="Path to arvo.db"
    )
    args = parser.parse_args()

    # Load ARVO index
    print(f"Loading ARVO database from {args.arvo_db}...")
    arvo_index = build_arvo_index(args.arvo_db)
    print(f"  {len(arvo_index)} unique fix commits indexed")

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
        data_dir = Path(tempfile.mkdtemp(prefix="between-commits-"))
        print(f"Downloading from GCS to {data_dir}...")
        downloaded = download_from_gcs(bucket, case_ids, data_dir)
        print(f"  Downloaded data for {downloaded} cases")

    # Run analysis
    print("\nAnalyzing...")
    report = analyze(case_ids, data_dir, arvo_index, bucket)

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
