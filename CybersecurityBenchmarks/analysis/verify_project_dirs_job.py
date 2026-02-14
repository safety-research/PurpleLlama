#!/usr/bin/env python3
"""
Submit an Argo workflow to verify that the 'project' field in meta.json
corresponds to the actual /src/{project}/.git directory in ARVO containers.

This helps validate that we can use the project field from metadata
to reliably identify the project root directory.

Usage:
    python verify_project_dirs_job.py
    python verify_project_dirs_job.py --cases 1236,66835  # Test specific cases
    python verify_project_dirs_job.py --dry-run           # Print workflow without submitting
"""

import argparse
import json
import subprocess
import sys
from pathlib import Path

# Resolve paths relative to this script
SCRIPT_DIR = Path(__file__).parent.resolve()
REPO_ROOT = SCRIPT_DIR.parent
AUTOPATCH_META_DIR = REPO_ROOT / "datasets" / "autopatch" / "arvo_meta"
APB_CONFIG = REPO_ROOT / "benchmark" / "gcp" / "configs" / "autopatchbench_all.json"
DEFAULT_GKE_CONFIG = REPO_ROOT / "benchmark" / "gcp" / ".gke-config.json"
WORKFLOW_YAML = (
    REPO_ROOT / "benchmark" / "gcp" / "argo" / "workflows" / "verify-project-dirs.yaml"
)


def load_gke_config(path: Path) -> dict:
    with open(path) as f:
        return json.load(f)


def load_case_metadata(case_id: int) -> dict | None:
    meta_file = AUTOPATCH_META_DIR / f"{case_id}-meta.json"
    if not meta_file.exists():
        return None
    with open(meta_file) as f:
        return json.load(f)


def get_project_name(meta: dict) -> str | None:
    """Get the project name from metadata."""
    return meta.get("arvo_metadata", {}).get("project")


def get_current_user() -> str:
    """Get current GKE user for workflow labels."""
    try:
        result = subprocess.run(
            ["gcloud", "config", "get-value", "account"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        email = result.stdout.strip()
        return email.split("@")[0].replace(".", "-").replace("_", "-").lower()[:63]
    except Exception:
        return "unknown"


def submit_workflow(
    workflow_path: str,
    parameters: dict[str, str],
    labels: dict[str, str],
    dry_run: bool = False,
) -> str:
    """Submit an Argo workflow with parameters and labels."""
    cmd = ["argo", "submit", workflow_path, "-n", "argo"]

    for key, value in parameters.items():
        cmd.extend(["-p", f"{key}={value}"])

    for key, value in labels.items():
        cmd.extend(["-l", f"{key}={value}"])

    if dry_run:
        cmd.append("--dry-run")
        cmd.append("-o")
        cmd.append("yaml")

    print(f"Running: {' '.join(cmd[:10])}...")
    result = subprocess.run(cmd, capture_output=True, text=True)

    if result.returncode != 0:
        print(f"Error: {result.stderr}", file=sys.stderr)
        sys.exit(1)

    return result.stdout


def main():
    parser = argparse.ArgumentParser(
        description="Verify project directory mapping for ARVO cases"
    )
    parser.add_argument(
        "--cases",
        type=str,
        help="Comma-separated list of case IDs (default: all from autopatchbench_all.json)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print workflow YAML without submitting",
    )
    parser.add_argument(
        "--gke-config",
        type=Path,
        default=DEFAULT_GKE_CONFIG,
        help="Path to GKE config JSON",
    )
    args = parser.parse_args()

    # Load GKE config
    gke_config = load_gke_config(args.gke_config)
    bucket = gke_config.get("bucket_name", "") or gke_config.get("bucket", "")
    if not bucket:
        print("Error: bucket_name not set in GKE config", file=sys.stderr)
        sys.exit(1)

    # Determine which cases to verify
    if args.cases:
        case_ids = [int(c.strip()) for c in args.cases.split(",")]
    else:
        with open(APB_CONFIG) as f:
            apb_config = json.load(f)
        case_ids = apb_config.get("cases", [])

    print(f"Verifying {len(case_ids)} cases...")

    # Build cases JSON with project info
    cases_data = []
    missing_meta = []
    missing_project = []

    for case_id in case_ids:
        meta = load_case_metadata(case_id)
        if not meta:
            missing_meta.append(case_id)
            continue

        project = get_project_name(meta)
        if not project:
            missing_project.append(case_id)
            continue

        cases_data.append({"case_id": case_id, "project": project})

    if missing_meta:
        print(f"Warning: Missing metadata for cases: {missing_meta}")
    if missing_project:
        print(f"Warning: Missing project field for cases: {missing_project}")

    print(f"Processing {len(cases_data)} cases with valid metadata")

    # Print sample of cases
    print("\nSample cases:")
    for case in cases_data[:5]:
        print(f"  {case['case_id']}: {case['project']}")
    if len(cases_data) > 5:
        print(f"  ... and {len(cases_data) - 5} more")

    # Submit workflow
    parameters = {
        "cases-json": json.dumps(cases_data),
        "bucket": bucket,
        "experiment-id": "verify-project-dirs",
    }

    labels = {
        "owner": get_current_user(),
    }

    print(f"\nSubmitting workflow to verify {len(cases_data)} cases...")
    output = submit_workflow(
        str(WORKFLOW_YAML),
        parameters,
        labels,
        dry_run=args.dry_run,
    )

    if args.dry_run:
        print("\n=== Dry Run Output ===")
        print(output)
    else:
        print(output)
        print("\nWorkflow submitted. Monitor with:")
        print("  argo list -n argo | head")
        print("  argo watch <workflow-name> -n argo")


if __name__ == "__main__":
    main()
