#!/usr/bin/env python3
"""
Submit an Argo workflow to extract intermediate commits for each APB case.

Uses a single Argo workflow with withParam to fan out all cases in parallel.
Each case runs as a pod with two init containers (-vul for HEAD, -fix for git log)
and a main container that uploads results to GCS.

Usage:
    python extract_commits_job.py
    python extract_commits_job.py --cases 11429,3408   # Test on specific cases
    python extract_commits_job.py --dry-run             # Print workflow without submitting
"""

import argparse
import json
import subprocess
import sys
from pathlib import Path

# Resolve paths relative to this script
SCRIPT_DIR = Path(__file__).parent.resolve()
REPO_ROOT = SCRIPT_DIR.parent.parent
AUTOPATCH_META_DIR = REPO_ROOT / "datasets" / "autopatch" / "arvo_meta"
APB_CONFIG = REPO_ROOT / "benchmark" / "gcp" / "configs" / "autopatchbench_all.json"
DEFAULT_GKE_CONFIG = REPO_ROOT / "benchmark" / "gcp" / ".gke-config.json"
WORKFLOW_YAML = (
    REPO_ROOT / "benchmark" / "gcp" / "argo" / "workflows" / "between-commits.yaml"
)


def load_gke_config(path: Path) -> dict:
    with open(path) as f:
        return json.load(f)


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
        # Convert email to K8s-safe label
        return email.split("@")[0].replace(".", "-").replace("_", "-").lower()[:63]
    except Exception:
        return "unknown"


def submit_workflow(
    workflow_path: str,
    parameters: dict[str, str],
    labels: dict[str, str] | None = None,
) -> str | None:
    """Submit an Argo workflow and return its name."""
    args = ["argo", "submit", workflow_path, "-n", "argo", "--wait=false"]

    for key, value in parameters.items():
        args.extend(["-p", f"{key}={value}"])

    all_labels = {"owner": get_current_user()}
    if labels:
        all_labels.update(labels)
    for key, value in all_labels.items():
        args.extend(["--labels", f"{key}={value}"])

    result = subprocess.run(args, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"Error submitting workflow: {result.stderr}", file=sys.stderr)
        return None

    # Extract workflow name from output
    for line in result.stdout.split("\n"):
        if line.startswith("Name:"):
            return line.split(":", 1)[1].strip()

    print(result.stdout)
    return None


def main():
    parser = argparse.ArgumentParser(
        description="Submit between-commits extraction workflow"
    )
    parser.add_argument(
        "--config", type=Path, default=DEFAULT_GKE_CONFIG, help="GKE config file"
    )
    parser.add_argument(
        "--cases",
        type=str,
        default=None,
        help="Comma-separated case IDs (default: all APB cases)",
    )
    parser.add_argument("--build-version", type=str, default="latest")
    parser.add_argument(
        "--dry-run", action="store_true", help="Print parameters without submitting"
    )
    args = parser.parse_args()

    # Load config
    gke_config = load_gke_config(args.config)
    registry = gke_config["artifact_registry"]
    bucket = gke_config["bucket_name"]

    # Get case IDs
    if args.cases:
        case_ids = [int(c.strip()) for c in args.cases.split(",")]
    else:
        with open(APB_CONFIG) as f:
            case_ids = json.load(f)["cases"]

    cases_json = json.dumps([str(c) for c in case_ids])

    print(f"Cases: {len(case_ids)}")
    print(f"Registry: {registry}")
    print(f"Bucket: {bucket}")
    print(f"Workflow: {WORKFLOW_YAML}")
    print()

    parameters = {
        "cases-json": cases_json,
        "bucket": bucket,
        "registry": registry,
        "build-version": args.build_version,
    }

    if args.dry_run:
        print("=== Dry Run ===")
        for key, value in parameters.items():
            if key == "cases-json":
                print(f"  {key}: [{len(case_ids)} cases]")
            else:
                print(f"  {key}: {value}")
        return

    # Submit
    print("Submitting workflow...")
    workflow_name = submit_workflow(str(WORKFLOW_YAML), parameters)

    if workflow_name:
        print(f"\nWorkflow submitted: {workflow_name}")
        print()
        print("Monitor:")
        print(f"  argo get {workflow_name} -n argo")
        print(f"  argo watch {workflow_name} -n argo")
        print()
        print("Results will be at:")
        print(f"  gs://{bucket}/analysis/between_commits/{{case_id}}/")
    else:
        print("Failed to submit workflow", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
