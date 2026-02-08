#!/usr/bin/env python3
"""
Submit an Argo workflow to collect PoCs for ARVO IDs identified by the analysis.

Usage:
    python collect_pocs_job.py --report report.json
    python collect_pocs_job.py --arvo-ids 42471599,42471602
    python collect_pocs_job.py --report report.json --dry-run
"""

import argparse
import json
import subprocess
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).parent.resolve()
REPO_ROOT = SCRIPT_DIR.parent.parent
DEFAULT_GKE_CONFIG = REPO_ROOT / "benchmark" / "gcp" / ".gke-config.json"
WORKFLOW_YAML = (
    REPO_ROOT / "benchmark" / "gcp" / "argo" / "workflows" / "collect-pocs.yaml"
)


def load_gke_config(path: Path) -> dict:
    with open(path) as f:
        return json.load(f)


def get_current_user() -> str:
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
) -> str | None:
    args = ["argo", "submit", workflow_path, "-n", "argo", "--wait=false"]

    for key, value in parameters.items():
        args.extend(["-p", f"{key}={value}"])

    args.extend(["--labels", f"owner={get_current_user()}"])

    result = subprocess.run(args, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"Error: {result.stderr}", file=sys.stderr)
        return None

    for line in result.stdout.split("\n"):
        if line.startswith("Name:"):
            return line.split(":", 1)[1].strip()

    print(result.stdout)
    return None


def main():
    parser = argparse.ArgumentParser(description="Submit PoC collection workflow")
    parser.add_argument("--config", type=Path, default=DEFAULT_GKE_CONFIG)
    parser.add_argument(
        "--report", type=Path, default=None, help="Path to between-commits report.json"
    )
    parser.add_argument(
        "--arvo-ids", type=str, default=None, help="Comma-separated ARVO IDs"
    )
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    gke_config = load_gke_config(args.config)
    bucket = gke_config["bucket_name"]

    # Get ARVO IDs
    if args.arvo_ids:
        arvo_ids = [int(x.strip()) for x in args.arvo_ids.split(",")]
    elif args.report:
        with open(args.report) as f:
            report = json.load(f)
        arvo_ids = report.get("all_needed_arvo_ids", [])
    else:
        print("ERROR: Provide --report or --arvo-ids", file=sys.stderr)
        return 1

    if not arvo_ids:
        print("No ARVO IDs to collect PoCs for.")
        return 0

    ids_json = json.dumps([str(aid) for aid in arvo_ids])

    print(f"ARVO IDs: {len(arvo_ids)}")
    print(f"Bucket: {bucket}")
    print()

    parameters = {
        "arvo-ids-json": ids_json,
        "bucket": bucket,
    }

    if args.dry_run:
        print("=== Dry Run ===")
        print(f"  ARVO IDs: {arvo_ids}")
        print(f"  Bucket: {bucket}")
        return 0

    print("Submitting workflow...")
    workflow_name = submit_workflow(str(WORKFLOW_YAML), parameters)

    if workflow_name:
        print(f"\nWorkflow submitted: {workflow_name}")
        print()
        print("Monitor:")
        print(f"  argo get {workflow_name} -n argo")
        print(f"  argo watch {workflow_name} -n argo")
    else:
        print("Failed to submit workflow", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
