#!/usr/bin/env python3
"""
Submit an Argo workflow to find the closest vulnerable commit (C) for each APB case.

For each case, the workflow:
1. Extracts the vul commit (A) from the -vul image
2. In the -fix image, walks backwards from K-1 towards A (max 10 attempts)
   where K = min(fix_commits) by position in git history
3. Finds the first commit that compiles and crashes on the PoC
4. Uploads result.json to GCS

Usage:
    python find_closest_vul_job.py
    python find_closest_vul_job.py --cases 11429,3408   # Test on specific cases
    python find_closest_vul_job.py --dry-run             # Print workflow without submitting
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
    REPO_ROOT / "benchmark" / "gcp" / "argo" / "workflows" / "find-closest-vul.yaml"
)


def load_gke_config(path: Path) -> dict:
    with open(path) as f:
        return json.load(f)


def get_fix_commits(meta: dict) -> list[str]:
    """Get fix commit(s) as a list. Handles both str and list formats."""
    fc = meta.get("arvo_metadata", {}).get("fix_commit")
    if isinstance(fc, list):
        return fc
    elif fc:
        return [fc]
    return []


def get_project_name(meta: dict) -> str | None:
    """Get project name from metadata."""
    return meta.get("arvo_metadata", {}).get("project")


def load_case_metadata(case_id: int) -> dict | None:
    meta_file = AUTOPATCH_META_DIR / f"{case_id}-meta.json"
    if not meta_file.exists():
        return None
    with open(meta_file) as f:
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

    for line in result.stdout.split("\n"):
        if line.startswith("Name:"):
            return line.split(":", 1)[1].strip()

    print(result.stdout)
    return None


def main():
    parser = argparse.ArgumentParser(description="Submit find-closest-vul workflow")
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

    # Build cases-json with fix_commits per case
    cases = []
    skipped = []
    for cid in case_ids:
        meta = load_case_metadata(cid)
        if not meta:
            skipped.append(cid)
            continue

        fix_commits = get_fix_commits(meta)
        project = get_project_name(meta)
        if not fix_commits or not project:
            skipped.append(cid)
            continue

        cases.append(
            {
                "id": str(cid),
                "fix_commits": ",".join(fix_commits),
                "project": project,
            }
        )

    cases_json = json.dumps(cases)

    print(f"Cases: {len(cases)} (skipped {len(skipped)} without metadata/fix_commits)")
    print(f"Registry: {registry}")
    print(f"Bucket: {bucket}")
    print(f"Workflow: {WORKFLOW_YAML}")
    if skipped:
        print(f"Skipped: {skipped}")
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
                print(f"  {key}: [{len(cases)} cases]")
                # Show first few for inspection
                for c in cases[:5]:
                    fc = c["fix_commits"]
                    fc_display = fc[:40] + "..." if len(fc) > 40 else fc
                    print(
                        f"    {c['id']}: project={c['project']}, fix_commits={fc_display}"
                    )
                if len(cases) > 5:
                    print(f"    ... and {len(cases) - 5} more")
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
        print(f"  gs://{bucket}/analysis/closest_vul/{{case_id}}/result.json")
    else:
        print("Failed to submit workflow", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
