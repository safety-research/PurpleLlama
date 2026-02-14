#!/usr/bin/env python3
"""
Submit an Argo workflow to build closest-vul images for each APB case.

Reads the Phase 1 report (from analyze_closest_vul.py) to get case_id -> commit C
mappings, and submits a workflow that builds the thin closest-vul Docker image
(upstream -fix base + git checkout to C) for each case where C was found.

Usage:
    python build_closest_vul_job.py --report report.json
    python build_closest_vul_job.py --report report.json --cases 11429,3408
    python build_closest_vul_job.py --report report.json --dry-run
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
DEFAULT_GKE_CONFIG = REPO_ROOT / "benchmark" / "gcp" / ".gke-config.json"
DEFAULT_REPORT = SCRIPT_DIR / "report.json"
WORKFLOW_YAML = (
    REPO_ROOT / "benchmark" / "gcp" / "argo" / "workflows" / "build-closest-vul.yaml"
)


def load_gke_config(path: Path) -> dict:
    with open(path) as f:
        return json.load(f)


def load_case_metadata(case_id: int) -> dict | None:
    """Load metadata for a case from arvo_meta directory."""
    meta_file = AUTOPATCH_META_DIR / f"{case_id}-meta.json"
    if not meta_file.exists():
        return None
    with open(meta_file) as f:
        return json.load(f)


def get_project_name(meta: dict) -> str | None:
    """Get project name from metadata."""
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
    parser = argparse.ArgumentParser(description="Submit build-closest-vul workflow")
    parser.add_argument(
        "--config", type=Path, default=DEFAULT_GKE_CONFIG, help="GKE config file"
    )
    parser.add_argument(
        "--report",
        type=Path,
        default=DEFAULT_REPORT,
        help="Phase 1 report.json from analyze_closest_vul.py",
    )
    parser.add_argument(
        "--cases",
        type=str,
        default=None,
        help="Comma-separated case IDs to build (default: all found in report)",
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

    # Load report
    if not args.report.exists():
        print(f"Error: Report not found at {args.report}", file=sys.stderr)
        print("Run analyze_closest_vul.py first to generate the report.")
        sys.exit(1)

    with open(args.report) as f:
        report = json.load(f)

    # Filter to cases with status "found" that have a closest_vul_commit
    found_cases = {}
    missing_project = []
    for detail in report.get("details", []):
        if detail.get("status") == "found" and detail.get("closest_vul_commit"):
            cid = str(detail["case_id"])
            # Get project name from report or metadata
            project = detail.get("project")
            if not project:
                meta = load_case_metadata(int(cid))
                project = get_project_name(meta) if meta else None
            if not project:
                missing_project.append(cid)
                continue
            found_cases[cid] = {
                "target_commit": detail["closest_vul_commit"],
                "vul_date": detail.get("vul_date", ""),
                "project": project,
            }

    if missing_project:
        print(f"Warning: Skipping cases without project info: {missing_project}")

    # Filter by --cases if provided
    if args.cases:
        requested = {c.strip() for c in args.cases.split(",")}
        found_cases = {k: v for k, v in found_cases.items() if k in requested}
        missing = requested - set(found_cases.keys())
        if missing:
            print(f"Warning: Cases not found in report: {sorted(missing)}")

    if not found_cases:
        print("No cases to build (no 'found' cases in report).")
        sys.exit(0)

    # Build cases-json (includes vul_date for shallow-since fetch and project for source dir)
    cases = [
        {
            "id": cid,
            "target_commit": info["target_commit"],
            "vul_date": info["vul_date"],
            "project": info["project"],
        }
        for cid, info in sorted(found_cases.items(), key=lambda x: int(x[0]))
    ]
    cases_json = json.dumps(cases)

    print(f"Cases to build: {len(cases)}")
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
                print(f"  {key}: [{len(cases)} cases]")
                for c in cases[:10]:
                    print(
                        f"    {c['id']}: project={c['project']}, commit={c['target_commit'][:12]}..."
                    )
                if len(cases) > 10:
                    print(f"    ... and {len(cases) - 10} more")
            else:
                print(f"  {key}: {value}")
        return

    # Apply templates first
    templates_dir = REPO_ROOT / "benchmark" / "gcp" / "argo" / "templates"
    print("Applying Argo workflow templates...")
    result = subprocess.run(
        ["kubectl", "apply", "-f", str(templates_dir)],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        print(f"Warning: Failed to apply templates: {result.stderr}")
    else:
        for line in result.stdout.strip().split("\n"):
            if line:
                print(f"  {line}")
    print()

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
        print("Images will be pushed as:")
        print(f"  {registry}/arvo-{{case_id}}-closest-vul:{args.build_version}")
    else:
        print("Failed to submit workflow", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
