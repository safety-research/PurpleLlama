"""
Submit command for benchmark workflows.
"""

import json
import subprocess
from pathlib import Path
from typing import Annotated, Optional

import typer

from ..argo import get_current_user, submit_workflow
from ..config import GKEConfig, RunConfig, get_script_dir, parse_cases
from ..hashing import (
    AUTOPATCH_BUILD_DIR,
    compute_deps_source_hash,
    get_deps_manifest_from_gcs,
)
from ..output import echo_info, echo_success, echo_warning


def _check_deps_status(
    bucket: str,
    build_dir: Path,
) -> tuple[bool, bool]:
    """Check if dependencies need rebuilding.

    Args:
        bucket: GCS bucket name
        build_dir: Path to autopatch build directory

    Returns:
        Tuple of (casr_needs_build, dd_needs_build)
    """
    # Compute local hashes
    local_casr_hash, local_dd_hash = compute_deps_source_hash(build_dir)
    manifest = get_deps_manifest_from_gcs(bucket)

    gcs_casr_hash = manifest.get("casr_hash", "")
    gcs_dd_hash = manifest.get("dd_hash", "")

    casr_changed = bool(local_casr_hash and local_casr_hash != gcs_casr_hash)
    dd_changed = bool(local_dd_hash and local_dd_hash != gcs_dd_hash)

    return casr_changed, dd_changed


def _report_deps_status(
    casr_changed: bool,
    dd_changed: bool,
    bucket: str,
    build_dir: Path,
    auto_build: bool = False,
    dry_run: bool = False,
) -> tuple[bool, bool, bool]:
    """Report dependency status and get user confirmation.

    Args:
        casr_changed: True if CASR needs rebuilding
        dd_changed: True if DD needs rebuilding
        bucket: GCS bucket name
        build_dir: Path to autopatch build directory
        auto_build: If True, automatically include builds in workflow
        dry_run: If True, only show what would be done

    Returns:
        Tuple of (should_continue, build_casr, build_dd)
    """
    if not casr_changed and not dd_changed:
        echo_success("Dependencies up to date")
        return True, False, False

    # Get hashes for display
    local_casr_hash, local_dd_hash = compute_deps_source_hash(build_dir)
    manifest = get_deps_manifest_from_gcs(bucket)
    gcs_casr_hash = manifest.get("casr_hash", "")
    gcs_dd_hash = manifest.get("dd_hash", "")

    # Show what changed
    typer.echo()
    echo_warning("Dependencies need rebuilding:")
    if casr_changed:
        typer.echo(
            f"  CASR: {gcs_casr_hash[:8] if gcs_casr_hash else 'none'}... -> {local_casr_hash[:8]}..."
        )
    if dd_changed:
        typer.echo(
            f"  DD:   {gcs_dd_hash[:8] if gcs_dd_hash else 'none'}... -> {local_dd_hash[:8]}..."
        )
    typer.echo()

    if dry_run:
        if auto_build:
            typer.echo("  [DRY RUN] Would include dependency builds in workflow")
        else:
            typer.echo("  [DRY RUN] Would warn about outdated deps")
        return True, casr_changed and auto_build, dd_changed and auto_build

    build_casr = False
    build_dd = False

    if auto_build:
        # Include builds in the workflow
        if casr_changed:
            echo_info("CASR build will run as part of workflow (~15-30 min)")
            build_casr = True

        if dd_changed:
            echo_warning("DD build will run as part of workflow (~2-4 hours)")
            if typer.confirm("Include DD build in workflow?", default=False):
                build_dd = True
            else:
                echo_warning(
                    "Skipping DD build - workflow may fail if DD deps are missing in GCS"
                )

        return True, build_casr, build_dd
    else:
        # Warn user but continue
        echo_warning("Dependencies are outdated. Options:")
        typer.echo("  1. Use --auto-build-deps to include builds in workflow")
        typer.echo("  2. Run builds separately first:")
        if casr_changed:
            typer.echo("       python -m cli build-casr")
        if dd_changed:
            typer.echo("       python -m cli build-dd")
        typer.echo()

        if not typer.confirm("Continue without rebuilding?", default=True):
            return False, False, False

        return True, False, False


def submit(
    cases: Annotated[
        Optional[str],
        typer.Option(help="Case IDs: '42,43,44', '42-50', or '@path/to/cases.json'"),
    ] = None,
    model: Annotated[
        str, typer.Option(help="LLM model to use")
    ] = "claude-sonnet-4-20250514",
    experiment_id: Annotated[
        Optional[str], typer.Option("--experiment", "-e", help="Experiment ID")
    ] = None,
    fuzzing_duration: Annotated[
        int, typer.Option(help="Fuzzing duration in seconds")
    ] = 300,
    run_gt: Annotated[
        bool, typer.Option("--gt/--no-gt", help="Run ground truth fuzzing")
    ] = True,
    build_version: Annotated[str, typer.Option(help="Build version tag")] = "latest",
    config_file: Annotated[
        Optional[Path], typer.Option("--config", "-c", help="Config file (JSON)")
    ] = None,
    upload_runtime: Annotated[
        bool,
        typer.Option(
            "--upload-runtime/--no-upload-runtime",
            help="Upload agent runtime before submit",
        ),
    ] = True,
    check_deps: Annotated[
        bool,
        typer.Option(
            "--check-deps/--no-check-deps", help="Check if CASR/DD need rebuilding"
        ),
    ] = True,
    auto_build_deps: Annotated[
        bool,
        typer.Option(
            "--auto-build-deps", help="Automatically trigger dep builds if needed"
        ),
    ] = False,
    dry_run: Annotated[
        bool, typer.Option("--dry-run", help="Show what would be submitted")
    ] = False,
) -> None:
    """Submit a benchmark workflow to Argo."""
    gke_config = GKEConfig.load()
    if not gke_config.is_configured():
        typer.echo("Error: GKE not configured. Run: python -m cli setup")
        raise typer.Exit(1)

    # Load run config
    run_config = RunConfig()

    if config_file:
        with open(config_file) as f:
            data = json.load(f)
        if "cases" in data:
            if isinstance(data["cases"], str):
                run_config.cases = parse_cases(data["cases"])
            else:
                run_config.cases = data["cases"]
        if "model" in data:
            run_config.model = data["model"]
        if "experiment_id" in data:
            run_config.experiment_id = data["experiment_id"]
        if "fuzzing_duration" in data:
            run_config.fuzzing_duration = data["fuzzing_duration"]
        if "run_gt" in data:
            run_config.run_gt = data["run_gt"]
        if "build_version" in data:
            run_config.build_version = data["build_version"]

    # CLI overrides
    if cases:
        run_config.cases = parse_cases(cases)
    if model:
        run_config.model = model
    if experiment_id:
        run_config.experiment_id = experiment_id
    if fuzzing_duration:
        run_config.fuzzing_duration = fuzzing_duration
    run_config.run_gt = run_gt
    if build_version:
        run_config.build_version = build_version

    # Generate experiment ID if not provided
    if not run_config.experiment_id or run_config.experiment_id == "default":
        from datetime import datetime

        run_config.experiment_id = datetime.now().strftime("%Y%m%d-%H%M%S")

    # Validate
    if not run_config.cases:
        typer.echo("Error: No cases specified. Use --cases or --config.")
        raise typer.Exit(1)

    owner = get_current_user()

    typer.echo("=" * 50)
    typer.echo("ARVO Benchmark Submission")
    typer.echo("=" * 50)
    typer.echo(f"Owner:       {owner}")
    typer.echo(f"Experiment:  {run_config.experiment_id}")
    typer.echo(f"Cases:       {len(run_config.cases)} cases")
    typer.echo(f"Model:       {run_config.model}")
    typer.echo(f"Fuzz Time:   {run_config.fuzzing_duration}s")
    typer.echo(f"Run GT:      {run_config.run_gt}")
    typer.echo(f"Build Ver:   {run_config.build_version}")
    typer.echo()

    # Check if dependencies need rebuilding
    build_casr = False
    build_dd = False
    if check_deps:
        typer.echo("Checking dependencies...")
        casr_changed, dd_changed = _check_deps_status(
            bucket=gke_config.bucket_name,
            build_dir=AUTOPATCH_BUILD_DIR,
        )
        should_continue, build_casr, build_dd = _report_deps_status(
            casr_changed=casr_changed,
            dd_changed=dd_changed,
            bucket=gke_config.bucket_name,
            build_dir=AUTOPATCH_BUILD_DIR,
            auto_build=auto_build_deps,
            dry_run=dry_run,
        )
        if not should_continue:
            typer.echo("Aborting submission.")
            raise typer.Exit(1)
        typer.echo()

    # Upload agent runtime
    if upload_runtime and not dry_run:
        typer.echo("Uploading agent runtime...")
        runtime_dir = get_script_dir() / "portable-runtime" / "output"
        runtime_tar = runtime_dir / "agent-runtime.tar.gz"

        if not runtime_tar.exists():
            typer.echo("  Building runtime...")
            build_script = get_script_dir() / "portable-runtime" / "build.sh"
            subprocess.run(["bash", str(build_script)], check=True)

        if runtime_tar.exists():
            result = subprocess.run(
                [
                    "gsutil",
                    "cp",
                    str(runtime_tar),
                    f"gs://{gke_config.bucket_name}/agent-runtime/",
                ],
                capture_output=True,
                text=True,
            )
            if result.returncode == 0:
                typer.echo("  Runtime uploaded.")
            else:
                typer.echo(f"  Warning: {result.stderr}")
        else:
            typer.echo("  Warning: Runtime tarball not found.")
        typer.echo()

    # Build workflow parameters
    workflow_path = get_script_dir() / "argo" / "workflows" / "arvo-benchmark.yaml"
    parameters = {
        "cases": json.dumps(run_config.cases),
        "model": run_config.model,
        "experiment-id": run_config.experiment_id,
        "bucket": gke_config.bucket_name,
        "registry": gke_config.artifact_registry,
        "build-version": run_config.build_version,
        "fuzzing-duration": str(run_config.fuzzing_duration),
        "run-gt": str(run_config.run_gt).lower(),
        "build-casr": str(build_casr).lower(),
        "build-dd": str(build_dd).lower(),
    }

    if dry_run:
        typer.echo("Dry run - would submit workflow with:")
        for key, value in parameters.items():
            typer.echo(f"  {key}: {value}")
        if build_casr or build_dd:
            typer.echo()
            echo_info("Dependency builds included in workflow:")
            if build_casr:
                typer.echo("  - CASR (~15-30 min)")
            if build_dd:
                typer.echo("  - DD (~2-4 hours)")
        return

    if build_casr or build_dd:
        echo_info("Submitting workflow with dependency builds...")
        if build_casr:
            typer.echo("  - CASR build will run first (~15-30 min)")
        if build_dd:
            typer.echo("  - DD build will run first (~2-4 hours)")
    else:
        typer.echo("Submitting workflow...")

    workflow_name = submit_workflow(str(workflow_path), parameters)

    if workflow_name:
        typer.echo()
        typer.echo(f"Workflow submitted: {workflow_name}")
        typer.echo()
        typer.echo("Monitor:")
        typer.echo(f"  python -m cli status {workflow_name}")
        typer.echo(f"  python -m cli status {workflow_name} -w")
        typer.echo()
        typer.echo("Logs:")
        typer.echo(f"  python -m cli logs {workflow_name}")
        typer.echo()
        typer.echo("Argo UI:")
        typer.echo("  kubectl port-forward svc/argo-server -n argo 2746:2746")
        typer.echo("  https://localhost:2746")
    else:
        typer.echo("Error: Failed to submit workflow.")
        raise typer.Exit(1)
