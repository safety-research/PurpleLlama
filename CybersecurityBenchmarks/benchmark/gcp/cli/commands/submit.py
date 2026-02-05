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
from ..output import echo_error, echo_info, echo_success, echo_warning
from . import semaphore


def _check_semaphore_limits(models: list[str], dry_run: bool = False) -> bool:
    """Check if all models have semaphore limits configured.

    Args:
        models: List of model names to check (excludes 'gt')
        dry_run: If True, only show what would be done

    Returns:
        True if should continue, False if user aborted
    """
    # Filter out 'gt' as it doesn't need rate limiting
    llm_models = [m for m in models if m != "gt"]

    if not llm_models:
        echo_info("No LLM models to check (only ground truth)")
        return True

    # Check which models are missing limits
    models_with_limits: list[tuple[str, Optional[int]]] = []
    models_without_limits = []

    for model in llm_models:
        is_configured, limit = semaphore.get_model_limit(model)
        if is_configured:
            models_with_limits.append((model, limit))
        else:
            models_without_limits.append(model)

    # Show status for models with limits
    for model, limit in models_with_limits:
        if limit is None:
            echo_success(f"Semaphore limit for '{model}': unlimited")
        else:
            echo_success(f"Semaphore limit for '{model}': {limit} concurrent jobs")

    # If all models have limits, we're done
    if not models_without_limits:
        return True

    # Show models without limits
    typer.echo()
    echo_warning(
        f"No semaphore limits configured for {len(models_without_limits)} model(s):"
    )
    for model in models_without_limits:
        typer.echo(f"  - {model}")
    typer.echo()
    typer.echo("Without limits, patch jobs will run without rate limiting.")
    typer.echo()

    if dry_run:
        typer.echo("  [DRY RUN] Would prompt to set limits")
        return True

    # Ask user what to do
    typer.echo("Options:")
    typer.echo("  1. Set limits for all unconfigured models now")
    typer.echo("  2. Continue without limits (unlimited concurrency)")
    typer.echo("  3. Abort submission")
    typer.echo()

    choice = typer.prompt("Choose an option", type=int, default=1)

    if choice == 1:
        # Prompt for each model
        default_limit = "20"
        for model in models_without_limits:
            limit_value = typer.prompt(
                f"Enter max concurrent jobs for '{model}' (number or 'unlimited')",
                type=str,
                default=default_limit,
            )
            semaphore.set_limit(model, limit_value)
            # Use the same limit as default for subsequent models
            default_limit = limit_value
        return True
    elif choice == 2:
        echo_info("Continuing without semaphore limits")
        return True
    else:
        return False


def _apply_argo_templates(dry_run: bool = False) -> bool:
    """Apply Argo workflow templates to the cluster.

    Args:
        dry_run: If True, only show what would be done

    Returns:
        True if successful, False otherwise
    """
    templates_dir = get_script_dir() / "argo" / "templates"

    if not templates_dir.exists():
        echo_error(f"Templates directory not found: {templates_dir}")
        return False

    if dry_run:
        typer.echo(f"  [DRY RUN] Would apply templates from {templates_dir}")
        return True

    result = subprocess.run(
        ["kubectl", "apply", "-f", str(templates_dir)],
        capture_output=True,
        text=True,
    )

    if result.returncode != 0:
        echo_error(f"Failed to apply templates: {result.stderr}")
        return False

    # Show what was applied
    for line in result.stdout.strip().split("\n"):
        if line:
            typer.echo(f"  {line}")

    return True


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
        Optional[str], typer.Option(help="LLM model to use (overrides config agents)")
    ] = None,
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
    agents_from_config: list[str] = []  # Track all agents/models from config

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
        if "agents" in data:
            # Config has multiple agents - track them for semaphore check
            agents_from_config = data["agents"]
            # Use first non-gt agent as the model if model not specified
            if "model" not in data:
                for agent in agents_from_config:
                    if agent != "gt":
                        run_config.model = agent
                        break
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
    if model is not None:
        # Explicit --model flag overrides config agents
        run_config.model = model
        agents_from_config = []
    if experiment_id:
        run_config.experiment_id = experiment_id
    if fuzzing_duration:
        run_config.fuzzing_duration = fuzzing_duration
    run_config.run_gt = run_gt
    if build_version:
        run_config.build_version = build_version

    # Build final list of models to check
    # Priority: 1) CLI --model flag, 2) config agents, 3) default model
    if agents_from_config:
        models_to_check = agents_from_config
    elif run_config.model:
        models_to_check = [run_config.model]
    else:
        # No model specified anywhere - use default
        run_config.model = "claude-sonnet-4-20250514"
        models_to_check = [run_config.model]

    # Generate experiment ID if not provided
    if not run_config.experiment_id:
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
    if len(models_to_check) > 1:
        typer.echo(f"Models:      {len(models_to_check)} agents")
        for m in models_to_check:
            typer.echo(f"             - {m}")
    else:
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

    # Check semaphore limits for all models
    typer.echo("Checking semaphore limits...")
    if not _check_semaphore_limits(models_to_check, dry_run=dry_run):
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

    # Build list of LLM models (exclude 'gt' - it's handled by fuzz-gt)
    llm_models = [m for m in models_to_check if m != "gt"]

    parameters = {
        "cases": json.dumps(run_config.cases),
        "models": json.dumps(llm_models),
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

    # Apply Argo workflow templates
    typer.echo("Applying Argo workflow templates...")
    if not _apply_argo_templates(dry_run=dry_run):
        typer.echo("Error: Failed to apply workflow templates.")
        raise typer.Exit(1)
    typer.echo()

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
