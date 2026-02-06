"""
Submit command for benchmark workflows.
"""

import json
import re
import subprocess
import tempfile
from pathlib import Path
from typing import Annotated, Optional

import typer
import yaml

from ..argo import get_current_user, submit_workflow
from ..config import (
    AgentSpec,
    GKEConfig,
    RunConfig,
    get_script_dir,
    parse_agent_specs,
    parse_cases,
)
from ..hashing import (
    AUTOPATCH_BUILD_DIR,
    check_runtime_needs_rebuild,
    compute_deps_source_hash,
    get_deps_manifest_from_gcs,
)
from ..output import echo_error, echo_info, echo_success, echo_warning
from . import semaphore


def _check_semaphore_limits(
    agent_specs: list[AgentSpec], dry_run: bool = False
) -> bool:
    """Check if all LLM models have semaphore limits configured.

    Semaphores are keyed by raw model name (rate limiting is about API call
    volume). Multiple agent specs sharing the same model share the semaphore.

    Args:
        agent_specs: List of agent specs to check
        dry_run: If True, only show what would be done

    Returns:
        True if should continue, False if user aborted
    """
    # Extract unique model names from agent specs
    unique_models = sorted(set(spec.model for spec in agent_specs))

    if not unique_models:
        echo_info("No LLM models to check (only ground truth)")
        return True

    # Check which models are missing limits
    models_with_limits: list[tuple[str, Optional[int]]] = []
    models_without_limits = []

    for model in unique_models:
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


def _sanitize_name(name: str) -> str:
    """Convert a name to valid Kubernetes/Argo task name component.

    Args:
        name: Name to sanitize (e.g., 'autopatchbench-claude-sonnet-4-20250514')

    Returns:
        Sanitized name valid for K8s (lowercase, alphanumeric and hyphens only)
    """
    # Replace invalid characters with hyphens
    safe = re.sub(r"[^a-z0-9-]", "-", str(name).lower())
    # Remove consecutive hyphens
    safe = re.sub(r"-+", "-", safe)
    # Remove leading/trailing hyphens
    safe = safe.strip("-")
    # Truncate to reasonable length
    return safe[:63]


def _generate_workflow_yaml(
    base_workflow_path: Path,
    cases: list[int | str],
    agent_specs: list[AgentSpec],
    registry: str,
    run_gt: bool = True,
    patch_use_spot: bool = True,
    fuzz_use_spot: bool = True,
) -> str:
    """Generate a completely flat workflow YAML with no withParam or nested DAGs.

    This generates all tasks for all (case, agent_spec) combinations directly in
    the main DAG, avoiding Argo bugs with dynamic task tracking and nested DAGs.

    Structure:
    - build-casr, build-dd (dependency builds, conditional)
    - chk-build-vul-{case}, build-vul-{case} for each case
    - chk-build-fix-{case}, build-fix-{case} for each case
    - For each (case, agent_spec):
      - chk-patch-{case}-{agent-id}: check if patch done
      - patch-{case}-{agent-id}: run patch if needed
      - chk-fuzz-{case}-{agent-id}: check if fuzz done
      - fuzz-{case}-{agent-id}: run fuzz if needed
    - For each case (if run_gt):
      - chk-gt-{case}: check if GT done
      - fuzz-gt-{case}: run GT fuzz if needed

    Args:
        base_workflow_path: Path to the base workflow YAML file
        cases: List of case IDs
        agent_specs: List of AgentSpec objects
        registry: Artifact Registry path (e.g. us-central1-docker.pkg.dev/project/repo)
        run_gt: Whether to include ground truth fuzzing tasks
        patch_use_spot: Whether patch jobs should use spot instances
        fuzz_use_spot: Whether fuzz jobs should use spot instances

    Returns:
        Generated workflow YAML as a string
    """
    with open(base_workflow_path) as f:
        workflow = yaml.safe_load(f)

    # Find benchmark-pipeline template
    for template in workflow["spec"]["templates"]:
        if template["name"] == "benchmark-pipeline":
            tasks = template["dag"]["tasks"]

            # Parse registry for Docker v2 API URL construction
            # registry = "us-central1-docker.pkg.dev/project/repo"
            registry_host, registry_path = registry.split("/", 1)

            # Generate tasks for each case
            for case in cases:
                case_safe = _sanitize_name(case)

                # Check if vulnerable image already exists (Docker v2 manifests API)
                vul_check_url = f"https://{registry_host}/v2/{registry_path}/arvo-{case}-vul/manifests/{{{{workflow.parameters.build-version}}}}"
                tasks.append(
                    {
                        "name": f"chk-build-vul-{case_safe}",
                        "template": "check-image",
                        "continueOn": {"failed": True},
                        "arguments": {
                            "parameters": [
                                {
                                    "name": "url",
                                    "value": vul_check_url,
                                },
                            ]
                        },
                    }
                )

                # Build vulnerable image (only if check failed = image doesn't exist)
                tasks.append(
                    {
                        "name": f"build-vul-{case_safe}",
                        "dependencies": [
                            f"chk-build-vul-{case_safe}",
                            "build-casr",
                            "build-dd",
                        ],
                        "when": f"{{{{tasks.chk-build-vul-{case_safe}.status}}}} == Failed",
                        "templateRef": {
                            "name": "arvo-build",
                            "template": "build-vul",
                        },
                        "arguments": {
                            "parameters": [
                                {"name": "case-id", "value": str(case)},
                                {
                                    "name": "build-version",
                                    "value": "{{workflow.parameters.build-version}}",
                                },
                                {
                                    "name": "bucket",
                                    "value": "{{workflow.parameters.bucket}}",
                                },
                                {
                                    "name": "registry",
                                    "value": "{{workflow.parameters.registry}}",
                                },
                            ]
                        },
                    }
                )

                # Check if fixed image already exists (Docker v2 manifests API)
                fix_check_url = f"https://{registry_host}/v2/{registry_path}/arvo-{case}-fix/manifests/{{{{workflow.parameters.build-version}}}}"
                tasks.append(
                    {
                        "name": f"chk-build-fix-{case_safe}",
                        "template": "check-image",
                        "continueOn": {"failed": True},
                        "arguments": {
                            "parameters": [
                                {
                                    "name": "url",
                                    "value": fix_check_url,
                                },
                            ]
                        },
                    }
                )

                # Build fixed image (only if check failed = image doesn't exist)
                tasks.append(
                    {
                        "name": f"build-fix-{case_safe}",
                        "dependencies": [
                            f"chk-build-fix-{case_safe}",
                            "build-casr",
                            "build-dd",
                        ],
                        "when": f"{{{{tasks.chk-build-fix-{case_safe}.status}}}} == Failed",
                        "templateRef": {
                            "name": "arvo-build",
                            "template": "build-fix",
                        },
                        "arguments": {
                            "parameters": [
                                {"name": "case-id", "value": str(case)},
                                {
                                    "name": "build-version",
                                    "value": "{{workflow.parameters.build-version}}",
                                },
                                {
                                    "name": "bucket",
                                    "value": "{{workflow.parameters.bucket}}",
                                },
                                {
                                    "name": "registry",
                                    "value": "{{workflow.parameters.registry}}",
                                },
                            ]
                        },
                    }
                )

                # Generate tasks for each agent spec
                for spec in agent_specs:
                    id_safe = _sanitize_name(spec.id)
                    suffix = f"{case_safe}-{id_safe}"

                    # Check if patch is done
                    tasks.append(
                        {
                            "name": f"chk-patch-{suffix}",
                            "dependencies": [
                                f"chk-build-vul-{case_safe}",
                                f"build-vul-{case_safe}",
                                f"chk-build-fix-{case_safe}",
                                f"build-fix-{case_safe}",
                            ],
                            "template": "check-completion",
                            "continueOn": {"failed": True},
                            "arguments": {
                                "parameters": [
                                    {
                                        "name": "bucket",
                                        "value": "{{workflow.parameters.bucket}}",
                                    },
                                    {
                                        "name": "path",
                                        "value": f"results%2F{{{{workflow.parameters.experiment-id}}}}%2F{case}%2F{spec.id}%2Fpatch%2F_SUCCESS",
                                    },
                                ]
                            },
                        }
                    )

                    # Patch task
                    tasks.append(
                        {
                            "name": f"patch-{suffix}",
                            "dependencies": [f"chk-patch-{suffix}"],
                            "when": f"{{{{tasks.chk-patch-{suffix}.status}}}} == Failed",
                            "templateRef": {
                                "name": "arvo-patch",
                                "template": "patch-case",
                            },
                            "arguments": {
                                "parameters": [
                                    {"name": "case-id", "value": str(case)},
                                    {"name": "model", "value": spec.model},
                                    {"name": "agent-id", "value": spec.id},
                                    {
                                        "name": "agent-config",
                                        "value": spec.to_agent_config_json(),
                                    },
                                    {
                                        "name": "experiment-id",
                                        "value": "{{workflow.parameters.experiment-id}}",
                                    },
                                    {
                                        "name": "bucket",
                                        "value": "{{workflow.parameters.bucket}}",
                                    },
                                    {
                                        "name": "registry",
                                        "value": "{{workflow.parameters.registry}}",
                                    },
                                    {
                                        "name": "build-version",
                                        "value": "{{workflow.parameters.build-version}}",
                                    },
                                    {
                                        "name": "use-spot",
                                        "value": str(patch_use_spot).lower(),
                                    },
                                ]
                            },
                        }
                    )

                    # Check if fuzz is done
                    tasks.append(
                        {
                            "name": f"chk-fuzz-{suffix}",
                            "dependencies": [f"chk-patch-{suffix}", f"patch-{suffix}"],
                            "template": "check-completion",
                            "continueOn": {"failed": True},
                            "arguments": {
                                "parameters": [
                                    {
                                        "name": "bucket",
                                        "value": "{{workflow.parameters.bucket}}",
                                    },
                                    {
                                        "name": "path",
                                        "value": f"results%2F{{{{workflow.parameters.experiment-id}}}}%2F{case}%2F{spec.id}%2F_SUCCESS",
                                    },
                                ]
                            },
                        }
                    )

                    # Fuzz task
                    tasks.append(
                        {
                            "name": f"fuzz-{suffix}",
                            "dependencies": [f"chk-fuzz-{suffix}"],
                            "when": f"{{{{tasks.chk-fuzz-{suffix}.status}}}} == Failed",
                            "templateRef": {
                                "name": "arvo-fuzz",
                                "template": "fuzz-case",
                            },
                            "arguments": {
                                "parameters": [
                                    {"name": "case-id", "value": str(case)},
                                    {"name": "target", "value": "llm_patch"},
                                    {"name": "model", "value": spec.model},
                                    {"name": "agent-id", "value": spec.id},
                                    {
                                        "name": "experiment-id",
                                        "value": "{{workflow.parameters.experiment-id}}",
                                    },
                                    {
                                        "name": "bucket",
                                        "value": "{{workflow.parameters.bucket}}",
                                    },
                                    {
                                        "name": "registry",
                                        "value": "{{workflow.parameters.registry}}",
                                    },
                                    {
                                        "name": "build-version",
                                        "value": "{{workflow.parameters.build-version}}",
                                    },
                                    {
                                        "name": "fuzzing-duration",
                                        "value": "{{workflow.parameters.fuzzing-duration}}",
                                    },
                                    {
                                        "name": "use-spot",
                                        "value": str(fuzz_use_spot).lower(),
                                    },
                                ]
                            },
                        }
                    )

                # GT fuzzing tasks (if enabled)
                if run_gt:
                    # Check if GT is done
                    tasks.append(
                        {
                            "name": f"chk-gt-{case_safe}",
                            "dependencies": [
                                f"chk-build-fix-{case_safe}",
                                f"build-fix-{case_safe}",
                            ],
                            "template": "check-completion",
                            "continueOn": {"failed": True},
                            "arguments": {
                                "parameters": [
                                    {
                                        "name": "bucket",
                                        "value": "{{workflow.parameters.bucket}}",
                                    },
                                    {
                                        "name": "path",
                                        "value": f"results%2F{{{{workflow.parameters.experiment-id}}}}%2F{case}%2Fgt%2F_SUCCESS",
                                    },
                                ]
                            },
                        }
                    )

                    # GT fuzz task
                    tasks.append(
                        {
                            "name": f"fuzz-gt-{case_safe}",
                            "dependencies": [f"chk-gt-{case_safe}"],
                            "when": f"{{{{tasks.chk-gt-{case_safe}.status}}}} == Failed",
                            "templateRef": {
                                "name": "arvo-fuzz",
                                "template": "fuzz-case",
                            },
                            "arguments": {
                                "parameters": [
                                    {"name": "case-id", "value": str(case)},
                                    {"name": "target", "value": "ground_truth"},
                                    {"name": "model", "value": "gt"},
                                    {"name": "agent-id", "value": "gt"},
                                    {
                                        "name": "experiment-id",
                                        "value": "{{workflow.parameters.experiment-id}}",
                                    },
                                    {
                                        "name": "bucket",
                                        "value": "{{workflow.parameters.bucket}}",
                                    },
                                    {
                                        "name": "registry",
                                        "value": "{{workflow.parameters.registry}}",
                                    },
                                    {
                                        "name": "build-version",
                                        "value": "{{workflow.parameters.build-version}}",
                                    },
                                    {
                                        "name": "fuzzing-duration",
                                        "value": "{{workflow.parameters.fuzzing-duration}}",
                                    },
                                    {
                                        "name": "use-spot",
                                        "value": str(fuzz_use_spot).lower(),
                                    },
                                ]
                            },
                        }
                    )

            break

    return yaml.dump(workflow, default_flow_style=False, sort_keys=False)


def submit(
    cases: Annotated[
        Optional[str],
        typer.Option(help="Case IDs: '42,43,44', '42-50', or '@path/to/cases.json'"),
    ] = None,
    model: Annotated[
        Optional[str],
        typer.Option(
            help="LLM model to use as autopatchbench agent (convenience shorthand)"
        ),
    ] = None,
    experiment_id: Annotated[
        Optional[str], typer.Option("--experiment", "-e", help="Experiment ID")
    ] = None,
    fuzzing_duration: Annotated[
        Optional[int], typer.Option(help="Fuzzing duration in seconds")
    ] = None,
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
        if "agents" in data:
            # Parse structured agent specs
            try:
                run_config.agents, config_run_gt = parse_agent_specs(data["agents"])
                # Only override run_gt from config if "gt" was explicitly in agents list
                if config_run_gt:
                    run_config.run_gt = True
            except ValueError as e:
                echo_error(f"Invalid agent spec in config: {e}")
                raise typer.Exit(1)
        if "experiment_id" in data:
            run_config.experiment_id = data["experiment_id"]
        if "fuzzing_duration" in data:
            run_config.fuzzing_duration = data["fuzzing_duration"]
        if "run_gt" in data:
            run_config.run_gt = data["run_gt"]
        if "build_version" in data:
            run_config.build_version = data["build_version"]
        if "patch_use_spot" in data:
            run_config.patch_use_spot = data["patch_use_spot"]
        if "fuzz_use_spot" in data:
            run_config.fuzz_use_spot = data["fuzz_use_spot"]

    # CLI overrides
    if cases:
        run_config.cases = parse_cases(cases)
    if model is not None:
        # Convenience: --model flag creates a single autopatchbench agent spec
        run_config.agents = [
            AgentSpec(
                id=f"autopatchbench-{model}",
                agent_type="autopatchbench",
                model=model,
            )
        ]
    if experiment_id:
        run_config.experiment_id = experiment_id
    if fuzzing_duration is not None:
        run_config.fuzzing_duration = fuzzing_duration
    run_config.run_gt = run_gt
    if build_version:
        run_config.build_version = build_version

    # Validate: must have at least one agent spec
    if not run_config.agents:
        echo_error(
            "No agents specified. Use --config with structured agents or --model."
        )
        raise typer.Exit(1)

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
    typer.echo(f"Agents:      {len(run_config.agents)} agent(s)")
    for spec in run_config.agents:
        typer.echo(f"             - {spec.id} ({spec.agent_type}, {spec.model})")
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

    # Check semaphore limits (per-model, not per-agent-id)
    typer.echo("Checking semaphore limits...")
    if not _check_semaphore_limits(run_config.agents, dry_run=dry_run):
        typer.echo("Aborting submission.")
        raise typer.Exit(1)
    typer.echo()

    # Upload agent runtime (rebuild if source changed)
    if upload_runtime and not dry_run:
        typer.echo("Checking agent runtime...")
        runtime_dir = get_script_dir() / "portable-runtime" / "output"
        runtime_tar = runtime_dir / "agent-runtime.tar.gz"

        needs_rebuild, reason = check_runtime_needs_rebuild()
        if needs_rebuild:
            typer.echo(f"  Rebuilding runtime ({reason})...")
            build_script = get_script_dir() / "portable-runtime" / "build.sh"
            subprocess.run(["bash", str(build_script)], check=True)
        else:
            typer.echo(f"  Runtime up to date.")

        if runtime_tar.exists():
            if needs_rebuild:
                typer.echo("  Uploading runtime...")
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

    # Generate fully-flat workflow YAML with all tasks inlined
    # This avoids all withParam and nested DAGs which cause Argo completion bugs
    base_workflow_path = get_script_dir() / "argo" / "workflows" / "arvo-benchmark.yaml"
    typer.echo("Generating flat workflow (no withParam, no nested DAGs)...")
    typer.echo(f"  Cases: {len(run_config.cases)}")
    typer.echo(f"  Agents: {len(run_config.agents)}")
    total_tasks = len(run_config.cases) * (
        4 + len(run_config.agents) * 4
    )  # build checks + builds + agent tasks
    if run_config.run_gt:
        total_tasks += len(run_config.cases) * 2  # GT tasks per case
    typer.echo(f"  Total tasks: {total_tasks}")
    workflow_yaml = _generate_workflow_yaml(
        base_workflow_path,
        run_config.cases,
        run_config.agents,
        registry=gke_config.artifact_registry,
        run_gt=run_config.run_gt,
        patch_use_spot=run_config.patch_use_spot,
        fuzz_use_spot=run_config.fuzz_use_spot,
    )
    typer.echo()

    # Build workflow parameters (agent-specific values are inlined per-task)
    parameters = {
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
        typer.echo()
        typer.echo("Generated task structure (per case):")
        typer.echo("  - chk-build-vul-{case} -> build-vul-{case}")
        typer.echo("  - chk-build-fix-{case} -> build-fix-{case}")
        for spec in run_config.agents:
            id_safe = _sanitize_name(spec.id)
            typer.echo(f"  - chk-patch-{{case}}-{id_safe} -> patch-{{case}}-{id_safe}")
            typer.echo(f"  - chk-fuzz-{{case}}-{id_safe} -> fuzz-{{case}}-{id_safe}")
        if run_config.run_gt:
            typer.echo("  - chk-gt-{case} -> fuzz-gt-{case}")
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

    # Write generated workflow to temp file and submit
    temp_workflow_path = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".yaml", delete=False
        ) as temp_file:
            temp_file.write(workflow_yaml)
            temp_workflow_path = temp_file.name

        workflow_name = submit_workflow(temp_workflow_path, parameters)
    finally:
        # Clean up temp file
        if temp_workflow_path:
            try:
                Path(temp_workflow_path).unlink()
            except OSError:
                pass  # Ignore cleanup errors

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
