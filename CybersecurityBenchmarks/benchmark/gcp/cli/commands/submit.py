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
    compute_image_build_version,
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
    agent_specs: list[AgentSpec],
    run_gt: bool = True,
) -> str:
    """Generate workflow YAML with a case-pipeline template for withParam expansion.

    Instead of inlining O(cases x agents) tasks in a flat DAG, this generates a
    single case-pipeline DAG template with O(agents) tasks. The main DAG uses
    withParam to iterate over cases, invoking this template once per case.
    Cases are passed at submit time via the cases-json workflow parameter.

    The case-pipeline template contains:
    - chk-build-vul, build-vul: check/build vulnerable image
    - chk-build-fix, build-fix: check/build fixed image
    - For each agent_spec:
      - chk-patch-{agent-id}: check if patch done
      - patch-{agent-id}: run patch if needed
      - chk-fuzz-{agent-id}: check if fuzz done
      - fuzz-{agent-id}: run fuzz if needed
    - If run_gt:
      - chk-gt: check if GT done
      - fuzz-gt: run GT fuzz if needed

    Args:
        base_workflow_path: Path to the base workflow YAML file
        agent_specs: List of AgentSpec objects
        run_gt: Whether to include ground truth fuzzing tasks

    Returns:
        Generated workflow YAML as a string
    """
    with open(base_workflow_path) as f:
        workflow = yaml.safe_load(f)

    # Build the case-pipeline DAG template tasks
    # All case-specific references use {{inputs.parameters.case-id}}
    # All workflow-level references use {{workflow.parameters.*}}
    case_tasks: list[dict] = []

    # --- Build tasks ---

    # Check if vulnerable image already exists (Docker v2 manifests API)
    # Outputs status="done" (skip) or status="needed" (build); continueOn is a safety net for pod crashes
    case_tasks.append(
        {
            "name": "chk-build-vul",
            "template": "check-image",
            "continueOn": {"failed": True},
            "arguments": {
                "parameters": [
                    {
                        "name": "url",
                        "value": "{{workflow.parameters.registry-api-prefix}}/arvo-{{inputs.parameters.case-id}}-vul/manifests/{{workflow.parameters.build-version}}",
                    },
                ]
            },
        }
    )

    # Build vulnerable image (only if check reports image is needed)
    case_tasks.append(
        {
            "name": "build-vul",
            "dependencies": ["chk-build-vul"],
            "when": '"{{tasks.chk-build-vul.outputs.parameters.status}}" == "needed"',
            "templateRef": {
                "name": "arvo-build",
                "template": "build-vul",
            },
            "arguments": {
                "parameters": [
                    {
                        "name": "case-id",
                        "value": "{{inputs.parameters.case-id}}",
                    },
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
    # Outputs status="done" (skip) or status="needed" (build); continueOn is a safety net for pod crashes
    case_tasks.append(
        {
            "name": "chk-build-fix",
            "template": "check-image",
            "continueOn": {"failed": True},
            "arguments": {
                "parameters": [
                    {
                        "name": "url",
                        "value": "{{workflow.parameters.registry-api-prefix}}/arvo-{{inputs.parameters.case-id}}-fix/manifests/{{workflow.parameters.build-version}}",
                    },
                ]
            },
        }
    )

    # Build fixed image (only if check reports image is needed)
    case_tasks.append(
        {
            "name": "build-fix",
            "dependencies": ["chk-build-fix"],
            "when": '"{{tasks.chk-build-fix.outputs.parameters.status}}" == "needed"',
            "templateRef": {
                "name": "arvo-build",
                "template": "build-fix",
            },
            "arguments": {
                "parameters": [
                    {
                        "name": "case-id",
                        "value": "{{inputs.parameters.case-id}}",
                    },
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

    # --- Agent tasks (one set per agent spec, statically expanded) ---
    for spec in agent_specs:
        id_safe = _sanitize_name(spec.id)

        # Check if patch is done
        case_tasks.append(
            {
                "name": f"chk-patch-{id_safe}",
                "dependencies": [
                    "chk-build-vul",
                    "build-vul",
                    "chk-build-fix",
                    "build-fix",
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
                            "value": f"results%2F{{{{workflow.parameters.experiment-id}}}}%2F{{{{inputs.parameters.case-id}}}}%2F{spec.id}%2Fpatch%2F_SUCCESS",
                        },
                    ]
                },
            }
        )

        # Patch task
        case_tasks.append(
            {
                "name": f"patch-{id_safe}",
                "dependencies": [f"chk-patch-{id_safe}"],
                "when": f'"{{{{tasks.chk-patch-{id_safe}.outputs.parameters.status}}}}" == "needed"',
                "templateRef": {
                    "name": "arvo-patch",
                    "template": "patch-case",
                },
                "arguments": {
                    "parameters": [
                        {
                            "name": "case-id",
                            "value": "{{inputs.parameters.case-id}}",
                        },
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
                            "value": "{{workflow.parameters.patch-use-spot}}",
                        },
                    ]
                },
            }
        )

        # Check if fuzz is done
        case_tasks.append(
            {
                "name": f"chk-fuzz-{id_safe}",
                "dependencies": [f"chk-patch-{id_safe}", f"patch-{id_safe}"],
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
                            "value": f"results%2F{{{{workflow.parameters.experiment-id}}}}%2F{{{{inputs.parameters.case-id}}}}%2F{spec.id}%2F_SUCCESS",
                        },
                    ]
                },
            }
        )

        # Fuzz task
        case_tasks.append(
            {
                "name": f"fuzz-{id_safe}",
                "dependencies": [f"chk-fuzz-{id_safe}"],
                "when": f'"{{{{tasks.chk-fuzz-{id_safe}.outputs.parameters.status}}}}" == "needed"',
                "templateRef": {
                    "name": "arvo-fuzz",
                    "template": "fuzz-case",
                },
                "arguments": {
                    "parameters": [
                        {
                            "name": "case-id",
                            "value": "{{inputs.parameters.case-id}}",
                        },
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
                            "value": "{{workflow.parameters.fuzz-use-spot}}",
                        },
                    ]
                },
            }
        )

    # --- GT fuzzing tasks (if enabled) ---
    if run_gt:
        # Check if GT is done
        case_tasks.append(
            {
                "name": "chk-gt",
                "dependencies": [
                    "chk-build-fix",
                    "build-fix",
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
                            "value": "results%2F{{workflow.parameters.experiment-id}}%2F{{inputs.parameters.case-id}}%2Fgt%2F_SUCCESS",
                        },
                    ]
                },
            }
        )

        # GT fuzz task
        case_tasks.append(
            {
                "name": "fuzz-gt",
                "dependencies": ["chk-gt"],
                "when": '"{{tasks.chk-gt.outputs.parameters.status}}" == "needed"',
                "templateRef": {
                    "name": "arvo-fuzz",
                    "template": "fuzz-case",
                },
                "arguments": {
                    "parameters": [
                        {
                            "name": "case-id",
                            "value": "{{inputs.parameters.case-id}}",
                        },
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
                            "value": "{{workflow.parameters.fuzz-use-spot}}",
                        },
                    ]
                },
            }
        )

    # Add case-pipeline template to workflow
    case_pipeline_template = {
        "name": "case-pipeline",
        "inputs": {
            "parameters": [
                {"name": "case-id"},
            ]
        },
        "dag": {
            "tasks": case_tasks,
        },
    }
    workflow["spec"]["templates"].append(case_pipeline_template)

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
    build_version: Annotated[str, typer.Option(help="Build version tag ('auto' = content hash)")] = "auto",
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

    # Auto-compute build version from content hash of all image inputs
    if run_config.build_version == "auto":
        typer.echo("Computing build version from image inputs...")
        version_hash, input_hashes = compute_image_build_version(AUTOPATCH_BUILD_DIR)
        run_config.build_version = version_hash
        typer.echo(f"  Build version: {version_hash}")
        if dry_run:
            for name, h in sorted(input_hashes.items()):
                typer.echo(f"    {name}: {h[:12]}...")
        typer.echo()

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

    # Upload patch files for gtbackporter agents
    has_backporter = any(
        spec.agent_type == "gtbackporter" for spec in run_config.agents
    )
    if has_backporter and not dry_run:
        typer.echo("Uploading patch files for gtbackporter agents...")
        patch_dir = (
            get_script_dir().parent.parent / "datasets" / "autopatch" / "arvo_meta"
        )
        uploaded = 0
        for case_id in run_config.cases:
            patch_file = patch_dir / f"{case_id}-patch.json"
            if patch_file.exists():
                result = subprocess.run(
                    [
                        "gsutil",
                        "cp",
                        str(patch_file),
                        f"gs://{gke_config.bucket_name}/patches/{case_id}-patch.json",
                    ],
                    capture_output=True,
                    text=True,
                )
                if result.returncode == 0:
                    uploaded += 1
            else:
                typer.echo(f"  Warning: No patch file for case {case_id}")
        typer.echo(f"  Uploaded {uploaded}/{len(run_config.cases)} patch files.")
        typer.echo()

    # Generate workflow YAML with case-pipeline template (withParam over cases)
    # Agent tasks are statically expanded in the template; cases are passed via parameter
    base_workflow_path = get_script_dir() / "argo" / "workflows" / "arvo-benchmark.yaml"
    tasks_per_case = 4 + len(run_config.agents) * 4  # build checks + agent tasks
    if run_config.run_gt:
        tasks_per_case += 2  # GT tasks
    total_tasks = len(run_config.cases) * tasks_per_case
    typer.echo("Generating workflow (withParam over cases)...")
    typer.echo(f"  Cases: {len(run_config.cases)}")
    typer.echo(f"  Agents: {len(run_config.agents)}")
    typer.echo(f"  Tasks per case: {tasks_per_case}")
    typer.echo(f"  Total tasks (runtime): {total_tasks}")
    workflow_yaml = _generate_workflow_yaml(
        base_workflow_path,
        run_config.agents,
        run_gt=run_config.run_gt,
    )
    typer.echo()

    # Compute derived parameter values
    registry_host, registry_path = gke_config.artifact_registry.split("/", 1)
    registry_api_prefix = f"https://{registry_host}/v2/{registry_path}"
    cases_json = json.dumps([str(c) for c in run_config.cases])

    # Build workflow parameters
    parameters = {
        "experiment-id": run_config.experiment_id,
        "bucket": gke_config.bucket_name,
        "registry": gke_config.artifact_registry,
        "registry-api-prefix": registry_api_prefix,
        "build-version": run_config.build_version,
        "fuzzing-duration": str(run_config.fuzzing_duration),
        "cases-json": cases_json,
        "patch-use-spot": str(run_config.patch_use_spot).lower(),
        "fuzz-use-spot": str(run_config.fuzz_use_spot).lower(),
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
            if key == "cases-json":
                typer.echo(f"  {key}: [{len(run_config.cases)} cases]")
            else:
                typer.echo(f"  {key}: {value}")
        typer.echo()
        typer.echo("Workflow structure:")
        typer.echo("  Main DAG: build-casr, build-dd -> process-cases (withParam)")
        typer.echo(f"  case-pipeline template ({tasks_per_case} tasks per case):")
        typer.echo("    - chk-build-vul -> build-vul")
        typer.echo("    - chk-build-fix -> build-fix")
        for spec in run_config.agents:
            id_safe = _sanitize_name(spec.id)
            typer.echo(f"    - chk-patch-{id_safe} -> patch-{id_safe}")
            typer.echo(f"    - chk-fuzz-{id_safe} -> fuzz-{id_safe}")
        if run_config.run_gt:
            typer.echo("    - chk-gt -> fuzz-gt")
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
