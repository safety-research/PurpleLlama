"""
Submit command for submitting benchmark jobs to Cloud Batch.
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Annotated, Optional

import typer

from ..config import (
    DEFAULT_MODEL,
    RunConfig,
    load_run_config,
    merge_run_config,
    parse_agents,
    parse_cases,
)
from ..gcp_utils import (
    get_gcp_username,
    get_script_dir,
    get_vm_image_if_exists,
    load_config,
    run_gcloud,
    run_gsutil,
    save_config,
)
from ..hashing import (
    AUTOPATCH_BUILD_DIR,
    check_deps_need_rebuild,
    get_build_version_from_gcs,
)
from ..output import echo_error, echo_info, echo_success, echo_warning
from .deps import submit_deps_job_impl
from .runs import create_run_manifest, upload_run_manifest
from .upload import upload_build_assets_impl, upload_deps_sources_impl, upload_runtime_impl


def submit(
    cases: Annotated[
        Optional[str],
        typer.Option(help="Case IDs: 'all', '42,43,44', or '@path/to/cases.json'"),
    ] = None,
    agents: Annotated[
        Optional[str],
        typer.Option(
            help="Agents to run: model names and/or 'gt' (e.g., 'claude-sonnet-4-20250514,gt')"
        ),
    ] = None,
    fuzzing_duration: Annotated[
        Optional[int], typer.Option(help="Fuzzing duration in seconds")
    ] = None,
    build_only: Annotated[
        bool, typer.Option("--build-only", help="Only run build jobs (skip agents)")
    ] = False,
    run_id: Annotated[Optional[str], typer.Option(help="Custom run ID")] = None,
    max_concurrent_vms: Annotated[
        Optional[int],
        typer.Option(help="Max concurrent VMs for all job types (default: 50)"),
    ] = None,
    build_max_concurrent_vms: Annotated[
        Optional[int], typer.Option(help="Max concurrent VMs for build jobs")
    ] = None,
    eval_max_concurrent_vms: Annotated[
        Optional[int], typer.Option(help="Max concurrent VMs for eval jobs")
    ] = None,
    gt_max_concurrent_vms: Annotated[
        Optional[int], typer.Option(help="Max concurrent VMs for GT jobs")
    ] = None,
    config_file: Annotated[
        Optional[Path], typer.Option("--config", "-c", help="Run config file (JSON)")
    ] = None,
    force_repatch: Annotated[
        bool,
        typer.Option(
            "--force-repatch", help="Ignore cached patches, re-run LLM patching"
        ),
    ] = False,
    fuzz_only: Annotated[
        bool,
        typer.Option("--fuzz-only", help="Require cached patches (fail if not found)"),
    ] = False,
    force_rebuild: Annotated[
        bool,
        typer.Option(
            "--force-rebuild", help="Rebuild containers even if versioned image exists"
        ),
    ] = False,
    skip_deps_check: Annotated[
        bool,
        typer.Option("--skip-deps-check", help="Skip automatic deps rebuild check"),
    ] = False,
    force_deps_rebuild: Annotated[
        bool,
        typer.Option("--force-deps-rebuild", help="Force rebuild of CASR and DD deps"),
    ] = False,
    dry_run: Annotated[
        bool, typer.Option("--dry-run", help="Show what would be done")
    ] = False,
) -> None:
    """Submit benchmark jobs to Cloud Batch.

    Configuration can be provided via CLI flags or a config file (--config).
    CLI flags override config file values.

    Agents can include LLM model names (e.g., 'claude-sonnet-4-20250514') and/or
    'gt' for ground truth fuzzing. Multiple agents run as separate jobs.

    Example config file (JSON):

        {
          "cases": "@datasets/autopatch/autopatch_bench.json",
          "agents": ["claude-sonnet-4-20250514", "gt"],
          "fuzzing_duration": 300,
          "max_concurrent_vms": 50
        }
    """
    gcp_config = load_config()
    if not gcp_config:
        echo_error("GCP not configured. Run 'setup' first.")
        raise typer.Exit(1)

    # Load config file if provided
    file_config = {}
    if config_file:
        try:
            file_config = load_run_config(config_file)
            echo_info(f"Loaded config from {config_file}")
        except (FileNotFoundError, ImportError, ValueError) as e:
            echo_error(str(e))
            raise typer.Exit(1)

    # Build CLI overrides dict (only include explicitly set values)
    cli_overrides = {}
    if cases is not None:
        cli_overrides["cases"] = parse_cases(cases)
    if agents is not None:
        cli_overrides["agents"] = parse_agents(agents)
    if fuzzing_duration is not None:
        cli_overrides["fuzzing_duration"] = fuzzing_duration
    if run_id is not None:
        cli_overrides["run_id"] = run_id
    if max_concurrent_vms is not None:
        cli_overrides["max_concurrent_vms"] = max_concurrent_vms
    if build_max_concurrent_vms is not None:
        cli_overrides["build_max_concurrent_vms"] = build_max_concurrent_vms
    if eval_max_concurrent_vms is not None:
        cli_overrides["eval_max_concurrent_vms"] = eval_max_concurrent_vms
    if gt_max_concurrent_vms is not None:
        cli_overrides["gt_max_concurrent_vms"] = gt_max_concurrent_vms
    if build_only:
        cli_overrides["build_only"] = build_only
    if force_repatch:
        cli_overrides["force_repatch"] = force_repatch
    if fuzz_only:
        cli_overrides["fuzz_only"] = fuzz_only
    if force_rebuild:
        cli_overrides["force_rebuild"] = force_rebuild

    # Merge configs
    run_config = merge_run_config(file_config, cli_overrides)

    # Validate: cases are required
    if not run_config.cases:
        echo_error("No cases specified. Use --cases or provide in config file.")
        raise typer.Exit(1)

    case_str = ",".join(str(c) for c in run_config.cases)
    task_count = len(run_config.cases)

    # Generate run ID if not provided
    if not run_config.run_id:
        run_config.run_id = datetime.now().strftime("%Y%m%d-%H%M%S")

    # Validate: agents are required (unless build_only)
    if not run_config.build_only and not run_config.agents:
        echo_error("No agents specified. Use --agents or provide in config file.")
        raise typer.Exit(1)

    # Validate: force_repatch and fuzz_only are mutually exclusive
    if run_config.force_repatch and run_config.fuzz_only:
        echo_error("Cannot use both --force-repatch and --fuzz-only")
        raise typer.Exit(1)

    llm_agents = run_config.get_llm_agents()
    has_gt = run_config.has_gt()

    typer.echo("=" * 50)
    typer.echo("ARVO Benchmark Job Submission")
    typer.echo("=" * 50)
    typer.echo()
    typer.echo(f"Run ID:           {run_config.run_id}")
    typer.echo(f"Project:          {gcp_config['project_id']}")
    typer.echo(f"Region:           {gcp_config['region']}")
    typer.echo(f"Cases:            {task_count} cases")
    typer.echo(f"Agents:           {', '.join(run_config.agents)}")
    typer.echo(f"Fuzzing Duration: {run_config.fuzzing_duration}s")
    typer.echo(
        f"Max VMs:          build={run_config.get_max_concurrent_vms('build')}, "
        f"eval={run_config.get_max_concurrent_vms('eval')}, "
        f"gt={run_config.get_max_concurrent_vms('gt')}"
    )
    if run_config.force_repatch:
        typer.echo("Force Repatch:    Yes (ignoring cached patches)")
    if run_config.fuzz_only:
        typer.echo("Fuzz Only:        Yes (using cached patches only)")
    if run_config.force_rebuild:
        typer.echo("Force Rebuild:    Yes (rebuilding containers)")
    typer.echo()

    bucket = gcp_config["bucket_name"]

    if dry_run:
        echo_warning("DRY RUN MODE")
        typer.echo()
        # In dry run, just get the version without uploading
        build_version = get_build_version_from_gcs(bucket) or "latest"
        typer.echo(f"Build Version:    {build_version}")
        typer.echo()
    else:
        # Auto-upload runtime with auto-rebuild if source changed
        typer.echo()
        echo_info("Checking agent runtime...")
        if not upload_runtime_impl(bucket, quiet=False, auto_rebuild=True):
            echo_warning(
                "Runtime upload failed - continuing anyway (may already exist)"
            )

        # Auto-upload build assets (only if changed)
        typer.echo()
        success, build_version = upload_build_assets_impl(bucket, quiet=False)
        if not success:
            echo_warning("Build assets upload failed")
            build_version = get_build_version_from_gcs(bucket) or "latest"

        typer.echo(f"Build Version:    {build_version}")
        typer.echo()

    # Auto-detect custom VM image (for faster job startup)
    vm_image = gcp_config.get("vm_image")
    if not vm_image:
        # Check if image exists in GCP even if not in config
        vm_image = get_vm_image_if_exists(gcp_config["project_id"])
        if vm_image and not dry_run:
            # Save to config for future use
            gcp_config["vm_image"] = vm_image
            save_config(gcp_config)

    if vm_image:
        typer.echo(
            f"VM Image:         {vm_image.split('/')[-1]} (Docker pre-installed)"
        )
    else:
        typer.echo("VM Image:         default (Docker will be installed at runtime)")
    typer.echo()

    # ==========================================================================
    # Check and handle deps (CASR + DD)
    # ==========================================================================
    deps_job_name = None

    if not skip_deps_check:
        typer.echo()
        echo_info("Checking dependencies (CASR + DD)...")
        needs_rebuild, reason = check_deps_need_rebuild(bucket, AUTOPATCH_BUILD_DIR)

        if force_deps_rebuild:
            needs_rebuild = True
            reason = "forced rebuild requested"

        if needs_rebuild:
            echo_warning(f"Deps need rebuild: {reason}")

            if dry_run:
                typer.echo("Would submit deps build job")
            else:
                # Upload deps sources
                echo_info("Uploading deps sources...")
                if upload_deps_sources_impl(bucket, AUTOPATCH_BUILD_DIR, quiet=True):
                    # Submit deps job
                    deps_job_name = submit_deps_job_impl(
                        gcp_config,
                        username=get_gcp_username(),
                        run_id=run_config.run_id,
                        force_rebuild=force_deps_rebuild,
                        quiet=False,
                    )
                    if deps_job_name:
                        typer.echo()
                        echo_warning(
                            "Deps job submitted - build jobs may fail if deps aren't ready"
                        )
                        echo_info("Monitor deps progress: python -m cli monitor")
                        echo_info(
                            "Re-run submit after deps complete, or wait ~2-4 hours"
                        )
                    else:
                        echo_warning("Failed to submit deps job - continuing anyway")
                else:
                    echo_warning("Failed to upload deps sources - continuing anyway")
        else:
            echo_success("Dependencies up to date")
    else:
        echo_info("Skipping deps check (--skip-deps-check)")

    # Upload task scripts
    typer.echo()
    echo_info("Uploading task scripts to GCS...")
    script_dir = get_script_dir() / "scripts"

    if not dry_run:
        # New job structure: build, patch (LLM only), fuzz (unified)
        for script in ["build_task.sh", "patch_task.sh", "fuzz_task.sh"]:
            script_path = script_dir / script
            if script_path.exists():
                run_gsutil(["cp", str(script_path), f"gs://{bucket}/scripts/"])

    # Submit jobs
    jobs_dir = get_script_dir() / "jobs"
    submitted_jobs: dict[str, str] = {}  # job_key -> job_name

    def submit_job(
        job_type: str,
        template_file: str,
        agent: Optional[str] = None,
        target: Optional[str] = None,
        depends_on: Optional[dict[str, str]] = None,
    ) -> Optional[str]:
        """Submit a job to Cloud Batch.

        Args:
            job_type: "build", "patch", or "fuzz"
            template_file: Job spec template filename
            agent: Agent/model name (e.g., "claude-sonnet-4-20250514" or "ground_truth")
            target: Fuzzing target for fuzz jobs ("ground_truth" or "llm_patch")
            depends_on: Job dependencies as {job_name: required_state} where
                required_state is "SUCCEEDED", "FAILED", or "FINISHED"

        Returns:
            Job name if submitted successfully, None otherwise
        """
        # Build job name with username prefix for identification
        username = get_gcp_username()
        if agent and agent != "ground_truth":
            # Sanitize agent name for job name
            agent_suffix = agent.replace(".", "-").replace("_", "-").lower()[:20]
            job_name = f"{username}-{job_type}-{agent_suffix}-{run_config.run_id}"
        elif target == "ground_truth":
            job_name = f"{username}-{job_type}-gt-{run_config.run_id}"
        else:
            job_name = f"{username}-{job_type}-{run_config.run_id}"

        # Map job types to parallelism settings
        # patch jobs use eval parallelism, fuzz jobs depend on target
        if job_type == "patch":
            job_parallelism = run_config.get_max_concurrent_vms("eval")
        elif job_type == "fuzz" and target == "ground_truth":
            job_parallelism = run_config.get_max_concurrent_vms("gt")
        elif job_type == "fuzz":
            job_parallelism = run_config.get_max_concurrent_vms("eval")
        else:
            job_parallelism = run_config.get_max_concurrent_vms(job_type)

        typer.echo()
        if target:
            echo_info(
                f"Submitting {job_type} job ({target}) for {agent}: {job_name} (parallelism={job_parallelism})"
            )
        elif agent:
            echo_info(
                f"Submitting {job_type} job for {agent}: {job_name} (parallelism={job_parallelism})"
            )
        else:
            echo_info(
                f"Submitting {job_type} job: {job_name} (parallelism={job_parallelism})"
            )

        template_path = jobs_dir / template_file
        if not template_path.exists():
            echo_error(f"Template not found: {template_path}")
            return None

        # Read and substitute template
        with open(template_path) as f:
            spec = f.read()

        # Agent/model label (sanitize for GCP labels)
        agent_label = (agent or "none").replace(".", "_").replace("-", "_").lower()[:63]
        target_label = (target or "none").replace(".", "_").replace("-", "_").lower()[:63]

        spec = spec.replace("${BUCKET_NAME}", bucket)
        spec = spec.replace(
            "${SERVICE_ACCOUNT_EMAIL}", gcp_config["service_account_email"]
        )
        spec = spec.replace("${ARTIFACT_REGISTRY}", gcp_config["artifact_registry"])
        spec = spec.replace("${PROJECT_NUMBER}", gcp_config.get("project_number", ""))
        spec = spec.replace("${TASK_COUNT}", str(task_count))
        spec = spec.replace("${ARVO_CASES}", case_str)
        spec = spec.replace("${MODEL}", agent or "")
        spec = spec.replace("${MODEL_LABEL}", agent_label)
        spec = spec.replace("${TARGET}", target or "")
        spec = spec.replace("${TARGET_LABEL}", target_label)
        spec = spec.replace("${SECRET_NAME}", gcp_config["secret_name"])
        spec = spec.replace("${FUZZING_DURATION}", str(run_config.fuzzing_duration))
        spec = spec.replace("${RUN_ID}", run_config.run_id)
        spec = spec.replace("${USERNAME}", username)
        spec = spec.replace(
            "${FORCE_REPATCH}", "true" if run_config.force_repatch else "false"
        )
        spec = spec.replace("${FUZZ_ONLY}", "true" if run_config.fuzz_only else "false")
        spec = spec.replace("${BUILD_VERSION}", build_version)
        spec = spec.replace(
            "${FORCE_REBUILD}", "true" if run_config.force_rebuild else "false"
        )

        # Parse spec to modify parallelism and VM image
        spec_json = json.loads(spec)

        # Set parallelism for this job type
        if spec_json.get("taskGroups"):
            spec_json["taskGroups"][0]["parallelism"] = job_parallelism

        # If custom VM image exists, use it for faster startup
        if gcp_config.get("vm_image"):
            instances = spec_json.get("allocationPolicy", {}).get("instances", [])
            if instances:
                boot_disk = instances[0].get("policy", {}).get("bootDisk", {})
                boot_disk["image"] = gcp_config["vm_image"]
                instances[0]["policy"]["bootDisk"] = boot_disk

        # Add job dependencies if specified (Cloud Batch native dependency feature)
        if depends_on:
            spec_json["dependencies"] = [{"items": depends_on}]
            dep_str = ", ".join(f"{k}={v}" for k, v in depends_on.items())
            echo_info(f"  Dependencies: {dep_str}")

        spec = json.dumps(spec_json, indent=2)

        # Write temp spec file
        temp_spec = jobs_dir / f"{job_name}.json"
        with open(temp_spec, "w") as f:
            f.write(spec)

        if dry_run:
            typer.echo(f"Would submit: {job_name}")
            temp_spec.unlink()
            return job_name  # Return job name even in dry run

        # Submit job
        # Use alpha API if job has dependencies (required for dependencies feature)
        # Add --quiet flag to suppress interactive prompts (especially for alpha component installation)
        gcloud_cmd = ["alpha", "--quiet", "batch"] if depends_on else ["batch"]
        result = run_gcloud(
            gcloud_cmd
            + [
                "jobs",
                "submit",
                job_name,
                f"--project={gcp_config['project_id']}",
                f"--location={gcp_config['region']}",
                f"--config={temp_spec}",
            ],
            check=False,
        )
        if result.returncode == 0:
            echo_success(f"Job submitted: {job_name}")
            temp_spec.unlink()
            return job_name
        else:
            echo_error(f"Failed to submit job: {job_name}")
            if result.stderr:
                typer.echo(result.stderr)
            if result.stdout:
                typer.echo(result.stdout)
            typer.echo(f"Job spec saved at: {temp_spec}")
            typer.echo("You can inspect and retry manually with:")
            gcloud_prefix = "gcloud alpha batch" if depends_on else "gcloud batch"
            typer.echo(
                f"  {gcloud_prefix} jobs submit {job_name} --project={gcp_config['project_id']} --location={gcp_config['region']} --config={temp_spec}"
            )
            return None

    # Always submit build job first (no dependencies)
    build_job = submit_job("build", "build-job.json")
    if build_job:
        submitted_jobs["build"] = build_job

    # Submit agent jobs (skip if build_only)
    if not run_config.build_only:
        # For each LLM model: submit PATCH job (patching only) and FUZZ job (fuzzing)
        for agent in llm_agents:
            # Patch job depends on build job succeeding
            patch_job = submit_job(
                "patch",
                "patch-job.json",
                agent=agent,
                depends_on={build_job: "SUCCEEDED"} if build_job else None,
            )
            if patch_job:
                # Sanitize agent name for job key
                agent_key = agent.replace(".", "-").replace("_", "-").lower()[:20]
                submitted_jobs[f"patch-{agent_key}"] = patch_job

            # Fuzz job depends on patch job succeeding
            fuzz_job = submit_job(
                "fuzz",
                "fuzz-job.json",
                agent=agent,
                target="llm_patch",
                depends_on={patch_job: "SUCCEEDED"} if patch_job else None,
            )
            if fuzz_job:
                agent_key = agent.replace(".", "-").replace("_", "-").lower()[:20]
                submitted_jobs[f"fuzz-{agent_key}"] = fuzz_job

        # For GT: submit FUZZ job only (no patching needed, uses built-in GT binary)
        # GT fuzz depends only on build job succeeding
        if has_gt:
            gt_job = submit_job(
                "fuzz",
                "fuzz-job.json",
                agent="ground_truth",
                target="ground_truth",
                depends_on={build_job: "SUCCEEDED"} if build_job else None,
            )
            if gt_job:
                submitted_jobs["fuzz-gt"] = gt_job

    # Create and upload run manifest
    if submitted_jobs and not dry_run:
        typer.echo()
        echo_info("Creating run manifest...")
        manifest = create_run_manifest(run_config, gcp_config, submitted_jobs)
        if upload_run_manifest(manifest, bucket):
            echo_success(f"Run manifest created: gs://{bucket}/runs/{run_config.run_id}/manifest.json")
        else:
            echo_warning("Failed to upload run manifest")

    typer.echo()
    typer.echo("=" * 50)
    typer.echo(f"Run ID: {run_config.run_id}")
    typer.echo()
    typer.echo("Monitor jobs:")
    typer.echo("  python -m cli monitor")
    typer.echo("  python -m cli runs status " + run_config.run_id)
    typer.echo()
    typer.echo("View logs:")
    typer.echo(f"  python -m cli runs logs {run_config.run_id} build --follow")
    typer.echo()
    typer.echo("Results will be saved to:")
    typer.echo(f"  gs://{bucket}/results/")
