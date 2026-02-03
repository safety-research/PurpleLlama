"""
Dependencies build command: build-deps.
"""

import json
from datetime import datetime
from typing import Annotated, Optional

import typer

from ..config import get_cli_tmp_dir
from ..gcp_utils import (
    get_gcp_username,
    get_script_dir,
    load_config,
    run_gcloud,
    run_gsutil,
)
from ..hashing import AUTOPATCH_BUILD_DIR
from ..output import echo_error, echo_info, echo_success, echo_warning
from .upload import upload_deps_sources_impl


def submit_deps_job_impl(
    config: dict,
    username: str,
    run_id: str,
    force_rebuild: bool = False,
    build_lldb: bool = False,
    quiet: bool = False,
) -> Optional[str]:
    """Submit deps build job.

    Returns:
        Job name if submitted, None if failed
    """
    project = config["project_id"]
    region = config["region"]
    bucket = config["bucket_name"]

    # Upload deps_task.sh script
    script_path = get_script_dir() / "scripts" / "deps_task.sh"
    if script_path.exists():
        run_gsutil(["cp", str(script_path), f"gs://{bucket}/scripts/"], check=False)

    # Generate job name
    job_name = f"{username}-deps-{run_id}"

    # Load job template
    jobs_dir = get_script_dir() / "jobs"
    template_path = jobs_dir / "deps-job.json"

    if not template_path.exists():
        if not quiet:
            echo_error(f"Job template not found: {template_path}")
        return None

    with open(template_path) as f:
        spec = f.read()

    # Substitute variables
    spec = spec.replace("${BUCKET_NAME}", bucket)
    spec = spec.replace("${SERVICE_ACCOUNT_EMAIL}", config["service_account_email"])
    spec = spec.replace("${USERNAME}", username)
    spec = spec.replace("${FORCE_REBUILD}", "true" if force_rebuild else "false")

    # Parse and optionally add VM image
    spec_json = json.loads(spec)
    if config.get("vm_image"):
        instances = spec_json.get("allocationPolicy", {}).get("instances", [])
        if instances:
            boot_disk = instances[0].get("policy", {}).get("bootDisk", {})
            boot_disk["image"] = config["vm_image"]
            instances[0]["policy"]["bootDisk"] = boot_disk

    # Scale up to 32 cores if building LLDB (it's a heavy compile)
    if build_lldb:
        # Update compute resource requirements
        task_spec = spec_json["taskGroups"][0]["taskSpec"]
        task_spec["computeResource"]["cpuMilli"] = 32000
        task_spec["computeResource"]["memoryMib"] = 131072  # 128GB
        # Update machine type
        instances = spec_json["allocationPolicy"]["instances"]
        instances[0]["policy"]["machineType"] = "e2-standard-32"

    # Add BUILD_LLDB environment variable
    env_vars = spec_json["taskGroups"][0]["taskSpec"]["environment"]["variables"]
    env_vars["BUILD_LLDB"] = "true" if build_lldb else "false"

    spec = json.dumps(spec_json, indent=2)

    # Write temp spec file to CLI temp directory (not in repo)
    temp_spec = get_cli_tmp_dir() / f"{job_name}.json"
    with open(temp_spec, "w") as f:
        f.write(spec)

    # Submit job
    if not quiet:
        echo_info(f"Submitting deps job: {job_name}")

    result = run_gcloud(
        [
            "batch",
            "jobs",
            "submit",
            job_name,
            f"--project={project}",
            f"--location={region}",
            f"--config={temp_spec}",
        ],
        check=False,
    )

    temp_spec.unlink(missing_ok=True)

    if result.returncode == 0:
        if not quiet:
            echo_success(f"Deps job submitted: {job_name}")
        return job_name
    else:
        if not quiet:
            echo_error("Failed to submit deps job")
            if result.stderr:
                typer.echo(result.stderr)
        return None


def build_deps(
    force_rebuild: Annotated[
        bool, typer.Option("--force", "-f", help="Force rebuild even if hashes match")
    ] = False,
    build_lldb: Annotated[
        bool,
        typer.Option(
            "--build-lldb", help="Build LLDB (uses 32 vCPUs instead of 4)"
        ),
    ] = False,
    dry_run: Annotated[
        bool, typer.Option("--dry-run", help="Show what would be done")
    ] = False,
) -> None:
    """Submit a Cloud Batch job to build CASR and differential-debugging-deps.

    This builds the heavy dependencies on native x86_64 GCP VMs:
    - CASR (Crash Analysis and Severity Reporting) binaries
    - differential-debugging-deps .deb packages (Python 3.7, optionally LLDB 13)

    The job uses hash-based change detection - it only rebuilds if the
    source files have changed since the last build.

    This command automatically uploads deps sources before submitting the job.

    Use --build-lldb to include LLDB compilation (requires 32 vCPUs, ~2-4 hours).
    Without --build-lldb, only CASR is built (4 vCPUs, much faster).
    """
    config = load_config()
    if not config:
        echo_error("GCP not configured. Run 'setup' first.")
        raise typer.Exit(1)

    project = config["project_id"]
    region = config["region"]
    bucket = config["bucket_name"]
    username = get_gcp_username()

    typer.echo("=" * 50)
    typer.echo("Build Dependencies Job")
    typer.echo("=" * 50)
    typer.echo()
    typer.echo(f"Project:       {project}")
    typer.echo(f"Region:        {region}")
    typer.echo(f"Bucket:        gs://{bucket}")
    typer.echo(f"Force Rebuild: {force_rebuild}")
    typer.echo(f"Build LLDB:    {build_lldb}" + (" (32 vCPUs)" if build_lldb else " (4 vCPUs)"))
    typer.echo()

    # Check if CASR submodule exists locally
    casr_dir = AUTOPATCH_BUILD_DIR / "casr"
    if not casr_dir.exists():
        echo_error(f"CASR submodule not found at {casr_dir}")
        echo_info("Initialize with: git submodule update --init")
        raise typer.Exit(1)

    # Upload deps sources to GCS
    echo_info("Uploading deps sources to GCS...")
    if not dry_run:
        if not upload_deps_sources_impl(bucket, AUTOPATCH_BUILD_DIR, quiet=False):
            echo_error("Failed to upload deps sources")
            raise typer.Exit(1)
    else:
        typer.echo("Would upload deps sources")

    # Upload deps_task.sh script
    echo_info("Uploading deps_task.sh to GCS...")
    script_path = get_script_dir() / "scripts" / "deps_task.sh"
    if not script_path.exists():
        echo_error(f"deps_task.sh not found at {script_path}")
        raise typer.Exit(1)

    if not dry_run:
        run_gsutil(["cp", str(script_path), f"gs://{bucket}/scripts/"])

    # Generate job name
    run_id = datetime.now().strftime("%Y%m%d-%H%M%S")
    job_name = f"{username}-deps-{run_id}"

    # Load job template
    jobs_dir = get_script_dir() / "jobs"
    template_path = jobs_dir / "deps-job.json"

    if not template_path.exists():
        echo_error(f"Job template not found: {template_path}")
        raise typer.Exit(1)

    with open(template_path) as f:
        spec = f.read()

    # Substitute variables
    spec = spec.replace("${BUCKET_NAME}", bucket)
    spec = spec.replace("${SERVICE_ACCOUNT_EMAIL}", config["service_account_email"])
    spec = spec.replace("${USERNAME}", username)
    spec = spec.replace("${FORCE_REBUILD}", "true" if force_rebuild else "false")

    # Parse and optionally add VM image
    spec_json = json.loads(spec)
    if config.get("vm_image"):
        instances = spec_json.get("allocationPolicy", {}).get("instances", [])
        if instances:
            boot_disk = instances[0].get("policy", {}).get("bootDisk", {})
            boot_disk["image"] = config["vm_image"]
            instances[0]["policy"]["bootDisk"] = boot_disk

    # Scale up to 32 cores if building LLDB (it's a heavy compile)
    if build_lldb:
        # Update compute resource requirements
        task_spec = spec_json["taskGroups"][0]["taskSpec"]
        task_spec["computeResource"]["cpuMilli"] = 32000
        task_spec["computeResource"]["memoryMib"] = 131072  # 128GB
        # Update machine type
        instances = spec_json["allocationPolicy"]["instances"]
        instances[0]["policy"]["machineType"] = "e2-standard-32"

    # Add BUILD_LLDB environment variable
    env_vars = spec_json["taskGroups"][0]["taskSpec"]["environment"]["variables"]
    env_vars["BUILD_LLDB"] = "true" if build_lldb else "false"

    spec = json.dumps(spec_json, indent=2)

    # Write temp spec file to CLI temp directory (not in repo)
    temp_spec = get_cli_tmp_dir() / f"{job_name}.json"
    with open(temp_spec, "w") as f:
        f.write(spec)

    if dry_run:
        echo_warning("DRY RUN MODE")
        typer.echo(f"Would submit job: {job_name}")
        typer.echo()
        typer.echo("Job spec:")
        typer.echo(spec[:500] + "..." if len(spec) > 500 else spec)
        temp_spec.unlink()
        return

    # Submit job
    echo_info(f"Submitting job: {job_name}")

    result = run_gcloud(
        [
            "batch",
            "jobs",
            "submit",
            job_name,
            f"--project={project}",
            f"--location={region}",
            f"--config={temp_spec}",
        ],
        check=False,
    )

    if result.returncode == 0:
        echo_success(f"Job submitted: {job_name}")
        temp_spec.unlink()
    else:
        echo_error(f"Failed to submit job: {job_name}")
        if result.stderr:
            typer.echo(result.stderr)
        if result.stdout:
            typer.echo(result.stdout)
        typer.echo(f"Job spec saved at: {temp_spec}")
        raise typer.Exit(1)

    typer.echo()
    typer.echo("=" * 50)
    typer.echo(f"Job: {job_name}")
    typer.echo()
    if build_lldb:
        typer.echo("This job builds CASR and LLDB (~2-4 hours)")
    else:
        typer.echo("This job builds CASR only (~15-30 minutes)")
    typer.echo()
    typer.echo("Monitor with:")
    typer.echo(f"  python -m cli monitor --job {job_name}")
    typer.echo()
    typer.echo("View logs:")
    typer.echo(
        f"  gcloud logging read 'resource.labels.job_uid=\"{job_name}\"' --project={project} --limit=100"
    )
