"""
VM management commands: create-vm-image, debug-vm, delete-debug-vm, debug.
"""

import json
import tempfile
import time
from datetime import datetime
from pathlib import Path
from typing import Annotated, Optional

import typer

from ..config import get_cli_tmp_dir
from ..gcp_utils import (
    get_gcp_username,
    get_script_dir,
    load_config,
    run_gcloud,
    run_gsutil,
    save_config,
)
from ..hashing import get_build_version_from_gcs
from ..output import echo_error, echo_info, echo_success, echo_warning
from .upload import upload_runtime_impl


VM_IMAGE_NAME = "arvo-docker-vm"
TEMP_VM_NAME = "arvo-image-builder"


def create_vm_image(
    force: Annotated[
        bool, typer.Option("--force", "-f", help="Recreate image if exists")
    ] = False,
) -> None:
    """Create a Docker-ready VM image for faster task startup."""
    config = load_config()
    if not config:
        echo_error("GCP not configured. Run 'setup' first.")
        raise typer.Exit(1)

    project = config["project_id"]
    region = config["region"]
    zone = f"{region}-a"
    username = get_gcp_username()
    image_name = f"{username}-{VM_IMAGE_NAME}"
    vm_name = f"{username}-{TEMP_VM_NAME}"

    typer.echo("=" * 50)
    typer.echo("Create Docker-Ready VM Image")
    typer.echo("=" * 50)
    typer.echo()
    typer.echo(f"Project:    {project}")
    typer.echo(f"Zone:       {zone}")
    typer.echo(f"Image name: {image_name}")
    typer.echo()

    # Check if image already exists
    result = run_gcloud(
        [
            "compute",
            "images",
            "describe",
            image_name,
            f"--project={project}",
        ],
        check=False,
    )
    if result.returncode == 0:
        if not force:
            echo_warning("Image already exists. Use --force to recreate.")
            typer.echo()
            typer.echo("To use this image, run:")
            typer.echo("  arvo-gcp use-vm-image")
            return
        else:
            echo_info("Deleting existing image...")
            run_gcloud(
                [
                    "compute",
                    "images",
                    "delete",
                    image_name,
                    f"--project={project}",
                    "--quiet",
                ],
                check=False,
            )

    # Step 1: Create temporary VM
    typer.echo("Step 1: Creating temporary VM...")

    # Delete existing VM if any
    run_gcloud(
        [
            "compute",
            "instances",
            "delete",
            vm_name,
            f"--project={project}",
            f"--zone={zone}",
            "--quiet",
        ],
        check=False,
    )

    run_gcloud(
        [
            "compute",
            "instances",
            "create",
            vm_name,
            f"--project={project}",
            f"--zone={zone}",
            "--machine-type=e2-medium",
            "--image-family=debian-11",
            "--image-project=debian-cloud",
            "--boot-disk-size=50GB",
            "--boot-disk-type=pd-balanced",
            f"--service-account={config['service_account_email']}",
            "--scopes=cloud-platform",
        ]
    )
    echo_success("VM created")

    # Step 2: Wait for VM to be ready and install Docker
    typer.echo()
    typer.echo("Step 2: Installing Docker (this may take a minute)...")

    # Wait for SSH to be ready
    time.sleep(30)

    install_script = """
        set -e
        sudo apt-get update
        sudo apt-get install -y docker.io
        sudo systemctl enable docker
        sudo systemctl start docker
        # Pre-pull gcloud for faster auth
        sudo docker version
        echo "Docker installed successfully"
    """

    result = run_gcloud(
        [
            "compute",
            "ssh",
            vm_name,
            f"--project={project}",
            f"--zone={zone}",
            "--command",
            install_script,
        ],
        check=False,
    )
    if result.returncode != 0:
        echo_error("Failed to install Docker. Check VM logs.")
        typer.echo(result.stderr)
        # Cleanup
        run_gcloud(
            [
                "compute",
                "instances",
                "delete",
                vm_name,
                f"--project={project}",
                f"--zone={zone}",
                "--quiet",
            ],
            check=False,
        )
        raise typer.Exit(1)

    echo_success("Docker installed")

    # Step 3: Stop VM
    typer.echo()
    typer.echo("Step 3: Stopping VM...")
    run_gcloud(
        [
            "compute",
            "instances",
            "stop",
            vm_name,
            f"--project={project}",
            f"--zone={zone}",
        ]
    )
    echo_success("VM stopped")

    # Step 4: Create image from disk
    typer.echo()
    typer.echo("Step 4: Creating image from disk...")
    run_gcloud(
        [
            "compute",
            "images",
            "create",
            image_name,
            f"--project={project}",
            f"--source-disk={vm_name}",
            f"--source-disk-zone={zone}",
            "--family=arvo-docker",
            "--description=Docker-ready VM for ARVO benchmark",
        ]
    )
    echo_success("Image created")

    # Step 5: Delete temporary VM
    typer.echo()
    typer.echo("Step 5: Cleaning up temporary VM...")
    run_gcloud(
        [
            "compute",
            "instances",
            "delete",
            vm_name,
            f"--project={project}",
            f"--zone={zone}",
            "--quiet",
        ]
    )
    echo_success("VM deleted")

    # Save image name to config
    config["vm_image"] = f"projects/{project}/global/images/{image_name}"
    save_config(config)

    typer.echo()
    typer.echo("=" * 50)
    echo_success("VM image created!")
    typer.echo("=" * 50)
    typer.echo()
    typer.echo(f"Image: {config['vm_image']}")
    typer.echo()
    typer.echo("All future jobs will automatically use this image.")


def debug_vm(
    case_id: Annotated[int, typer.Argument(help="ARVO case ID to debug")],
    job_type: Annotated[
        str, typer.Option("--job-type", "-j", help="Job type: build, patch, or fuzz")
    ] = "fuzz",
    target: Annotated[
        str,
        typer.Option("--target", "-t", help="Fuzz target: ground_truth or llm_patch"),
    ] = "ground_truth",
    model: Annotated[
        str, typer.Option("--model", "-m", help="Model name for patches")
    ] = "ground_truth",
    keep: Annotated[
        bool, typer.Option("--keep", "-k", help="Keep VM running (don't auto-delete)")
    ] = True,
    run_id: Annotated[
        Optional[str], typer.Option("--run-id", help="Run ID for results")
    ] = None,
) -> None:
    """Create a debug VM matching Cloud Batch configuration for interactive debugging.

    This creates a VM with the same spec as Cloud Batch jobs, sets up environment
    variables, and provides SSH access for debugging.

    Example:
        python -m cli debug-vm 12803 --job-type fuzz --target ground_truth

    Once connected, you can run the task script manually:
        /tmp/fuzz_task.sh    # Run the full fuzz task
        /tmp/patch_task.sh   # Run the patch task
        /tmp/build_task.sh   # Run the build task
    """
    config = load_config()
    if not config:
        echo_error("GCP not configured. Run 'setup' first.")
        raise typer.Exit(1)

    project = config["project_id"]
    region = config["region"]
    zone = f"{region}-a"
    bucket = config["bucket_name"]
    service_account = config["service_account_email"]
    artifact_registry = config["artifact_registry"]
    username = get_gcp_username()

    # Generate run ID if not provided
    if not run_id:
        run_id = datetime.now().strftime("%Y%m%d-%H%M%S")

    # Get build version
    build_version = get_build_version_from_gcs(bucket) or "latest"

    vm_name = f"{username}-debug-vm"

    typer.echo("=" * 60)
    typer.echo("ARVO Debug VM")
    typer.echo("=" * 60)
    typer.echo()
    typer.echo(f"Project:          {project}")
    typer.echo(f"Zone:             {zone}")
    typer.echo(f"VM Name:          {vm_name}")
    typer.echo(f"Case ID:          {case_id}")
    typer.echo(f"Job Type:         {job_type}")
    typer.echo(f"Target:           {target}")
    typer.echo(f"Model:            {model}")
    typer.echo(f"Run ID:           {run_id}")
    typer.echo(f"Build Version:    {build_version}")
    typer.echo()

    # Check if VM already exists
    result = run_gcloud(
        [
            "compute",
            "instances",
            "describe",
            vm_name,
            f"--project={project}",
            f"--zone={zone}",
        ],
        check=False,
    )
    if result.returncode == 0:
        echo_warning(f"VM {vm_name} already exists")
        typer.echo()
        typer.echo("Options:")
        typer.echo(f"  1. SSH into it:  gcloud compute ssh {vm_name} --zone={zone}")
        typer.echo(
            f"  2. Delete it:    gcloud compute instances delete {vm_name} --zone={zone}"
        )
        typer.echo()

        if typer.confirm("Delete existing VM and create a new one?"):
            echo_info("Deleting existing VM...")
            run_gcloud(
                [
                    "compute",
                    "instances",
                    "delete",
                    vm_name,
                    f"--project={project}",
                    f"--zone={zone}",
                    "--quiet",
                ]
            )
        else:
            typer.echo()
            typer.echo("Connect with:")
            typer.echo(f"  gcloud compute ssh {vm_name} --zone={zone}")
            return

    # Create startup script that sets up the environment
    startup_script = f'''#!/bin/bash
set -e

# Install Docker
apt-get update
apt-get install -y docker.io
systemctl enable docker
systemctl start docker

# Set environment variables (persist in /etc/environment)
cat >> /etc/environment << 'ENVEOF'
BUCKET_NAME={bucket}
ARTIFACT_REGISTRY={artifact_registry}
ARVO_CASES={case_id}
CASE_ID={case_id}
MODEL={model}
TARGET={target}
RUN_ID={run_id}
FUZZING_DURATION=300
BUILD_VERSION={build_version}
BATCH_TASK_INDEX=0
ENVEOF

# Also export for current session
export BUCKET_NAME="{bucket}"
export ARTIFACT_REGISTRY="{artifact_registry}"
export ARVO_CASES="{case_id}"
export CASE_ID="{case_id}"
export MODEL="{model}"
export TARGET="{target}"
export RUN_ID="{run_id}"
export FUZZING_DURATION=300
export BUILD_VERSION="{build_version}"
export BATCH_TASK_INDEX=0

# Create exports file for easy sourcing
cat > /tmp/env.sh << 'ENVEOF'
export BUCKET_NAME="{bucket}"
export ARTIFACT_REGISTRY="{artifact_registry}"
export ARVO_CASES="{case_id}"
export CASE_ID="{case_id}"
export MODEL="{model}"
export TARGET="{target}"
export RUN_ID="{run_id}"
export FUZZING_DURATION=300
export BUILD_VERSION="{build_version}"
export BATCH_TASK_INDEX=0
ENVEOF

# Download task scripts
gsutil cp "gs://{bucket}/scripts/fuzz_task.sh" /tmp/fuzz_task.sh 2>/dev/null || true
gsutil cp "gs://{bucket}/scripts/patch_task.sh" /tmp/patch_task.sh 2>/dev/null || true
gsutil cp "gs://{bucket}/scripts/build_task.sh" /tmp/build_task.sh 2>/dev/null || true
chmod +x /tmp/*_task.sh 2>/dev/null || true

# Configure Docker auth for Artifact Registry
REGISTRY_HOST=$(echo "{artifact_registry}" | cut -d'/' -f1)
gcloud auth configure-docker "$REGISTRY_HOST" --quiet

echo ""
echo "==========================================="
echo "Debug VM Ready!"
echo "==========================================="
echo ""
echo "Environment variables are set. Source them with:"
echo "  source /tmp/env.sh"
echo ""
echo "Run task scripts:"
echo "  /tmp/fuzz_task.sh    # Full fuzz task"
echo "  /tmp/patch_task.sh   # Patch task"
echo "  /tmp/build_task.sh   # Build task"
echo ""
echo "Or run commands step by step for debugging."
echo "==========================================="
'''

    # Write startup script to temp file
    startup_script_path = Path(tempfile.gettempdir()) / f"debug-vm-startup-{vm_name}.sh"
    startup_script_path.write_text(startup_script)

    echo_info("Creating debug VM...")

    # Create VM with same spec as Cloud Batch jobs
    create_cmd = [
        "compute",
        "instances",
        "create",
        vm_name,
        f"--project={project}",
        f"--zone={zone}",
        "--machine-type=e2-standard-4",  # Same as fuzz jobs
        "--boot-disk-size=50GB",
        "--boot-disk-type=pd-balanced",
        f"--service-account={service_account}",
        "--scopes=cloud-platform",
        f"--metadata-from-file=startup-script={startup_script_path}",
    ]

    # Use custom image if available (faster startup)
    if config.get("vm_image"):
        create_cmd.extend(
            [
                f"--image={config['vm_image'].split('/')[-1]}",
                f"--image-project={project}",
            ]
        )
    else:
        create_cmd.extend(["--image-family=debian-11", "--image-project=debian-cloud"])

    result = run_gcloud(create_cmd, check=False)

    # Clean up startup script
    startup_script_path.unlink(missing_ok=True)

    if result.returncode != 0:
        echo_error("Failed to create VM")
        if result.stderr:
            typer.echo(result.stderr)
        raise typer.Exit(1)

    echo_success(f"VM created: {vm_name}")

    typer.echo()
    echo_info("Waiting for VM to be ready (startup script running)...")
    time.sleep(30)  # Give startup script time to run

    typer.echo()
    typer.echo("=" * 60)
    echo_success("Debug VM Ready!")
    typer.echo("=" * 60)
    typer.echo()
    typer.echo("SSH into the VM:")
    typer.echo(f"  gcloud compute ssh {vm_name} --zone={zone}")
    typer.echo()
    typer.echo("Once connected, source the environment and run:")
    typer.echo("  source /tmp/env.sh")
    typer.echo(f"  /tmp/{job_type}_task.sh")
    typer.echo()
    typer.echo("Or debug step-by-step interactively.")
    typer.echo()
    if not keep:
        typer.echo("The VM will be auto-deleted when you're done.")
    else:
        typer.echo("Delete when done:")
        typer.echo(f"  gcloud compute instances delete {vm_name} --zone={zone}")


def delete_debug_vm() -> None:
    """Delete the debug VM."""
    config = load_config()
    if not config:
        echo_error("GCP not configured. Run 'setup' first.")
        raise typer.Exit(1)

    project = config["project_id"]
    region = config["region"]
    zone = f"{region}-a"
    username = get_gcp_username()
    vm_name = f"{username}-debug-vm"

    echo_info(f"Deleting debug VM: {vm_name}")

    result = run_gcloud(
        [
            "compute",
            "instances",
            "delete",
            vm_name,
            f"--project={project}",
            f"--zone={zone}",
            "--quiet",
        ],
        check=False,
    )

    if result.returncode == 0:
        echo_success("Debug VM deleted")
    else:
        echo_error("Failed to delete VM (may not exist)")


def debug_job(
    case_id: Annotated[int, typer.Argument(help="ARVO case ID to debug")],
    job_type: Annotated[
        str, typer.Option("--job-type", "-j", help="Job type: build, patch, or fuzz")
    ] = "fuzz",
    target: Annotated[
        str,
        typer.Option("--target", "-t", help="Fuzz target: ground_truth or llm_patch"),
    ] = "ground_truth",
    model: Annotated[
        str, typer.Option("--model", "-m", help="Model name for patches")
    ] = "ground_truth",
) -> None:
    """Submit a debug job to Cloud Batch for interactive debugging.

    This submits a Cloud Batch job that sets up the environment and waits,
    allowing you to SSH into the worker VM for debugging.

    Example:
        python -m cli debug 12803 --job-type fuzz --target ground_truth

    After the job starts:
        1. Find the VM:  gcloud compute instances list --filter="name~batch"
        2. SSH into it:  gcloud compute ssh <vm-name> --zone=<zone>
        3. Run commands: source /tmp/debug_env.sh && /tmp/container_shell.sh
    """
    gcp_config = load_config()
    if not gcp_config:
        echo_error("GCP not configured. Run 'setup' first.")
        raise typer.Exit(1)

    project = gcp_config["project_id"]
    region = gcp_config["region"]
    bucket = gcp_config["bucket_name"]
    username = get_gcp_username()

    # Generate run ID
    run_id = datetime.now().strftime("%Y%m%d-%H%M%S")
    job_name = f"{username}-debug-{run_id}"

    # Get build version
    build_version = get_build_version_from_gcs(bucket) or "latest"

    typer.echo("=" * 60)
    typer.echo("ARVO Debug Job")
    typer.echo("=" * 60)
    typer.echo()
    typer.echo(f"Project:          {project}")
    typer.echo(f"Region:           {region}")
    typer.echo(f"Job Name:         {job_name}")
    typer.echo(f"Case ID:          {case_id}")
    typer.echo(f"Job Type:         {job_type}")
    typer.echo(f"Target:           {target}")
    typer.echo(f"Model:            {model}")
    typer.echo(f"Build Version:    {build_version}")
    typer.echo()

    # Upload agent runtime (with auto-rebuild if source changed)
    echo_info("Uploading agent runtime...")
    if not upload_runtime_impl(bucket, quiet=False, auto_rebuild=True):
        echo_warning("Runtime upload failed - continuing anyway (may already exist)")

    # Upload debug task script
    echo_info("Uploading debug task script...")
    script_dir = get_script_dir() / "scripts"
    debug_script = script_dir / "debug_task.sh"
    if debug_script.exists():
        run_gsutil(["cp", str(debug_script), f"gs://{bucket}/scripts/"])
    else:
        echo_error(f"Debug script not found: {debug_script}")
        raise typer.Exit(1)

    # Load job template
    jobs_dir = get_script_dir() / "jobs"
    template_path = jobs_dir / "debug-job.json"

    if not template_path.exists():
        echo_error(f"Job template not found: {template_path}")
        raise typer.Exit(1)

    with open(template_path) as f:
        spec = f.read()

    # Substitute variables
    agent_label = model.replace(".", "_").replace("-", "_").lower()[:63]
    target_label = target.replace(".", "_").replace("-", "_").lower()[:63]

    spec = spec.replace("${BUCKET_NAME}", bucket)
    spec = spec.replace("${SERVICE_ACCOUNT_EMAIL}", gcp_config["service_account_email"])
    spec = spec.replace("${ARTIFACT_REGISTRY}", gcp_config["artifact_registry"])
    spec = spec.replace("${ARVO_CASES}", str(case_id))
    spec = spec.replace("${MODEL}", model)
    spec = spec.replace("${MODEL_LABEL}", agent_label)
    spec = spec.replace("${TARGET}", target)
    spec = spec.replace("${TARGET_LABEL}", target_label)
    spec = spec.replace("${RUN_ID}", run_id)
    spec = spec.replace("${FUZZING_DURATION}", "300")
    spec = spec.replace("${BUILD_VERSION}", build_version)
    spec = spec.replace("${JOB_TYPE}", job_type)
    spec = spec.replace("${USERNAME}", username)

    # Parse and optionally add VM image
    spec_json = json.loads(spec)
    if gcp_config.get("vm_image"):
        instances = spec_json.get("allocationPolicy", {}).get("instances", [])
        if instances:
            boot_disk = instances[0].get("policy", {}).get("bootDisk", {})
            boot_disk["image"] = gcp_config["vm_image"]
            instances[0]["policy"]["bootDisk"] = boot_disk

    spec = json.dumps(spec_json, indent=2)

    # Write temp spec file to CLI temp directory (not in repo)
    temp_spec = get_cli_tmp_dir() / f"{job_name}.json"
    with open(temp_spec, "w") as f:
        f.write(spec)

    # Submit job
    echo_info(f"Submitting debug job: {job_name}")

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

    if result.returncode != 0:
        echo_error("Failed to submit debug job")
        if result.stderr:
            typer.echo(result.stderr)
        raise typer.Exit(1)

    echo_success(f"Debug job submitted: {job_name}")

    typer.echo()
    typer.echo("=" * 60)
    typer.echo("Debug Job Submitted")
    typer.echo("=" * 60)
    typer.echo()
    typer.echo("Wait for the job to start (1-2 minutes), then:")
    typer.echo()
    typer.echo("  1. Find the VM:")
    typer.echo('     gcloud compute instances list --filter="name~batch"')
    typer.echo()
    typer.echo("  2. SSH into it:")
    typer.echo("     gcloud compute ssh <vm-name> --zone=<zone>")
    typer.echo()
    typer.echo("  3. On the VM, run commands:")
    typer.echo("     source /tmp/debug_env.sh")
    typer.echo("     /tmp/container_shell.sh")
    typer.echo()
    typer.echo("  4. Or run the task script directly:")
    typer.echo(f"     /tmp/{job_type}_task.sh")
    typer.echo()
    typer.echo("Monitor job status:")
    typer.echo(f"  python -m cli monitor --job {job_name}")
    typer.echo()
    typer.echo("Cancel when done:")
    typer.echo(f"  gcloud batch jobs delete {job_name} --location={region}")
