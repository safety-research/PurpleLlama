"""
Monitor command for watching Cloud Batch jobs.
"""

import time
from datetime import datetime
from typing import Annotated, Optional

import typer

from ..gcp_utils import load_config, run_gcloud
from ..output import echo_error


def get_job_status(job_name: str, project: str, region: str) -> dict:
    """Get status of a Cloud Batch job.

    Returns:
        Dictionary with status info
    """
    import json

    result = run_gcloud(
        [
            "batch",
            "jobs",
            "describe",
            job_name,
            f"--project={project}",
            f"--location={region}",
            "--format=json",
        ],
        check=False,
    )
    if result.returncode == 0:
        try:
            return json.loads(result.stdout)
        except json.JSONDecodeError:
            pass
    return {"error": f"Failed to get job status: {result.stderr}"}


def monitor(
    job: Annotated[
        Optional[str], typer.Option(help="Specific job name to monitor")
    ] = None,
    run_id: Annotated[
        Optional[str], typer.Option("--run-id", "-r", help="Monitor jobs for a specific run")
    ] = None,
    watch: Annotated[
        bool, typer.Option("--watch", "-w", help="Continuous monitoring")
    ] = False,
    logs: Annotated[bool, typer.Option("--logs", help="Show job logs")] = False,
) -> None:
    """Monitor Cloud Batch jobs.

    Shows status of recent jobs, or jobs from a specific run if --run-id is provided.
    """
    config = load_config()
    if not config:
        echo_error("GCP not configured. Run 'setup' first.")
        raise typer.Exit(1)

    project = config["project_id"]
    region = config["region"]
    bucket = config["bucket_name"]

    # If run_id specified, get manifest for run-specific monitoring
    manifest = None
    if run_id:
        from .runs import get_run_manifest
        manifest = get_run_manifest(run_id, bucket)
        if not manifest:
            echo_error(f"Run not found: {run_id}")
            raise typer.Exit(1)

    def show_status() -> None:
        if not watch:
            typer.clear()

        typer.echo("=" * 60)
        typer.echo("ARVO Benchmark Job Monitor")
        typer.echo("=" * 60)
        typer.echo(f"Project: {project}")
        typer.echo(f"Region:  {region}")
        typer.echo(f"Time:    {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        if run_id:
            typer.echo(f"Run ID:  {run_id}")
        typer.echo()

        if logs and job:
            typer.echo(f"=== Logs for {job} ===")
            result = run_gcloud(
                [
                    "logging",
                    "read",
                    'resource.type="cloud_batch_job"',
                    f"--project={project}",
                    "--limit=50",
                    "--format=table(timestamp,textPayload)",
                ],
                check=False,
            )
            typer.echo(result.stdout)
            return

        if job:
            # Show specific job
            typer.echo(f"=== Job: {job} ===")
            result = run_gcloud(
                [
                    "batch",
                    "jobs",
                    "describe",
                    job,
                    f"--project={project}",
                    f"--location={region}",
                    "--format=yaml(name,status,createTime,updateTime)",
                ],
                check=False,
            )
            typer.echo(result.stdout)
        elif manifest:
            # Show jobs for the specific run
            typer.echo(f"=== Jobs in Run {run_id} ===")
            typer.echo()
            typer.echo(f"{'JOB KEY':<25} {'STATUS':<15} {'JOB NAME':<40}")
            typer.echo("-" * 80)

            for job_key, job_name in manifest.jobs.items():
                job_info = get_job_status(job_name, project, region)
                if "error" in job_info:
                    status = "UNKNOWN"
                else:
                    status = job_info.get("status", {}).get("state", "UNKNOWN")

                # Color status
                if status == "SUCCEEDED":
                    status_str = typer.style(status, fg=typer.colors.GREEN)
                elif status in ("RUNNING", "SCHEDULED"):
                    status_str = typer.style(status, fg=typer.colors.BLUE)
                elif status == "FAILED":
                    status_str = typer.style(status, fg=typer.colors.RED)
                else:
                    status_str = status

                typer.echo(f"{job_key:<25} {status_str:<15} {job_name:<40}")

            typer.echo()
        else:
            # List all recent jobs
            typer.echo("=== Recent Jobs ===")
            result = run_gcloud(
                [
                    "batch",
                    "jobs",
                    "list",
                    f"--project={project}",
                    f"--location={region}",
                    "--limit=15",
                    "--format=table(name.basename(),status.state,createTime.date())",
                ],
                check=False,
            )
            typer.echo(result.stdout)

        typer.echo()

    if watch:
        try:
            while True:
                show_status()
                typer.echo("Refreshing in 10 seconds... (Ctrl+C to stop)")
                time.sleep(10)
                typer.clear()
        except KeyboardInterrupt:
            typer.echo("\nStopped.")
    else:
        show_status()
