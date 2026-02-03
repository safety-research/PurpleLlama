"""
Run management commands: runs list, runs status, runs jobs, runs logs, runs delete, runs get-result.
"""

import json
import subprocess
import tempfile
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Annotated, Optional

import typer

from ..config import RunConfig
from ..gcp_utils import get_gcp_username, load_config, run_gcloud, run_gsutil
from ..output import echo_error, echo_info, echo_success, echo_warning


# =============================================================================
# Run Manifest Data Class
# =============================================================================


@dataclass
class RunManifest:
    """Metadata for a benchmark run."""

    run_id: str
    created_at: str
    owner: str
    config: dict
    jobs: dict
    total_cases: int
    status: str = "submitted"

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "run_id": self.run_id,
            "created_at": self.created_at,
            "owner": self.owner,
            "config": self.config,
            "jobs": self.jobs,
            "total_cases": self.total_cases,
            "status": self.status,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "RunManifest":
        """Create from dictionary."""
        return cls(
            run_id=data["run_id"],
            created_at=data["created_at"],
            owner=data["owner"],
            config=data["config"],
            jobs=data["jobs"],
            total_cases=data["total_cases"],
            status=data.get("status", "unknown"),
        )


# =============================================================================
# Run Manifest Helper Functions
# =============================================================================


def create_run_manifest(
    run_config: RunConfig, gcp_config: dict, job_names: dict
) -> RunManifest:
    """Create a run manifest from configuration."""
    return RunManifest(
        run_id=run_config.run_id,
        created_at=datetime.utcnow().isoformat() + "Z",
        owner=get_gcp_username(),
        config={
            "cases": run_config.cases,
            "agents": run_config.agents,
            "experiment_id": run_config.experiment_id,
            "fuzzing_duration": run_config.fuzzing_duration,
            "force_repatch": run_config.force_repatch,
            "fuzz_only": run_config.fuzz_only,
            "force_rebuild": run_config.force_rebuild,
        },
        jobs=job_names,
        total_cases=len(run_config.cases),
        status="submitted",
    )


def upload_run_manifest(manifest: RunManifest, bucket: str) -> bool:
    """Upload run manifest to GCS.

    Returns:
        True if upload succeeded, False otherwise
    """
    manifest_json = json.dumps(manifest.to_dict(), indent=2)
    gcs_path = f"gs://{bucket}/runs/{manifest.run_id}/manifest.json"

    # Use echo and pipe to gsutil
    result = subprocess.run(
        ["gsutil", "cp", "-", gcs_path],
        input=manifest_json,
        capture_output=True,
        text=True,
    )
    return result.returncode == 0


def get_run_manifest(
    run_id: str, bucket: Optional[str] = None
) -> Optional[RunManifest]:
    """Fetch run manifest from GCS.

    Args:
        run_id: The run ID to fetch
        bucket: GCS bucket name (optional, loads from config if not provided)

    Returns:
        RunManifest if found, None otherwise
    """
    if not bucket:
        config = load_config()
        if not config:
            return None
        bucket = config["bucket_name"]

    result = run_gsutil(
        ["cat", f"gs://{bucket}/runs/{run_id}/manifest.json"],
        check=False,
    )
    if result.returncode == 0:
        try:
            data = json.loads(result.stdout)
            return RunManifest.from_dict(data)
        except (json.JSONDecodeError, KeyError):
            pass
    return None


def list_runs(bucket: str, limit: int = 50) -> list[dict]:
    """List all runs from GCS.

    Returns:
        List of run info dictionaries with run_id and metadata
    """
    # List all manifest files in runs/
    result = run_gsutil(
        ["ls", f"gs://{bucket}/runs/*/manifest.json"],
        check=False,
    )
    if result.returncode != 0:
        return []

    manifests = []
    for line in result.stdout.strip().split("\n"):
        if not line:
            continue
        # Extract run_id from path: gs://bucket/runs/RUN_ID/manifest.json
        parts = line.split("/")
        if len(parts) >= 4:
            run_id = parts[-2]
            # Fetch the manifest
            manifest = get_run_manifest(run_id, bucket)
            if manifest:
                manifests.append(manifest.to_dict())

        if len(manifests) >= limit:
            break

    # Sort by created_at descending (most recent first)
    manifests.sort(key=lambda x: x.get("created_at", ""), reverse=True)
    return manifests


def resolve_job_name(manifest: RunManifest, job_key: str) -> Optional[str]:
    """Resolve a job key to the actual job name.

    Args:
        manifest: The run manifest
        job_key: Short job key like "build", "patch-claude-sonnet", "fuzz-gt"

    Returns:
        Full job name if found, None otherwise
    """
    # Direct match
    if job_key in manifest.jobs:
        return manifest.jobs[job_key]

    # Try to match partial keys
    job_key_lower = job_key.lower()
    for key, name in manifest.jobs.items():
        if job_key_lower in key.lower():
            return name

    return None


def get_job_status(job_name: str, project: str, region: str) -> dict:
    """Get status of a Cloud Batch job.

    Returns:
        Dictionary with status info
    """
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


def format_time_ago(iso_timestamp: str) -> str:
    """Format an ISO timestamp as a human-readable 'time ago' string."""
    try:
        dt = datetime.fromisoformat(iso_timestamp.replace("Z", "+00:00"))
        now = datetime.now(dt.tzinfo) if dt.tzinfo else datetime.utcnow()
        delta = now - dt.replace(tzinfo=None) if not dt.tzinfo else now - dt

        if delta.days > 0:
            return f"{delta.days}d ago"
        elif delta.seconds >= 3600:
            return f"{delta.seconds // 3600}h ago"
        elif delta.seconds >= 60:
            return f"{delta.seconds // 60}m ago"
        else:
            return "just now"
    except (ValueError, TypeError):
        return "unknown"


# =============================================================================
# Runs Subcommand Commands
# =============================================================================


def runs_list(
    limit: Annotated[int, typer.Option(help="Maximum number of runs to list")] = 20,
    owner: Annotated[Optional[str], typer.Option(help="Filter by owner")] = None,
) -> None:
    """List all benchmark runs."""
    config = load_config()
    if not config:
        echo_error("GCP not configured. Run 'setup' first.")
        raise typer.Exit(1)

    bucket = config["bucket_name"]

    echo_info("Fetching runs...")
    runs = list_runs(bucket, limit=limit * 2)  # Fetch more to account for filtering

    if owner:
        runs = [r for r in runs if r.get("owner") == owner]

    runs = runs[:limit]

    if not runs:
        echo_warning("No runs found.")
        return

    # Print header
    typer.echo()
    typer.echo(
        f"{'RUN_ID':<20} {'OWNER':<12} {'CASES':>6} {'AGENTS':<20} {'STATUS':<12} {'CREATED':<10}"
    )
    typer.echo("-" * 85)

    for run in runs:
        run_id = run.get("run_id", "?")[:20]
        run_owner = run.get("owner", "?")[:12]
        cases = run.get("total_cases", 0)
        agents = ",".join(run.get("config", {}).get("agents", []))[:20]
        status = run.get("status", "?")[:12]
        created = format_time_ago(run.get("created_at", ""))

        typer.echo(
            f"{run_id:<20} {run_owner:<12} {cases:>6} {agents:<20} {status:<12} {created:<10}"
        )

    typer.echo()
    typer.echo(f"Total: {len(runs)} run(s)")


def runs_status(
    run_id: Annotated[str, typer.Argument(help="Run ID to check status for")],
    verbose: Annotated[
        bool, typer.Option("--verbose", "-v", help="Show detailed output")
    ] = False,
) -> None:
    """Show detailed status of a specific run."""
    config = load_config()
    if not config:
        echo_error("GCP not configured. Run 'setup' first.")
        raise typer.Exit(1)

    bucket = config["bucket_name"]
    project = config["project_id"]
    region = config["region"]

    manifest = get_run_manifest(run_id, bucket)
    if not manifest:
        echo_error(f"Run not found: {run_id}")
        raise typer.Exit(1)

    typer.echo("=" * 60)
    typer.echo(f"Run: {manifest.run_id}")
    typer.echo("=" * 60)
    typer.echo()
    typer.echo(f"Owner:            {manifest.owner}")
    typer.echo(f"Created:          {manifest.created_at}")
    typer.echo(f"Cases:            {manifest.total_cases}")
    typer.echo(f"Agents:           {', '.join(manifest.config.get('agents', []))}")
    typer.echo(f"Fuzzing Duration: {manifest.config.get('fuzzing_duration', '?')}s")
    typer.echo()

    if verbose:
        typer.echo("Configuration:")
        for key, value in manifest.config.items():
            if key != "cases":  # Skip cases list (too long)
                typer.echo(f"  {key}: {value}")
        typer.echo()

    typer.echo("Job Status:")
    typer.echo("-" * 60)

    for job_key, job_name in manifest.jobs.items():
        # Query Cloud Batch for job status
        job_info = get_job_status(job_name, project, region)

        if "error" in job_info:
            status = "UNKNOWN"
            task_info = ""
        else:
            status_obj = job_info.get("status", {})
            status = status_obj.get("state", "UNKNOWN")

            # Get task counts
            task_groups = job_info.get("taskGroups", [{}])
            if task_groups:
                task_count = int(task_groups[0].get("taskCount", 0))
                task_info = f"({task_count} tasks)"
            else:
                task_info = ""

        # Format status with color
        if status == "SUCCEEDED":
            status_str = typer.style(f"{status:<12}", fg=typer.colors.GREEN)
        elif status in ("RUNNING", "SCHEDULED"):
            status_str = typer.style(f"{status:<12}", fg=typer.colors.BLUE)
        elif status == "FAILED":
            status_str = typer.style(f"{status:<12}", fg=typer.colors.RED)
        else:
            status_str = f"{status:<12}"

        typer.echo(f"  {job_key:<30} {status_str} {task_info}")

    typer.echo()


def runs_jobs(
    run_id: Annotated[str, typer.Argument(help="Run ID to list jobs for")],
) -> None:
    """List all jobs in a run with their status."""
    config = load_config()
    if not config:
        echo_error("GCP not configured. Run 'setup' first.")
        raise typer.Exit(1)

    bucket = config["bucket_name"]
    project = config["project_id"]
    region = config["region"]

    manifest = get_run_manifest(run_id, bucket)
    if not manifest:
        echo_error(f"Run not found: {run_id}")
        raise typer.Exit(1)

    typer.echo()
    typer.echo(f"Jobs in run {run_id}:")
    typer.echo()
    typer.echo(f"{'JOB NAME':<50} {'TYPE':<10} {'STATUS':<12}")
    typer.echo("-" * 75)

    for job_key, job_name in manifest.jobs.items():
        job_info = get_job_status(job_name, project, region)

        if "error" in job_info:
            status = "UNKNOWN"
        else:
            status = job_info.get("status", {}).get("state", "UNKNOWN")

        # Determine job type from key
        if "build" in job_key:
            job_type = "build"
        elif "patch" in job_key:
            job_type = "patch"
        elif "fuzz" in job_key:
            job_type = "fuzz"
        else:
            job_type = "other"

        typer.echo(f"{job_name:<50} {job_type:<10} {status:<12}")

    typer.echo()


def runs_logs(
    run_id: Annotated[str, typer.Argument(help="Run ID")],
    job: Annotated[str, typer.Argument(help="Job type (build, patch-*, fuzz-*)")],
    case_id: Annotated[
        Optional[int], typer.Option("--case-id", "-c", help="Filter by case ID")
    ] = None,
    limit: Annotated[int, typer.Option(help="Number of log entries")] = 500,
    follow: Annotated[
        bool, typer.Option("--follow", "-f", help="Stream logs in real-time")
    ] = False,
    open_editor: Annotated[
        bool, typer.Option("--open", "-o", help="Open logs in Cursor editor")
    ] = False,
) -> None:
    """View logs for a job in a run using Cloud Logging."""
    config = load_config()
    if not config:
        echo_error("GCP not configured. Run 'setup' first.")
        raise typer.Exit(1)

    bucket = config["bucket_name"]
    project = config["project_id"]

    manifest = get_run_manifest(run_id, bucket)
    if not manifest:
        echo_error(f"Run not found: {run_id}")
        raise typer.Exit(1)

    job_name = resolve_job_name(manifest, job)
    if not job_name:
        echo_error(f"Job not found: {job}")
        echo_info(f"Available jobs: {', '.join(manifest.jobs.keys())}")
        raise typer.Exit(1)

    # Build Cloud Logging filter
    # Cloud Batch logs use resource.type="batch.googleapis.com/Job"
    # The full job name appears in labels.task_group_name
    log_filter = f'resource.type="batch.googleapis.com/Job" AND labels.task_group_name:"{job_name}"'

    if case_id is not None:
        # Map case_id to task index (task IDs are like "...-group0-{index}")
        cases = manifest.config.get("cases", [])
        if case_id in cases:
            task_index = cases.index(case_id)
            log_filter += f' AND labels.task_id:"-group0-{task_index}"'
        else:
            echo_error(f"Case ID {case_id} not found in this run")
            raise typer.Exit(1)

    echo_info(f"Job: {job_name}")
    echo_info(f"Filter: {log_filter}")

    if follow:
        # Real-time streaming with gcloud beta logging tail
        cmd = ["gcloud", "beta", "logging", "tail", log_filter, f"--project={project}"]

        if open_editor:
            # Stream to temp file and open in Cursor
            case_suffix = f"_case{case_id}" if case_id else ""
            log_path = (
                Path(tempfile.gettempdir()) / f"logs_{run_id}_{job}{case_suffix}.log"
            )
            echo_info(f"Streaming logs to {log_path}")

            with open(log_path, "w") as f:
                process = subprocess.Popen(cmd, stdout=f, stderr=subprocess.DEVNULL)

            # Open in Cursor
            subprocess.run(["cursor", str(log_path)], check=False)
            echo_success(f"Opened {log_path} in Cursor")
            echo_info("Logs streaming in real-time (Ctrl+C to stop)")

            # Wait for user interrupt
            try:
                process.wait()
            except KeyboardInterrupt:
                process.terminate()
                echo_info("Stopped streaming.")
        else:
            # Stream to terminal
            echo_info(f"Streaming logs for {job_name}...")
            echo_info("Press Ctrl+C to stop")
            typer.echo()
            try:
                subprocess.run(cmd)
            except KeyboardInterrupt:
                typer.echo()
                echo_info("Stopped streaming.")
    else:
        # One-time query with gcloud logging read
        cmd = [
            "gcloud",
            "logging",
            "read",
            log_filter,
            f"--project={project}",
            f"--limit={limit}",
            "--format=value(timestamp,textPayload)",
        ]

        result = subprocess.run(cmd, capture_output=True, text=True)

        if open_editor:
            case_suffix = f"_case{case_id}" if case_id else ""
            log_path = (
                Path(tempfile.gettempdir()) / f"logs_{run_id}_{job}{case_suffix}.log"
            )
            log_path.write_text(result.stdout)
            subprocess.run(["cursor", str(log_path)], check=False)
            echo_success(f"Opened {log_path} in Cursor")
        else:
            if result.stdout.strip():
                typer.echo(result.stdout)
            else:
                echo_warning("No logs found. The job may not have started yet.")
                if result.stderr:
                    echo_info(f"stderr: {result.stderr[:500]}")
                echo_info("Try running manually:")
                echo_info(
                    f"  gcloud logging read '{log_filter}' --project={project} --limit=10"
                )


def runs_delete(
    run_id: Annotated[str, typer.Argument(help="Run ID to delete")],
    force: Annotated[
        bool, typer.Option("--force", "-f", help="Skip confirmation")
    ] = False,
    delete_results: Annotated[
        bool, typer.Option("--delete-results", help="Also delete results from GCS")
    ] = False,
) -> None:
    """Delete a run manifest (and optionally results)."""
    config = load_config()
    if not config:
        echo_error("GCP not configured. Run 'setup' first.")
        raise typer.Exit(1)

    bucket = config["bucket_name"]

    manifest = get_run_manifest(run_id, bucket)
    if not manifest:
        echo_error(f"Run not found: {run_id}")
        raise typer.Exit(1)

    typer.echo(f"Run: {run_id}")
    typer.echo(f"Cases: {manifest.total_cases}")
    typer.echo(f"Jobs: {len(manifest.jobs)}")
    typer.echo()

    if delete_results:
        echo_warning("This will also delete all results for this run!")

    if not force:
        confirm = typer.confirm("Are you sure you want to delete this run?")
        if not confirm:
            typer.echo("Aborted.")
            raise typer.Exit(0)

    # Delete manifest
    echo_info("Deleting run manifest...")
    run_gsutil(["rm", f"gs://{bucket}/runs/{run_id}/manifest.json"], check=False)

    # Optionally delete results
    if delete_results:
        echo_info("Deleting results...")
        # Results are stored at gs://bucket/results/case_{id}/{model}/{run_id}/
        # We need to find and delete all matching paths
        for case_id in manifest.config.get("cases", []):
            for agent in manifest.config.get("agents", []):
                if agent == "gt":
                    result_path = f"gs://{bucket}/results/case_{case_id}/gt/{run_id}/"
                else:
                    result_path = (
                        f"gs://{bucket}/results/case_{case_id}/{agent}/{run_id}/"
                    )
                run_gsutil(["-m", "rm", "-r", result_path], check=False)

    echo_success(f"Run {run_id} deleted.")


# =============================================================================
# Result Key Registry
# =============================================================================

# Registry of result keys mapping to their storage location and path
# Format: "key" -> (location, path_pattern, description)
# location: "results" (persistent experiment data) or "logs" (run logs)
# Path patterns can use {model} placeholder
RESULT_KEY_REGISTRY = {
    # Results (persistent experiment data)
    "result": ("results", "result.json", "Patch result JSON (status, metrics)"),
    "patch": ("results", "patch.txt", "Generated patch content"),
    "crashes": ("results", "crashes.json", "Fuzzing crashes JSON"),
    "metadata": ("results", "metadata.json", "Result metadata (run info)"),
    # Run logs (debugging/ephemeral)
    "chat": ("logs", "chat.md", "LLM chat history from patching"),
    "crash-output": ("logs", "crash_output.txt", "Original crash output"),
    "fuzz-log": ("logs", "fuzz.log", "Fuzzing log output"),
    "fuzz-result": (
        "logs",
        "fuzzing_result_llm_patch.json",
        "Detailed fuzzing result JSON",
    ),
    # Ground truth
    "gt-crashes": ("results", "crashes.json", "Ground truth fuzzing crashes"),
    "gt-metadata": ("results", "metadata.json", "Ground truth metadata"),
    "gt-fuzz-log": ("logs", "fuzz.log", "Ground truth fuzzing log"),
}


def get_result_path(
    bucket: str,
    run_id: str,
    experiment_id: str,
    case_id: int,
    model: str,
    key: str,
) -> str:
    """
    Resolve a result key to a GCS path.

    Args:
        bucket: GCS bucket name
        run_id: Run ID
        experiment_id: Experiment ID
        case_id: Case ID
        model: Model name (e.g., "claude-sonnet-4-20250514") or "gt"
        key: Result key (e.g., "chat", "result") or raw path

    Returns:
        Full GCS path to the result
    """
    # Check if it's a registered key
    if key in RESULT_KEY_REGISTRY:
        location, filename, _ = RESULT_KEY_REGISTRY[key]

        # Handle ground truth special case
        if key.startswith("gt-"):
            model = "gt"

        if location == "results":
            return f"gs://{bucket}/results/{experiment_id}/{case_id}/{model}/{filename}"
        else:  # logs
            return f"gs://{bucket}/runs/{run_id}/logs/{case_id}/{model}/{filename}"

    # Otherwise treat as raw path - try to find it in run logs first
    return f"gs://{bucket}/runs/{run_id}/logs/{case_id}/{model}/{key}"


def runs_get_result(
    run_id: Annotated[str, typer.Argument(help="Run ID")],
    key: Annotated[
        str,
        typer.Argument(
            help="Result key (chat, result, patch, crashes) or raw GCS path"
        ),
    ],
    case_id: Annotated[
        Optional[int],
        typer.Option("--case-id", "-c", help="Case ID (required if run has multiple)"),
    ] = None,
    model: Annotated[
        Optional[str],
        typer.Option("--model", "-m", help="Model name (required if run has multiple)"),
    ] = None,
    experiment_id: Annotated[
        Optional[str],
        typer.Option(
            "--experiment-id", "-e", help="Experiment ID (default: from run config)"
        ),
    ] = None,
    output: Annotated[
        Optional[Path],
        typer.Option("--output", "-o", help="Save to file instead of printing"),
    ] = None,
    list_keys: Annotated[
        bool, typer.Option("--list-keys", "-l", help="List available result keys")
    ] = False,
) -> None:
    """Get a result file from a run.

    Results are stored in two locations:
      - Results (persistent): gs://{bucket}/results/{experiment_id}/{case_id}/{model}/
      - Run logs (ephemeral): gs://{bucket}/runs/{run_id}/logs/{case_id}/{model}/

    Use registered keys for common files:
      - result: Patch result JSON (from results)
      - patch: Generated patch content (from results)
      - crashes: Fuzzing crashes JSON (from results)
      - chat: LLM chat history (from run logs)
      - fuzz-log: Fuzzing log (from run logs)

    Or provide a raw filename/path to fetch from run logs.

    Examples:
      runs {run_id} get-result chat
      runs {run_id} get-result result --case-id 42
      runs {run_id} get-result crashes --model claude-sonnet-4-20250514
    """
    # List keys mode
    if list_keys:
        typer.echo("\nAvailable result keys:\n")
        typer.echo(f"{'KEY':<15} {'LOCATION':<10} {'DESCRIPTION':<45}")
        typer.echo("-" * 70)
        for k, (loc, _, desc) in RESULT_KEY_REGISTRY.items():
            typer.echo(f"{k:<15} {loc:<10} {desc:<45}")
        typer.echo()
        return

    config = load_config()
    if not config:
        echo_error("GCP not configured. Run 'setup' first.")
        raise typer.Exit(1)

    bucket = config["bucket_name"]

    # Get run manifest
    manifest = get_run_manifest(run_id, bucket)
    if not manifest:
        echo_error(f"Run not found: {run_id}")
        raise typer.Exit(1)

    # Resolve case_id
    cases = manifest.config.get("cases", [])
    if case_id is None:
        if len(cases) == 1:
            case_id = cases[0]
        else:
            echo_error(f"Run has {len(cases)} cases. Please specify --case-id")
            echo_info(f"Available cases: {cases[:10]}{'...' if len(cases) > 10 else ''}")
            raise typer.Exit(1)
    elif case_id not in cases:
        echo_error(f"Case {case_id} not found in this run")
        raise typer.Exit(1)

    # Resolve experiment_id
    resolved_experiment_id = experiment_id or manifest.config.get(
        "experiment_id", "default"
    )

    # Resolve model
    agents = manifest.config.get("agents", [])
    # Filter out "gt" for model selection (gt uses special paths)
    llm_agents = [a for a in agents if a != "gt"]

    if key.startswith("gt-"):
        # Ground truth results don't need a model
        resolved_model = "gt"
    elif model is None:
        if len(llm_agents) == 1:
            resolved_model = llm_agents[0]
        elif len(llm_agents) == 0:
            echo_error("No LLM agents in this run (only ground truth)")
            raise typer.Exit(1)
        else:
            echo_error(f"Run has {len(llm_agents)} models. Please specify --model")
            echo_info(f"Available models: {llm_agents}")
            raise typer.Exit(1)
    else:
        if model not in agents:
            echo_error(f"Model '{model}' not found in this run")
            echo_info(f"Available models: {agents}")
            raise typer.Exit(1)
        resolved_model = model

    # Build GCS path
    gcs_path = get_result_path(
        bucket, run_id, resolved_experiment_id, case_id, resolved_model, key
    )

    # Handle directory listing for crashes keys
    if key in ("crashes", "gt-crashes") or gcs_path.endswith("/"):
        echo_info(f"Listing: {gcs_path}")
        result = run_gsutil(["ls", "-l", gcs_path], check=False)
        if result.returncode == 0:
            typer.echo(result.stdout)
        else:
            echo_warning(f"No files found at {gcs_path}")
            if result.stderr:
                echo_info(result.stderr.strip())
        return

    # Fetch the file
    echo_info(f"Fetching: {gcs_path}")

    if output:
        # Download to file
        result = run_gsutil(["cp", gcs_path, str(output)], check=False)
        if result.returncode == 0:
            echo_success(f"Saved to {output}")
        else:
            echo_error(f"Failed to download: {result.stderr}")
            raise typer.Exit(1)
    else:
        # Print to stdout
        result = run_gsutil(["cat", gcs_path], check=False)
        if result.returncode == 0:
            typer.echo(result.stdout)
        else:
            echo_error(f"Failed to fetch result")
            if "No URLs matched" in result.stderr or "not found" in result.stderr.lower():
                echo_info("The result file may not exist yet (job still running?)")
                # Try to list what's available
                parent_path = "/".join(gcs_path.rsplit("/", 1)[:-1]) + "/"
                echo_info(f"\nAvailable files in {parent_path}:")
                list_result = run_gsutil(["ls", parent_path], check=False)
                if list_result.returncode == 0:
                    typer.echo(list_result.stdout)
            raise typer.Exit(1)
