"""
ARVO Benchmark CLI - Argo Workflows on GKE.

Usage:
    python -m cli setup              # Set up GKE cluster and Argo
    python -m cli submit --cases=42  # Submit benchmark workflow
    python -m cli status             # List workflows
    python -m cli logs <workflow>    # View logs
"""

import json
from pathlib import Path
from typing import Optional

import typer

from .commands import (
    cancel,
    debug_vm,
    deps,
    experiments,
    logs,
    secrets,
    semaphore,
    setup,
    status,
    submit,
)

app = typer.Typer(
    name="arvo-cli",
    help="ARVO Benchmark CLI for Argo Workflows on GKE",
    no_args_is_help=True,
)


# Setup commands
@app.command("setup")
def cmd_setup(
    project_id: str = typer.Option(None, help="GCP project ID"),
    zone: str = typer.Option("us-central1-a", help="GCP zone (zonal cluster)"),
    cluster_name: str = typer.Option("arvo-cluster", help="GKE cluster name"),
    skip_cluster: bool = typer.Option(
        False, "--skip-cluster", help="Skip cluster creation"
    ),
    skip_argo: bool = typer.Option(False, "--skip-argo", help="Skip Argo installation"),
) -> None:
    """Set up GKE cluster and Argo Workflows."""
    setup.setup(
        project_id=project_id,
        zone=zone,
        cluster_name=cluster_name,
        skip_cluster=skip_cluster,
        skip_argo=skip_argo,
    )


@app.command("setup-status")
def cmd_setup_status() -> None:
    """Check GKE/Argo setup status."""
    setup.status()


# Submit command
@app.command("submit")
def cmd_submit(
    cases: str = typer.Option(None, help="Case IDs: '42,43', '42-50', or '@file.json'"),
    model: str = typer.Option(None, help="LLM model (overrides config agents)"),
    experiment_id: str = typer.Option(None, "--experiment", "-e", help="Experiment ID"),
    fuzzing_duration: Optional[int] = typer.Option(
        None, help="Fuzzing duration (seconds)"
    ),
    build_version: str = typer.Option(
        "auto", help="Build version tag ('auto' = content hash)"
    ),
    config_file: str = typer.Option(None, "--config", "-c", help="Config file"),
    upload_runtime: bool = typer.Option(True, "--upload-runtime/--no-upload-runtime"),
    check_deps: bool = typer.Option(
        True, "--check-deps/--no-check-deps", help="Check if CASR/DD need rebuilding"
    ),
    auto_build_deps: bool = typer.Option(
        False, "--auto-build-deps", help="Auto-trigger dep builds if needed"
    ),
    dry_run: bool = typer.Option(
        False, "--dry-run", help="Show what would be submitted"
    ),
) -> None:
    """Submit a benchmark workflow."""
    from pathlib import Path

    submit.submit(
        cases=cases,
        model=model,
        experiment_id=experiment_id,
        fuzzing_duration=fuzzing_duration,
        build_version=build_version,
        config_file=Path(config_file) if config_file else None,
        upload_runtime=upload_runtime,
        check_deps=check_deps,
        auto_build_deps=auto_build_deps,
        dry_run=dry_run,
    )


# Status command
@app.command("status")
def cmd_status(
    workflow_name: str = typer.Argument(None, help="Workflow name"),
    watch: bool = typer.Option(False, "-w", "--watch", help="Watch in real-time"),
    running: bool = typer.Option(False, "--running", help="Show only running"),
    limit: int = typer.Option(20, "-n", "--limit", help="Max workflows"),
    hide_done: bool = typer.Option(
        False,
        "--hide-done",
        "--active-only",
        help="Hide completed/skipped tasks (implies watch mode)",
    ),
    brief: bool = typer.Option(
        False, "-b", "--brief", help="Brief summary only"
    ),
) -> None:
    """Show workflow status."""
    status.status(
        workflow_name=workflow_name,
        watch=watch,
        running=running,
        limit=limit,
        hide_done=hide_done,
        brief=brief,
    )


# Logs command
@app.command("logs")
def cmd_logs(
    workflow_name: str = typer.Argument(..., help="Workflow name"),
    follow: bool = typer.Option(False, "-f", "--follow", help="Follow output"),
    grep: str = typer.Option(None, "-g", "--grep", help="Filter pattern"),
    task: str = typer.Option(None, "-t", "--task", help="Filter by task"),
) -> None:
    """View workflow logs."""
    logs.logs(
        workflow_name=workflow_name,
        follow=follow,
        grep=grep,
        task=task,
    )


# Cancel command
@app.command("cancel")
def cmd_cancel(
    workflow_name: str = typer.Argument(..., help="Workflow name"),
    delete: bool = typer.Option(False, "-d", "--delete", help="Also delete"),
) -> None:
    """Cancel a workflow."""
    cancel.cancel(workflow_name=workflow_name, delete=delete)


# Experiments commands
experiments_app = typer.Typer(help="Manage experiments and results")
app.add_typer(experiments_app, name="experiments")


@experiments_app.command("list")
def cmd_exp_list(
    limit: int = typer.Option(20, "-n", "--limit"),
) -> None:
    """List experiments."""
    experiments.list_experiments(limit=limit)


@experiments_app.command("results")
def cmd_exp_results(
    experiment_id: str = typer.Argument(..., help="Experiment ID"),
    agent_id: str = typer.Option(None, "-a", "--agent-id", help="Filter by agent ID"),
) -> None:
    """Show experiment results."""
    experiments.show_results(experiment_id=experiment_id, agent_id=agent_id)


@experiments_app.command("result")
def cmd_exp_result(
    experiment_id: str = typer.Argument(..., help="Experiment ID"),
    case_id: int = typer.Argument(..., help="Case ID"),
    key: str = typer.Argument(
        "result", help="Result key (crashes, result, patch, chat)"
    ),
    agent_id: str = typer.Option(
        "",
        "-a",
        "--agent-id",
        help="Agent ID (e.g., autopatchbench-claude-sonnet-4-20250514)",
    ),
    list_keys: bool = typer.Option(
        False, "-l", "--list-keys", help="List available keys"
    ),
) -> None:
    """Get a specific result file from an experiment."""
    experiments.get_result(
        experiment_id=experiment_id,
        case_id=case_id,
        key=key,
        agent_id=agent_id,
        list_keys=list_keys,
    )


@experiments_app.command("compare")
def cmd_exp_compare(
    exp1: str = typer.Argument(..., help="First experiment"),
    exp2: str = typer.Argument(..., help="Second experiment"),
) -> None:
    """Compare two experiments."""
    experiments.compare_experiments(exp1=exp1, exp2=exp2)


# Upload runtime command
@app.command("upload-runtime")
def cmd_upload_runtime() -> None:
    """Build and upload agent runtime to GCS."""
    import subprocess

    from .config import GKEConfig, get_script_dir

    config = GKEConfig.load()
    if not config.is_configured():
        typer.echo("Error: Not configured. Run: python -m cli setup")
        raise typer.Exit(1)

    typer.echo("Building agent runtime...")
    build_script = get_script_dir() / "portable-runtime" / "build.sh"
    result = subprocess.run(["bash", str(build_script)], capture_output=True, text=True)
    if result.returncode != 0:
        typer.echo(f"Build failed: {result.stderr}")
        raise typer.Exit(1)

    typer.echo("Uploading to GCS...")
    runtime_tar = (
        get_script_dir() / "portable-runtime" / "output" / "agent-runtime.tar.gz"
    )
    result = subprocess.run(
        ["gsutil", "cp", str(runtime_tar), f"gs://{config.bucket_name}/agent-runtime/"],
        capture_output=True,
        text=True,
    )
    if result.returncode == 0:
        typer.echo(f"Uploaded to: gs://{config.bucket_name}/agent-runtime/")
    else:
        typer.echo(f"Upload failed: {result.stderr}")
        raise typer.Exit(1)


# Dependencies build commands
@app.command("upload-deps-sources")
def cmd_upload_deps_sources(
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Reduce output"),
) -> None:
    """Upload CASR source and DD build scripts to GCS."""
    deps.upload_deps_sources(quiet=quiet)


@app.command("upload-build-assets")
def cmd_upload_build_assets(
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Reduce output"),
) -> None:
    """Upload build assets (Dockerfile templates, libfuzzer, etc.) to GCS."""
    deps.upload_build_assets(quiet=quiet)


@app.command("build-casr")
def cmd_build_casr(
    force: bool = typer.Option(False, "--force", "-f", help="Force rebuild"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Show what would be done"),
) -> None:
    """Build CASR binaries on GKE (~15-30 min)."""
    deps.build_casr(force=force, dry_run=dry_run)


@app.command("build-dd")
def cmd_build_dd(
    force: bool = typer.Option(False, "--force", "-f", help="Force rebuild"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Show what would be done"),
) -> None:
    """Build differential-debugging-deps on GKE (~2-4 hours)."""
    deps.build_dd(force=force, dry_run=dry_run)


@app.command("build-deps")
def cmd_build_deps(
    casr_only: bool = typer.Option(False, "--casr-only", help="Only build CASR"),
    dd_only: bool = typer.Option(False, "--dd-only", help="Only build DD"),
    force: bool = typer.Option(False, "--force", "-f", help="Force rebuild"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Show what would be done"),
) -> None:
    """Build all dependencies (CASR and DD) on GKE."""
    deps.build_deps(casr_only=casr_only, dd_only=dd_only, force=force, dry_run=dry_run)


# Semaphore commands (rate limiting for LLM patch jobs)
semaphore_app = typer.Typer(help="Manage patch job concurrency limits per model")
app.add_typer(semaphore_app, name="semaphore")


@semaphore_app.command("set")
def cmd_semaphore_set(
    model: str = typer.Argument(
        ..., help="Model name (e.g., claude-sonnet-4-20250514)"
    ),
    limit: str = typer.Argument(
        ..., help="Max concurrent jobs (number or 'unlimited')"
    ),
) -> None:
    """Set the concurrency limit for a specific model.

    Use a number to set a specific limit, or 'unlimited' for no rate limiting.
    """
    semaphore.set_limit(model=model, limit=limit)


@semaphore_app.command("list")
def cmd_semaphore_list() -> None:
    """List all configured semaphore limits."""
    semaphore.list_limits()


@semaphore_app.command("remove")
def cmd_semaphore_remove(
    model: str = typer.Argument(..., help="Model name to remove limit for"),
) -> None:
    """Remove the concurrency limit for a model (becomes unlimited)."""
    semaphore.remove_limit(model=model)


# Secrets commands
secrets_app = typer.Typer(help="Manage Kubernetes secrets")
app.add_typer(secrets_app, name="secrets")


@secrets_app.command("sync")
def cmd_secrets_sync(
    env_file: str = typer.Option(None, "--env-file", "-e", help="Path to .env file"),
    namespace: str = typer.Option(
        "argo", "--namespace", "-n", help="Kubernetes namespace"
    ),
    secret_name: str = typer.Option(
        "arvo-secrets", "--secret", "-s", help="Secret name"
    ),
    key: list[str] = typer.Option(None, "--key", "-k", help="Specific keys to sync"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Show what would be synced"),
) -> None:
    """Sync secrets from .env file to Kubernetes."""
    from pathlib import Path

    secrets.sync_secrets(
        env_file=Path(env_file) if env_file else None,
        namespace=namespace,
        secret_name=secret_name,
        keys=key if key else None,
        dry_run=dry_run,
    )


@secrets_app.command("list")
def cmd_secrets_list(
    namespace: str = typer.Option("argo", "--namespace", "-n"),
) -> None:
    """List secrets in namespace."""
    secrets.list_secrets(namespace=namespace)


@secrets_app.command("show")
def cmd_secrets_show(
    secret_name: str = typer.Argument(..., help="Secret name"),
    namespace: str = typer.Option("argo", "--namespace", "-n"),
    decode: bool = typer.Option(False, "--decode", "-d", help="Decode values"),
) -> None:
    """Show secret details."""
    secrets.show_secret(secret_name=secret_name, namespace=namespace, decode=decode)


# Debug VM commands (interactive debugging on non-SPOT nodes)
debug_vm_app = typer.Typer(help="Debug VM management for interactive debugging")
app.add_typer(debug_vm_app, name="debug-vm")


@debug_vm_app.command("launch")
def cmd_debug_vm_launch(
    case_id: int = typer.Argument(..., help="ARVO case ID to debug"),
    job_type: str = typer.Option(
        "fuzz", "--type", "-t", help="Job type: fuzz or patch"
    ),
    agent_id: str = typer.Option(
        "gt",
        "--agent-id",
        "-a",
        help="Agent ID (e.g., autopatchbench-claude-sonnet-4-20250514), or 'gt' for ground truth",
    ),
    target: str = typer.Option(
        "ground_truth",
        "--target",
        help="Fuzz target: ground_truth or llm_patch",
    ),
    experiment_id: Optional[str] = typer.Option(
        None, "--experiment", "-e", help="Experiment ID"
    ),
    build_version: str = typer.Option(
        "latest", "--build-version", help="Build version tag"
    ),
) -> None:
    """Launch a debug pod with fuzz/patch environment."""
    debug_vm.launch(
        case_id=case_id,
        job_type=job_type,
        agent_id=agent_id,
        target=target,
        experiment_id=experiment_id,
        build_version=build_version,
    )


@debug_vm_app.command("ssh")
def cmd_debug_vm_ssh(
    pod_name: str = typer.Argument(..., help="Debug pod name"),
) -> None:
    """SSH into a debug pod."""
    debug_vm.ssh(pod_name=pod_name)


@debug_vm_app.command("delete")
def cmd_debug_vm_delete(
    pod_name: str = typer.Argument(..., help="Debug pod name"),
) -> None:
    """Delete a debug pod."""
    debug_vm.delete(pod_name=pod_name)


@debug_vm_app.command("list")
def cmd_debug_vm_list() -> None:
    """List all debug pods."""
    debug_vm.list_pods()


# Sync templates command
@app.command("sync-templates")
def cmd_sync_templates() -> None:
    """Apply/update workflow templates to the cluster.

    Use this after modifying files in argo/templates/ to sync changes
    without running the full setup.
    """
    from .argo import apply_templates, run_kubectl
    from .config import get_script_dir

    templates_dir = get_script_dir() / "argo" / "templates"

    typer.echo("Syncing workflow templates...")
    typer.echo(f"Source: {templates_dir}")
    typer.echo()

    # List templates before applying
    for template_file in sorted(templates_dir.glob("*.yaml")):
        typer.echo(f"  - {template_file.name}")

    typer.echo()

    if apply_templates(str(templates_dir)):
        typer.echo("Templates applied successfully.")
        typer.echo()

        # Show what's in the cluster
        result = run_kubectl(
            ["get", "workflowtemplates", "-n", "argo", "-o", "name"],
            check=False,
        )
        if result.returncode == 0 and result.stdout.strip():
            typer.echo("Workflow templates in cluster:")
            for tmpl in result.stdout.strip().split("\n"):
                typer.echo(f"  - {tmpl.replace('workflowtemplate.argoproj.io/', '')}")
    else:
        typer.echo("Error: Failed to apply templates.")
        raise typer.Exit(1)


# Port forward command
@app.command("ui")
def cmd_ui() -> None:
    """Open Argo UI (port-forward)."""
    import subprocess

    typer.echo("Starting port-forward to Argo UI...")
    typer.echo("Open: https://localhost:2746")
    typer.echo("Press Ctrl+C to stop")
    subprocess.run(
        ["kubectl", "port-forward", "svc/argo-server", "-n", "argo", "2746:2746"]
    )


# Between-commits analysis commands
analysis_app = typer.Typer(help="Between-commits analysis for fairness evaluation")
app.add_typer(analysis_app, name="analyze-between-commits")

ANALYSIS_DIR = (
    Path(__file__).parent.parent.parent.parent / "analysis" / "between_commits"
)


@analysis_app.command("extract")
def cmd_analysis_extract(
    cases: Optional[str] = typer.Option(
        None, help="Comma-separated case IDs (default: all)"
    ),
    batch_size: int = typer.Option(20, help="Parallel batch size"),
    build_version: str = typer.Option("latest", help="Build version tag"),
    cleanup: bool = typer.Option(False, help="Delete pods after completion"),
    dry_run: bool = typer.Option(False, help="Show what would be done"),
) -> None:
    """Submit GKE jobs to extract intermediate commits for each APB case."""
    import subprocess

    cmd = ["python", str(ANALYSIS_DIR / "extract_commits_job.py")]
    if cases:
        cmd += ["--cases", cases]
    cmd += ["--batch-size", str(batch_size)]
    cmd += ["--build-version", build_version]
    if cleanup:
        cmd.append("--cleanup")
    if dry_run:
        cmd.append("--dry-run")

    subprocess.run(cmd)


@analysis_app.command("analyze")
def cmd_analysis_analyze(
    local_dir: Optional[str] = typer.Option(
        None, help="Local directory with extracted data"
    ),
    output: Optional[str] = typer.Option(None, help="Output report path"),
) -> None:
    """Analyze extracted commits and cross-reference against ARVO database."""
    import subprocess

    cmd = ["python", str(ANALYSIS_DIR / "analyze_between_commits.py")]
    if local_dir:
        cmd += ["--local-dir", local_dir]
    if output:
        cmd += ["--output", output]

    subprocess.run(cmd)


@analysis_app.command("collect-pocs")
def cmd_analysis_collect_pocs(
    report: Optional[str] = typer.Option(None, help="Path to report.json"),
    arvo_ids: Optional[str] = typer.Option(None, help="Comma-separated ARVO IDs"),
    batch_size: int = typer.Option(20, help="Parallel batch size"),
    cleanup: bool = typer.Option(False, help="Delete pods after completion"),
    dry_run: bool = typer.Option(False, help="Show what would be done"),
) -> None:
    """Collect PoCs for ARVO IDs identified in the analysis."""
    import subprocess

    cmd = ["python", str(ANALYSIS_DIR / "collect_pocs_job.py")]
    if report:
        cmd += ["--report", report]
    elif arvo_ids:
        cmd += ["--arvo-ids", arvo_ids]
    else:
        # Default to the report in the analysis directory
        default_report = ANALYSIS_DIR / "report.json"
        if default_report.exists():
            cmd += ["--report", str(default_report)]
        else:
            typer.echo(
                "Error: No report found. Run 'analyze' first or provide --report/--arvo-ids."
            )
            raise typer.Exit(1)

    cmd += ["--batch-size", str(batch_size)]
    if cleanup:
        cmd.append("--cleanup")
    if dry_run:
        cmd.append("--dry-run")

    subprocess.run(cmd)


@analysis_app.command("run")
def cmd_analysis_run(
    batch_size: int = typer.Option(20, help="Parallel batch size"),
    build_version: str = typer.Option("latest", help="Build version tag"),
    cleanup: bool = typer.Option(True, help="Delete pods after completion"),
) -> None:
    """Run full pipeline: extract commits, analyze, collect PoCs."""
    import subprocess

    typer.echo("=" * 60)
    typer.echo("Step 1: Extract intermediate commits")
    typer.echo("=" * 60)
    r = subprocess.run(
        [
            "python",
            str(ANALYSIS_DIR / "extract_commits_job.py"),
            "--batch-size",
            str(batch_size),
            "--build-version",
            build_version,
        ]
        + (["--cleanup"] if cleanup else [])
    )
    if r.returncode != 0:
        typer.echo("Extract step failed")
        raise typer.Exit(1)

    typer.echo()
    typer.echo("=" * 60)
    typer.echo("Step 2: Analyze and cross-reference")
    typer.echo("=" * 60)
    report_path = ANALYSIS_DIR / "report.json"
    r = subprocess.run(
        [
            "python",
            str(ANALYSIS_DIR / "analyze_between_commits.py"),
            "--output",
            str(report_path),
        ]
    )
    if r.returncode != 0:
        typer.echo("Analyze step failed")
        raise typer.Exit(1)

    # Check if we need to collect PoCs
    with open(report_path) as f:
        report = json.load(f)
    needed = report.get("all_needed_arvo_ids", [])
    if not needed:
        typer.echo("\nNo bonus ARVO fixes found -- all cases are clean!")
        return

    typer.echo()
    typer.echo("=" * 60)
    typer.echo(f"Step 3: Collect PoCs for {len(needed)} ARVO IDs")
    typer.echo("=" * 60)
    r = subprocess.run(
        [
            "python",
            str(ANALYSIS_DIR / "collect_pocs_job.py"),
            "--report",
            str(report_path),
            "--batch-size",
            str(batch_size),
        ]
        + (["--cleanup"] if cleanup else [])
    )
    if r.returncode != 0:
        typer.echo("PoC collection step failed")
        raise typer.Exit(1)

    typer.echo("\nDone! Report at: " + str(report_path))


def main() -> None:
    """Entry point."""
    app()


if __name__ == "__main__":
    main()
