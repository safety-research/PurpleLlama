"""
Status command for monitoring workflows.
"""

from typing import Annotated, Optional

import typer

import subprocess

from ..argo import (
    get_current_user,
    get_workflow_status,
    list_workflows,
    resolve_workflow_name,
    run_argo_via_server_interactive,
    run_kubectl,
    watch_workflow,
)


def _print_kubectl_status(workflow_name: str) -> None:
    """Print detailed workflow status using kubectl (works with offloaded node status).

    Queries the workflow resource for the header, then queries pods belonging
    to this workflow to reconstruct per-task status -- no PostgreSQL needed.
    """
    import json

    # --- Workflow header ---
    result = run_kubectl(
        ["get", "workflow", workflow_name, "-n", "argo", "-o", "json"],
        check=False,
    )
    if result.returncode != 0:
        typer.echo(f"Workflow not found: {workflow_name}")
        return

    try:
        wf = json.loads(result.stdout)
    except json.JSONDecodeError:
        typer.echo("Error: Failed to parse workflow data")
        return

    status_data = wf.get("status", {})
    metadata = wf.get("metadata", {})
    labels = metadata.get("labels", {})

    phase = status_data.get("phase", "Unknown")
    progress = status_data.get("progress", "")
    started = status_data.get("startedAt", "-")
    finished = status_data.get("finishedAt", "")
    message = status_data.get("message", "")
    owner = labels.get("owner", "-")

    progress_parts = progress.split("/") if "/" in progress else []
    completed = int(progress_parts[0]) if len(progress_parts) == 2 else 0
    total = int(progress_parts[1]) if len(progress_parts) == 2 else 0
    pct = f"{completed * 100 / total:.1f}%" if total > 0 else "-"

    typer.echo(f"Name:      {workflow_name}")
    typer.echo(f"Phase:     {phase}")
    typer.echo(f"Progress:  {progress}  ({pct})")
    typer.echo(f"Owner:     {owner}")
    typer.echo(f"Started:   {started}")
    if finished:
        typer.echo(f"Finished:  {finished}")
    if message:
        typer.echo(f"Message:   {message}")

    # Progress bar
    if total > 0:
        bar_w = 50
        filled = int(bar_w * completed / total)
        bar = "\033[32m" + "#" * filled + "\033[0m" + "-" * (bar_w - filled)
        typer.echo(f"\n[{bar}] {completed}/{total}")

    # --- Pod-level task details ---
    result = run_kubectl(
        [
            "get",
            "pods",
            "-n",
            "argo",
            "-l",
            f"workflows.argoproj.io/workflow={workflow_name}",
            "-o",
            "json",
        ],
        check=False,
    )
    if result.returncode != 0:
        return

    try:
        pod_data = json.loads(result.stdout)
    except json.JSONDecodeError:
        return

    pods = pod_data.get("items", [])
    if not pods:
        typer.echo("\nNo pods found for this workflow.")
        return

    # Classify pods by phase
    running_pods: list[dict] = []
    pending_pods: list[dict] = []
    failed_pods: list[dict] = []
    succeeded_count = 0
    for pod in pods:
        pod_phase = pod.get("status", {}).get("phase", "Unknown")
        pod_name = pod.get("metadata", {}).get("name", "")
        pod_labels = pod.get("metadata", {}).get("labels", {})
        # Extract the human-readable template name from annotations
        annotations = pod.get("metadata", {}).get("annotations", {})
        template = annotations.get("workflows.argoproj.io/template", "")
        started_at = pod.get("status", {}).get("startTime", "")
        node_name = pod.get("spec", {}).get("nodeName", "")

        # Check for OOMKilled or other container-level failures
        container_statuses = pod.get("status", {}).get("containerStatuses", [])
        exit_reason = ""
        for cs in container_statuses:
            terminated = cs.get("state", {}).get("terminated", {})
            if terminated:
                reason = terminated.get("reason", "")
                exit_code = terminated.get("exitCode", 0)
                if reason:
                    exit_reason = reason
                elif exit_code != 0:
                    exit_reason = f"exit={exit_code}"

        info = {
            "name": pod_name,
            "template": template,
            "started": started_at[:19] if started_at else "",
            "node": node_name,
            "reason": exit_reason,
        }

        if pod_phase == "Running":
            running_pods.append(info)
        elif pod_phase == "Pending":
            pending_pods.append(info)
        elif pod_phase == "Failed":
            failed_pods.append(info)
        elif pod_phase == "Succeeded":
            succeeded_count += 1

    # Summary line
    parts = []
    if running_pods:
        parts.append(f"\033[36mRunning: {len(running_pods)}\033[0m")
    if pending_pods:
        parts.append(f"\033[33mPending: {len(pending_pods)}\033[0m")
    parts.append(f"\033[32mSucceeded: {succeeded_count}\033[0m")
    if failed_pods:
        parts.append(f"\033[31mFailed: {len(failed_pods)}\033[0m")
    typer.echo(f"\nPods: {' | '.join(parts)}")

    # Running pods
    if running_pods:
        typer.echo(f"\n\033[1mRunning ({len(running_pods)}):\033[0m")
        for p in sorted(running_pods, key=lambda x: x["started"])[:50]:
            tmpl = f"  [{p['template']}]" if p["template"] else ""
            typer.echo(f"  \033[36m●\033[0m {p['name']}{tmpl}  {p['started']}")
        if len(running_pods) > 50:
            typer.echo(f"  ... and {len(running_pods) - 50} more")

    # Pending pods
    if pending_pods:
        typer.echo(f"\n\033[1mPending ({len(pending_pods)}):\033[0m")
        for p in pending_pods[:20]:
            tmpl = f"  [{p['template']}]" if p["template"] else ""
            typer.echo(f"  \033[33m◷\033[0m {p['name']}{tmpl}")
        if len(pending_pods) > 20:
            typer.echo(f"  ... and {len(pending_pods) - 20} more")

    # Failed pods (most recent first)
    if failed_pods:
        typer.echo(f"\n\033[1mFailed ({len(failed_pods)}):\033[0m")
        for p in sorted(failed_pods, key=lambda x: x["started"], reverse=True)[:20]:
            reason = f"  ({p['reason']})" if p["reason"] else ""
            tmpl = f"  [{p['template']}]" if p["template"] else ""
            typer.echo(f"  \033[31m✖\033[0m {p['name']}{tmpl}{reason}  {p['started']}")
        if len(failed_pods) > 20:
            typer.echo(f"  ... and {len(failed_pods) - 20} more")


def status(
    workflow_name: Annotated[
        Optional[str], typer.Argument(help="Workflow name to check")
    ] = None,
    watch: Annotated[
        bool, typer.Option("-w", "--watch", help="Watch workflow in real-time")
    ] = False,
    running: Annotated[
        bool, typer.Option("--running", help="Show only running workflows")
    ] = False,
    mine: Annotated[
        bool, typer.Option("--mine", "-m", help="Show only my workflows")
    ] = False,
    owner: Annotated[
        Optional[str], typer.Option("--owner", help="Filter by owner")
    ] = None,
    limit: Annotated[
        int, typer.Option("--limit", "-n", help="Max workflows to show")
    ] = 20,
    hide_done: Annotated[
        bool,
        typer.Option(
            "--hide-done",
            "--active-only",
            help="Hide completed/skipped tasks (implies watch mode)",
        ),
    ] = False,
    brief: Annotated[
        bool,
        typer.Option(
            "--brief",
            "-b",
            help="Show only header summary (phase, progress, timestamps)",
        ),
    ] = False,
) -> None:
    """Show workflow status.

    Examples:
        python -m cli status                    # List all workflows
        python -m cli status --mine             # List only your workflows
        python -m cli status --owner camyang    # Filter by owner
        python -m cli status --running --mine   # Your running workflows
        python -m cli status arvo-benchmark-xyz # Specific workflow (full node tree)
        python -m cli status arvo-benchmark-xyz -b  # Brief summary only
        python -m cli status <wf> -w --active-only # Watch, hiding completed tasks
        python -m cli status <wf> --active-only    # Same (implies -w)
    """
    if workflow_name:
        # Resolve special patterns like "latest" or "last-2"
        workflow_name = resolve_workflow_name(workflow_name)

        # --active-only implies watch mode
        if hide_done and not watch:
            watch = True

        # Show specific workflow
        if watch:
            watch_workflow(workflow_name, hide_done=hide_done)
            return

        if brief:
            wf_status = get_workflow_status(workflow_name)
            if not wf_status:
                typer.echo(f"Workflow not found: {workflow_name}")
                raise typer.Exit(1)

            typer.echo("=" * 50)
            typer.echo(f"Workflow: {wf_status.name}")
            typer.echo("=" * 50)
            typer.echo(f"Phase:    {wf_status.phase}")
            typer.echo(f"Progress: {wf_status.progress}")
            if wf_status.owner:
                typer.echo(f"Owner:    {wf_status.owner}")
            if wf_status.started_at:
                typer.echo(f"Started:  {wf_status.started_at}")
            if wf_status.finished_at:
                typer.echo(f"Finished: {wf_status.finished_at}")
            if wf_status.message:
                typer.echo(f"Message:  {wf_status.message}")
            return

        # Try argo get first (prints the full node tree). If it fails
        # due to "offload node status is not supported" (local CLI can't
        # reach in-cluster PostgreSQL), transparently retry via the
        # argo-server which CAN reach the database.
        result = subprocess.run(
            ["argo", "get", workflow_name, "-n", "argo"],
            capture_output=True,
            text=True,
        )
        if result.returncode == 0:
            print(result.stdout, end="")
        elif "offload node status" in (result.stderr + result.stdout).lower():
            typer.echo("Node status offloaded — routing through argo-server...")
            rc = run_argo_via_server_interactive(["get", workflow_name, "-n", "argo"])
            if rc != 0:
                # Server route also failed — fall back to kubectl pod view
                _print_kubectl_status(workflow_name)
        else:
            typer.echo(f"Error: {result.stderr.strip()}")

    elif not workflow_name:
        # Build label selector
        label_selector = None
        if mine:
            current_user = get_current_user()
            label_selector = f"owner={current_user}"
            typer.echo(f"Filtering by owner: {current_user}")
        elif owner:
            label_selector = f"owner={owner}"
            typer.echo(f"Filtering by owner: {owner}")

        # List workflows
        status_filter = "Running" if running else None
        workflows = list_workflows(
            status=status_filter,
            limit=limit,
            label_selector=label_selector,
        )

        if not workflows:
            if mine or owner:
                typer.echo("No workflows found for this owner.")
            else:
                typer.echo("No workflows found.")
            return

        typer.echo()
        typer.echo(
            f"{'NAME':<40} {'OWNER':<12} {'PHASE':<12} {'PROGRESS':<12} {'STARTED'}"
        )
        typer.echo("-" * 95)

        for wf in workflows:
            started = wf.started_at[:19] if wf.started_at else "-"
            owner_str = wf.owner[:12] if wf.owner else "-"
            typer.echo(
                f"{wf.name:<40} {owner_str:<12} {wf.phase:<12} {wf.progress:<12} {started}"
            )

        typer.echo()
        typer.echo(f"Total: {len(workflows)} workflow(s)")
