"""
Status command for monitoring workflows.
"""

from typing import Annotated, Optional

import typer

from ..argo import (
    get_current_user,
    get_workflow_status,
    list_workflows,
    resolve_workflow_name,
    watch_workflow,
)


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
) -> None:
    """Show workflow status.

    Examples:
        python -m cli status                    # List all workflows
        python -m cli status --mine             # List only your workflows
        python -m cli status --owner camyang    # Filter by owner
        python -m cli status --running --mine   # Your running workflows
        python -m cli status arvo-benchmark-xyz # Specific workflow status
    """
    if workflow_name:
        # Resolve special patterns like "latest" or "last-2"
        workflow_name = resolve_workflow_name(workflow_name)

        # Show specific workflow
        if watch:
            watch_workflow(workflow_name)
            return

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

    else:
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
