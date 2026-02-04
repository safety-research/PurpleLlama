"""
Cancel command for terminating workflows.
"""

from typing import Annotated

import typer

from ..argo import cancel_workflow, delete_workflow, resolve_workflow_name


def cancel(
    workflow_name: Annotated[str, typer.Argument(help="Workflow name to cancel")],
    delete: Annotated[
        bool, typer.Option("--delete", "-d", help="Also delete the workflow")
    ] = False,
) -> None:
    """Cancel a running workflow."""
    # Resolve special patterns like "latest" or "last-2"
    workflow_name = resolve_workflow_name(workflow_name)
    if cancel_workflow(workflow_name):
        typer.echo(f"Workflow cancelled: {workflow_name}")

        if delete:
            if delete_workflow(workflow_name):
                typer.echo(f"Workflow deleted: {workflow_name}")
            else:
                typer.echo("Warning: Could not delete workflow.")
    else:
        typer.echo(f"Error: Could not cancel workflow: {workflow_name}")
        raise typer.Exit(1)
