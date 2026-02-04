"""
Logs command for viewing workflow logs.
"""

from typing import Annotated, Optional

import typer

from ..argo import get_workflow_logs, resolve_workflow_name


def logs(
    workflow_name: Annotated[str, typer.Argument(help="Workflow name")],
    follow: Annotated[
        bool, typer.Option("-f", "--follow", help="Follow log output")
    ] = False,
    grep: Annotated[
        Optional[str], typer.Option("--grep", "-g", help="Filter logs by pattern")
    ] = None,
    task: Annotated[
        Optional[str], typer.Option("--task", "-t", help="Filter by task name")
    ] = None,
) -> None:
    """View workflow logs."""
    # Resolve special patterns like "latest" or "last-2"
    workflow_name = resolve_workflow_name(workflow_name)
    grep_pattern = task or grep
    get_workflow_logs(workflow_name, follow=follow, grep=grep_pattern)
