"""
Argo Workflows client wrapper.
"""

import json
import os
import re
import subprocess
from dataclasses import dataclass
from typing import Optional

import typer


def get_current_user() -> str:
    """Get the current user for resource labeling.

    Tries in order:
    1. ARVO_USER environment variable
    2. Git user.name config
    3. OS username
    """
    # Check environment variable first
    if user := os.environ.get("ARVO_USER"):
        return sanitize_label(user)

    # Try git config
    try:
        result = subprocess.run(
            ["git", "config", "user.name"],
            capture_output=True,
            text=True,
            check=True,
        )
        if result.stdout.strip():
            return sanitize_label(result.stdout.strip())
    except (subprocess.CalledProcessError, FileNotFoundError):
        pass

    # Fall back to OS username
    return sanitize_label(os.environ.get("USER", "unknown"))


def sanitize_label(value: str) -> str:
    """Sanitize a string for use as a Kubernetes label value.

    Label values must:
    - Be 63 characters or less
    - Begin and end with alphanumeric
    - Contain only alphanumerics, dashes, underscores, and dots
    """
    # Convert to lowercase and replace spaces/special chars
    value = value.lower().replace(" ", "-")
    # Remove invalid characters
    sanitized = "".join(c if c.isalnum() or c in "-_." else "-" for c in value)
    # Trim to 63 chars and strip leading/trailing non-alphanumeric
    sanitized = sanitized[:63].strip("-_.")
    return sanitized or "unknown"


@dataclass
class WorkflowStatus:
    """Status of an Argo workflow."""

    name: str
    phase: str  # Pending, Running, Succeeded, Failed, Error
    started_at: Optional[str] = None
    finished_at: Optional[str] = None
    progress: str = ""
    message: str = ""
    owner: str = ""


def run_argo(args: list[str], check: bool = True) -> subprocess.CompletedProcess:
    """Run an argo CLI command."""
    cmd = ["argo"] + args
    return subprocess.run(cmd, capture_output=True, text=True, check=check)


def run_kubectl(args: list[str], check: bool = True) -> subprocess.CompletedProcess:
    """Run a kubectl command."""
    cmd = ["kubectl"] + args
    return subprocess.run(cmd, capture_output=True, text=True, check=check)


def submit_workflow(
    workflow_path: str,
    parameters: dict[str, str],
    namespace: str = "argo",
    wait: bool = False,
    labels: Optional[dict[str, str]] = None,
) -> Optional[str]:
    """Submit a workflow and return its name.

    Args:
        workflow_path: Path to the workflow YAML file
        parameters: Workflow parameters
        namespace: Kubernetes namespace
        wait: Whether to wait for completion
        labels: Labels to apply to the workflow (e.g., {"owner": "username"})
    """
    args = ["submit", workflow_path, "-n", namespace]

    for key, value in parameters.items():
        args.extend(["-p", f"{key}={value}"])

    # Add labels (including owner by default)
    all_labels = {"owner": get_current_user()}
    if labels:
        all_labels.update(labels)

    for key, value in all_labels.items():
        args.extend(["--labels", f"{key}={value}"])

    if not wait:
        args.append("--wait=false")

    result = run_argo(args, check=False)
    if result.returncode != 0:
        print(f"Error submitting workflow: {result.stderr}")
        return None

    # Extract workflow name from output
    for line in result.stdout.split("\n"):
        if line.startswith("Name:"):
            return line.split(":")[1].strip()

    return None


def get_workflow_status(name: str, namespace: str = "argo") -> Optional[WorkflowStatus]:
    """Get status of a workflow."""
    result = run_argo(
        ["get", name, "-n", namespace, "-o", "json"],
        check=False,
    )
    if result.returncode != 0:
        return None

    try:
        data = json.loads(result.stdout)
        status = data.get("status", {})
        metadata = data.get("metadata", {})
        labels = metadata.get("labels", {})
        return WorkflowStatus(
            name=metadata.get("name", name),
            phase=status.get("phase", "Unknown"),
            started_at=status.get("startedAt"),
            finished_at=status.get("finishedAt"),
            progress=status.get("progress", ""),
            message=status.get("message", ""),
            owner=labels.get("owner", ""),
        )
    except json.JSONDecodeError:
        return None


def list_workflows(
    namespace: str = "argo",
    status: Optional[str] = None,
    limit: int = 20,
    label_selector: Optional[str] = None,
) -> list[WorkflowStatus]:
    """List workflows.

    Args:
        namespace: Kubernetes namespace
        status: Filter by status (Running, Succeeded, Failed)
        limit: Maximum number of workflows to return
        label_selector: Label selector (e.g., "owner=camyang")
    """
    args = ["list", "-n", namespace, "-o", "json"]
    if status:
        args.extend(["--status", status])
    if label_selector:
        args.extend(["--selector", label_selector])

    result = run_argo(args, check=False)
    if result.returncode != 0:
        return []

    try:
        data = json.loads(result.stdout)
        workflows = []
        # Handle both list format and {"items": [...]} format
        items = data if isinstance(data, list) else data.get("items", [])
        for item in items:
            status_data = item.get("status", {})
            metadata = item.get("metadata", {})
            labels = metadata.get("labels", {})
            workflows.append(
                WorkflowStatus(
                    name=metadata.get("name", ""),
                    phase=status_data.get("phase", "Unknown"),
                    started_at=status_data.get("startedAt"),
                    finished_at=status_data.get("finishedAt"),
                    progress=status_data.get("progress", ""),
                    owner=labels.get("owner", ""),
                )
            )
        # Sort by started_at descending (most recent first)
        workflows.sort(key=lambda w: w.started_at or "", reverse=True)
        # Apply limit after sorting
        return workflows[:limit]
    except json.JSONDecodeError:
        return []


def resolve_workflow_name(name: str, namespace: str = "argo") -> str:
    """Resolve special workflow name patterns to actual names.

    Supports:
        - "latest" or "last" -> most recent workflow
        - "last-n" -> n-th most recent (1-indexed, so last-1 == latest)

    Args:
        name: Workflow name or special pattern
        namespace: Kubernetes namespace

    Returns:
        Resolved workflow name

    Raises:
        typer.Exit: If pattern is invalid or no matching workflow found
    """
    # Check for special patterns
    if name in ("latest", "last"):
        index = 0
    elif match := re.match(r"^last-(\d+)$", name):
        index = int(match.group(1)) - 1  # Convert to 0-indexed
        if index < 0:
            typer.echo(
                "Error: 'last-0' is invalid. Use 'latest' or 'last-1' for the most recent."
            )
            raise typer.Exit(1)
    else:
        # Not a special pattern, return as-is
        return name

    # Fetch workflows ordered by creation time
    result = run_argo(["list", "-n", namespace, "-o", "json"], check=False)
    if result.returncode != 0:
        typer.echo(
            f"Error: Failed to list workflows: {result.stderr.strip() or 'Unknown error'}"
        )
        raise typer.Exit(1)

    try:
        data = json.loads(result.stdout)
        # Handle both list format and {"items": [...]} format
        items = data if isinstance(data, list) else data.get("items", [])
    except json.JSONDecodeError:
        typer.echo("Error: Failed to parse workflow list.")
        raise typer.Exit(1)

    if not items:
        typer.echo("Error: No workflows found.")
        raise typer.Exit(1)

    # Sort by startedAt descending (most recent first)
    items.sort(key=lambda w: w.get("status", {}).get("startedAt") or "", reverse=True)

    if index >= len(items):
        typer.echo(
            f"Error: Only {len(items)} workflow(s) exist. Cannot get 'last-{index + 1}'."
        )
        raise typer.Exit(1)

    resolved = items[index].get("metadata", {}).get("name", "")
    if not resolved:
        typer.echo("Error: Could not get workflow name.")
        raise typer.Exit(1)

    typer.echo(f"Resolved '{name}' -> {resolved}")
    return resolved


def watch_workflow(name: str, namespace: str = "argo") -> None:
    """Watch a workflow in real-time."""
    subprocess.run(["argo", "watch", name, "-n", namespace])


def get_workflow_logs(
    name: str,
    namespace: str = "argo",
    follow: bool = False,
    grep: Optional[str] = None,
) -> None:
    """Stream workflow logs."""
    args = ["logs", name, "-n", namespace]
    if follow:
        args.append("--follow")
    if grep:
        args.extend(["--grep", grep])

    subprocess.run(["argo"] + args)


def cancel_workflow(name: str, namespace: str = "argo") -> bool:
    """Cancel a running workflow."""
    result = run_argo(["terminate", name, "-n", namespace], check=False)
    return result.returncode == 0


def delete_workflow(name: str, namespace: str = "argo") -> bool:
    """Delete a workflow."""
    result = run_argo(["delete", name, "-n", namespace], check=False)
    return result.returncode == 0


def apply_templates(templates_dir: str, namespace: str = "argo") -> bool:
    """Apply all workflow templates from a directory."""
    result = run_kubectl(
        ["apply", "-f", templates_dir, "-n", namespace],
        check=False,
    )
    return result.returncode == 0


def check_argo_installed() -> bool:
    """Check if Argo is installed in the cluster."""
    result = run_kubectl(
        ["get", "deployment", "argo-server", "-n", "argo"],
        check=False,
    )
    return result.returncode == 0


def check_argo_cli() -> bool:
    """Check if argo CLI is installed."""
    result = subprocess.run(
        ["which", "argo"],
        capture_output=True,
        check=False,
    )
    return result.returncode == 0
