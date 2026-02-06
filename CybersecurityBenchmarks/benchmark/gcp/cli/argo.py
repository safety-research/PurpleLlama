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


def watch_workflow(
    name: str,
    namespace: str = "argo",
    hide_done: bool = False,
) -> None:
    """Watch a workflow in real-time.

    Args:
        name: Workflow name
        namespace: Kubernetes namespace
        hide_done: If True, hide Succeeded and Skipped tasks (show only active/pending/failed)
    """
    if not hide_done:
        # Use standard argo watch
        subprocess.run(["argo", "watch", name, "-n", namespace])
        return

    # Custom watch with filtering
    import sys
    import time

    # Status symbols and colors
    SYMBOLS = {
        "Pending": "\033[33m◷\033[0m",  # Yellow clock
        "Running": "\033[36m●\033[0m",  # Cyan circle
        "Succeeded": "\033[32m✔\033[0m",  # Green check
        "Failed": "\033[31m✖\033[0m",  # Red X
        "Error": "\033[31m✖\033[0m",  # Red X
        "Skipped": "\033[90m○\033[0m",  # Gray circle
        "Omitted": "\033[90m○\033[0m",  # Gray circle
    }

    # Phases to show when hide_done is True (only truly in-progress tasks)
    # Note: "Failed" is excluded because condition checks (chk-*) that evaluate
    # to false are marked as Failed, but they're not really errors
    ACTIVE_PHASES = {"Pending", "Running"}

    try:
        while True:
            # Get workflow status as JSON
            result = run_argo(
                ["get", name, "-n", namespace, "-o", "json"],
                check=False,
            )
            if result.returncode != 0:
                typer.echo(f"Error getting workflow: {result.stderr}")
                raise typer.Exit(1)

            try:
                data = json.loads(result.stdout)
            except json.JSONDecodeError:
                typer.echo("Error parsing workflow data")
                raise typer.Exit(1)

            status = data.get("status", {})
            phase = status.get("phase", "Unknown")
            progress = status.get("progress", "")
            nodes = status.get("nodes", {})

            # Clear screen and move cursor to top
            sys.stdout.write("\033[2J\033[H")
            sys.stdout.flush()

            # Header
            typer.echo(f"Workflow: {name}")
            typer.echo(f"Phase: {phase}  Progress: {progress}")
            typer.echo(f"Mode: Hiding completed/skipped tasks (--hide-done)")
            typer.echo("-" * 60)

            # Count by phase
            phase_counts: dict[str, int] = {}
            active_nodes = []

            for node_id, node in nodes.items():
                node_phase = node.get("phase", "Unknown")
                node_type = node.get("type", "")
                display_name = node.get("displayName", node.get("name", node_id))

                # Count all phases
                phase_counts[node_phase] = phase_counts.get(node_phase, 0) + 1

                # Skip DAG/Steps container nodes (only show actual tasks)
                if node_type in ("DAG", "Steps", "StepGroup"):
                    continue

                # Collect active nodes
                if node_phase in ACTIVE_PHASES:
                    active_nodes.append((display_name, node_phase, node))

            # Show summary line
            summary_parts = []
            for p in ["Running", "Pending", "Succeeded", "Failed", "Skipped"]:
                if p in phase_counts:
                    summary_parts.append(f"{p}: {phase_counts[p]}")
            typer.echo(" | ".join(summary_parts))
            typer.echo()

            # Show active nodes
            if active_nodes:
                typer.echo(f"Active tasks ({len(active_nodes)}):")
                for display_name, node_phase, node in sorted(
                    active_nodes, key=lambda x: x[0]
                ):
                    symbol = SYMBOLS.get(node_phase, "?")
                    started = (
                        node.get("startedAt", "")[:19] if node.get("startedAt") else ""
                    )
                    typer.echo(f"  {symbol} {display_name:<50} {started}")
            else:
                typer.echo("No active tasks.")

            typer.echo()
            typer.echo("Press Ctrl+C to exit")

            # Check if workflow is done
            if phase in ("Succeeded", "Failed", "Error"):
                typer.echo()
                typer.echo(f"Workflow {phase.lower()}.")
                break

            time.sleep(2)

    except KeyboardInterrupt:
        typer.echo("\nStopped watching.")


def _fetch_gcs_archived_logs(
    name: str,
    bucket: str,
    grep: Optional[str] = None,
) -> bool:
    """Fetch workflow logs from GCS archive. Returns True if logs were found."""
    typer.echo(f"Fetching archived logs from GCS for {name}...")

    # List all log files for this workflow under argo-logs/
    gcs_result = subprocess.run(
        ["gsutil", "ls", "-r", f"gs://{bucket}/argo-logs/"],
        capture_output=True,
        text=True,
    )
    if gcs_result.returncode != 0 or not gcs_result.stdout.strip():
        return False

    # Filter to lines matching this workflow name
    log_files = [
        line
        for line in gcs_result.stdout.strip().split("\n")
        if name in line and not line.endswith("/") and not line.endswith(":")
    ]

    if not log_files:
        return False

    typer.echo(f"Found {len(log_files)} archived log file(s) in GCS.\n")

    for log_file in sorted(log_files):
        # Extract pod name from path: .../workflow-name/pod-name
        pod_name = log_file.rsplit("/", 1)[-1] if "/" in log_file else log_file
        typer.echo(f"--- {pod_name} ---")

        cat_result = subprocess.run(
            ["gsutil", "cat", log_file],
            capture_output=True,
            text=True,
        )
        if cat_result.returncode != 0:
            typer.echo(f"  (failed to read: {cat_result.stderr.strip()})")
            continue

        output = cat_result.stdout
        if grep:
            output = "\n".join(
                line for line in output.split("\n") if grep in line
            )

        if output.strip():
            print(output)
        else:
            typer.echo("  (empty or no matching lines)")

    return True


def get_workflow_logs(
    name: str,
    namespace: str = "argo",
    follow: bool = False,
    grep: Optional[str] = None,
) -> None:
    """Stream workflow logs.

    Tries the Argo API first (live pod logs). If that returns empty
    (pods already cleaned up), falls back to GCS-archived logs.
    """
    import sys as _s

    # Follow mode: stream directly, no fallback possible
    if follow:
        args = ["logs", name, "-n", namespace, "--follow"]
        if grep:
            args.extend(["--grep", grep])
        subprocess.run(["argo"] + args)
        return

    # Non-follow mode: capture output so we can fall back to GCS if empty
    args = ["logs", name, "-n", namespace]
    if grep:
        args.extend(["--grep", grep])

    result = subprocess.run(["argo"] + args, capture_output=True, text=True)

    if result.stdout.strip():
        # Argo returned logs from live pods — print and return
        print(result.stdout, end="")
        if result.stderr:
            print(result.stderr, end="", file=_s.stderr)
        return

    # argo logs returned empty — fall back to GCS archived logs
    typer.echo("No live pod logs available from Argo (pods may have been cleaned up).")

    from .config import GKEConfig

    config = GKEConfig.load()
    if not config.bucket_name:
        typer.echo("Error: No bucket configured. Run: python -m cli setup")
        return

    # Check if archiveLogs is configured in the cluster
    cm = subprocess.run(
        [
            "kubectl", "get", "configmap", "workflow-controller-configmap",
            "-n", "argo", "-o", "jsonpath={.data.artifactRepository}",
        ],
        capture_output=True,
        text=True,
    )
    artifact_repo_config = cm.stdout.strip() if cm.returncode == 0 else ""

    if "archiveLogs" not in artifact_repo_config:
        typer.echo()
        typer.echo(
            "Warning: archiveLogs is NOT configured in the workflow-controller-configmap."
        )
        typer.echo(
            "Logs are not being archived to GCS. Re-run setup to fix:"
        )
        typer.echo("  python -m cli setup --skip-cluster")
        typer.echo()

    found = _fetch_gcs_archived_logs(name, config.bucket_name, grep=grep)

    if not found:
        typer.echo(f"No archived logs found in GCS for workflow '{name}'.")
        typer.echo(
            f"Checked: gs://{config.bucket_name}/argo-logs/.../{name}/..."
        )
        if "archiveLogs" not in artifact_repo_config:
            typer.echo()
            typer.echo(
                "This is expected — archiveLogs is not configured."
            )
            typer.echo(
                "Fix with: python -m cli setup --skip-cluster"
            )


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
