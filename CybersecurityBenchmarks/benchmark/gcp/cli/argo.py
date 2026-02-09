"""
Argo Workflows client wrapper.
"""

import atexit
import json
import os
import re
import subprocess
import time as _time
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


# ---------------------------------------------------------------------------
# Argo-server proxy for offloaded-node-status workflows
# ---------------------------------------------------------------------------

# Module-level port-forward process so we can clean up on exit.
_port_forward_proc: Optional[subprocess.Popen] = None


def _cleanup_port_forward() -> None:
    global _port_forward_proc
    if _port_forward_proc is not None:
        _port_forward_proc.terminate()
        try:
            _port_forward_proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            _port_forward_proc.kill()
        _port_forward_proc = None


atexit.register(_cleanup_port_forward)


def _ensure_argo_server_proxy(port: int = 2746) -> dict[str, str]:
    """Start a kubectl port-forward to the argo-server and return env vars
    that make the ``argo`` CLI route through it.

    The port-forward is started once and reused for the lifetime of the process.
    Returns a dict of environment variables to pass to subprocess calls.
    """
    global _port_forward_proc

    # If we already have a running port-forward, reuse it
    if _port_forward_proc is not None and _port_forward_proc.poll() is None:
        pass
    else:
        # Kill anything leftover on the port
        subprocess.run(
            ["lsof", "-ti", f":{port}"],
            capture_output=True,
        )

        _port_forward_proc = subprocess.Popen(
            [
                "kubectl",
                "port-forward",
                "svc/argo-server",
                f"{port}:{port}",
                "-n",
                "argo",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        # Give port-forward a moment to bind
        _time.sleep(2)

    # Get a short-lived token for the argo-server service account
    token_result = run_kubectl(
        ["create", "token", "argo-server", "-n", "argo", "--duration=10m"],
        check=False,
    )
    if token_result.returncode != 0:
        raise RuntimeError(f"Failed to create token: {token_result.stderr}")

    token = token_result.stdout.strip()
    return {
        "ARGO_SERVER": f"localhost:{port}",
        "ARGO_SECURE": "true",
        "ARGO_INSECURE_SKIP_VERIFY": "true",
        "ARGO_TOKEN": f"Bearer {token}",
    }


def run_argo_via_server(
    args: list[str],
    check: bool = False,
) -> subprocess.CompletedProcess:
    """Run an ``argo`` CLI command routed through the argo-server.

    Automatically sets up a port-forward and auth token so the server can
    serve offloaded node statuses from PostgreSQL.
    """
    env_overrides = _ensure_argo_server_proxy()
    env = {**os.environ, **env_overrides}
    cmd = ["argo"] + args
    return subprocess.run(cmd, capture_output=True, text=True, check=check, env=env)


def run_argo_via_server_interactive(args: list[str]) -> int:
    """Run an argo CLI command via argo-server, inheriting stdout/stderr.

    Returns the exit code.
    """
    env_overrides = _ensure_argo_server_proxy()
    env = {**os.environ, **env_overrides}
    cmd = ["argo"] + args
    result = subprocess.run(cmd, env=env)
    return result.returncode


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
    """Get status of a workflow.

    Uses kubectl to query the workflow resource directly. This avoids the
    'offload node status is not supported' error that occurs with `argo get`
    when nodeStatusOffLoad is enabled and the local CLI can't reach the
    in-cluster PostgreSQL database.
    """
    result = run_kubectl(
        [
            "get",
            "workflow",
            name,
            "-n",
            namespace,
            "-o",
            "json",
        ],
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


def _get_workflow_pods(workflow_name: str, namespace: str = "argo") -> list[dict]:
    """Get pods for a workflow, classified by phase.

    Returns a list of pod info dicts with keys:
        name, template, phase, started, reason
    """
    result = run_kubectl(
        [
            "get",
            "pods",
            "-n",
            namespace,
            "-l",
            f"workflows.argoproj.io/workflow={workflow_name}",
            "-o",
            "json",
        ],
        check=False,
    )
    if result.returncode != 0:
        return []

    try:
        pod_data = json.loads(result.stdout)
    except json.JSONDecodeError:
        return []

    pods = []
    for pod in pod_data.get("items", []):
        pod_phase = pod.get("status", {}).get("phase", "Unknown")
        annotations = pod.get("metadata", {}).get("annotations", {})
        template = annotations.get("workflows.argoproj.io/template", "")

        # Check container-level exit info
        exit_reason = ""
        for cs in pod.get("status", {}).get("containerStatuses", []):
            terminated = cs.get("state", {}).get("terminated", {})
            if terminated:
                reason = terminated.get("reason", "")
                exit_code = terminated.get("exitCode", 0)
                if reason:
                    exit_reason = reason
                elif exit_code != 0:
                    exit_reason = f"exit={exit_code}"

        started_at = pod.get("status", {}).get("startTime", "")
        pods.append(
            {
                "name": pod.get("metadata", {}).get("name", ""),
                "template": template,
                "phase": pod_phase,
                "started": started_at[:19] if started_at else "",
                "reason": exit_reason,
            }
        )

    return pods


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
        # Try standard argo watch first
        result = subprocess.run(
            ["argo", "watch", name, "-n", namespace],
            capture_output=True,
            text=True,
        )
        if result.returncode == 0:
            print(result.stdout, end="")
            return
        if "offload node status" not in result.stderr.lower():
            # Non-offloading error — print it
            typer.echo(f"Error: {result.stderr.strip()}")
            return
        # Offloaded — retry through argo-server
        typer.echo("Node status offloaded — routing through argo-server...")
        rc = run_argo_via_server_interactive(["watch", name, "-n", namespace])
        if rc == 0:
            return
        # Server route also failed — fall through to kubectl-based watch

    # kubectl + pod-based watch (also used for --hide-done)
    import sys
    import time

    try:
        while True:
            wf = get_workflow_status(name, namespace)
            if not wf:
                typer.echo(f"Error: Workflow not found: {name}")
                raise typer.Exit(1)

            pods = _get_workflow_pods(name, namespace)

            # Clear screen
            sys.stdout.write("\033[2J\033[H")
            sys.stdout.flush()

            # Parse progress
            progress_parts = wf.progress.split("/") if "/" in wf.progress else []
            completed = int(progress_parts[0]) if len(progress_parts) == 2 else 0
            total_tasks = int(progress_parts[1]) if len(progress_parts) == 2 else 0
            pct = f"{completed * 100 / total_tasks:.1f}%" if total_tasks > 0 else "-"

            # Header
            typer.echo(
                f"Workflow: {name}   Phase: {wf.phase}   Progress: {wf.progress} ({pct})"
            )
            typer.echo(f"Started:  {wf.started_at or '-'}")

            # Progress bar
            if total_tasks > 0:
                bar_w = 50
                filled = int(bar_w * completed / total_tasks)
                bar = "\033[32m" + "#" * filled + "\033[0m" + "-" * (bar_w - filled)
                typer.echo(f"[{bar}] {completed}/{total_tasks}")

            # Classify pods
            running = [p for p in pods if p["phase"] == "Running"]
            pending = [p for p in pods if p["phase"] == "Pending"]
            failed = [p for p in pods if p["phase"] == "Failed"]
            succeeded = sum(1 for p in pods if p["phase"] == "Succeeded")

            parts = []
            if running:
                parts.append(f"\033[36mRunning: {len(running)}\033[0m")
            if pending:
                parts.append(f"\033[33mPending: {len(pending)}\033[0m")
            parts.append(f"\033[32mSucceeded: {succeeded}\033[0m")
            if failed:
                parts.append(f"\033[31mFailed: {len(failed)}\033[0m")
            typer.echo(f"Pods: {' | '.join(parts)}")
            typer.echo("-" * 70)

            if running:
                typer.echo(f"\n\033[1mRunning ({len(running)}):\033[0m")
                for p in sorted(running, key=lambda x: x["started"])[:30]:
                    tmpl = f"  [{p['template']}]" if p["template"] else ""
                    typer.echo(f"  \033[36m●\033[0m {p['name']}{tmpl}  {p['started']}")
                if len(running) > 30:
                    typer.echo(f"  ... and {len(running) - 30} more")

            if pending and not hide_done:
                typer.echo(f"\n\033[1mPending ({len(pending)}):\033[0m")
                for p in pending[:10]:
                    tmpl = f"  [{p['template']}]" if p["template"] else ""
                    typer.echo(f"  \033[33m◷\033[0m {p['name']}{tmpl}")
                if len(pending) > 10:
                    typer.echo(f"  ... and {len(pending) - 10} more")

            if failed:
                typer.echo(
                    f"\n\033[1mRecent failures ({min(len(failed), 10)}/{len(failed)}):\033[0m"
                )
                for p in sorted(failed, key=lambda x: x["started"], reverse=True)[:10]:
                    reason = f"  ({p['reason']})" if p["reason"] else ""
                    tmpl = f"  [{p['template']}]" if p["template"] else ""
                    typer.echo(f"  \033[31m✖\033[0m {p['name']}{tmpl}{reason}")

            typer.echo("\nPress Ctrl+C to exit")

            if wf.phase in ("Succeeded", "Failed", "Error"):
                typer.echo(f"\nWorkflow {wf.phase.lower()}.")
                break

            time.sleep(5)

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
            output = "\n".join(line for line in output.split("\n") if grep in line)

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
            "kubectl",
            "get",
            "configmap",
            "workflow-controller-configmap",
            "-n",
            "argo",
            "-o",
            "jsonpath={.data.artifactRepository}",
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
        typer.echo("Logs are not being archived to GCS. Re-run setup to fix:")
        typer.echo("  python -m cli setup --skip-cluster")
        typer.echo()

    found = _fetch_gcs_archived_logs(name, config.bucket_name, grep=grep)

    if not found:
        typer.echo(f"No archived logs found in GCS for workflow '{name}'.")
        typer.echo(f"Checked: gs://{config.bucket_name}/argo-logs/.../{name}/...")
        if "archiveLogs" not in artifact_repo_config:
            typer.echo()
            typer.echo("This is expected — archiveLogs is not configured.")
            typer.echo("Fix with: python -m cli setup --skip-cluster")


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
