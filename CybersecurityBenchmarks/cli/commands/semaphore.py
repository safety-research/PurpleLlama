"""
Semaphore management for rate-limiting LLM patch jobs.

Manages a Kubernetes ConfigMap that Argo Workflows uses as a semaphore
to limit concurrent patch jobs per model.
"""

import json
import subprocess
from typing import Annotated, Optional

import typer

from ..argo import run_kubectl
from ..output import echo_error, echo_info, echo_success, echo_warning

CONFIGMAP_NAME = "patch-semaphores"
NAMESPACE = "argo"


def get_model_limit(model: str) -> tuple[bool, Optional[int]]:
    """Get the configured limit for a specific model.

    Args:
        model: Model name to check

    Returns:
        Tuple of (is_configured, limit):
        - (False, None) - Not configured at all
        - (True, None) - Explicitly set to unlimited
        - (True, N) - Set to N concurrent jobs
    """
    data = get_configmap_data()
    if data is None or model not in data:
        return (False, None)

    value = data[model]
    if value.lower() in ("unlimited", "none", "0"):
        return (True, None)  # Explicitly unlimited

    try:
        return (True, int(value))
    except ValueError:
        return (False, None)


def get_configmap_data() -> Optional[dict[str, str]]:
    """Get current semaphore ConfigMap data.

    Returns:
        Dictionary of model -> limit mappings, or None if ConfigMap doesn't exist.
    """
    result = run_kubectl(
        ["get", "configmap", CONFIGMAP_NAME, "-n", NAMESPACE, "-o", "json"],
        check=False,
    )
    if result.returncode != 0:
        return None

    try:
        data = json.loads(result.stdout)
        return data.get("data", {})
    except json.JSONDecodeError:
        return None


def _create_or_update_configmap(data: dict[str, str]) -> bool:
    """Create or update the semaphore ConfigMap.

    Args:
        data: Dictionary of model -> limit mappings

    Returns:
        True if successful, False otherwise.
    """
    # Build ConfigMap YAML
    configmap = {
        "apiVersion": "v1",
        "kind": "ConfigMap",
        "metadata": {
            "name": CONFIGMAP_NAME,
            "namespace": NAMESPACE,
        },
        "data": data,
    }

    configmap_yaml = json.dumps(configmap)

    # Apply using kubectl
    result = subprocess.run(
        ["kubectl", "apply", "-f", "-"],
        input=configmap_yaml,
        capture_output=True,
        text=True,
    )

    return result.returncode == 0


def set_limit(
    model: Annotated[
        str, typer.Argument(help="Model name (e.g., claude-sonnet-4-20250514)")
    ],
    limit: Annotated[
        str, typer.Argument(help="Max concurrent jobs (number or 'unlimited')")
    ],
) -> None:
    """Set the concurrency limit for a specific model.

    Use a number to set a specific limit, or 'unlimited' (or '0') for no rate limiting.
    """
    # Parse the limit value
    if limit.lower() in ("unlimited", "none", "0"):
        limit_value = "unlimited"
        limit_display = "unlimited"
    else:
        try:
            limit_int = int(limit)
            if limit_int < 1:
                echo_error("Limit must be at least 1 (or use 'unlimited' for no limit)")
                raise typer.Exit(1)
            limit_value = str(limit_int)
            limit_display = f"{limit_int} concurrent jobs"
        except ValueError:
            echo_error(f"Invalid limit value: '{limit}'. Use a number or 'unlimited'.")
            raise typer.Exit(1)

    # Get existing data or start fresh
    current_data = get_configmap_data() or {}

    # Update the limit for this model
    current_data[model] = limit_value

    if _create_or_update_configmap(current_data):
        echo_success(f"Set limit for '{model}' to {limit_display}")
    else:
        echo_error("Failed to update semaphore ConfigMap")
        raise typer.Exit(1)


def list_limits() -> None:
    """List all configured semaphore limits."""
    data = get_configmap_data()

    if data is None:
        echo_info("No semaphore limits configured yet.")
        typer.echo()
        typer.echo(
            "Use 'python -m cli semaphore set <model> <limit>' to configure limits."
        )
        return

    if not data:
        echo_info("Semaphore ConfigMap exists but has no limits configured.")
        return

    typer.echo()
    typer.echo(f"{'Model':<45} {'Limit':>12}")
    typer.echo("-" * 59)

    for model, limit in sorted(data.items()):
        # Display "unlimited" nicely
        if limit.lower() in ("unlimited", "none", "0"):
            display_limit = "unlimited"
        else:
            display_limit = limit
        typer.echo(f"{model:<45} {display_limit:>12}")

    typer.echo()
    typer.echo(f"Total: {len(data)} model(s) configured")


def remove_limit(
    model: Annotated[str, typer.Argument(help="Model name to remove limit for")],
) -> None:
    """Remove the concurrency limit for a model (becomes unlimited)."""
    current_data = get_configmap_data()

    if current_data is None:
        echo_warning("No semaphore ConfigMap exists - nothing to remove.")
        return

    if model not in current_data:
        echo_warning(f"No limit configured for model '{model}'")
        return

    # Remove the model from the data
    del current_data[model]

    if _create_or_update_configmap(current_data):
        echo_success(f"Removed limit for '{model}' - jobs will now run unlimited")
    else:
        echo_error("Failed to update semaphore ConfigMap")
        raise typer.Exit(1)
