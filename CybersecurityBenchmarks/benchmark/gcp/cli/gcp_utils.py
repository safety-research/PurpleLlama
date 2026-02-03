"""
GCP interaction utilities for the ARVO GCP CLI.
"""

import json
import subprocess
from pathlib import Path
from typing import Optional

from .output import echo_warning


def get_gcp_username() -> str:
    """Get username from GCP account (e.g., 'camyang' from 'camyang@csail.mit.edu')."""
    try:
        result = subprocess.run(
            ["gcloud", "config", "get-value", "account"],
            capture_output=True,
            text=True,
            check=True,
        )
        email = result.stdout.strip()
        if email and "@" in email:
            return email.split("@")[0]
    except subprocess.CalledProcessError:
        pass
    return "arvo"  # Fallback


def get_service_account_name() -> str:
    """Get service account name based on GCP username."""
    username = get_gcp_username()
    return f"{username}-arvo-runner"


def get_bucket_suffix() -> str:
    """Get bucket suffix based on GCP username."""
    username = get_gcp_username()
    return f"{username}-arvo-benchmark"


def get_script_dir() -> Path:
    """Get the directory containing the CLI package (benchmark/gcp/)."""
    return Path(__file__).parent.parent


def get_config_path() -> Path:
    """Get path to config file."""
    return get_script_dir() / ".gcp-config.json"


def load_config() -> dict:
    """Load GCP configuration from file."""
    config_path = get_config_path()
    if not config_path.exists():
        return {}
    with open(config_path) as f:
        return json.load(f)


def save_config(config: dict) -> None:
    """Save GCP configuration to file."""
    config_path = get_config_path()
    with open(config_path, "w") as f:
        json.dump(config, f, indent=2)


def run_gcloud(
    args: list[str], capture: bool = True, check: bool = True
) -> subprocess.CompletedProcess:
    """Run a gcloud command."""
    cmd = ["gcloud"] + args
    # Use stdin=DEVNULL to prevent hanging on interactive prompts
    return subprocess.run(
        cmd, capture_output=capture, text=True, check=check, stdin=subprocess.DEVNULL
    )


def run_gsutil(
    args: list[str], capture: bool = True, check: bool = True
) -> subprocess.CompletedProcess:
    """Run a gsutil command."""
    cmd = ["gsutil"] + args
    return subprocess.run(cmd, capture_output=capture, text=True, check=check)


def get_project_number(project_id: str) -> str:
    """Get the project number from project ID."""
    result = run_gcloud(
        [
            "projects",
            "describe",
            project_id,
            "--format=value(projectNumber)",
        ],
        check=False,
    )
    if result.returncode == 0:
        return result.stdout.strip()
    return ""


def get_vm_image_if_exists(project: str) -> Optional[str]:
    """Check if custom VM image exists and return its path.

    Args:
        project: GCP project ID

    Returns:
        Full image path if exists, None otherwise
    """
    username = get_gcp_username()
    image_name = f"{username}-arvo-docker-vm"

    result = run_gcloud(
        [
            "compute",
            "images",
            "describe",
            image_name,
            f"--project={project}",
            "--format=value(selfLink)",
        ],
        check=False,
    )
    if result.returncode == 0 and result.stdout.strip():
        # Return the full image path
        return f"projects/{project}/global/images/{image_name}"
    return None
