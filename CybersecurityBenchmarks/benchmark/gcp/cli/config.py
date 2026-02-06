"""
Configuration management for Argo/GKE CLI.
"""

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


@dataclass
class GKEConfig:
    """GKE and Argo configuration."""

    project_id: str = ""
    region: str = "us-central1"
    zone: str = "us-central1-a"
    cluster_name: str = "arvo-cluster"
    bucket_name: str = ""
    artifact_registry: str = ""
    gcp_service_account: str = ""
    secret_name: str = "anthropic-api-key"

    @classmethod
    def load(cls, path: Optional[Path] = None) -> "GKEConfig":
        """Load config from file."""
        if path is None:
            path = get_config_path()
        if not path.exists():
            return cls()
        with open(path) as f:
            data = json.load(f)
        return cls(**data)

    def save(self, path: Optional[Path] = None) -> None:
        """Save config to file."""
        if path is None:
            path = get_config_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w") as f:
            json.dump(self.__dict__, f, indent=2)

    def is_configured(self) -> bool:
        """Check if minimal config is set."""
        return bool(self.project_id and self.bucket_name and self.artifact_registry)


@dataclass
class RunConfig:
    """Configuration for a benchmark run."""

    cases: list[int] = field(default_factory=list)
    model: str = "claude-sonnet-4-20250514"
    experiment_id: str = "default"
    fuzzing_duration: int = 300
    run_gt: bool = True
    build_version: str = "latest"
    patch_use_spot: bool = True
    fuzz_use_spot: bool = True


def get_config_path() -> Path:
    """Get path to config file."""
    return Path(__file__).parent.parent / ".gke-config.json"


def get_script_dir() -> Path:
    """Get the directory containing the CLI package (benchmark/gcp/)."""
    return Path(__file__).parent.parent


def parse_cases(cases_str: str) -> list[int]:
    """Parse cases from string.

    Supports:
    - Comma-separated: "42,43,44"
    - Range: "42-50"
    - File reference: "@path/to/cases.json"
    - "all" for all cases
    """
    if cases_str.startswith("@"):
        # Load from file
        path = Path(cases_str[1:])
        if not path.is_absolute():
            path = get_script_dir().parent.parent / path
        with open(path) as f:
            data = json.load(f)
        if isinstance(data, list):
            if isinstance(data[0], dict):
                return [item.get("arvo_id") or item.get("id") for item in data]
            return data
        raise ValueError(f"Expected list in {path}")

    if "-" in cases_str and "," not in cases_str:
        # Range
        start, end = cases_str.split("-")
        return list(range(int(start), int(end) + 1))

    # Comma-separated
    return [int(c.strip()) for c in cases_str.split(",")]
