"""
Configuration constants, types, and parsing utilities for the ARVO GCP CLI.
"""

import json
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


# =============================================================================
# Configuration Constants
# =============================================================================

DEFAULT_REGION = "us-central1"
DEFAULT_MODEL = "claude-sonnet-4-20250514"
DEFAULT_FUZZING_DURATION = 300
DEFAULT_EXPERIMENT_ID = "default"
SECRET_NAME = "anthropic-api-key"
# Default parallelism for each job type
DEFAULT_PARALLELISM = 50

# Special agent name for ground truth (no LLM, just fuzzing)
GT_AGENT = "gt"


# =============================================================================
# CLI Temp Directory
# =============================================================================


def get_cli_tmp_dir() -> Path:
    """Get the temp directory for CLI-generated files (job specs, logs, etc.).

    Uses system temp directory with a dedicated subdirectory for arvo-cli.
    This avoids cluttering the repository with generated files.

    Returns:
        Path to the CLI temp directory (created if it doesn't exist).
    """
    tmp_dir = Path(tempfile.gettempdir()) / "arvo-cli"
    tmp_dir.mkdir(parents=True, exist_ok=True)
    return tmp_dir


# =============================================================================
# Data Classes
# =============================================================================


@dataclass
class RunConfig:
    """Configuration for a benchmark run."""

    cases: list[int] = field(default_factory=list)
    agents: list[str] = field(default_factory=lambda: [DEFAULT_MODEL])
    fuzzing_duration: int = DEFAULT_FUZZING_DURATION
    run_id: Optional[str] = None
    # Experiment ID for grouping results across runs
    experiment_id: str = DEFAULT_EXPERIMENT_ID
    # Max concurrent VMs (workers) for each job type
    max_concurrent_vms: int = DEFAULT_PARALLELISM
    build_max_concurrent_vms: Optional[int] = None
    eval_max_concurrent_vms: Optional[int] = None
    gt_max_concurrent_vms: Optional[int] = None
    build_only: bool = False
    # Patch caching options
    force_repatch: bool = False  # Ignore cached patches, re-run LLM
    fuzz_only: bool = False  # Require cached patches (fail if not found)
    # Build caching options
    force_rebuild: bool = False  # Rebuild containers even if versioned image exists

    def get_max_concurrent_vms(self, job_type: str) -> int:
        """Get max concurrent VMs for a specific job type."""
        specific = {
            "build": self.build_max_concurrent_vms,
            "eval": self.eval_max_concurrent_vms,
            "gt": self.gt_max_concurrent_vms,
        }.get(job_type)
        return specific if specific is not None else self.max_concurrent_vms

    def get_llm_agents(self) -> list[str]:
        """Get list of LLM agents (excludes gt)."""
        return [a for a in self.agents if a != GT_AGENT]

    def has_gt(self) -> bool:
        """Check if ground truth agent is included."""
        return GT_AGENT in self.agents


# =============================================================================
# Parsing Functions
# =============================================================================


def parse_cases(cases_input: str | list) -> list[int]:
    """Parse cases from various formats.

    Supported formats:
    - "42,43,44": Comma-separated list
    - [42, 43, 44]: List of integers
    - "@path/to/cases.json": Load from JSON file (list of integers)
    """
    if isinstance(cases_input, list):
        return [int(c) for c in cases_input]

    # Check for @filepath syntax
    if cases_input.startswith("@"):
        filepath = Path(cases_input[1:])
        if not filepath.exists():
            raise FileNotFoundError(f"Cases file not found: {filepath}")
        with open(filepath) as f:
            data = json.load(f)
        if not isinstance(data, list):
            raise ValueError(f"Cases file must contain a JSON array: {filepath}")
        return [int(c) for c in data]

    # Comma-separated list
    return [int(c.strip()) for c in cases_input.split(",")]


def parse_agents(agents_input: str | list) -> list[str]:
    """Parse agents from various formats.

    Supported formats:
    - "claude-sonnet-4-20250514": Single agent
    - "claude-sonnet-4-20250514,gt": Comma-separated list
    - ["claude-sonnet-4-20250514", "gt"]: List of strings

    Special agent "gt" runs ground truth fuzzing (no LLM).
    """
    if isinstance(agents_input, list):
        return [str(a).strip() for a in agents_input]

    return [a.strip() for a in agents_input.split(",")]


def load_run_config(config_path: Path) -> dict:
    """Load run configuration from a JSON file."""
    if not config_path.exists():
        raise FileNotFoundError(f"Config file not found: {config_path}")

    with open(config_path) as f:
        content = f.read()

    try:
        return json.loads(content)
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON in config file {config_path}: {e}")


def merge_run_config(file_config: dict, cli_overrides: dict) -> RunConfig:
    """Merge file config with CLI overrides (CLI takes precedence)."""
    # Start with defaults
    config = RunConfig()

    # Apply file config
    if "cases" in file_config:
        config.cases = parse_cases(file_config["cases"])

    if "agents" in file_config:
        config.agents = parse_agents(file_config["agents"])

    if "fuzzing_duration" in file_config:
        config.fuzzing_duration = int(file_config["fuzzing_duration"])
    if "run_id" in file_config:
        config.run_id = file_config["run_id"]
    if "experiment_id" in file_config:
        config.experiment_id = str(file_config["experiment_id"])
    if "max_concurrent_vms" in file_config:
        config.max_concurrent_vms = int(file_config["max_concurrent_vms"])
    if "build_max_concurrent_vms" in file_config:
        config.build_max_concurrent_vms = int(file_config["build_max_concurrent_vms"])
    if "eval_max_concurrent_vms" in file_config:
        config.eval_max_concurrent_vms = int(file_config["eval_max_concurrent_vms"])
    if "gt_max_concurrent_vms" in file_config:
        config.gt_max_concurrent_vms = int(file_config["gt_max_concurrent_vms"])
    if "force_repatch" in file_config:
        config.force_repatch = bool(file_config["force_repatch"])
    if "fuzz_only" in file_config:
        config.fuzz_only = bool(file_config["fuzz_only"])
    if "force_rebuild" in file_config:
        config.force_rebuild = bool(file_config["force_rebuild"])

    # Apply CLI overrides (only if explicitly set)
    for key, value in cli_overrides.items():
        if value is not None:
            setattr(config, key, value)

    return config
