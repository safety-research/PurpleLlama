"""
Configuration management for Argo/GKE CLI.
"""

import json
import json5
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional


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
class AgentSpec:
    """Parsed agent specification from config.

    Represents a single agent+model combination with optional parameters.
    The `id` is the primary identifier used in GCS paths, Argo task names,
    and completion check paths.

    Config format examples:
        {"agent": "autopatchbench", "model": "claude-sonnet-4-20250514"}
        {"id": "cc-sonnet", "agent": "claudecode", "model": "claude-sonnet-4-20250514", "max_turns": 50}
    """

    id: str  # Unique identifier (used in GCS paths, task names)
    agent_type: str  # Agent class name (autopatchbench, claudecode)
    model: str  # LLM model name (for API calls)
    params: dict = field(default_factory=dict)  # Additional agent-specific parameters

    def to_agent_config(self) -> dict[str, Any]:
        """Serialize to JSON-compatible dict for passing to agent runtime.

        This is the blob passed via AGENT_CONFIG env var to the container.
        """
        config: dict[str, Any] = {
            "id": self.id,
            "agent": self.agent_type,
            "model": self.model,
        }
        config.update(self.params)
        return config

    def to_agent_config_json(self) -> str:
        """Serialize to JSON string for passing to agent runtime."""
        return json.dumps(self.to_agent_config(), separators=(",", ":"))


def parse_agent_specs(raw_agents: list) -> tuple[list[AgentSpec], bool]:
    """Parse agent specs from config JSON.

    Accepts a list of structured agent objects and the special "gt" string.

    Args:
        raw_agents: List from config "agents" field. Each entry is either:
            - "gt" (string): ground truth marker
            - dict with required "agent" and "model" keys, optional "id" and extra params

    Returns:
        Tuple of (agent_specs, run_gt) where:
            - agent_specs: List of AgentSpec (excludes "gt")
            - run_gt: True if "gt" was present in the list

    Raises:
        ValueError: If an agent spec is missing required fields or has duplicate IDs.
    """
    specs: list[AgentSpec] = []
    run_gt = False
    seen_ids: set[str] = set()

    for entry in raw_agents:
        if isinstance(entry, str):
            if entry == "gt":
                run_gt = True
            else:
                raise ValueError(
                    f"Invalid agent spec string: '{entry}'. "
                    f"Use a structured object like "
                    f'{{"agent": "autopatchbench", "model": "{entry}"}}'
                )
            continue

        if not isinstance(entry, dict):
            raise ValueError(f"Invalid agent spec: {entry!r}. Expected a dict or 'gt'.")

        # Validate required fields
        if "agent" not in entry:
            raise ValueError(f"Agent spec missing required 'agent' field: {entry}")
        if "model" not in entry:
            raise ValueError(f"Agent spec missing required 'model' field: {entry}")

        agent_type = entry["agent"]
        model = entry["model"]

        # Auto-generate ID if not provided
        agent_id = entry.get("id", f"{agent_type}-{model}")

        # Collect extra params (everything except id, agent, model)
        params = {k: v for k, v in entry.items() if k not in ("id", "agent", "model")}

        # Check for duplicate IDs
        if agent_id in seen_ids:
            raise ValueError(f"Duplicate agent ID: '{agent_id}'")
        seen_ids.add(agent_id)

        specs.append(
            AgentSpec(
                id=agent_id,
                agent_type=agent_type,
                model=model,
                params=params,
            )
        )

    return specs, run_gt


@dataclass
class RunConfig:
    """Configuration for a benchmark run."""

    cases: list[int] = field(default_factory=list)
    agents: list[AgentSpec] = field(default_factory=list)
    experiment_id: str = "default"
    fuzzing_duration: int = 300
    build_version: str = "latest"
    patch_use_spot: bool = True
    fuzz_use_spot: bool = True
    vul_base_image: str = (
        ""  # Override vul base image, e.g. "registry/arvo-{case_id}-closest-vul:latest"
    )


def get_config_path() -> Path:
    """Get path to config file."""
    return Path(__file__).parent.parent / ".gke-config.json"


def get_script_dir() -> Path:
    """Get the project root directory (parent of cli/)."""
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
            path = get_script_dir() / path
        with open(path) as f:
            data = json5.load(f)
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
