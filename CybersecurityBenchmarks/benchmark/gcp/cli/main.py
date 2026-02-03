#!/usr/bin/env python3
"""
ARVO Benchmark GCP CLI

Command-line interface for managing ARVO benchmark jobs on GCP Cloud Batch.

Usage:
    python -m cli setup --project my-project
    python -m cli submit --cases 42,43,44 --model claude-sonnet-4-20250514
    python -m cli monitor --watch
    python -m cli collect --output ./results
"""

import hashlib
import json
import os
import subprocess
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Annotated, Optional

import typer

app = typer.Typer(
    name="arvo-gcp",
    help="ARVO Benchmark GCP CLI - Manage benchmark jobs on Cloud Batch",
    add_completion=False,
)

# =============================================================================
# Configuration
# =============================================================================

DEFAULT_REGION = "us-central1"
DEFAULT_MODEL = "claude-sonnet-4-20250514"
DEFAULT_FUZZING_DURATION = 300
SECRET_NAME = "anthropic-api-key"
# Default parallelism for each job type
DEFAULT_PARALLELISM = 50

# Special agent name for ground truth (no LLM, just fuzzing)
GT_AGENT = "gt"


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


@dataclass
class RunConfig:
    """Configuration for a benchmark run."""

    cases: list[int] = field(default_factory=list)
    agents: list[str] = field(default_factory=lambda: [DEFAULT_MODEL])
    fuzzing_duration: int = DEFAULT_FUZZING_DURATION
    run_id: Optional[str] = None
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
    """Get the directory containing this script."""
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
    return subprocess.run(cmd, capture_output=capture, text=True, check=check)


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


def echo_success(msg: str) -> None:
    """Print success message."""
    typer.echo(typer.style(f"✓ {msg}", fg=typer.colors.GREEN))


def echo_info(msg: str) -> None:
    """Print info message."""
    typer.echo(typer.style(f"• {msg}", fg=typer.colors.BLUE))


def echo_warning(msg: str) -> None:
    """Print warning message."""
    typer.echo(typer.style(f"⚠ {msg}", fg=typer.colors.YELLOW))


def echo_error(msg: str) -> None:
    """Print error message."""
    typer.echo(typer.style(f"✗ {msg}", fg=typer.colors.RED), err=True)


# =============================================================================
# Setup Command
# =============================================================================


@app.command()
def setup(
    project: Annotated[Optional[str], typer.Option(help="GCP project ID")] = None,
    region: Annotated[str, typer.Option(help="GCP region")] = DEFAULT_REGION,
    dry_run: Annotated[
        bool, typer.Option("--dry-run", help="Show what would be done")
    ] = False,
) -> None:
    """Set up GCP infrastructure for ARVO benchmark."""
    typer.echo("=" * 50)
    typer.echo("ARVO Benchmark GCP Setup")
    typer.echo("=" * 50)
    typer.echo()

    # Get project ID
    if not project:
        result = run_gcloud(["config", "get-value", "project"], check=False)
        project = result.stdout.strip()
        if not project:
            echo_error("No project specified and no default project set")
            echo_info("Run: gcloud config set project PROJECT_ID")
            raise typer.Exit(1)

    service_account_name = get_service_account_name()
    bucket_name = f"{project}-{get_bucket_suffix()}"
    service_account_email = f"{service_account_name}@{project}.iam.gserviceaccount.com"
    artifact_repo = f"{get_gcp_username()}-arvo"
    artifact_registry = f"{region}-docker.pkg.dev/{project}/{artifact_repo}"

    typer.echo(f"Project:         {project}")
    typer.echo(f"Region:          {region}")
    typer.echo(f"Service Account: {service_account_email}")
    typer.echo(f"Bucket:          gs://{bucket_name}")
    typer.echo(f"Artifact Reg:    {artifact_registry}")
    typer.echo()

    if dry_run:
        echo_warning("DRY RUN MODE - No changes will be made")
        typer.echo()

    # Step 1: Enable APIs
    typer.echo("Step 1: Enable APIs")
    apis = [
        "batch.googleapis.com",
        "compute.googleapis.com",
        "storage.googleapis.com",
        "secretmanager.googleapis.com",
        "logging.googleapis.com",
        "artifactregistry.googleapis.com",
    ]
    for api in apis:
        echo_info(f"Enabling {api}")
        if not dry_run:
            run_gcloud(["services", "enable", api, f"--project={project}"], check=False)

    # Step 2: Create service account
    typer.echo()
    typer.echo("Step 2: Create Service Account")
    result = run_gcloud(
        [
            "iam",
            "service-accounts",
            "describe",
            service_account_email,
            f"--project={project}",
        ],
        check=False,
    )
    if result.returncode == 0:
        echo_warning("Service account already exists")
    elif not dry_run:
        echo_info(f"Creating {service_account_name}")
        run_gcloud(
            [
                "iam",
                "service-accounts",
                "create",
                service_account_name,
                f"--project={project}",
                "--display-name=ARVO Benchmark Batch Runner",
            ]
        )
        echo_success("Service account created")

    # Step 3: Grant IAM roles
    typer.echo()
    typer.echo("Step 3: Grant IAM Roles")
    roles = [
        "roles/batch.agentReporter",
        "roles/batch.jobsEditor",
        "roles/logging.logWriter",
        "roles/storage.objectAdmin",
        "roles/secretmanager.secretAccessor",
        "roles/compute.instanceAdmin.v1",
        "roles/artifactregistry.writer",
    ]
    for role in roles:
        echo_info(f"Granting {role}")
        if not dry_run:
            run_gcloud(
                [
                    "projects",
                    "add-iam-policy-binding",
                    project,
                    f"--member=serviceAccount:{service_account_email}",
                    f"--role={role}",
                    "--condition=None",
                    "--quiet",
                ],
                check=False,
            )

    # Step 4: Create GCS bucket
    typer.echo()
    typer.echo("Step 4: Create GCS Bucket")
    result = run_gsutil(["ls", "-b", f"gs://{bucket_name}"], check=False)
    if result.returncode == 0:
        echo_warning("Bucket already exists")
    elif not dry_run:
        echo_info(f"Creating gs://{bucket_name}")
        run_gsutil(["mb", "-p", project, "-l", region, f"gs://{bucket_name}"])
        echo_success("Bucket created")

    # Step 5: Create Artifact Registry repository
    typer.echo()
    typer.echo("Step 5: Create Artifact Registry")
    result = run_gcloud(
        [
            "artifacts",
            "repositories",
            "describe",
            artifact_repo,
            f"--project={project}",
            f"--location={region}",
        ],
        check=False,
    )
    if result.returncode == 0:
        echo_warning("Artifact Registry repository already exists")
    elif not dry_run:
        echo_info(f"Creating {artifact_repo}")
        run_gcloud(
            [
                "artifacts",
                "repositories",
                "create",
                artifact_repo,
                f"--project={project}",
                f"--location={region}",
                "--repository-format=docker",
                "--description=ARVO benchmark container images",
            ]
        )
        echo_success("Artifact Registry repository created")

    # Step 6: Create secret
    typer.echo()
    typer.echo("Step 6: Setup Secret Manager")
    result = run_gcloud(
        ["secrets", "describe", SECRET_NAME, f"--project={project}"],
        check=False,
    )
    if result.returncode == 0:
        echo_warning("Secret already exists")
    elif not dry_run:
        echo_info(f"Creating secret {SECRET_NAME}")
        run_gcloud(
            [
                "secrets",
                "create",
                SECRET_NAME,
                f"--project={project}",
                "--replication-policy=automatic",
            ]
        )
        echo_success("Secret created")
        echo_warning("Add your API key with:")
        typer.echo(
            f"  echo -n 'sk-ant-...' | gcloud secrets versions add {SECRET_NAME} --data-file=-"
        )

    # Save configuration
    if not dry_run:
        project_number = get_project_number(project)
        config = {
            "project_id": project,
            "project_number": project_number,
            "region": region,
            "bucket_name": bucket_name,
            "service_account_email": service_account_email,
            "secret_name": SECRET_NAME,
            "artifact_registry": artifact_registry,
            "created_at": datetime.utcnow().isoformat() + "Z",
        }
        save_config(config)

    typer.echo()
    typer.echo("=" * 50)
    echo_success("Setup complete!")
    typer.echo("=" * 50)


# =============================================================================
# Check Permissions Command
# =============================================================================


@app.command(name="check-permissions")
def check_permissions(
    project: Annotated[Optional[str], typer.Option(help="GCP project ID")] = None,
    region: Annotated[str, typer.Option(help="GCP region")] = DEFAULT_REGION,
    verbose: Annotated[
        bool, typer.Option("--verbose", "-v", help="Show detailed output")
    ] = False,
) -> None:
    """Check necessary GCP permissions and resources for ARVO benchmark."""
    typer.echo("=" * 50)
    typer.echo("ARVO Benchmark Permission Check")
    typer.echo("=" * 50)
    typer.echo()

    # Get project ID
    if not project:
        result = run_gcloud(["config", "get-value", "project"], check=False)
        project = result.stdout.strip()
        if not project:
            echo_error("No project specified and no default project set")
            echo_info("Run: gcloud config set project PROJECT_ID")
            raise typer.Exit(1)

    service_account_name = get_service_account_name()
    bucket_name = f"{project}-{get_bucket_suffix()}"
    service_account_email = f"{service_account_name}@{project}.iam.gserviceaccount.com"
    artifact_repo = f"{get_gcp_username()}-arvo"

    typer.echo(f"Project:         {project}")
    typer.echo(f"Region:          {region}")
    typer.echo(f"Service Account: {service_account_email}")
    typer.echo(f"Bucket:          gs://{bucket_name}")
    typer.echo(f"Artifact Repo:   {artifact_repo}")
    typer.echo()

    passed = 0
    failed = 0
    warnings = 0

    def check_pass(msg: str) -> None:
        nonlocal passed
        passed += 1
        echo_success(msg)

    def check_fail(msg: str) -> None:
        nonlocal failed
        failed += 1
        echo_error(msg)

    def check_warn(msg: str) -> None:
        nonlocal warnings
        warnings += 1
        echo_warning(msg)

    # Check 1: APIs enabled
    typer.echo("Checking APIs...")
    apis = [
        ("batch.googleapis.com", "Cloud Batch API"),
        ("compute.googleapis.com", "Compute Engine API"),
        ("storage.googleapis.com", "Cloud Storage API"),
        ("secretmanager.googleapis.com", "Secret Manager API"),
        ("logging.googleapis.com", "Cloud Logging API"),
        ("artifactregistry.googleapis.com", "Artifact Registry API"),
    ]
    for api, name in apis:
        result = run_gcloud(
            [
                "services",
                "list",
                f"--project={project}",
                f"--filter=config.name:{api}",
                "--format=value(config.name)",
            ],
            check=False,
        )
        if result.returncode == 0 and api in result.stdout:
            if verbose:
                check_pass(f"{name} enabled")
        else:
            check_fail(f"{name} NOT enabled")
            if verbose:
                echo_info(f"  Enable with: gcloud services enable {api}")

    if not verbose:
        api_check_result = run_gcloud(
            [
                "services",
                "list",
                f"--project={project}",
                "--format=value(config.name)",
            ],
            check=False,
        )
        enabled_apis = (
            api_check_result.stdout.strip().split("\n")
            if api_check_result.returncode == 0
            else []
        )
        missing_apis = [api for api, _ in apis if api not in enabled_apis]
        if not missing_apis:
            check_pass(f"All {len(apis)} required APIs enabled")
        # Failed ones already counted above

    typer.echo()

    # Check 2: Service account exists
    typer.echo("Checking service account...")
    result = run_gcloud(
        [
            "iam",
            "service-accounts",
            "describe",
            service_account_email,
            f"--project={project}",
        ],
        check=False,
    )
    if result.returncode == 0:
        check_pass(f"Service account exists: {service_account_name}")
    else:
        check_fail(f"Service account NOT found: {service_account_name}")
        echo_info("  Run 'arvo-gcp setup' to create it")
        typer.echo()

    # Check 3: IAM roles
    typer.echo()
    typer.echo("Checking IAM roles...")
    required_roles = [
        ("roles/batch.agentReporter", "Batch Agent Reporter"),
        ("roles/batch.jobsEditor", "Batch Jobs Editor"),
        ("roles/logging.logWriter", "Logs Writer"),
        ("roles/storage.objectAdmin", "Storage Object Admin"),
        ("roles/secretmanager.secretAccessor", "Secret Manager Accessor"),
        ("roles/compute.instanceAdmin.v1", "Compute Instance Admin"),
        ("roles/artifactregistry.writer", "Artifact Registry Writer"),
    ]

    # Get IAM policy
    result = run_gcloud(
        [
            "projects",
            "get-iam-policy",
            project,
            "--format=json",
        ],
        check=False,
    )

    granted_roles = set()
    if result.returncode == 0:
        try:
            policy = json.loads(result.stdout)
            member = f"serviceAccount:{service_account_email}"
            for binding in policy.get("bindings", []):
                if member in binding.get("members", []):
                    granted_roles.add(binding.get("role"))
        except json.JSONDecodeError:
            check_fail("Failed to parse IAM policy")

    missing_roles = []
    for role, name in required_roles:
        if role in granted_roles:
            if verbose:
                check_pass(f"{name}")
        else:
            missing_roles.append((role, name))
            check_fail(f"{name} NOT granted")

    if not missing_roles and not verbose:
        check_pass(f"All {len(required_roles)} required IAM roles granted")

    typer.echo()

    # Check 4: GCS bucket
    typer.echo("Checking GCS bucket...")
    result = run_gsutil(["ls", "-b", f"gs://{bucket_name}"], check=False)
    if result.returncode == 0:
        check_pass(f"Bucket exists: gs://{bucket_name}")
    else:
        check_fail(f"Bucket NOT found: gs://{bucket_name}")
        echo_info("  Run 'arvo-gcp setup' to create it")

    typer.echo()

    # Check 5: Artifact Registry
    typer.echo("Checking Artifact Registry...")
    result = run_gcloud(
        [
            "artifacts",
            "repositories",
            "describe",
            artifact_repo,
            f"--project={project}",
            f"--location={region}",
        ],
        check=False,
    )
    if result.returncode == 0:
        check_pass(f"Artifact Registry exists: {artifact_repo}")
    else:
        check_fail(f"Artifact Registry NOT found: {artifact_repo}")
        echo_info("  Run 'arvo-gcp setup' to create it")

    typer.echo()

    # Check 6: Secret Manager
    typer.echo("Checking Secret Manager...")
    result = run_gcloud(
        ["secrets", "describe", SECRET_NAME, f"--project={project}"],
        check=False,
    )
    if result.returncode == 0:
        check_pass(f"Secret exists: {SECRET_NAME}")

        # Check if secret has versions
        result = run_gcloud(
            [
                "secrets",
                "versions",
                "list",
                SECRET_NAME,
                f"--project={project}",
                "--format=value(name)",
                "--limit=1",
            ],
            check=False,
        )
        if result.returncode == 0 and result.stdout.strip():
            check_pass("Secret has at least one version")
        else:
            check_warn("Secret has NO versions (API key not set)")
            echo_info(
                f"  Add your API key: echo -n 'sk-ant-...' | gcloud secrets versions add {SECRET_NAME} --data-file=-"
            )
    else:
        check_fail(f"Secret NOT found: {SECRET_NAME}")
        echo_info("  Run 'arvo-gcp setup' to create it")

    typer.echo()

    # Check 7: Config file
    typer.echo("Checking local configuration...")
    config = load_config()
    if config:
        check_pass("Local config file exists")
        if verbose:
            typer.echo(f"  Project: {config.get('project_id', 'N/A')}")
            typer.echo(f"  Region: {config.get('region', 'N/A')}")
            typer.echo(f"  Created: {config.get('created_at', 'N/A')}")
    else:
        check_warn("Local config file not found")
        echo_info("  Run 'arvo-gcp setup' to create it")

    # Summary
    typer.echo()
    typer.echo("=" * 50)
    typer.echo("Summary")
    typer.echo("=" * 50)
    typer.echo(f"  Passed:   {passed}")
    typer.echo(f"  Failed:   {failed}")
    typer.echo(f"  Warnings: {warnings}")
    typer.echo()

    if failed == 0 and warnings == 0:
        echo_success("All checks passed! Ready to run benchmarks.")
    elif failed == 0:
        echo_warning("All required checks passed, but there are warnings.")
    else:
        echo_error(f"{failed} check(s) failed. Run 'arvo-gcp setup' to fix.")
        raise typer.Exit(1)


# =============================================================================
# Teardown Command
# =============================================================================


@app.command()
def teardown(
    project: Annotated[Optional[str], typer.Option(help="GCP project ID")] = None,
    dry_run: Annotated[
        bool, typer.Option("--dry-run", help="Show what would be done")
    ] = False,
    force: Annotated[
        bool, typer.Option("--force", "-f", help="Skip confirmation")
    ] = False,
) -> None:
    """Tear down GCP infrastructure."""
    config = load_config()
    project = project or config.get("project_id")

    if not project:
        echo_error("No project specified")
        raise typer.Exit(1)

    bucket_name = config.get("bucket_name", f"{project}-{get_bucket_suffix()}")
    service_account_email = config.get(
        "service_account_email",
        f"{get_service_account_name()}@{project}.iam.gserviceaccount.com",
    )

    typer.echo("=" * 50)
    echo_warning("ARVO Benchmark GCP Teardown")
    typer.echo("=" * 50)
    typer.echo()
    typer.echo("This will delete:")
    typer.echo(f"  - Bucket: gs://{bucket_name} (ALL CONTENTS)")
    typer.echo(f"  - Service Account: {service_account_email}")
    typer.echo(f"  - Secret: {SECRET_NAME}")
    typer.echo()

    if not force and not dry_run:
        confirm = typer.confirm("Are you sure you want to continue?")
        if not confirm:
            typer.echo("Aborted.")
            raise typer.Exit(0)

    if dry_run:
        echo_warning("DRY RUN MODE")
        return

    # Delete bucket
    echo_info(f"Deleting bucket gs://{bucket_name}")
    run_gsutil(["-m", "rm", "-r", f"gs://{bucket_name}/**"], check=False)
    run_gsutil(["rb", f"gs://{bucket_name}"], check=False)

    # Delete secret
    echo_info(f"Deleting secret {SECRET_NAME}")
    run_gcloud(
        ["secrets", "delete", SECRET_NAME, f"--project={project}", "--quiet"],
        check=False,
    )

    # Delete service account
    echo_info(f"Deleting service account {service_account_email}")
    run_gcloud(
        [
            "iam",
            "service-accounts",
            "delete",
            service_account_email,
            f"--project={project}",
            "--quiet",
        ],
        check=False,
    )

    # Remove config file
    config_path = get_config_path()
    if config_path.exists():
        config_path.unlink()

    echo_success("Teardown complete!")


# =============================================================================
# Submit Command
# =============================================================================


@app.command()
def submit(
    cases: Annotated[
        Optional[str],
        typer.Option(help="Case IDs: 'all', '42,43,44', or '@path/to/cases.json'"),
    ] = None,
    agents: Annotated[
        Optional[str],
        typer.Option(
            help="Agents to run: model names and/or 'gt' (e.g., 'claude-sonnet-4-20250514,gt')"
        ),
    ] = None,
    fuzzing_duration: Annotated[
        Optional[int], typer.Option(help="Fuzzing duration in seconds")
    ] = None,
    build_only: Annotated[
        bool, typer.Option("--build-only", help="Only run build jobs (skip agents)")
    ] = False,
    run_id: Annotated[Optional[str], typer.Option(help="Custom run ID")] = None,
    max_concurrent_vms: Annotated[
        Optional[int],
        typer.Option(help="Max concurrent VMs for all job types (default: 50)"),
    ] = None,
    build_max_concurrent_vms: Annotated[
        Optional[int], typer.Option(help="Max concurrent VMs for build jobs")
    ] = None,
    eval_max_concurrent_vms: Annotated[
        Optional[int], typer.Option(help="Max concurrent VMs for eval jobs")
    ] = None,
    gt_max_concurrent_vms: Annotated[
        Optional[int], typer.Option(help="Max concurrent VMs for GT jobs")
    ] = None,
    config_file: Annotated[
        Optional[Path], typer.Option("--config", "-c", help="Run config file (JSON)")
    ] = None,
    force_repatch: Annotated[
        bool,
        typer.Option(
            "--force-repatch", help="Ignore cached patches, re-run LLM patching"
        ),
    ] = False,
    fuzz_only: Annotated[
        bool,
        typer.Option("--fuzz-only", help="Require cached patches (fail if not found)"),
    ] = False,
    force_rebuild: Annotated[
        bool,
        typer.Option(
            "--force-rebuild", help="Rebuild containers even if versioned image exists"
        ),
    ] = False,
    skip_deps_check: Annotated[
        bool,
        typer.Option("--skip-deps-check", help="Skip automatic deps rebuild check"),
    ] = False,
    force_deps_rebuild: Annotated[
        bool,
        typer.Option("--force-deps-rebuild", help="Force rebuild of CASR and DD deps"),
    ] = False,
    dry_run: Annotated[
        bool, typer.Option("--dry-run", help="Show what would be done")
    ] = False,
) -> None:
    """Submit benchmark jobs to Cloud Batch.

    Configuration can be provided via CLI flags or a config file (--config).
    CLI flags override config file values.

    Agents can include LLM model names (e.g., 'claude-sonnet-4-20250514') and/or
    'gt' for ground truth fuzzing. Multiple agents run as separate jobs.

    Example config file (JSON):

        {
          "cases": "@datasets/autopatch/autopatch_bench.json",
          "agents": ["claude-sonnet-4-20250514", "gt"],
          "fuzzing_duration": 300,
          "max_concurrent_vms": 50
        }
    """
    gcp_config = load_config()
    if not gcp_config:
        echo_error("GCP not configured. Run 'setup' first.")
        raise typer.Exit(1)

    # Load config file if provided
    file_config = {}
    if config_file:
        try:
            file_config = load_run_config(config_file)
            echo_info(f"Loaded config from {config_file}")
        except (FileNotFoundError, ImportError, ValueError) as e:
            echo_error(str(e))
            raise typer.Exit(1)

    # Build CLI overrides dict (only include explicitly set values)
    cli_overrides = {}
    if cases is not None:
        cli_overrides["cases"] = parse_cases(cases)
    if agents is not None:
        cli_overrides["agents"] = parse_agents(agents)
    if fuzzing_duration is not None:
        cli_overrides["fuzzing_duration"] = fuzzing_duration
    if run_id is not None:
        cli_overrides["run_id"] = run_id
    if max_concurrent_vms is not None:
        cli_overrides["max_concurrent_vms"] = max_concurrent_vms
    if build_max_concurrent_vms is not None:
        cli_overrides["build_max_concurrent_vms"] = build_max_concurrent_vms
    if eval_max_concurrent_vms is not None:
        cli_overrides["eval_max_concurrent_vms"] = eval_max_concurrent_vms
    if gt_max_concurrent_vms is not None:
        cli_overrides["gt_max_concurrent_vms"] = gt_max_concurrent_vms
    if build_only:
        cli_overrides["build_only"] = build_only
    if force_repatch:
        cli_overrides["force_repatch"] = force_repatch
    if fuzz_only:
        cli_overrides["fuzz_only"] = fuzz_only
    if force_rebuild:
        cli_overrides["force_rebuild"] = force_rebuild

    # Merge configs
    run_config = merge_run_config(file_config, cli_overrides)

    # Validate: cases are required
    if not run_config.cases:
        echo_error("No cases specified. Use --cases or provide in config file.")
        raise typer.Exit(1)

    case_str = ",".join(str(c) for c in run_config.cases)
    task_count = len(run_config.cases)

    # Generate run ID if not provided
    if not run_config.run_id:
        run_config.run_id = datetime.now().strftime("%Y%m%d-%H%M%S")

    # Validate: agents are required (unless build_only)
    if not run_config.build_only and not run_config.agents:
        echo_error("No agents specified. Use --agents or provide in config file.")
        raise typer.Exit(1)

    # Validate: force_repatch and fuzz_only are mutually exclusive
    if run_config.force_repatch and run_config.fuzz_only:
        echo_error("Cannot use both --force-repatch and --fuzz-only")
        raise typer.Exit(1)

    llm_agents = run_config.get_llm_agents()
    has_gt = run_config.has_gt()

    typer.echo("=" * 50)
    typer.echo("ARVO Benchmark Job Submission")
    typer.echo("=" * 50)
    typer.echo()
    typer.echo(f"Run ID:           {run_config.run_id}")
    typer.echo(f"Project:          {gcp_config['project_id']}")
    typer.echo(f"Region:           {gcp_config['region']}")
    typer.echo(f"Cases:            {task_count} cases")
    typer.echo(f"Agents:           {', '.join(run_config.agents)}")
    typer.echo(f"Fuzzing Duration: {run_config.fuzzing_duration}s")
    typer.echo(
        f"Max VMs:          build={run_config.get_max_concurrent_vms('build')}, "
        f"eval={run_config.get_max_concurrent_vms('eval')}, "
        f"gt={run_config.get_max_concurrent_vms('gt')}"
    )
    if run_config.force_repatch:
        typer.echo("Force Repatch:    Yes (ignoring cached patches)")
    if run_config.fuzz_only:
        typer.echo("Fuzz Only:        Yes (using cached patches only)")
    if run_config.force_rebuild:
        typer.echo("Force Rebuild:    Yes (rebuilding containers)")
    typer.echo()

    bucket = gcp_config["bucket_name"]

    if dry_run:
        echo_warning("DRY RUN MODE")
        typer.echo()
        # In dry run, just get the version without uploading
        build_version = get_build_version_from_gcs(bucket) or "latest"
        typer.echo(f"Build Version:    {build_version}")
        typer.echo()
    else:
        # Auto-upload runtime (always, since agent code changes frequently)
        typer.echo()
        echo_info("Uploading agent runtime...")
        if not _upload_runtime_impl(bucket, quiet=True):
            echo_warning(
                "Runtime upload failed - continuing anyway (may already exist)"
            )

        # Auto-upload build assets (only if changed)
        typer.echo()
        success, build_version = _upload_build_assets_impl(bucket, quiet=False)
        if not success:
            echo_warning("Build assets upload failed")
            build_version = get_build_version_from_gcs(bucket) or "latest"

        typer.echo(f"Build Version:    {build_version}")
        typer.echo()

    # Auto-detect custom VM image (for faster job startup)
    vm_image = gcp_config.get("vm_image")
    if not vm_image:
        # Check if image exists in GCP even if not in config
        vm_image = get_vm_image_if_exists(gcp_config["project_id"])
        if vm_image and not dry_run:
            # Save to config for future use
            gcp_config["vm_image"] = vm_image
            save_config(gcp_config)

    if vm_image:
        typer.echo(
            f"VM Image:         {vm_image.split('/')[-1]} (Docker pre-installed)"
        )
    else:
        typer.echo("VM Image:         default (Docker will be installed at runtime)")
    typer.echo()

    # ==========================================================================
    # Check and handle deps (CASR + DD)
    # ==========================================================================
    deps_job_name = None

    if not skip_deps_check:
        typer.echo()
        echo_info("Checking dependencies (CASR + DD)...")
        needs_rebuild, reason = check_deps_need_rebuild(bucket, AUTOPATCH_BUILD_DIR)

        if force_deps_rebuild:
            needs_rebuild = True
            reason = "forced rebuild requested"

        if needs_rebuild:
            echo_warning(f"Deps need rebuild: {reason}")

            if dry_run:
                typer.echo("Would submit deps build job")
            else:
                # Upload deps sources
                echo_info("Uploading deps sources...")
                if _upload_deps_sources_impl(bucket, AUTOPATCH_BUILD_DIR, quiet=True):
                    # Submit deps job
                    deps_job_name = _submit_deps_job_impl(
                        gcp_config,
                        username=get_gcp_username(),
                        run_id=run_config.run_id,
                        force_rebuild=force_deps_rebuild,
                        quiet=False,
                    )
                    if deps_job_name:
                        typer.echo()
                        echo_warning(
                            "Deps job submitted - build jobs may fail if deps aren't ready"
                        )
                        echo_info("Monitor deps progress: python -m cli monitor")
                        echo_info(
                            "Re-run submit after deps complete, or wait ~2-4 hours"
                        )
                    else:
                        echo_warning("Failed to submit deps job - continuing anyway")
                else:
                    echo_warning("Failed to upload deps sources - continuing anyway")
        else:
            echo_success("Dependencies up to date")
    else:
        echo_info("Skipping deps check (--skip-deps-check)")

    # Upload task scripts
    typer.echo()
    echo_info("Uploading task scripts to GCS...")
    script_dir = get_script_dir() / "scripts"

    if not dry_run:
        for script in ["build_task.sh", "eval_task.sh", "gt_task.sh"]:
            script_path = script_dir / script
            if script_path.exists():
                run_gsutil(["cp", str(script_path), f"gs://{bucket}/scripts/"])

    # Submit jobs
    jobs_dir = get_script_dir() / "jobs"

    def submit_job(
        job_type: str, template_file: str, agent: Optional[str] = None
    ) -> None:
        """Submit a job to Cloud Batch.

        Args:
            job_type: "build", "eval", or "gt"
            template_file: Job spec template filename
            agent: Agent name (for eval jobs, this is the model name)
        """
        # Build job name with username prefix for identification
        username = get_gcp_username()
        if agent and job_type == "eval":
            # Sanitize agent name for job name
            agent_suffix = agent.replace(".", "-").replace("_", "-").lower()[:20]
            job_name = f"{username}-{job_type}-{agent_suffix}-{run_config.run_id}"
        else:
            job_name = f"{username}-{job_type}-{run_config.run_id}"

        job_parallelism = run_config.get_max_concurrent_vms(job_type)
        typer.echo()
        if agent:
            echo_info(
                f"Submitting {job_type} job for {agent}: {job_name} (parallelism={job_parallelism})"
            )
        else:
            echo_info(
                f"Submitting {job_type} job: {job_name} (parallelism={job_parallelism})"
            )

        template_path = jobs_dir / template_file
        if not template_path.exists():
            echo_error(f"Template not found: {template_path}")
            return

        # Read and substitute template
        with open(template_path) as f:
            spec = f.read()

        # Agent/model label (sanitize for GCP labels)
        agent_label = (agent or "none").replace(".", "_").replace("-", "_").lower()[:63]

        spec = spec.replace("${BUCKET_NAME}", bucket)
        spec = spec.replace(
            "${SERVICE_ACCOUNT_EMAIL}", gcp_config["service_account_email"]
        )
        spec = spec.replace("${ARTIFACT_REGISTRY}", gcp_config["artifact_registry"])
        spec = spec.replace("${PROJECT_NUMBER}", gcp_config.get("project_number", ""))
        spec = spec.replace("${TASK_COUNT}", str(task_count))
        spec = spec.replace("${ARVO_CASES}", case_str)
        spec = spec.replace("${MODEL}", agent or "")
        spec = spec.replace("${MODEL_LABEL}", agent_label)
        spec = spec.replace("${SECRET_NAME}", gcp_config["secret_name"])
        spec = spec.replace("${FUZZING_DURATION}", str(run_config.fuzzing_duration))
        spec = spec.replace("${RUN_ID}", run_config.run_id)
        spec = spec.replace("${USERNAME}", username)
        spec = spec.replace(
            "${FORCE_REPATCH}", "true" if run_config.force_repatch else "false"
        )
        spec = spec.replace("${FUZZ_ONLY}", "true" if run_config.fuzz_only else "false")
        spec = spec.replace("${BUILD_VERSION}", build_version)
        spec = spec.replace(
            "${FORCE_REBUILD}", "true" if run_config.force_rebuild else "false"
        )

        # Parse spec to modify parallelism and VM image
        spec_json = json.loads(spec)

        # Set parallelism for this job type
        if spec_json.get("taskGroups"):
            spec_json["taskGroups"][0]["parallelism"] = job_parallelism

        # If custom VM image exists, use it for faster startup
        if gcp_config.get("vm_image"):
            instances = spec_json.get("allocationPolicy", {}).get("instances", [])
            if instances:
                boot_disk = instances[0].get("policy", {}).get("bootDisk", {})
                boot_disk["image"] = gcp_config["vm_image"]
                instances[0]["policy"]["bootDisk"] = boot_disk

        spec = json.dumps(spec_json, indent=2)

        # Write temp spec file
        temp_spec = jobs_dir / f"{job_name}.json"
        with open(temp_spec, "w") as f:
            f.write(spec)

        if dry_run:
            typer.echo(f"Would submit: {job_name}")
            temp_spec.unlink()
            return

        # Submit job
        result = run_gcloud(
            [
                "batch",
                "jobs",
                "submit",
                job_name,
                f"--project={gcp_config['project_id']}",
                f"--location={gcp_config['region']}",
                f"--config={temp_spec}",
            ],
            check=False,
        )
        if result.returncode == 0:
            echo_success(f"Job submitted: {job_name}")
            temp_spec.unlink()
        else:
            echo_error(f"Failed to submit job: {job_name}")
            if result.stderr:
                typer.echo(result.stderr)
            if result.stdout:
                typer.echo(result.stdout)
            typer.echo(f"Job spec saved at: {temp_spec}")
            typer.echo("You can inspect and retry manually with:")
            typer.echo(
                f"  gcloud batch jobs submit {job_name} --project={gcp_config['project_id']} --location={gcp_config['region']} --config={temp_spec}"
            )

    # Always submit build job first
    submit_job("build", "build-job.json")

    # Submit agent jobs (skip if build_only)
    if not run_config.build_only:
        # Submit eval jobs for each LLM agent
        for agent in llm_agents:
            submit_job("eval", "eval-job.json", agent=agent)

        # Submit GT job if gt agent is specified
        if has_gt:
            submit_job("gt", "gt-job.json")

    typer.echo()
    typer.echo("=" * 50)
    typer.echo(f"Run ID: {run_config.run_id}")
    typer.echo()
    typer.echo("Monitor jobs:")
    typer.echo("  python -m cli monitor")
    typer.echo()
    typer.echo("Results will be saved to:")
    typer.echo(f"  gs://{bucket}/results/")


# =============================================================================
# Monitor Command
# =============================================================================


@app.command()
def monitor(
    job: Annotated[
        Optional[str], typer.Option(help="Specific job name to monitor")
    ] = None,
    watch: Annotated[
        bool, typer.Option("--watch", "-w", help="Continuous monitoring")
    ] = False,
    logs: Annotated[bool, typer.Option("--logs", help="Show job logs")] = False,
) -> None:
    """Monitor Cloud Batch jobs."""
    config = load_config()
    if not config:
        echo_error("GCP not configured. Run 'setup' first.")
        raise typer.Exit(1)

    project = config["project_id"]
    region = config["region"]

    def show_status() -> None:
        if not watch:
            typer.clear()

        typer.echo("=" * 50)
        typer.echo("ARVO Benchmark Job Monitor")
        typer.echo("=" * 50)
        typer.echo(f"Project: {project}")
        typer.echo(f"Region:  {region}")
        typer.echo(f"Time:    {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        typer.echo()

        if logs and job:
            typer.echo(f"=== Logs for {job} ===")
            result = run_gcloud(
                [
                    "logging",
                    "read",
                    f'resource.type="cloud_batch_job"',
                    f"--project={project}",
                    "--limit=50",
                    "--format=table(timestamp,textPayload)",
                ],
                check=False,
            )
            typer.echo(result.stdout)
            return

        if job:
            # Show specific job
            typer.echo(f"=== Job: {job} ===")
            result = run_gcloud(
                [
                    "batch",
                    "jobs",
                    "describe",
                    job,
                    f"--project={project}",
                    f"--location={region}",
                    "--format=yaml(name,status,createTime,updateTime)",
                ],
                check=False,
            )
            typer.echo(result.stdout)
        else:
            # List all jobs
            typer.echo("=== Recent Jobs ===")
            result = run_gcloud(
                [
                    "batch",
                    "jobs",
                    "list",
                    f"--project={project}",
                    f"--location={region}",
                    "--limit=15",
                    "--format=table(name.basename(),status.state,createTime.date())",
                ],
                check=False,
            )
            typer.echo(result.stdout)

        typer.echo()

    if watch:
        try:
            while True:
                show_status()
                typer.echo("Refreshing in 10 seconds... (Ctrl+C to stop)")
                time.sleep(10)
                typer.clear()
        except KeyboardInterrupt:
            typer.echo("\nStopped.")
    else:
        show_status()


# =============================================================================
# Collect Command
# =============================================================================


@app.command()
def collect(
    output: Annotated[Path, typer.Option(help="Output directory")] = Path("./results"),
    cases: Annotated[
        Optional[str], typer.Option(help="Specific case IDs to collect")
    ] = None,
) -> None:
    """Collect results from GCS."""
    config = load_config()
    if not config:
        echo_error("GCP not configured. Run 'setup' first.")
        raise typer.Exit(1)

    bucket = config["bucket_name"]
    output.mkdir(parents=True, exist_ok=True)

    typer.echo(f"Collecting results from gs://{bucket}/results/")
    typer.echo(f"Output directory: {output}")
    typer.echo()

    if cases:
        # Collect specific cases
        case_list = [c.strip() for c in cases.split(",")]
        for case_id in case_list:
            echo_info(f"Downloading case_{case_id}...")
            run_gsutil(
                [
                    "-m",
                    "cp",
                    "-r",
                    f"gs://{bucket}/results/case_{case_id}/",
                    str(output),
                ],
                check=False,
            )
    else:
        # Collect all
        echo_info("Downloading all results...")
        run_gsutil(
            [
                "-m",
                "cp",
                "-r",
                f"gs://{bucket}/results/",
                str(output),
            ],
            check=False,
        )

    echo_success(f"Results saved to {output}")


# =============================================================================
# Upload Runtime Command
# =============================================================================


def _upload_runtime_impl(bucket: str, quiet: bool = False) -> bool:
    """Upload portable runtime to GCS.

    Args:
        bucket: GCS bucket name
        quiet: If True, reduce output verbosity

    Returns:
        True if upload succeeded, False otherwise
    """
    runtime_tar = (
        get_script_dir() / "portable-runtime" / "output" / "agent-runtime.tar.gz"
    )
    if not runtime_tar.exists():
        if not quiet:
            echo_error(f"Runtime tarball not found: {runtime_tar}")
            echo_info("Build it first: cd portable-runtime && ./build.sh")
        return False

    if not quiet:
        echo_info(f"Uploading {runtime_tar.name} to gs://{bucket}/agent-runtime/")

    result = run_gsutil(
        ["cp", str(runtime_tar), f"gs://{bucket}/agent-runtime/"], check=False
    )
    if result.returncode != 0:
        if not quiet:
            echo_error("Failed to upload runtime")
        return False

    if not quiet:
        echo_success("Runtime uploaded!")
    return True


@app.command(name="upload-runtime")
def upload_runtime() -> None:
    """Upload portable runtime to GCS."""
    config = load_config()
    if not config:
        echo_error("GCP not configured. Run 'setup' first.")
        raise typer.Exit(1)

    runtime_tar = (
        get_script_dir() / "portable-runtime" / "output" / "agent-runtime.tar.gz"
    )
    if not runtime_tar.exists():
        echo_error(f"Runtime tarball not found: {runtime_tar}")
        echo_info("Build it first: cd portable-runtime && ./build.sh")
        raise typer.Exit(1)

    bucket = config["bucket_name"]
    echo_info(f"Uploading {runtime_tar.name} to gs://{bucket}/agent-runtime/")

    run_gsutil(["cp", str(runtime_tar), f"gs://{bucket}/agent-runtime/"])

    echo_success("Runtime uploaded!")


# =============================================================================
# Upload Build Assets Command
# =============================================================================


# Path to autopatch build directory (relative to benchmark/gcp/)
AUTOPATCH_BUILD_DIR = Path(__file__).parent.parent.parent / "autopatch" / "build"


# =============================================================================
# Dependencies (CASR + DD) Helper Functions
# =============================================================================


def compute_deps_source_hash(build_dir: Path) -> tuple[str, str]:
    """Compute hashes of deps source files.

    Returns:
        Tuple of (casr_hash, dd_hash)
    """
    casr_hash = ""
    dd_hash = ""

    # Hash CASR source (Cargo.toml and .rs files)
    casr_dir = build_dir / "casr"
    if casr_dir.exists():
        sha256 = hashlib.sha256()
        for filepath in sorted(casr_dir.rglob("*.rs")):
            sha256.update(str(filepath.relative_to(casr_dir)).encode())
            sha256.update(compute_file_hash(filepath).encode())
        for filepath in sorted(casr_dir.rglob("Cargo.toml")):
            sha256.update(str(filepath.relative_to(casr_dir)).encode())
            sha256.update(compute_file_hash(filepath).encode())
        casr_hash = sha256.hexdigest()[:16]

    # Hash DD build script
    dd_script = build_dir / "build_deb_packages.sh"
    if dd_script.exists():
        dd_hash = compute_file_hash(dd_script)[:16]

    return casr_hash, dd_hash


def get_deps_manifest_from_gcs(bucket: str) -> dict:
    """Get deps manifest from GCS."""
    result = run_gsutil(
        ["cat", f"gs://{bucket}/build-assets/deps-manifest.json"],
        check=False,
    )
    if result.returncode == 0:
        try:
            return json.loads(result.stdout)
        except json.JSONDecodeError:
            pass
    return {}


def check_deps_artifacts_exist(bucket: str) -> bool:
    """Check if all deps artifacts exist in GCS."""
    artifacts = [
        "casr-binaries.tar.gz",
        "differential-debugging-deps-16.04.deb",
        "differential-debugging-deps-20.04.deb",
    ]
    for artifact in artifacts:
        result = run_gsutil(
            ["ls", f"gs://{bucket}/build-assets/{artifact}"],
            check=False,
        )
        if result.returncode != 0:
            return False
    return True


def check_deps_need_rebuild(bucket: str, build_dir: Path) -> tuple[bool, str]:
    """Check if deps need to be rebuilt.

    Returns:
        Tuple of (needs_rebuild, reason)
    """
    # Check if artifacts exist
    if not check_deps_artifacts_exist(bucket):
        return True, "deps artifacts missing in GCS"

    # Compare hashes
    local_casr_hash, local_dd_hash = compute_deps_source_hash(build_dir)
    manifest = get_deps_manifest_from_gcs(bucket)

    gcs_casr_hash = manifest.get("casr_hash", "")[:16]
    gcs_dd_hash = manifest.get("dd_hash", "")[:16]

    if local_casr_hash != gcs_casr_hash:
        return (
            True,
            f"CASR source changed ({gcs_casr_hash[:8]}... -> {local_casr_hash[:8]}...)",
        )
    if local_dd_hash != gcs_dd_hash:
        return (
            True,
            f"DD script changed ({gcs_dd_hash[:8]}... -> {local_dd_hash[:8]}...)",
        )

    return False, "deps up to date"


def _upload_deps_sources_impl(
    bucket: str, build_dir: Path, quiet: bool = False
) -> bool:
    """Upload deps sources to GCS.

    Returns:
        True if upload succeeded
    """
    # Upload CASR submodule
    casr_dir = build_dir / "casr"
    if not casr_dir.exists():
        if not quiet:
            echo_error(f"CASR submodule not found at {casr_dir}")
        return False

    if not quiet:
        echo_info("Uploading CASR source...")
    result = subprocess.run(
        [
            "gsutil",
            "-m",
            "rsync",
            "-r",
            "-x",
            r"\.git|target|\.build-cache",
            str(casr_dir),
            f"gs://{bucket}/deps-sources/casr/",
        ],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        if not quiet:
            echo_error("Failed to upload CASR source")
        return False

    # Upload build_deb_packages.sh
    build_script = build_dir / "build_deb_packages.sh"
    if build_script.exists():
        run_gsutil(
            ["cp", str(build_script), f"gs://{bucket}/deps-sources/"], check=False
        )

    # Upload Dockerfile.casr-builder
    dockerfile = build_dir / "Dockerfile.casr-builder"
    if dockerfile.exists():
        run_gsutil(["cp", str(dockerfile), f"gs://{bucket}/deps-sources/"], check=False)

    # Upload test script
    test_script = build_dir / "test_deb_install.sh"
    if test_script.exists():
        run_gsutil(
            ["cp", str(test_script), f"gs://{bucket}/deps-sources/"], check=False
        )

    if not quiet:
        echo_success("Deps sources uploaded")
    return True


def _submit_deps_job_impl(
    config: dict,
    username: str,
    run_id: str,
    force_rebuild: bool = False,
    quiet: bool = False,
) -> Optional[str]:
    """Submit deps build job.

    Returns:
        Job name if submitted, None if failed
    """
    project = config["project_id"]
    region = config["region"]
    bucket = config["bucket_name"]

    # Upload deps_task.sh script
    script_path = get_script_dir() / "scripts" / "deps_task.sh"
    if script_path.exists():
        run_gsutil(["cp", str(script_path), f"gs://{bucket}/scripts/"], check=False)

    # Generate job name
    job_name = f"{username}-deps-{run_id}"

    # Load job template
    jobs_dir = get_script_dir() / "jobs"
    template_path = jobs_dir / "deps-job.json"

    if not template_path.exists():
        if not quiet:
            echo_error(f"Job template not found: {template_path}")
        return None

    with open(template_path) as f:
        spec = f.read()

    # Substitute variables
    spec = spec.replace("${BUCKET_NAME}", bucket)
    spec = spec.replace("${SERVICE_ACCOUNT_EMAIL}", config["service_account_email"])
    spec = spec.replace("${USERNAME}", username)
    spec = spec.replace("${FORCE_REBUILD}", "true" if force_rebuild else "false")

    # Parse and optionally add VM image
    spec_json = json.loads(spec)
    if config.get("vm_image"):
        instances = spec_json.get("allocationPolicy", {}).get("instances", [])
        if instances:
            boot_disk = instances[0].get("policy", {}).get("bootDisk", {})
            boot_disk["image"] = config["vm_image"]
            instances[0]["policy"]["bootDisk"] = boot_disk

    spec = json.dumps(spec_json, indent=2)

    # Write temp spec file
    temp_spec = jobs_dir / f"{job_name}.json"
    with open(temp_spec, "w") as f:
        f.write(spec)

    # Submit job
    if not quiet:
        echo_info(f"Submitting deps job: {job_name}")

    result = run_gcloud(
        [
            "batch",
            "jobs",
            "submit",
            job_name,
            f"--project={project}",
            f"--location={region}",
            f"--config={temp_spec}",
        ],
        check=False,
    )

    temp_spec.unlink(missing_ok=True)

    if result.returncode == 0:
        if not quiet:
            echo_success(f"Deps job submitted: {job_name}")
        return job_name
    else:
        if not quiet:
            echo_error("Failed to submit deps job")
            if result.stderr:
                typer.echo(result.stderr)
        return None


def compute_file_hash(filepath: Path) -> str:
    """Compute SHA256 hash of a file."""
    sha256 = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha256.update(chunk)
    return sha256.hexdigest()


def compute_directory_hash(dirpath: Path) -> str:
    """Compute combined SHA256 hash of all files in a directory."""
    sha256 = hashlib.sha256()
    # Sort files for deterministic ordering
    for filepath in sorted(dirpath.rglob("*")):
        if filepath.is_file():
            # Include relative path in hash for structure-awareness
            rel_path = filepath.relative_to(dirpath)
            sha256.update(str(rel_path).encode())
            sha256.update(compute_file_hash(filepath).encode())
    return sha256.hexdigest()


def compute_build_version(build_dir: Path) -> tuple[str, dict]:
    """Compute build version hash from all build assets.

    Returns:
        Tuple of (version_hash, asset_hashes_dict)
        version_hash is first 8 chars of combined hash
    """
    asset_hashes = {}

    # Hash Dockerfile templates
    templates = [
        "dockerfile_vul_template",
        "dockerfile_fix_template",
        "dockerfile_fuzzing_template",
    ]
    for template_name in templates:
        template_file = build_dir / template_name
        if template_file.exists():
            asset_hashes[template_name] = compute_file_hash(template_file)

    # Hash libfuzzer-modern directory
    libfuzzer_dir = build_dir / "libfuzzer-modern"
    if libfuzzer_dir.exists():
        asset_hashes["libfuzzer-modern"] = compute_directory_hash(libfuzzer_dir)

    # Hash CASR binaries tarball
    casr_tarball = build_dir / "casr-binaries.tar.gz"
    if casr_tarball.exists():
        asset_hashes["casr-binaries.tar.gz"] = compute_file_hash(casr_tarball)

    # Hash glibc deb
    glibc_deb = build_dir / "libc6_2.35-0ubuntu3_amd64.deb"
    if glibc_deb.exists():
        asset_hashes["libc6_2.35-0ubuntu3_amd64.deb"] = compute_file_hash(glibc_deb)

    # Hash differential-debugging-deps debs
    for deb_file in sorted(build_dir.glob("differential-debugging-deps-*.deb")):
        asset_hashes[deb_file.name] = compute_file_hash(deb_file)

    # Hash casr_cluster.py
    casr_cluster_py = build_dir / "casr_cluster.py"
    if casr_cluster_py.exists():
        asset_hashes["casr_cluster.py"] = compute_file_hash(casr_cluster_py)

    # Compute combined hash from all asset hashes
    combined = hashlib.sha256()
    for key in sorted(asset_hashes.keys()):
        combined.update(key.encode())
        combined.update(asset_hashes[key].encode())

    # Use first 8 chars as version (like git short hash)
    version_hash = combined.hexdigest()[:8]

    return version_hash, asset_hashes


def get_build_version_from_gcs(bucket: str) -> Optional[str]:
    """Get current build version from GCS manifest."""
    result = run_gsutil(
        ["cat", f"gs://{bucket}/build-assets/manifest.json"],
        check=False,
    )
    if result.returncode == 0:
        try:
            manifest = json.loads(result.stdout)
            return manifest.get("version")
        except json.JSONDecodeError:
            pass
    return None


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


def _upload_build_assets_impl(bucket: str, quiet: bool = False) -> tuple[bool, str]:
    """Upload build assets to GCS if they have changed.

    Args:
        bucket: GCS bucket name
        quiet: If True, reduce output verbosity

    Returns:
        Tuple of (success, version_hash)
    """
    build_dir = AUTOPATCH_BUILD_DIR

    if not build_dir.exists():
        if not quiet:
            echo_error(f"Build directory not found: {build_dir}")
        return False, ""

    # Compute local build version
    version_hash, asset_hashes = compute_build_version(build_dir)

    # Check if GCS version matches
    gcs_version = get_build_version_from_gcs(bucket)
    if gcs_version == version_hash:
        if not quiet:
            echo_info(f"Build assets unchanged (version: {version_hash})")
        return True, version_hash

    if not quiet:
        echo_info(f"Build assets changed: {gcs_version or 'none'} -> {version_hash}")
        echo_info("Uploading build assets...")

    # Upload all assets (simplified - just the essential ones)
    templates = [
        "dockerfile_vul_template",
        "dockerfile_fix_template",
        "dockerfile_fuzzing_template",
    ]
    for template_name in templates:
        template_file = build_dir / template_name
        if template_file.exists():
            run_gsutil(
                ["cp", str(template_file), f"gs://{bucket}/build-assets/"], check=False
            )

    # Upload libfuzzer-modern directory
    libfuzzer_dir = build_dir / "libfuzzer-modern"
    if libfuzzer_dir.exists():
        run_gsutil(
            ["-m", "cp", "-r", str(libfuzzer_dir), f"gs://{bucket}/build-assets/"],
            check=False,
        )

    # Upload casr-binaries.tar.gz
    casr_tarball = build_dir / "casr-binaries.tar.gz"
    if casr_tarball.exists():
        run_gsutil(
            ["cp", str(casr_tarball), f"gs://{bucket}/build-assets/"], check=False
        )

    # Upload glibc 2.35
    glibc_deb = build_dir / "libc6_2.35-0ubuntu3_amd64.deb"
    if glibc_deb.exists():
        run_gsutil(["cp", str(glibc_deb), f"gs://{bucket}/build-assets/"], check=False)

    # Upload differential-debugging-deps debs
    for deb_file in build_dir.glob("differential-debugging-deps-*.deb"):
        run_gsutil(["cp", str(deb_file), f"gs://{bucket}/build-assets/"], check=False)

    # Upload microsnapshots directory
    microsnapshots_dir = build_dir / "microsnapshots"
    if microsnapshots_dir.exists():
        run_gsutil(
            ["-m", "cp", "-r", str(microsnapshots_dir), f"gs://{bucket}/build-assets/"],
            check=False,
        )

    # Upload casr_cluster.py
    casr_cluster_py = build_dir / "casr_cluster.py"
    if casr_cluster_py.exists():
        run_gsutil(
            ["cp", str(casr_cluster_py), f"gs://{bucket}/build-assets/"], check=False
        )

    # Generate and upload manifest
    manifest = {
        "version": version_hash,
        "assets": asset_hashes,
        "updated_at": datetime.utcnow().isoformat() + "Z",
    }
    manifest_path = build_dir / "manifest.json"
    with open(manifest_path, "w") as f:
        json.dump(manifest, f, indent=2)

    run_gsutil(["cp", str(manifest_path), f"gs://{bucket}/build-assets/"], check=False)
    manifest_path.unlink()  # Clean up local file

    if not quiet:
        echo_success(f"Build assets uploaded (version: {version_hash})")

    return True, version_hash


@app.command(name="upload-build-assets")
def upload_build_assets(
    skip_if_unchanged: Annotated[
        bool, typer.Option("--skip-if-unchanged", help="Skip upload if hashes match")
    ] = False,
) -> None:
    """Upload build assets (Dockerfile template, libfuzzer, CASR) to GCS.

    These assets are required by the build job to create ARVO container images.
    Source: benchmark/autopatch/build/

    Computes SHA256 hashes of all assets and generates a manifest.json with a
    version hash. The version hash changes when any build asset changes, which
    triggers container rebuilds.
    """
    config = load_config()
    if not config:
        echo_error("GCP not configured. Run 'setup' first.")
        raise typer.Exit(1)

    bucket = config["bucket_name"]
    build_dir = AUTOPATCH_BUILD_DIR

    if not build_dir.exists():
        echo_error(f"Build directory not found: {build_dir}")
        raise typer.Exit(1)

    typer.echo("=" * 50)
    typer.echo("Upload Build Assets")
    typer.echo("=" * 50)
    typer.echo(f"Source:      {build_dir}")
    typer.echo(f"Destination: gs://{bucket}/build-assets/")
    typer.echo()

    # Compute build version hash
    echo_info("Computing build version hash...")
    version_hash, asset_hashes = compute_build_version(build_dir)
    typer.echo(f"Build version: {version_hash}")
    typer.echo()

    # Check if we should skip upload
    if skip_if_unchanged:
        current_version = get_build_version_from_gcs(bucket)
        if current_version == version_hash:
            echo_success(f"Build assets unchanged (version: {version_hash})")
            typer.echo("Skipping upload.")
            return

    # Upload all Dockerfile templates
    templates = [
        "dockerfile_vul_template",  # For -vul images (minimal, just libfuzzer)
        "dockerfile_fix_template",  # For GT -fix images (with 10-min QA fuzzing)
        "dockerfile_fuzzing_template",  # For eval -fix images (no 10-min QA)
    ]
    for template_name in templates:
        template_file = build_dir / template_name
        if template_file.exists():
            echo_info(f"Uploading {template_name}...")
            run_gsutil(["cp", str(template_file), f"gs://{bucket}/build-assets/"])
            echo_success(f"{template_name} uploaded")
        else:
            echo_warning(f"{template_name} not found at {template_file}")

    # Upload libfuzzer-modern directory
    libfuzzer_dir = build_dir / "libfuzzer-modern"
    if libfuzzer_dir.exists():
        echo_info("Uploading libfuzzer-modern/...")
        run_gsutil(
            ["-m", "cp", "-r", str(libfuzzer_dir), f"gs://{bucket}/build-assets/"]
        )
        echo_success("libfuzzer-modern uploaded")
    else:
        echo_warning(f"libfuzzer-modern not found at {libfuzzer_dir}")

    # Upload casr-binaries.tar.gz (required for CASR crash deduplication)
    casr_tarball = build_dir / "casr-binaries.tar.gz"
    if casr_tarball.exists():
        echo_info("Uploading casr-binaries.tar.gz...")
        run_gsutil(["cp", str(casr_tarball), f"gs://{bucket}/build-assets/"])
        echo_success("casr-binaries.tar.gz uploaded")
    else:
        casr_dir = build_dir / "casr"
        if casr_dir.exists():
            echo_warning("casr-binaries.tar.gz not found")
            echo_info("You may need to build CASR binaries first:")
            echo_info(f"  cd {casr_dir} && cargo build --release")
            echo_info("  Then create casr-binaries.tar.gz with the binaries")
        else:
            echo_warning("Neither casr-binaries.tar.gz nor casr/ source found")

    # Upload glibc 2.35 (required by CASR in containers with older glibc)
    glibc_deb = build_dir / "libc6_2.35-0ubuntu3_amd64.deb"
    if glibc_deb.exists():
        echo_info("Uploading libc6_2.35-0ubuntu3_amd64.deb...")
        run_gsutil(["cp", str(glibc_deb), f"gs://{bucket}/build-assets/"])
        echo_success("libc6_2.35-0ubuntu3_amd64.deb uploaded")
    else:
        echo_warning(f"libc6_2.35-0ubuntu3_amd64.deb not found at {glibc_deb}")

    # Upload differential-debugging-deps debs
    for deb_file in build_dir.glob("differential-debugging-deps-*.deb"):
        echo_info(f"Uploading {deb_file.name}...")
        run_gsutil(["cp", str(deb_file), f"gs://{bucket}/build-assets/"])
        echo_success(f"{deb_file.name} uploaded")

    # Upload microsnapshots directory (for differential debugging)
    microsnapshots_dir = build_dir / "microsnapshots"
    if microsnapshots_dir.exists():
        echo_info("Uploading microsnapshots/...")
        run_gsutil(
            ["-m", "cp", "-r", str(microsnapshots_dir), f"gs://{bucket}/build-assets/"]
        )
        echo_success("microsnapshots uploaded")
    else:
        echo_warning(f"microsnapshots not found at {microsnapshots_dir}")

    # Upload casr_cluster.py (custom CASR clustering script)
    casr_cluster_py = build_dir / "casr_cluster.py"
    if casr_cluster_py.exists():
        echo_info("Uploading casr_cluster.py...")
        run_gsutil(["cp", str(casr_cluster_py), f"gs://{bucket}/build-assets/"])
        echo_success("casr_cluster.py uploaded")
    else:
        echo_warning(f"casr_cluster.py not found at {casr_cluster_py}")

    # Generate and upload manifest
    typer.echo()
    echo_info("Generating manifest.json...")
    manifest = {
        "version": version_hash,
        "assets": asset_hashes,
        "updated_at": datetime.utcnow().isoformat() + "Z",
    }
    manifest_path = build_dir / "manifest.json"
    with open(manifest_path, "w") as f:
        json.dump(manifest, f, indent=2)

    run_gsutil(["cp", str(manifest_path), f"gs://{bucket}/build-assets/"])
    manifest_path.unlink()  # Clean up local file
    echo_success(f"manifest.json uploaded (version: {version_hash})")

    typer.echo()
    echo_success("Build assets uploaded!")
    typer.echo()
    typer.echo(f"Build version: {version_hash}")
    typer.echo()
    typer.echo("Verify with:")
    typer.echo(f"  gsutil ls gs://{bucket}/build-assets/")
    typer.echo(f"  gsutil cat gs://{bucket}/build-assets/manifest.json")


# =============================================================================
# Upload Deps Sources Command
# =============================================================================


@app.command(name="upload-deps-sources")
def upload_deps_sources() -> None:
    """Upload CASR source and DD build scripts to GCS for deps build.

    This uploads the source files needed by the deps build job:
    - benchmark/autopatch/build/casr/ (CASR submodule)
    - benchmark/autopatch/build/build_deb_packages.sh
    - benchmark/autopatch/build/Dockerfile.casr-builder

    Run this before submitting a deps build job.
    """
    config = load_config()
    if not config:
        echo_error("GCP not configured. Run 'setup' first.")
        raise typer.Exit(1)

    bucket = config["bucket_name"]
    build_dir = AUTOPATCH_BUILD_DIR

    typer.echo("=" * 50)
    typer.echo("Upload Dependencies Sources")
    typer.echo("=" * 50)
    typer.echo(f"Source:      {build_dir}")
    typer.echo(f"Destination: gs://{bucket}/deps-sources/")
    typer.echo()

    # Upload CASR submodule
    casr_dir = build_dir / "casr"
    if casr_dir.exists():
        echo_info("Uploading CASR source (this may take a moment)...")
        # Exclude .git and target directories to reduce size
        result = subprocess.run(
            [
                "gsutil",
                "-m",
                "rsync",
                "-r",
                "-x",
                r"\.git|target|\.build-cache",
                str(casr_dir),
                f"gs://{bucket}/deps-sources/casr/",
            ],
            capture_output=True,
            text=True,
        )
        if result.returncode == 0:
            echo_success("CASR source uploaded")
        else:
            echo_error("Failed to upload CASR source")
            typer.echo(result.stderr)
    else:
        echo_error(f"CASR submodule not found at {casr_dir}")
        echo_info("Initialize with: git submodule update --init")
        raise typer.Exit(1)

    # Upload build_deb_packages.sh
    build_script = build_dir / "build_deb_packages.sh"
    if build_script.exists():
        echo_info("Uploading build_deb_packages.sh...")
        run_gsutil(["cp", str(build_script), f"gs://{bucket}/deps-sources/"])
        echo_success("build_deb_packages.sh uploaded")
    else:
        echo_warning(f"build_deb_packages.sh not found at {build_script}")

    # Upload Dockerfile.casr-builder
    dockerfile = build_dir / "Dockerfile.casr-builder"
    if dockerfile.exists():
        echo_info("Uploading Dockerfile.casr-builder...")
        run_gsutil(["cp", str(dockerfile), f"gs://{bucket}/deps-sources/"])
        echo_success("Dockerfile.casr-builder uploaded")
    else:
        echo_warning(f"Dockerfile.casr-builder not found at {dockerfile}")

    # Upload test script
    test_script = build_dir / "test_deb_install.sh"
    if test_script.exists():
        echo_info("Uploading test_deb_install.sh...")
        run_gsutil(["cp", str(test_script), f"gs://{bucket}/deps-sources/"])
        echo_success("test_deb_install.sh uploaded")

    typer.echo()
    echo_success("Dependencies sources uploaded!")
    typer.echo()
    typer.echo("Verify with:")
    typer.echo(f"  gsutil ls gs://{bucket}/deps-sources/")


# =============================================================================
# Build Deps Command
# =============================================================================


@app.command(name="build-deps")
def build_deps(
    force_rebuild: Annotated[
        bool, typer.Option("--force", "-f", help="Force rebuild even if hashes match")
    ] = False,
    dry_run: Annotated[
        bool, typer.Option("--dry-run", help="Show what would be done")
    ] = False,
) -> None:
    """Submit a Cloud Batch job to build CASR and differential-debugging-deps.

    This builds the heavy dependencies on native x86_64 GCP VMs:
    - CASR (Crash Analysis and Severity Reporting) binaries
    - differential-debugging-deps .deb packages (Python 3.7 + LLDB 13)

    The job uses hash-based change detection - it only rebuilds if the
    source files have changed since the last build.

    This command automatically uploads deps sources before submitting the job.
    """
    config = load_config()
    if not config:
        echo_error("GCP not configured. Run 'setup' first.")
        raise typer.Exit(1)

    project = config["project_id"]
    region = config["region"]
    bucket = config["bucket_name"]
    username = get_gcp_username()

    typer.echo("=" * 50)
    typer.echo("Build Dependencies Job")
    typer.echo("=" * 50)
    typer.echo()
    typer.echo(f"Project:       {project}")
    typer.echo(f"Region:        {region}")
    typer.echo(f"Bucket:        gs://{bucket}")
    typer.echo(f"Force Rebuild: {force_rebuild}")
    typer.echo()

    # Check if CASR submodule exists locally
    casr_dir = AUTOPATCH_BUILD_DIR / "casr"
    if not casr_dir.exists():
        echo_error(f"CASR submodule not found at {casr_dir}")
        echo_info("Initialize with: git submodule update --init")
        raise typer.Exit(1)

    # Upload deps sources to GCS
    echo_info("Uploading deps sources to GCS...")
    if not dry_run:
        if not _upload_deps_sources_impl(bucket, AUTOPATCH_BUILD_DIR, quiet=False):
            echo_error("Failed to upload deps sources")
            raise typer.Exit(1)
    else:
        typer.echo("Would upload deps sources")

    # Upload deps_task.sh script
    echo_info("Uploading deps_task.sh to GCS...")
    script_path = get_script_dir() / "scripts" / "deps_task.sh"
    if not script_path.exists():
        echo_error(f"deps_task.sh not found at {script_path}")
        raise typer.Exit(1)

    if not dry_run:
        run_gsutil(["cp", str(script_path), f"gs://{bucket}/scripts/"])

    # Generate job name
    run_id = datetime.now().strftime("%Y%m%d-%H%M%S")
    job_name = f"{username}-deps-{run_id}"

    # Load job template
    jobs_dir = get_script_dir() / "jobs"
    template_path = jobs_dir / "deps-job.json"

    if not template_path.exists():
        echo_error(f"Job template not found: {template_path}")
        raise typer.Exit(1)

    with open(template_path) as f:
        spec = f.read()

    # Substitute variables
    spec = spec.replace("${BUCKET_NAME}", bucket)
    spec = spec.replace("${SERVICE_ACCOUNT_EMAIL}", config["service_account_email"])
    spec = spec.replace("${USERNAME}", username)
    spec = spec.replace("${FORCE_REBUILD}", "true" if force_rebuild else "false")

    # Parse and optionally add VM image
    spec_json = json.loads(spec)
    if config.get("vm_image"):
        instances = spec_json.get("allocationPolicy", {}).get("instances", [])
        if instances:
            boot_disk = instances[0].get("policy", {}).get("bootDisk", {})
            boot_disk["image"] = config["vm_image"]
            instances[0]["policy"]["bootDisk"] = boot_disk

    spec = json.dumps(spec_json, indent=2)

    # Write temp spec file
    temp_spec = jobs_dir / f"{job_name}.json"
    with open(temp_spec, "w") as f:
        f.write(spec)

    if dry_run:
        echo_warning("DRY RUN MODE")
        typer.echo(f"Would submit job: {job_name}")
        typer.echo()
        typer.echo("Job spec:")
        typer.echo(spec[:500] + "..." if len(spec) > 500 else spec)
        temp_spec.unlink()
        return

    # Submit job
    echo_info(f"Submitting job: {job_name}")

    result = run_gcloud(
        [
            "batch",
            "jobs",
            "submit",
            job_name,
            f"--project={project}",
            f"--location={region}",
            f"--config={temp_spec}",
        ],
        check=False,
    )

    if result.returncode == 0:
        echo_success(f"Job submitted: {job_name}")
        temp_spec.unlink()
    else:
        echo_error(f"Failed to submit job: {job_name}")
        if result.stderr:
            typer.echo(result.stderr)
        if result.stdout:
            typer.echo(result.stdout)
        typer.echo(f"Job spec saved at: {temp_spec}")
        raise typer.Exit(1)

    typer.echo()
    typer.echo("=" * 50)
    typer.echo(f"Job: {job_name}")
    typer.echo()
    typer.echo("This job builds CASR and DD deps (~2-4 hours)")
    typer.echo()
    typer.echo("Monitor with:")
    typer.echo(f"  python -m cli monitor --job {job_name}")
    typer.echo()
    typer.echo("View logs:")
    typer.echo(
        f"  gcloud logging read 'resource.labels.job_uid=\"{job_name}\"' --project={project} --limit=100"
    )


# =============================================================================
# Create VM Image Command
# =============================================================================

VM_IMAGE_NAME = "arvo-docker-vm"
TEMP_VM_NAME = "arvo-image-builder"


@app.command(name="create-vm-image")
def create_vm_image(
    force: Annotated[
        bool, typer.Option("--force", "-f", help="Recreate image if exists")
    ] = False,
) -> None:
    """Create a Docker-ready VM image for faster task startup."""
    config = load_config()
    if not config:
        echo_error("GCP not configured. Run 'setup' first.")
        raise typer.Exit(1)

    project = config["project_id"]
    region = config["region"]
    zone = f"{region}-a"
    username = get_gcp_username()
    image_name = f"{username}-{VM_IMAGE_NAME}"
    vm_name = f"{username}-{TEMP_VM_NAME}"

    typer.echo("=" * 50)
    typer.echo("Create Docker-Ready VM Image")
    typer.echo("=" * 50)
    typer.echo()
    typer.echo(f"Project:    {project}")
    typer.echo(f"Zone:       {zone}")
    typer.echo(f"Image name: {image_name}")
    typer.echo()

    # Check if image already exists
    result = run_gcloud(
        [
            "compute",
            "images",
            "describe",
            image_name,
            f"--project={project}",
        ],
        check=False,
    )
    if result.returncode == 0:
        if not force:
            echo_warning("Image already exists. Use --force to recreate.")
            typer.echo()
            typer.echo("To use this image, run:")
            typer.echo("  arvo-gcp use-vm-image")
            return
        else:
            echo_info("Deleting existing image...")
            run_gcloud(
                [
                    "compute",
                    "images",
                    "delete",
                    image_name,
                    f"--project={project}",
                    "--quiet",
                ],
                check=False,
            )

    # Step 1: Create temporary VM
    typer.echo("Step 1: Creating temporary VM...")

    # Delete existing VM if any
    run_gcloud(
        [
            "compute",
            "instances",
            "delete",
            vm_name,
            f"--project={project}",
            f"--zone={zone}",
            "--quiet",
        ],
        check=False,
    )

    run_gcloud(
        [
            "compute",
            "instances",
            "create",
            vm_name,
            f"--project={project}",
            f"--zone={zone}",
            "--machine-type=e2-medium",
            "--image-family=debian-11",
            "--image-project=debian-cloud",
            "--boot-disk-size=50GB",
            "--boot-disk-type=pd-balanced",
            f"--service-account={config['service_account_email']}",
            "--scopes=cloud-platform",
        ]
    )
    echo_success("VM created")

    # Step 2: Wait for VM to be ready and install Docker
    typer.echo()
    typer.echo("Step 2: Installing Docker (this may take a minute)...")

    # Wait for SSH to be ready
    time.sleep(30)

    install_script = """
        set -e
        sudo apt-get update
        sudo apt-get install -y docker.io
        sudo systemctl enable docker
        sudo systemctl start docker
        # Pre-pull gcloud for faster auth
        sudo docker version
        echo "Docker installed successfully"
    """

    result = run_gcloud(
        [
            "compute",
            "ssh",
            vm_name,
            f"--project={project}",
            f"--zone={zone}",
            "--command",
            install_script,
        ],
        check=False,
    )
    if result.returncode != 0:
        echo_error("Failed to install Docker. Check VM logs.")
        typer.echo(result.stderr)
        # Cleanup
        run_gcloud(
            [
                "compute",
                "instances",
                "delete",
                vm_name,
                f"--project={project}",
                f"--zone={zone}",
                "--quiet",
            ],
            check=False,
        )
        raise typer.Exit(1)

    echo_success("Docker installed")

    # Step 3: Stop VM
    typer.echo()
    typer.echo("Step 3: Stopping VM...")
    run_gcloud(
        [
            "compute",
            "instances",
            "stop",
            vm_name,
            f"--project={project}",
            f"--zone={zone}",
        ]
    )
    echo_success("VM stopped")

    # Step 4: Create image from disk
    typer.echo()
    typer.echo("Step 4: Creating image from disk...")
    run_gcloud(
        [
            "compute",
            "images",
            "create",
            image_name,
            f"--project={project}",
            f"--source-disk={vm_name}",
            f"--source-disk-zone={zone}",
            "--family=arvo-docker",
            "--description=Docker-ready VM for ARVO benchmark",
        ]
    )
    echo_success("Image created")

    # Step 5: Delete temporary VM
    typer.echo()
    typer.echo("Step 5: Cleaning up temporary VM...")
    run_gcloud(
        [
            "compute",
            "instances",
            "delete",
            vm_name,
            f"--project={project}",
            f"--zone={zone}",
            "--quiet",
        ]
    )
    echo_success("VM deleted")

    # Save image name to config
    config["vm_image"] = f"projects/{project}/global/images/{image_name}"
    save_config(config)

    typer.echo()
    typer.echo("=" * 50)
    echo_success("VM image created!")
    typer.echo("=" * 50)
    typer.echo()
    typer.echo(f"Image: {config['vm_image']}")
    typer.echo()
    typer.echo("All future jobs will automatically use this image.")


# =============================================================================
# Main
# =============================================================================


def main() -> None:
    """Entry point."""
    app()


if __name__ == "__main__":
    main()
