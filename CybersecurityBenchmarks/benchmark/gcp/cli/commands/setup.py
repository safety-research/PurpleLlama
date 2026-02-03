"""
Setup-related commands: setup, check-permissions, teardown.
"""

import json
from datetime import datetime
from typing import Annotated, Optional

import typer

from ..config import SECRET_NAME, DEFAULT_REGION
from ..gcp_utils import (
    get_bucket_suffix,
    get_config_path,
    get_gcp_username,
    get_project_number,
    get_service_account_name,
    load_config,
    run_gcloud,
    run_gsutil,
    save_config,
)
from ..output import echo_error, echo_info, echo_success, echo_warning


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
