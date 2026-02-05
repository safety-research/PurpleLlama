"""
Setup command for GKE cluster and Argo Workflows.
"""

import json
import subprocess
import tempfile
from typing import Annotated, Optional

import typer

from ..argo import apply_templates, check_argo_cli, check_argo_installed, run_kubectl
from ..config import GKEConfig, get_config_path, get_script_dir


def get_gcp_username() -> str:
    """Get the GCP username (part before @ in the account email)."""
    result = subprocess.run(
        ["gcloud", "config", "get-value", "account"],
        capture_output=True,
        text=True,
    )
    if result.returncode == 0 and result.stdout.strip():
        return result.stdout.strip().split("@")[0]
    return "arvo"


def setup(
    project_id: Annotated[Optional[str], typer.Option(help="GCP project ID")] = None,
    zone: Annotated[
        str, typer.Option(help="GCP zone (zonal cluster for cost efficiency)")
    ] = "us-central1-a",
    cluster_name: Annotated[
        str, typer.Option(help="GKE cluster name")
    ] = "arvo-cluster",
    skip_cluster: Annotated[
        bool, typer.Option("--skip-cluster", help="Skip cluster creation")
    ] = False,
    skip_argo: Annotated[
        bool, typer.Option("--skip-argo", help="Skip Argo installation")
    ] = False,
) -> None:
    """Set up GKE cluster and Argo Workflows."""
    config = GKEConfig.load()

    # Get project ID
    if project_id:
        config.project_id = project_id
    elif not config.project_id:
        result = subprocess.run(
            ["gcloud", "config", "get-value", "project"],
            capture_output=True,
            text=True,
        )
        config.project_id = result.stdout.strip()

    if not config.project_id:
        typer.echo("Error: No project ID. Set with --project-id or gcloud config.")
        raise typer.Exit(1)

    # Extract region from zone (us-central1-a -> us-central1)
    region = zone.rsplit("-", 1)[0]
    config.region = region
    config.zone = zone
    config.cluster_name = cluster_name

    typer.echo("=" * 50)
    typer.echo("ARVO GKE/Argo Setup")
    typer.echo("=" * 50)
    typer.echo(f"Project:  {config.project_id}")
    typer.echo(f"Zone:     {config.zone}")
    typer.echo(f"Region:   {config.region}")
    typer.echo(f"Cluster:  {config.cluster_name}")
    typer.echo()

    # Check argo CLI
    if not check_argo_cli():
        typer.echo("Warning: argo CLI not found. Install from:")
        typer.echo("  https://github.com/argoproj/argo-workflows/releases")
        typer.echo()

    # Enable required APIs
    if not skip_cluster:
        typer.echo("[1/6] Enabling required GCP APIs...")
        result = subprocess.run(
            [
                "gcloud",
                "services",
                "enable",
                "container.googleapis.com",
                "artifactregistry.googleapis.com",
                f"--project={config.project_id}",
            ],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            typer.echo(f"  Error enabling APIs: {result.stderr}")
            raise typer.Exit(1)
        typer.echo("  APIs enabled.")

    # Get the owner (GCP username) for labeling all resources
    owner = get_gcp_username()

    # Create cluster
    if not skip_cluster:
        typer.echo(f"[2/6] Creating GKE cluster (owner: {owner})...")
        result = subprocess.run(
            [
                "gcloud",
                "container",
                "clusters",
                "create",
                config.cluster_name,
                f"--project={config.project_id}",
                f"--zone={config.zone}",
                "--num-nodes=1",
                "--machine-type=e2-small",
                "--enable-autoscaling",
                "--min-nodes=1",
                "--max-nodes=3",
                f"--workload-pool={config.project_id}.svc.id.goog",
                f"--labels=owner={owner}",
            ],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            if "already exists" in result.stderr:
                typer.echo("  Cluster already exists, continuing...")
            else:
                typer.echo(f"  Error: {result.stderr}")
                raise typer.Exit(1)
        else:
            typer.echo("  Cluster created.")

        # Create batch-build pool for build jobs (8-16 vCPU)
        typer.echo("[3/6] Creating Spot node pools...")
        typer.echo("  Creating batch-build pool (e2-standard-16 for builds)...")
        result = subprocess.run(
            [
                "gcloud",
                "container",
                "node-pools",
                "create",
                "batch-build",
                f"--cluster={config.cluster_name}",
                f"--project={config.project_id}",
                f"--zone={config.zone}",
                "--machine-type=e2-standard-16",
                "--spot",
                "--num-nodes=0",
                "--enable-autoscaling",
                "--min-nodes=0",
                "--max-nodes=50",
                "--node-taints=workload=build:NoSchedule",
                f"--node-labels=owner={owner},workload-type=build",
            ],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            if "already exists" in result.stderr:
                typer.echo("    batch-build pool already exists.")
            else:
                typer.echo(f"    Error: {result.stderr}")

        # Create batch-work pool for 2-vCPU fuzz/patch jobs
        typer.echo("  Creating batch-work pool (e2-standard-4 for fuzz/patch)...")
        result = subprocess.run(
            [
                "gcloud",
                "container",
                "node-pools",
                "create",
                "batch-work",
                f"--cluster={config.cluster_name}",
                f"--project={config.project_id}",
                f"--zone={config.zone}",
                "--machine-type=e2-standard-4",
                "--spot",
                "--num-nodes=0",
                "--enable-autoscaling",
                "--min-nodes=0",
                "--max-nodes=100",
                "--node-taints=workload=work:NoSchedule",
                f"--node-labels=owner={owner},workload-type=work",
            ],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            if "already exists" in result.stderr:
                typer.echo("    batch-work pool already exists.")
            else:
                typer.echo(f"    Error: {result.stderr}")

        # Get credentials
        typer.echo("[4/6] Getting cluster credentials...")
        subprocess.run(
            [
                "gcloud",
                "container",
                "clusters",
                "get-credentials",
                config.cluster_name,
                f"--zone={config.zone}",
                f"--project={config.project_id}",
            ],
            check=True,
        )
    else:
        typer.echo("[1-4/6] Skipping cluster creation...")

    # Install Argo
    if not skip_argo:
        typer.echo("[5/6] Installing Argo Workflows...")

        # Create namespace
        run_kubectl(["create", "namespace", "argo"], check=False)

        # Install Argo
        result = run_kubectl(
            [
                "apply",
                "-n",
                "argo",
                "-f",
                "https://github.com/argoproj/argo-workflows/releases/download/v3.5.12/install.yaml",
            ],
            check=False,
        )
        if result.returncode != 0:
            typer.echo(f"  Warning: {result.stderr}")

        # Patch auth mode
        run_kubectl(
            [
                "patch",
                "deployment",
                "argo-server",
                "-n",
                "argo",
                "--type=json",
                '-p=[{"op": "replace", "path": "/spec/template/spec/containers/0/args", "value": ["server", "--auth-mode=server"]}]',
            ],
            check=False,
        )
        typer.echo("  Argo installed.")

        # Apply workflow templates
        typer.echo("[6/6] Applying workflow templates...")
        templates_dir = get_script_dir() / "argo" / "templates"
        if apply_templates(str(templates_dir)):
            typer.echo("  Templates applied.")
        else:
            typer.echo("  Warning: Could not apply templates.")
    else:
        typer.echo("[5-6/6] Skipping Argo installation...")

    # Derive bucket, registry, and service account names (consistent with old Cloud Batch setup)
    result = subprocess.run(
        ["gcloud", "config", "get-value", "account"],
        capture_output=True,
        text=True,
    )
    username = result.stdout.strip().split("@")[0] if result.stdout else "arvo"

    # Use the same bucket naming as Cloud Batch: {project_id}-{username}-arvo-benchmark
    config.bucket_name = f"{config.project_id}-{username}-arvo-benchmark"
    config.artifact_registry = (
        f"{config.region}-docker.pkg.dev/{config.project_id}/arvo"
    )
    config.gcp_service_account = (
        f"{username}-arvo-runner@{config.project_id}.iam.gserviceaccount.com"
    )

    # Save config
    config.save()

    # Configure Argo workflow controller for log archiving
    if not skip_argo:
        typer.echo()
        typer.echo("[7/10] Configuring Argo log archiving to GCS...")
        workflow_controller_config = f"""apiVersion: v1
kind: ConfigMap
metadata:
  name: workflow-controller-configmap
  namespace: argo
data:
  artifactRepository: |
    archiveLogs: true
    gcs:
      bucket: {config.bucket_name}
      keyFormat: "argo-logs/{{{{workflow.creationTimestamp.Y}}}}/{{{{workflow.creationTimestamp.m}}}}/{{{{workflow.creationTimestamp.d}}}}/{{{{workflow.name}}}}/{{{{pod.name}}}}"
  retentionPolicy: |
    completed: 604800
    failed: 604800
    errored: 604800
"""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".yaml", delete=False
        ) as config_file:
            config_file.write(workflow_controller_config)
            config_path = config_file.name

        result = run_kubectl(["apply", "-f", config_path], check=False)
        if result.returncode == 0:
            typer.echo("  Log archiving configured (7-day retention to GCS).")
            typer.echo(
                f"  Logs will be archived to: gs://{config.bucket_name}/argo-logs/"
            )
            # Restart workflow controller to pick up new config
            run_kubectl(
                [
                    "rollout",
                    "restart",
                    "deployment",
                    "workflow-controller",
                    "-n",
                    "argo",
                ],
                check=False,
            )
        else:
            typer.echo(f"  Warning: Could not configure log archiving: {result.stderr}")

    # Set up service account and RBAC
    typer.echo()
    typer.echo("[8/10] Setting up Kubernetes service account...")
    rbac_dir = get_script_dir() / "argo" / "rbac"
    if rbac_dir.exists():
        result = run_kubectl(
            ["apply", "-f", str(rbac_dir)],
            check=False,
        )
        if result.returncode == 0:
            typer.echo("  Service account and RBAC created.")
        else:
            typer.echo(f"  Warning: {result.stderr}")

        # Annotate service accounts with GCP SA for Workload Identity
        # arvo-workflow-sa: for workflow pods to access GCS
        run_kubectl(
            [
                "annotate",
                "serviceaccount",
                "arvo-workflow-sa",
                "-n",
                "argo",
                f"iam.gke.io/gcp-service-account={config.gcp_service_account}",
                "--overwrite",
            ],
            check=False,
        )
        # argo-server: for UI to access GCS artifacts
        run_kubectl(
            [
                "annotate",
                "serviceaccount",
                "argo-server",
                "-n",
                "argo",
                f"iam.gke.io/gcp-service-account={config.gcp_service_account}",
                "--overwrite",
            ],
            check=False,
        )
        # argo: for workflow controller to archive logs to GCS
        run_kubectl(
            [
                "annotate",
                "serviceaccount",
                "argo",
                "-n",
                "argo",
                f"iam.gke.io/gcp-service-account={config.gcp_service_account}",
                "--overwrite",
            ],
            check=False,
        )
    else:
        typer.echo("  Warning: RBAC directory not found.")

    # Set up Workload Identity bindings for all service accounts
    typer.echo("[9/10] Setting up Workload Identity...")
    # arvo-workflow-sa: workflow pods, argo-server: UI artifact access, argo: log archiving
    for k8s_sa in ["arvo-workflow-sa", "argo-server", "argo"]:
        result = subprocess.run(
            [
                "gcloud",
                "iam",
                "service-accounts",
                "add-iam-policy-binding",
                config.gcp_service_account,
                f"--project={config.project_id}",
                "--role=roles/iam.workloadIdentityUser",
                f"--member=serviceAccount:{config.project_id}.svc.id.goog[argo/{k8s_sa}]",
                "--quiet",
            ],
            capture_output=True,
            text=True,
        )
        if result.returncode == 0:
            typer.echo(f"  Workload Identity binding created for {k8s_sa}.")
        else:
            typer.echo(f"  Warning ({k8s_sa}): {result.stderr}")

    # Restart argo-server to pick up Workload Identity for UI artifact access
    typer.echo("  Restarting argo-server for Workload Identity...")
    run_kubectl(
        ["rollout", "restart", "deployment", "argo-server", "-n", "argo"],
        check=False,
    )

    # Configure GCS lifecycle policy for temp file cleanup
    typer.echo("[10/10] Configuring GCS lifecycle policy for temp cleanup...")
    lifecycle_config = {
        "rule": [
            {
                "action": {"type": "Delete"},
                "condition": {"age": 14, "matchesPrefix": ["results/.tmp/"]},
            }
        ]
    }
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".json", delete=False
    ) as lifecycle_file:
        json.dump(lifecycle_config, lifecycle_file)
        lifecycle_path = lifecycle_file.name

    result = subprocess.run(
        ["gsutil", "lifecycle", "set", lifecycle_path, f"gs://{config.bucket_name}"],
        capture_output=True,
        text=True,
    )
    if result.returncode == 0:
        typer.echo(
            "  Lifecycle policy configured (14-day auto-delete for results/.tmp/)."
        )
    else:
        typer.echo(f"  Warning: Could not set lifecycle policy: {result.stderr}")
        typer.echo("  You may need to create the bucket first, then re-run setup.")

    # Create memoization cache ConfigMaps with required label
    run_kubectl(
        ["create", "configmap", "arvo-build-cache", "-n", "argo"],
        check=False,
    )
    run_kubectl(
        [
            "label",
            "configmap",
            "arvo-build-cache",
            "-n",
            "argo",
            "workflows.argoproj.io/configmap-type=Cache",
            "--overwrite",
        ],
        check=False,
    )
    # Create fuzz memoization cache ConfigMap
    run_kubectl(
        ["create", "configmap", "arvo-fuzz-cache", "-n", "argo"],
        check=False,
    )
    run_kubectl(
        [
            "label",
            "configmap",
            "arvo-fuzz-cache",
            "-n",
            "argo",
            "workflows.argoproj.io/configmap-type=Cache",
            "--overwrite",
        ],
        check=False,
    )
    typer.echo()
    typer.echo(f"Config saved to: {get_config_path()}")
    typer.echo()
    typer.echo("Next steps:")
    typer.echo("  1. Create GCS bucket (if not exists):")
    typer.echo(f"     gsutil mb gs://{config.bucket_name}")
    typer.echo("  2. Create Artifact Registry (if not exists):")
    typer.echo(
        f"     gcloud artifacts repositories create arvo --repository-format=docker --location={config.region}"
    )
    typer.echo("  3. Create Anthropic API key secret:")
    typer.echo(
        "     kubectl create secret generic anthropic-api-key -n argo --from-literal=key=$ANTHROPIC_API_KEY"
    )
    typer.echo("  4. Upload agent runtime:")
    typer.echo("     python -m cli upload-runtime")
    typer.echo("  5. Submit a benchmark:")
    typer.echo("     python -m cli submit --cases=42")


def status() -> None:
    """Check status of GKE cluster and Argo."""
    config = GKEConfig.load()

    typer.echo("=" * 50)
    typer.echo("GKE/Argo Status")
    typer.echo("=" * 50)
    typer.echo()

    # Check config
    typer.echo("Configuration:")
    if config.is_configured():
        typer.echo(f"  Project:  {config.project_id}")
        typer.echo(f"  Cluster:  {config.cluster_name}")
        typer.echo(f"  Bucket:   {config.bucket_name}")
        typer.echo(f"  Registry: {config.artifact_registry}")
    else:
        typer.echo("  Not configured. Run: python -m cli setup")
        return

    typer.echo()

    # Check cluster
    typer.echo("GKE Cluster:")
    result = subprocess.run(
        [
            "gcloud",
            "container",
            "clusters",
            "describe",
            config.cluster_name,
            f"--zone={config.zone}",
            f"--project={config.project_id}",
            "--format=value(status)",
        ],
        capture_output=True,
        text=True,
    )
    if result.returncode == 0:
        typer.echo(f"  Status: {result.stdout.strip()}")
    else:
        typer.echo("  Not found")

    typer.echo()

    # Check Argo
    typer.echo("Argo Workflows:")
    if check_argo_installed():
        typer.echo("  Installed: Yes")

        # Check server
        result = run_kubectl(
            [
                "get",
                "pods",
                "-n",
                "argo",
                "-l",
                "app=argo-server",
                "-o",
                "jsonpath={.items[0].status.phase}",
            ],
            check=False,
        )
        if result.returncode == 0:
            typer.echo(f"  Server: {result.stdout}")
    else:
        typer.echo("  Installed: No")

    typer.echo()

    # Check templates
    typer.echo("Workflow Templates:")
    result = run_kubectl(
        ["get", "workflowtemplates", "-n", "argo", "-o", "name"],
        check=False,
    )
    if result.returncode == 0 and result.stdout.strip():
        for tmpl in result.stdout.strip().split("\n"):
            typer.echo(f"  - {tmpl.replace('workflowtemplate.argoproj.io/', '')}")
    else:
        typer.echo("  None")
