"""
Debug VM commands: launch, ssh, delete, list.

Creates Kubernetes pods that mirror the fuzz/patch template environment
on non-SPOT (on-demand) nodes for interactive debugging. Pods run
'sleep infinity' instead of the actual task, allowing users to exec in
and debug interactively.
"""

import json
import os
import subprocess
import tempfile
import time
from datetime import datetime, timezone
from typing import Annotated, Optional

import typer
import yaml

from ..argo import get_current_user, run_kubectl
from ..config import GKEConfig, get_script_dir
from ..hashing import check_runtime_needs_rebuild
from ..output import echo_error, echo_info, echo_success, echo_warning


NAMESPACE = "argo"
DEBUG_LABEL = "arvo-debug"
SERVICE_ACCOUNT = "arvo-workflow-sa"
CONTAINER_NAME = "task"


# ---------------------------------------------------------------------------
# Pod spec builders
# ---------------------------------------------------------------------------


def _generate_pod_name(owner: str, case_id: int, job_type: str) -> str:
    """Generate a unique pod name for a debug VM."""
    timestamp = datetime.now().strftime("%H%M%S")
    name = f"debug-{owner}-{case_id}-{job_type}-{timestamp}"
    # Ensure valid K8s name: lowercase, alphanumeric + hyphens, max 63 chars
    name = name.lower()
    return name[:63].rstrip("-")


def _build_fuzz_pod_spec(
    name: str,
    case_id: int,
    agent_id: str,
    target: str,
    experiment_id: str,
    bucket: str,
    registry: str,
    build_version: str,
    owner: str,
) -> dict:
    """Build a Pod spec mirroring fuzz-template.yaml for debugging.

    Replicates the same init containers, images, volumes, env vars, and
    resources as the production fuzz template, but runs ``sleep infinity``
    instead of the actual fuzzing command.

    When *agent_id* is ``"gt"`` the pod fuzzes the ground-truth binary already
    baked into the container image.  Any other agent_id value is treated as an
    LLM patch -- the init container downloads the rebuilt binary from
    ``gs://{bucket}/results/{experiment-id}/{case-id}/{agent-id}/rebuilt_binary``.
    """
    fetch_runtime_script = (
        "set -e\n"
        f"gsutil cp gs://{bucket}/agent-runtime/agent-runtime.tar.gz /tmp/\n"
        "tar -xzf /tmp/agent-runtime.tar.gz -C /agent-runtime --strip-components=1\n"
        "chmod +x /agent-runtime/bin/* 2>/dev/null || true\n"
    )

    fetch_binary_script = (
        "set -e\n"
        f'AGENT_ID="{agent_id}"\n'
        'if [ "${AGENT_ID}" != "gt" ]; then\n'
        f'  BUCKET="{bucket}"\n'
        f'  EXPERIMENT_ID="{experiment_id}"\n'
        f'  CASE_ID="{case_id}"\n'
        "\n"
        "  # Download rebuilt binary from patch results (uses agent-id in path)\n"
        '  echo "Downloading rebuilt binary for agent ${AGENT_ID} from experiment ${EXPERIMENT_ID}..."\n'
        '  gsutil cp "gs://${BUCKET}/results/${EXPERIMENT_ID}/${CASE_ID}/${AGENT_ID}/rebuilt_binary" '
        "/binary/rebuilt_binary || {\n"
        '    echo "Warning: Could not download rebuilt binary"\n'
        "    exit 0\n"
        "  }\n"
        "  chmod +x /binary/rebuilt_binary\n"
        '  echo "Binary ready at /binary/rebuilt_binary"\n'
        "else\n"
        '  echo "Agent is gt -- using ground-truth binary from container image"\n'
        "fi\n"
    )

    return {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {
            "name": name,
            "namespace": NAMESPACE,
            "labels": {
                DEBUG_LABEL: "true",
                "owner": owner,
                "case-id": str(case_id),
                "job-type": "fuzz",
            },
            "annotations": {
                # Disable AppArmor so SYS_ADMIN can mount overlayfs
                f"container.apparmor.security.beta.kubernetes.io/{CONTAINER_NAME}": "unconfined",
            },
        },
        "spec": {
            "serviceAccountName": SERVICE_ACCOUNT,
            "restartPolicy": "Never",
            "nodeSelector": {"workload-type": "debug"},
            "tolerations": [
                {
                    "key": "workload",
                    "operator": "Equal",
                    "value": "debug",
                    "effect": "NoSchedule",
                }
            ],
            "initContainers": [
                {
                    "name": "fetch-runtime",
                    "image": "gcr.io/google.com/cloudsdktool/cloud-sdk:slim",
                    "command": ["/bin/bash", "-c", fetch_runtime_script],
                    "volumeMounts": [
                        {"name": "agent-runtime", "mountPath": "/agent-runtime"}
                    ],
                },
                {
                    "name": "fetch-binary",
                    "image": "gcr.io/google.com/cloudsdktool/cloud-sdk:slim",
                    "command": ["/bin/bash", "-c", fetch_binary_script],
                    "volumeMounts": [{"name": "binary", "mountPath": "/binary"}],
                },
            ],
            "containers": [
                {
                    "name": CONTAINER_NAME,
                    "image": f"{registry}/arvo-{case_id}-fix:{build_version}",
                    "command": [
                        "/bin/bash",
                        "-c",
                        "cp /binary/rebuilt_binary /tmp/rebuilt_binary 2>/dev/null "
                        "&& chmod +x /tmp/rebuilt_binary "
                        '&& echo "Rebuilt binary available at /tmp/rebuilt_binary" '
                        "|| true; "
                        "exec sleep infinity",
                    ],
                    "env": [
                        {"name": "PYTHONPATH", "value": "/agent-runtime"},
                        {"name": "CASE_ID", "value": str(case_id)},
                        {"name": "AGENT_ID", "value": agent_id},
                        {"name": "TARGET", "value": target},
                        {"name": "BUCKET", "value": bucket},
                        {"name": "EXPERIMENT_ID", "value": experiment_id},
                    ],
                    "volumeMounts": [
                        {
                            "name": "agent-runtime",
                            "mountPath": "/agent-runtime",
                            "readOnly": True,
                        },
                        {
                            "name": "binary",
                            "mountPath": "/binary",
                            "readOnly": True,
                        },
                        {"name": "output", "mountPath": "/output"},
                    ],
                    "resources": {
                        "requests": {"cpu": "1.7", "memory": "6G"},
                        "limits": {"cpu": "1.8", "memory": "14G"},
                    },
                    "securityContext": {
                        "capabilities": {"add": ["SYS_ADMIN"]},
                    },
                },
            ],
            "volumes": [
                {"name": "agent-runtime", "emptyDir": {}},
                {"name": "binary", "emptyDir": {}},
                {"name": "output", "emptyDir": {}},
            ],
        },
    }


def _build_build_pod_spec(
    name: str,
    case_id: int,
    bucket: str,
    owner: str,
    image_suffix: str = "fix",
) -> dict:
    """Build a Pod spec for debugging the Docker build step.

    Uses the **base DockerHub image** (``n132/arvo:{case_id}-{suffix}``)
    directly, matching the build-template resource limits so we can
    interactively reproduce ``arvo compile`` failures.
    """
    return {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {
            "name": name,
            "namespace": NAMESPACE,
            "labels": {
                DEBUG_LABEL: "true",
                "owner": owner,
                "case-id": str(case_id),
                "job-type": "build",
            },
        },
        "spec": {
            "serviceAccountName": SERVICE_ACCOUNT,
            "restartPolicy": "Never",
            "nodeSelector": {"workload-type": "debug"},
            "tolerations": [
                {
                    "key": "workload",
                    "operator": "Equal",
                    "value": "debug",
                    "effect": "NoSchedule",
                }
            ],
            "containers": [
                {
                    "name": CONTAINER_NAME,
                    "image": f"docker.io/n132/arvo:{case_id}-{image_suffix}",
                    "command": ["sleep", "infinity"],
                    "env": [
                        {"name": "CASE_ID", "value": str(case_id)},
                    ],
                    "resources": {
                        "requests": {"cpu": "3", "memory": "12G"},
                        "limits": {"cpu": "7", "memory": "24G"},
                    },
                },
            ],
        },
    }


def _build_patch_pod_spec(
    name: str,
    case_id: int,
    agent_id: str,
    experiment_id: str,
    bucket: str,
    registry: str,
    build_version: str,
    owner: str,
) -> dict:
    """Build a Pod spec mirroring patch-template.yaml for debugging.

    Replicates the same init containers, images, volumes, env vars, and
    resources as the production patch template, but runs ``sleep infinity``
    instead of the actual patching command.
    """
    fetch_runtime_script = (
        "set -e\n"
        f"gsutil cp gs://{bucket}/agent-runtime/agent-runtime.tar.gz /tmp/\n"
        "tar -xzf /tmp/agent-runtime.tar.gz -C /agent-runtime --strip-components=1\n"
        "chmod +x /agent-runtime/bin/* 2>/dev/null || true\n"
    )

    return {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {
            "name": name,
            "namespace": NAMESPACE,
            "labels": {
                DEBUG_LABEL: "true",
                "owner": owner,
                "case-id": str(case_id),
                "job-type": "patch",
            },
            "annotations": {
                # Disable AppArmor so SYS_ADMIN can mount overlayfs
                f"container.apparmor.security.beta.kubernetes.io/{CONTAINER_NAME}": "unconfined",
            },
        },
        "spec": {
            "serviceAccountName": SERVICE_ACCOUNT,
            "restartPolicy": "Never",
            "nodeSelector": {"workload-type": "debug"},
            "tolerations": [
                {
                    "key": "workload",
                    "operator": "Equal",
                    "value": "debug",
                    "effect": "NoSchedule",
                }
            ],
            "initContainers": [
                {
                    "name": "fetch-runtime",
                    "image": "gcr.io/google.com/cloudsdktool/cloud-sdk:slim",
                    "command": ["/bin/bash", "-c", fetch_runtime_script],
                    "volumeMounts": [
                        {"name": "agent-runtime", "mountPath": "/agent-runtime"}
                    ],
                },
            ],
            "containers": [
                {
                    "name": CONTAINER_NAME,
                    "image": f"{registry}/arvo-{case_id}-vul:{build_version}",
                    "command": ["sleep", "infinity"],
                    "env": [
                        {"name": "PYTHONPATH", "value": "/agent-runtime"},
                        {"name": "CASE_ID", "value": str(case_id)},
                        {"name": "AGENT_ID", "value": agent_id},
                        {"name": "BUCKET", "value": bucket},
                        {"name": "EXPERIMENT_ID", "value": experiment_id},
                        {
                            "name": "ANTHROPIC_API_KEY",
                            "valueFrom": {
                                "secretKeyRef": {
                                    "name": "anthropic-api-key",
                                    "key": "key",
                                }
                            },
                        },
                    ],
                    "volumeMounts": [
                        {
                            "name": "agent-runtime",
                            "mountPath": "/agent-runtime",
                            "readOnly": True,
                        },
                        {"name": "output", "mountPath": "/output"},
                    ],
                    "resources": {
                        "requests": {"cpu": "1.7", "memory": "6G"},
                        "limits": {"cpu": "1.8", "memory": "14G"},
                    },
                    # SYS_ADMIN enables overlayfs for instant source revert
                    "securityContext": {
                        "capabilities": {"add": ["SYS_ADMIN"]},
                    },
                },
            ],
            "volumes": [
                {"name": "agent-runtime", "emptyDir": {}},
                {"name": "output", "emptyDir": {}},
            ],
        },
    }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _wait_for_pod_running(name: str, timeout: int = 300) -> bool:
    """Wait for a pod to reach Running state.

    Returns True if pod is Running, False on timeout or failure.
    """
    echo_info(f"Waiting for pod {name} to start...")
    start_time = time.time()
    last_phase = ""

    while time.time() - start_time < timeout:
        result = run_kubectl(
            [
                "get",
                "pod",
                name,
                "-n",
                NAMESPACE,
                "-o",
                "jsonpath={.status.phase}",
            ],
            check=False,
        )

        if result.returncode != 0:
            time.sleep(5)
            continue

        phase = result.stdout.strip()

        if phase != last_phase:
            echo_info(f"Pod status: {phase}")
            last_phase = phase

        if phase == "Running":
            return True

        if phase in ("Failed", "Unknown"):
            echo_error(f"Pod entered {phase} state")
            # Show recent events for debugging
            run_kubectl(
                ["describe", "pod", name, "-n", NAMESPACE],
                check=False,
            )
            return False

        time.sleep(5)

    echo_error(f"Timeout waiting for pod to start ({timeout}s)")
    return False


def _format_age(created_str: str) -> str:
    """Format a Kubernetes timestamp as a human-readable age string."""
    try:
        created = datetime.fromisoformat(created_str.replace("Z", "+00:00"))
        now = datetime.now(timezone.utc)
        total_seconds = int((now - created).total_seconds())
        if total_seconds < 60:
            return f"{total_seconds}s"
        elif total_seconds < 3600:
            return f"{total_seconds // 60}m"
        elif total_seconds < 86400:
            hours = total_seconds // 3600
            minutes = (total_seconds % 3600) // 60
            return f"{hours}h{minutes}m"
        else:
            days = total_seconds // 86400
            hours = (total_seconds % 86400) // 3600
            return f"{days}d{hours}h"
    except (ValueError, TypeError):
        return ""


# ---------------------------------------------------------------------------
# CLI commands
# ---------------------------------------------------------------------------


def launch(
    case_id: Annotated[int, typer.Argument(help="ARVO case ID to debug")],
    job_type: Annotated[
        str,
        typer.Option("--type", "-t", help="Job type: fuzz or patch"),
    ] = "fuzz",
    agent_id: Annotated[
        str,
        typer.Option(
            "--agent-id",
            "-a",
            help="Agent ID (e.g., autopatchbench-claude-sonnet-4-20250514), or 'gt' for ground truth",
        ),
    ] = "gt",
    target: Annotated[
        str,
        typer.Option(
            "--target",
            help="Fuzz target: ground_truth or llm_patch",
        ),
    ] = "ground_truth",
    experiment_id: Annotated[
        Optional[str],
        typer.Option(
            "--experiment",
            "-e",
            help="Experiment ID (required when agent-id is not 'gt')",
        ),
    ] = None,
    build_version: Annotated[
        str,
        typer.Option("--build-version", help="Build version tag"),
    ] = "latest",
    image_suffix: Annotated[
        str,
        typer.Option(
            "--image-suffix",
            help="Image suffix for build type: 'fix' (default) or 'vul'",
        ),
    ] = "fix",
) -> None:
    """Launch a debug pod with the same environment as fuzz/patch templates.

    The pod runs ``sleep infinity`` instead of the actual task, allowing you
    to exec in and debug interactively on a non-SPOT (on-demand) node.

    Use ``--agent-id gt`` (the default) to fuzz the ground-truth binary baked
    into the container image.  Use any other agent-id (e.g.
    ``autopatchbench-claude-sonnet-4-20250514``) to download and fuzz that
    agent's rebuilt binary from a previous experiment (requires ``--experiment``).

    Examples::

        python -m cli debug-vm launch 12803 --type fuzz
        python -m cli debug-vm launch 12803 --type fuzz -a autopatchbench-claude-sonnet-4-20250514 -e 20260205-120000
        python -m cli debug-vm launch 12803 --type patch
        python -m cli debug-vm launch 12803 --type build --image-suffix vul
    """
    # Validate job type
    if job_type not in ("fuzz", "patch", "build"):
        echo_error("Job type must be 'fuzz', 'patch', or 'build'")
        raise typer.Exit(1)

    # If agent_id is not gt, experiment_id is required for fuzz (to find the binary)
    if agent_id != "gt" and job_type == "fuzz" and not experiment_id:
        echo_error(
            "Experiment ID is required when agent-id is not 'gt'.\n"
            "  Use --experiment / -e to specify which experiment's rebuilt binary to download."
        )
        raise typer.Exit(1)

    # Load config
    config = GKEConfig.load()
    if not config.is_configured():
        echo_error("GKE not configured. Run: python -m cli setup")
        raise typer.Exit(1)

    owner = get_current_user()

    # Auto-generate experiment ID if not provided (gt or patch don't strictly need one)
    if not experiment_id:
        experiment_id = datetime.now().strftime("%Y%m%d-%H%M%S")

    pod_name = _generate_pod_name(owner, case_id, job_type)

    typer.echo("=" * 60)
    typer.echo("ARVO Debug VM")
    typer.echo("=" * 60)
    typer.echo()
    typer.echo(f"Pod Name:       {pod_name}")
    typer.echo(f"Case ID:        {case_id}")
    typer.echo(f"Job Type:       {job_type}")
    typer.echo(f"Agent ID:       {agent_id}")
    if job_type == "fuzz":
        typer.echo(f"Target:         {target}")
    if agent_id != "gt":
        typer.echo(f"Experiment:     {experiment_id}")
    typer.echo(f"Build Version:  {build_version}")
    typer.echo(f"Owner:          {owner}")
    typer.echo()

    # Check if agent runtime needs rebuild/upload (not needed for build type)
    if job_type == "build":
        echo_info("Skipping runtime check for build debug VM")
    else:
        echo_info("Checking agent runtime...")
        needs_rebuild, reason = check_runtime_needs_rebuild()
        if needs_rebuild:
            echo_warning(f"Runtime needs rebuild ({reason})")
            build_script = get_script_dir() / "portable-runtime" / "build.sh"
            echo_info("Rebuilding runtime...")
            result = subprocess.run(
                ["bash", str(build_script)], capture_output=True, text=True
            )
            if result.returncode != 0:
                echo_error(f"Runtime build failed: {result.stderr}")
                raise typer.Exit(1)
            echo_success("Runtime rebuilt")

            runtime_tar = (
                get_script_dir()
                / "portable-runtime"
                / "output"
                / "agent-runtime.tar.gz"
            )
            if runtime_tar.exists():
                echo_info("Uploading runtime to GCS...")
                result = subprocess.run(
                    [
                        "gsutil",
                        "cp",
                        str(runtime_tar),
                        f"gs://{config.bucket_name}/agent-runtime/",
                    ],
                    capture_output=True,
                    text=True,
                )
                if result.returncode == 0:
                    echo_success("Runtime uploaded")
                else:
                    echo_warning(f"Upload failed: {result.stderr}")
            else:
                echo_warning("Runtime tarball not found after build")
        else:
            echo_success("Runtime up to date")
    typer.echo()

    # Build pod spec
    if job_type == "fuzz":
        pod_spec = _build_fuzz_pod_spec(
            name=pod_name,
            case_id=case_id,
            agent_id=agent_id,
            target=target,
            experiment_id=experiment_id,
            bucket=config.bucket_name,
            registry=config.artifact_registry,
            build_version=build_version,
            owner=owner,
        )
    elif job_type == "build":
        pod_spec = _build_build_pod_spec(
            name=pod_name,
            case_id=case_id,
            bucket=config.bucket_name,
            owner=owner,
            image_suffix=image_suffix,
        )
    else:
        pod_spec = _build_patch_pod_spec(
            name=pod_name,
            case_id=case_id,
            agent_id=agent_id,
            experiment_id=experiment_id,
            bucket=config.bucket_name,
            registry=config.artifact_registry,
            build_version=build_version,
            owner=owner,
        )

    # Write pod spec to temp file and apply
    echo_info("Creating debug pod...")

    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
        yaml.dump(pod_spec, f, default_flow_style=False, sort_keys=False)
        temp_path = f.name

    try:
        result = run_kubectl(["apply", "-f", temp_path], check=False)
    finally:
        os.unlink(temp_path)

    if result.returncode != 0:
        echo_error("Failed to create debug pod")
        if result.stderr:
            typer.echo(result.stderr)
        raise typer.Exit(1)

    # Wait for pod to start
    if not _wait_for_pod_running(pod_name):
        echo_warning("Pod may still be starting. Check status with:")
        typer.echo(f"  kubectl get pod {pod_name} -n {NAMESPACE}")
        typer.echo()
        typer.echo("View events:")
        typer.echo(f"  kubectl describe pod {pod_name} -n {NAMESPACE}")
        raise typer.Exit(1)

    typer.echo()
    typer.echo("=" * 60)
    echo_success(f"Debug pod ready: {pod_name}")
    typer.echo("=" * 60)
    typer.echo()
    typer.echo("Connect to the pod:")
    typer.echo(f"  python -m cli debug-vm ssh {pod_name}")
    typer.echo()
    typer.echo("Or directly with kubectl:")
    typer.echo(
        f"  kubectl exec -it {pod_name} -n {NAMESPACE} -c {CONTAINER_NAME} -- /bin/bash"
    )
    typer.echo()
    typer.echo("Delete when done:")
    typer.echo(f"  python -m cli debug-vm delete {pod_name}")


def ssh(
    pod_name: Annotated[str, typer.Argument(help="Debug pod name")],
) -> None:
    """SSH into a debug pod (exec into the task container).

    Example::

        python -m cli debug-vm ssh debug-camyang-12803-fuzz-143052
    """
    # Verify pod exists and is running
    result = run_kubectl(
        [
            "get",
            "pod",
            pod_name,
            "-n",
            NAMESPACE,
            "-o",
            "jsonpath={.status.phase}",
        ],
        check=False,
    )

    if result.returncode != 0:
        echo_error(f"Pod '{pod_name}' not found in namespace '{NAMESPACE}'")
        typer.echo()
        typer.echo("List debug pods with:")
        typer.echo("  python -m cli debug-vm list")
        raise typer.Exit(1)

    phase = result.stdout.strip()
    if phase != "Running":
        echo_warning(f"Pod is in '{phase}' state (not Running)")
        if not typer.confirm("Try to connect anyway?"):
            raise typer.Exit(0)

    echo_info(f"Connecting to {pod_name}...")

    # Replace process with kubectl exec for proper interactive terminal
    os.execvp(
        "kubectl",
        [
            "kubectl",
            "exec",
            "-it",
            pod_name,
            "-n",
            NAMESPACE,
            "-c",
            CONTAINER_NAME,
            "--",
            "/bin/bash",
        ],
    )


def delete(
    pod_name: Annotated[str, typer.Argument(help="Debug pod name")],
) -> None:
    """Delete a debug pod.

    Example::

        python -m cli debug-vm delete debug-camyang-12803-fuzz-143052
    """
    echo_info(f"Deleting pod: {pod_name}")

    result = run_kubectl(
        ["delete", "pod", pod_name, "-n", NAMESPACE],
        check=False,
    )

    if result.returncode == 0:
        echo_success(f"Pod deleted: {pod_name}")
    else:
        echo_error(f"Failed to delete pod: {pod_name}")
        if result.stderr:
            typer.echo(result.stderr)
        raise typer.Exit(1)


def list_pods() -> None:
    """List all debug pods.

    Shows all pods with the arvo-debug=true label across all users.
    """
    result = run_kubectl(
        [
            "get",
            "pods",
            "-n",
            NAMESPACE,
            "-l",
            f"{DEBUG_LABEL}=true",
            "-o",
            "json",
        ],
        check=False,
    )

    if result.returncode != 0:
        echo_error("Failed to list debug pods")
        if result.stderr:
            typer.echo(result.stderr)
        raise typer.Exit(1)

    try:
        data = json.loads(result.stdout)
        items = data.get("items", [])
    except json.JSONDecodeError:
        echo_error("Failed to parse pod list")
        raise typer.Exit(1)

    if not items:
        typer.echo("No debug pods found.")
        typer.echo()
        typer.echo("Launch one with:")
        typer.echo("  python -m cli debug-vm launch <case-id> --type fuzz")
        return

    # Format as table
    typer.echo(
        f"{'NAME':<50} {'STATUS':<12} {'CASE':<8} {'TYPE':<8} {'OWNER':<15} {'AGE'}"
    )
    typer.echo("-" * 110)

    for item in items:
        metadata = item.get("metadata", {})
        status = item.get("status", {})
        labels = metadata.get("labels", {})

        pod_name = metadata.get("name", "")
        phase = status.get("phase", "Unknown")
        case_id = labels.get("case-id", "")
        job_type = labels.get("job-type", "")
        owner = labels.get("owner", "")

        created = metadata.get("creationTimestamp", "")
        age = _format_age(created) if created else ""

        typer.echo(
            f"{pod_name:<50} {phase:<12} {case_id:<8} {job_type:<8} {owner:<15} {age}"
        )
