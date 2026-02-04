"""
Secrets management - sync .env to Kubernetes secrets.
"""

import subprocess
from pathlib import Path
from typing import Annotated, Optional

import typer

from ..argo import run_kubectl


def _parse_env_file(path: Path) -> dict[str, str]:
    """Parse .env file into dict."""
    if not path.exists():
        return {}

    secrets = {}
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" in line:
                key, value = line.split("=", 1)
                secrets[key.strip()] = value.strip()
    return secrets


def sync_secrets(
    env_file: Annotated[
        Optional[Path],
        typer.Option("--env-file", "-e", help="Path to .env file"),
    ] = None,
    namespace: Annotated[
        str, typer.Option("--namespace", "-n", help="Kubernetes namespace")
    ] = "argo",
    secret_name: Annotated[
        str, typer.Option("--secret", "-s", help="Secret name to create/update")
    ] = "arvo-secrets",
    keys: Annotated[
        Optional[list[str]],
        typer.Option("--key", "-k", help="Specific keys to sync (can repeat)"),
    ] = None,
    dry_run: Annotated[
        bool, typer.Option("--dry-run", help="Show what would be synced")
    ] = False,
) -> None:
    """Sync secrets from .env file to Kubernetes."""
    # Find .env file
    if env_file is None:
        # Look in common locations
        candidates = [
            Path.cwd() / ".env",
            Path(__file__).parent.parent.parent.parent.parent / ".env",
        ]
        for candidate in candidates:
            if candidate.exists():
                env_file = candidate
                break

    if env_file is None or not env_file.exists():
        typer.echo("Error: No .env file found. Specify with --env-file.")
        raise typer.Exit(1)

    typer.echo(f"Reading secrets from: {env_file}")

    # Parse .env
    all_secrets = _parse_env_file(env_file)
    if not all_secrets:
        typer.echo("No secrets found in .env file.")
        return

    # Filter to requested keys
    if keys:
        secrets = {k: v for k, v in all_secrets.items() if k in keys}
        missing = set(keys) - set(secrets.keys())
        if missing:
            typer.echo(f"Warning: Keys not found in .env: {missing}")
    else:
        secrets = all_secrets

    if not secrets:
        typer.echo("No secrets to sync.")
        return

    typer.echo(f"Secrets to sync: {list(secrets.keys())}")
    typer.echo(f"Target: {namespace}/{secret_name}")
    typer.echo()

    if dry_run:
        typer.echo("Dry run - would create/update secret with:")
        for key in secrets:
            typer.echo(f"  {key}: ****")
        return

    # Build kubectl command
    # Delete existing secret (ignore if not exists)
    run_kubectl(["delete", "secret", secret_name, "-n", namespace], check=False)

    # Create new secret
    args = ["create", "secret", "generic", secret_name, "-n", namespace]
    for key, value in secrets.items():
        args.append(f"--from-literal={key}={value}")

    result = run_kubectl(args, check=False)
    if result.returncode == 0:
        typer.echo(
            f"Secret '{secret_name}' created/updated in namespace '{namespace}'."
        )

        # Also create individual secrets for common keys
        common_secrets = {
            "ANTHROPIC_API_KEY": "anthropic-api-key",
            "OPENAI_API_KEY": "openai-api-key",
        }

        for env_key, secret_key in common_secrets.items():
            if env_key in secrets:
                run_kubectl(
                    ["delete", "secret", secret_key, "-n", namespace],
                    check=False,
                )
                result = run_kubectl(
                    [
                        "create",
                        "secret",
                        "generic",
                        secret_key,
                        "-n",
                        namespace,
                        f"--from-literal=key={secrets[env_key]}",
                    ],
                    check=False,
                )
                if result.returncode == 0:
                    typer.echo(f"Secret '{secret_key}' created.")

        # Create Docker Hub registry secret if credentials are present
        docker_username = secrets.get("DOCKER_USERNAME")
        docker_password = secrets.get("DOCKER_PASSWORD")

        if docker_username and docker_password:
            _create_docker_registry_secret(
                namespace=namespace,
                username=docker_username,
                password=docker_password,
                dry_run=False,
            )
    else:
        typer.echo(f"Error creating secret: {result.stderr}")
        raise typer.Exit(1)


def _create_docker_registry_secret(
    namespace: str,
    username: str,
    password: str,
    secret_name: str = "dockerhub-registry",
    service_account: str = "arvo-workflow-sa",
    dry_run: bool = False,
) -> bool:
    """Create Docker Hub registry secret and patch service account.

    Returns True if successful, False otherwise.
    """
    import json

    typer.echo()
    typer.echo(f"Creating Docker Hub registry secret '{secret_name}'...")

    if dry_run:
        typer.echo(f"  (dry-run) Would create docker-registry secret")
        typer.echo(f"  (dry-run) Would patch service account '{service_account}'")
        return True

    # Delete existing secret (ignore if not exists)
    run_kubectl(["delete", "secret", secret_name, "-n", namespace], check=False)

    # Create docker-registry secret
    result = run_kubectl(
        [
            "create",
            "secret",
            "docker-registry",
            secret_name,
            "-n",
            namespace,
            "--docker-server=https://index.docker.io/v1/",
            f"--docker-username={username}",
            f"--docker-password={password}",
        ],
        check=False,
    )

    if result.returncode != 0:
        typer.echo(f"Warning: Failed to create docker-registry secret: {result.stderr}")
        return False

    typer.echo(f"Secret '{secret_name}' created.")

    # Patch service account with imagePullSecrets
    typer.echo(f"Patching service account '{service_account}'...")

    patch_data = json.dumps({"imagePullSecrets": [{"name": secret_name}]})
    result = run_kubectl(
        [
            "patch",
            "serviceaccount",
            service_account,
            "-n",
            namespace,
            "-p",
            patch_data,
        ],
        check=False,
    )

    if result.returncode == 0:
        typer.echo(
            f"Service account '{service_account}' patched with imagePullSecrets."
        )
        return True
    else:
        typer.echo(f"Warning: Failed to patch service account: {result.stderr}")
        return False


def list_secrets(
    namespace: Annotated[
        str, typer.Option("--namespace", "-n", help="Kubernetes namespace")
    ] = "argo",
) -> None:
    """List secrets in the namespace."""
    result = run_kubectl(
        ["get", "secrets", "-n", namespace, "-o", "wide"],
        check=False,
    )
    if result.returncode == 0:
        typer.echo(result.stdout)
    else:
        typer.echo(f"Error: {result.stderr}")


def show_secret(
    secret_name: Annotated[str, typer.Argument(help="Secret name")],
    namespace: Annotated[
        str, typer.Option("--namespace", "-n", help="Kubernetes namespace")
    ] = "argo",
    decode: Annotated[
        bool, typer.Option("--decode", "-d", help="Decode and show values")
    ] = False,
) -> None:
    """Show secret details."""
    if decode:
        result = run_kubectl(
            [
                "get",
                "secret",
                secret_name,
                "-n",
                namespace,
                "-o",
                "jsonpath={.data}",
            ],
            check=False,
        )
        if result.returncode == 0:
            import base64
            import json

            try:
                data = json.loads(result.stdout)
                typer.echo(f"Secret: {secret_name}")
                typer.echo("-" * 40)
                for key, value in data.items():
                    decoded = base64.b64decode(value).decode("utf-8")
                    # Mask most of the value
                    if len(decoded) > 8:
                        masked = decoded[:4] + "****" + decoded[-4:]
                    else:
                        masked = "****"
                    typer.echo(f"  {key}: {masked}")
            except json.JSONDecodeError:
                typer.echo(f"Raw data: {result.stdout}")
        else:
            typer.echo(f"Error: {result.stderr}")
    else:
        result = run_kubectl(
            ["describe", "secret", secret_name, "-n", namespace],
            check=False,
        )
        if result.returncode == 0:
            typer.echo(result.stdout)
        else:
            typer.echo(f"Error: {result.stderr}")
