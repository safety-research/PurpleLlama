"""
Experiments command for viewing and comparing results.
"""

import json
import subprocess
from typing import Annotated, Optional

import typer

from ..config import GKEConfig


def experiments(
    ctx: typer.Context,
) -> None:
    """Manage experiments and results."""
    if ctx.invoked_subcommand is None:
        typer.echo("Use: experiments list | results | compare")


app = typer.Typer()


@app.command("list")
def list_experiments(
    limit: Annotated[int, typer.Option("--limit", "-n")] = 20,
) -> None:
    """List experiments."""
    config = GKEConfig.load()
    if not config.is_configured():
        typer.echo("Error: Not configured. Run: python -m cli setup")
        raise typer.Exit(1)

    result = subprocess.run(
        ["gsutil", "ls", f"gs://{config.bucket_name}/results/"],
        capture_output=True,
        text=True,
    )

    if result.returncode != 0:
        typer.echo("No experiments found.")
        return

    experiments = []
    for line in result.stdout.strip().split("\n"):
        if line:
            exp_id = line.rstrip("/").split("/")[-1]
            if exp_id and exp_id != "results":
                experiments.append(exp_id)

    experiments = sorted(experiments, reverse=True)[:limit]

    typer.echo("Experiments:")
    for exp in experiments:
        typer.echo(f"  {exp}")


@app.command("results")
def show_results(
    experiment_id: Annotated[str, typer.Argument(help="Experiment ID")],
    agent_id: Annotated[
        Optional[str], typer.Option("--agent-id", "-a", help="Filter by agent ID")
    ] = None,
) -> None:
    """Show results for an experiment."""
    config = GKEConfig.load()
    if not config.is_configured():
        typer.echo("Error: Not configured. Run: python -m cli setup")
        raise typer.Exit(1)

    base_path = f"gs://{config.bucket_name}/results/{experiment_id}"

    # List cases
    result = subprocess.run(
        ["gsutil", "ls", f"{base_path}/"],
        capture_output=True,
        text=True,
    )

    if result.returncode != 0:
        typer.echo(f"Experiment not found: {experiment_id}")
        raise typer.Exit(1)

    cases = []
    for line in result.stdout.strip().split("\n"):
        if line:
            case_id = line.rstrip("/").split("/")[-1]
            if case_id.isdigit():
                cases.append(int(case_id))

    cases = sorted(cases)

    typer.echo(f"Experiment: {experiment_id}")
    typer.echo(f"Cases: {len(cases)}")
    typer.echo()

    # Collect results
    success_count = 0
    fail_count = 0
    pending_count = 0

    typer.echo(f"{'CASE':<10} {'AGENT':<40} {'CRASH_FIXED':<15} {'STATUS'}")
    typer.echo("-" * 80)

    for case_id in cases[:50]:  # Limit output
        # Check for agent results
        if agent_id:
            agents_to_check = [agent_id]
        else:
            # Auto-discover agents from GCS for this case
            agents_result = subprocess.run(
                ["gsutil", "ls", f"{base_path}/{case_id}/"],
                capture_output=True,
                text=True,
            )
            if agents_result.returncode == 0:
                agents_to_check = [
                    line.rstrip("/").split("/")[-1]
                    for line in agents_result.stdout.strip().split("\n")
                    if line and not line.rstrip("/").split("/")[-1].startswith("_")
                ]
            else:
                agents_to_check = ["gt"]  # Fallback

        for a in agents_to_check:
            result_path = f"{base_path}/{case_id}/{a}/result.json"
            result = subprocess.run(
                ["gsutil", "cat", result_path],
                capture_output=True,
                text=True,
            )

            if result.returncode == 0:
                try:
                    data = json.loads(result.stdout)
                    crash_fixed = data.get("crash_fixed", False)
                    status = "SUCCESS" if crash_fixed else "FAILED"
                    if crash_fixed:
                        success_count += 1
                    else:
                        fail_count += 1
                    typer.echo(f"{case_id:<10} {a:<40} {str(crash_fixed):<15} {status}")
                except json.JSONDecodeError:
                    typer.echo(f"{case_id:<10} {a:<40} {'?':<15} ERROR")
            else:
                pending_count += 1

    if len(cases) > 50:
        typer.echo(f"... and {len(cases) - 50} more cases")

    typer.echo()
    typer.echo(
        f"Summary: {success_count} success, {fail_count} failed, {pending_count} pending"
    )


# Registry of result keys -> filename
RESULT_KEYS = {
    "result": "result.json",
    "crashes": "crashes.json",
    "patch": "patch.patch",
    "chat": "chat.md",
    "metadata": "metadata.json",
    "fuzzing_result": "fuzzing_result.json",
}


@app.command("result")
def get_result(
    experiment_id: Annotated[str, typer.Argument(help="Experiment ID")],
    case_id: Annotated[int, typer.Argument(help="Case ID")],
    key: Annotated[
        str, typer.Argument(help="Result key (crashes, result, patch, chat, metadata)")
    ] = "result",
    agent_id: Annotated[
        str, typer.Option("--agent-id", "-a", help="Agent ID (e.g., autopatchbench-claude-sonnet-4-20250514)")
    ] = "",
    list_keys: Annotated[
        bool, typer.Option("--list-keys", "-l", help="List available keys")
    ] = False,
) -> None:
    """Get a specific result file from an experiment.

    Examples:
        experiments result default 12803 crashes --agent-id autopatchbench-claude-sonnet-4-20250514
        experiments result default 12803 result
        experiments result default 12803 patch -a gt
    """
    if list_keys:
        typer.echo("Available result keys:")
        for k, filename in RESULT_KEYS.items():
            typer.echo(f"  {k:<15} -> {filename}")
        return

    if not agent_id:
        typer.echo("Error: --agent-id is required. Specify the agent identifier.")
        typer.echo("Example: --agent-id autopatchbench-claude-sonnet-4-20250514")
        raise typer.Exit(1)

    config = GKEConfig.load()
    if not config.is_configured():
        typer.echo("Error: Not configured. Run: python -m cli setup")
        raise typer.Exit(1)

    # Resolve key to filename
    filename = RESULT_KEYS.get(key, key)

    gcs_path = f"gs://{config.bucket_name}/results/{experiment_id}/{case_id}/{agent_id}/{filename}"

    result = subprocess.run(
        ["gsutil", "cat", gcs_path],
        capture_output=True,
        text=True,
    )

    if result.returncode != 0:
        typer.echo(f"Error: Could not fetch {gcs_path}")
        typer.echo(f"  {result.stderr.strip()}")
        raise typer.Exit(1)

    # Pretty print JSON if applicable
    if filename.endswith(".json"):
        try:
            data = json.loads(result.stdout)
            typer.echo(json.dumps(data, indent=2))
        except json.JSONDecodeError:
            typer.echo(result.stdout)
    else:
        typer.echo(result.stdout)


@app.command("compare")
def compare_experiments(
    exp1: Annotated[str, typer.Argument(help="First experiment ID")],
    exp2: Annotated[str, typer.Argument(help="Second experiment ID")],
) -> None:
    """Compare two experiments."""
    config = GKEConfig.load()
    if not config.is_configured():
        typer.echo("Error: Not configured. Run: python -m cli setup")
        raise typer.Exit(1)

    typer.echo(f"Comparing: {exp1} vs {exp2}")
    typer.echo()
    typer.echo("(Comparison logic to be implemented)")
    # TODO: Implement detailed comparison
