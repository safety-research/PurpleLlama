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
    model: Annotated[
        Optional[str], typer.Option("--model", "-m", help="Filter by model")
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

    typer.echo(f"{'CASE':<10} {'MODEL':<30} {'CRASH_FIXED':<15} {'STATUS'}")
    typer.echo("-" * 70)

    for case_id in cases[:50]:  # Limit output
        # Check for model results
        models_to_check = [model] if model else ["claude-sonnet-4-20250514", "gt"]

        for m in models_to_check:
            result_path = f"{base_path}/{case_id}/{m}/result.json"
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
                    typer.echo(f"{case_id:<10} {m:<30} {str(crash_fixed):<15} {status}")
                except json.JSONDecodeError:
                    typer.echo(f"{case_id:<10} {m:<30} {'?':<15} ERROR")
            else:
                pending_count += 1

    if len(cases) > 50:
        typer.echo(f"... and {len(cases) - 50} more cases")

    typer.echo()
    typer.echo(
        f"Summary: {success_count} success, {fail_count} failed, {pending_count} pending"
    )


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
