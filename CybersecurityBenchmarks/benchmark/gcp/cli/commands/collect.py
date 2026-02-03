"""
Collect command for downloading results from GCS.
"""

from pathlib import Path
from typing import Annotated, Optional

import typer

from ..gcp_utils import load_config, run_gsutil
from ..output import echo_error, echo_info, echo_success


def collect(
    output: Annotated[Path, typer.Option(help="Output directory")] = Path("./results"),
    cases: Annotated[
        Optional[str], typer.Option(help="Specific case IDs to collect")
    ] = None,
    run_id: Annotated[
        Optional[str], typer.Option("--run-id", "-r", help="Collect results for a specific run only")
    ] = None,
) -> None:
    """Collect results from GCS.

    By default, collects all results. Use --run-id to collect results from a
    specific benchmark run, or --cases to filter by case IDs.
    """
    config = load_config()
    if not config:
        echo_error("GCP not configured. Run 'setup' first.")
        raise typer.Exit(1)

    bucket = config["bucket_name"]
    output.mkdir(parents=True, exist_ok=True)

    typer.echo(f"Collecting results from gs://{bucket}/results/")
    typer.echo(f"Output directory: {output}")

    # If run_id specified, get the manifest to know which cases/agents to collect
    if run_id:
        from .runs import get_run_manifest
        manifest = get_run_manifest(run_id, bucket)
        if not manifest:
            echo_error(f"Run not found: {run_id}")
            raise typer.Exit(1)

        typer.echo(f"Run ID: {run_id}")
        typer.echo(f"Cases: {manifest.total_cases}")
        typer.echo(f"Agents: {', '.join(manifest.config.get('agents', []))}")
        typer.echo()

        # Collect results for this specific run
        case_list = manifest.config.get("cases", [])
        agents = manifest.config.get("agents", [])

        for case_id in case_list:
            for agent in agents:
                if agent == "gt":
                    result_path = f"gs://{bucket}/results/case_{case_id}/gt/{run_id}/"
                else:
                    result_path = f"gs://{bucket}/results/case_{case_id}/{agent}/{run_id}/"

                # Check if path exists
                check = run_gsutil(["ls", result_path], check=False)
                if check.returncode == 0:
                    echo_info(f"Downloading case_{case_id}/{agent}/{run_id}...")
                    # Create output directory structure
                    local_path = output / f"case_{case_id}" / (agent if agent != "gt" else "gt") / run_id
                    local_path.mkdir(parents=True, exist_ok=True)
                    run_gsutil(
                        ["-m", "cp", "-r", f"{result_path}*", str(local_path)],
                        check=False,
                    )

        echo_success(f"Results for run {run_id} saved to {output}")
        return

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
