"""
Submit command for witnessed analysis workflows.

Submits Argo workflows that run witnessed pairwise patch comparison
analysis between any two patchers for each case. Each claim is backed
by a standalone witness script.
"""

import json
import re
import subprocess
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Optional

import typer
import yaml

from ..argo import get_current_user, submit_workflow
from ..config import GKEConfig, get_script_dir, parse_cases
from ..output import echo_error, echo_info, echo_success, echo_warning


AUTOPATCH_META_DIR = get_script_dir() / "datasets" / "autopatch" / "arvo_meta"


def _get_project_for_case(case_id: int) -> str:
    """Load project name from arvo_meta/{case_id}-meta.json."""
    meta_file = AUTOPATCH_META_DIR / f"{case_id}-meta.json"
    if meta_file.exists():
        with open(meta_file) as f:
            meta = json.load(f)
        return meta.get("arvo_metadata", {}).get("project", "")
    return ""


def _sanitize_name(name: str) -> str:
    """Convert a name to valid Kubernetes/Argo task name component."""
    safe = re.sub(r"[^a-z0-9-]", "-", str(name).lower())
    safe = re.sub(r"-+", "-", safe)
    safe = safe.strip("-")
    return safe[:63]


def _resolve_pairs(
    reference: Optional[str],
    pairs_str: Optional[str],
    agents: Optional[str],
) -> list[tuple[str, str]]:
    """Resolve patcher pairs from CLI flags.

    Modes:
        --reference X --agents A,B     -> [(A, X), (B, X)]
        --pairs "A:B,C:D"              -> [(A, B), (C, D)]
    """
    result = []

    if pairs_str:
        for pair in pairs_str.split(","):
            parts = pair.strip().split(":")
            if len(parts) != 2:
                raise ValueError(
                    f"Invalid pair format: '{pair}'. Expected 'patcher1:patcher2'"
                )
            result.append((parts[0].strip(), parts[1].strip()))
        return result

    if not agents:
        raise ValueError("--agents is required with --reference")

    agent_list = [a.strip() for a in agents.split(",")]

    if reference:
        for agent in agent_list:
            if agent != reference:
                result.append((agent, reference))
        return result

    raise ValueError("Specify one of: --reference or --pairs")


def _generate_witnessed_workflow_yaml(
    base_workflow_path: Path,
    pairs: list[tuple[str, str]],
    analysis_model: str,
    analysis_config: dict,
) -> str:
    """Generate witnessed analysis workflow YAML with case pipeline template."""
    with open(base_workflow_path) as f:
        workflow = yaml.safe_load(f)

    case_tasks: list[dict] = []

    for patcher_1, patcher_2 in pairs:
        pair_name = _sanitize_name(f"{patcher_1}-vs-{patcher_2}")

        agent_config_json = json.dumps(
            {
                "model": analysis_model,
                **analysis_config,
            },
            separators=(",", ":"),
        )

        success_path = (
            "analysis%2Fwitnessed-analysis%2F"
            "{{workflow.parameters.analysis-experiment}}%2F"
            "{{inputs.parameters.case-id}}%2F"
            f"{patcher_1}-vs-{patcher_2}%2F_SUCCESS"
        )

        case_tasks.append(
            {
                "name": f"chk-{pair_name}",
                "template": "check-completion",
                "continueOn": {"failed": True},
                "arguments": {
                    "parameters": [
                        {
                            "name": "bucket",
                            "value": "{{workflow.parameters.bucket}}",
                        },
                        {
                            "name": "path",
                            "value": success_path,
                        },
                    ]
                },
            }
        )

        case_tasks.append(
            {
                "name": f"witness-{pair_name}",
                "dependencies": [f"chk-{pair_name}"],
                "when": f'"{{{{tasks.chk-{pair_name}.outputs.parameters.status}}}}" == "needed"',
                "templateRef": {
                    "name": "arvo-witnessed-analysis",
                    "template": "witnessed-analysis",
                },
                "arguments": {
                    "parameters": [
                        {
                            "name": "case-id",
                            "value": "{{inputs.parameters.case-id}}",
                        },
                        {
                            "name": "project",
                            "value": "{{inputs.parameters.project}}",
                        },
                        {"name": "patcher-1-id", "value": patcher_1},
                        {"name": "patcher-2-id", "value": patcher_2},
                        {"name": "analysis-model", "value": analysis_model},
                        {"name": "agent-config", "value": agent_config_json},
                        {
                            "name": "source-experiment",
                            "value": "{{workflow.parameters.source-experiment}}",
                        },
                        {
                            "name": "analysis-experiment",
                            "value": "{{workflow.parameters.analysis-experiment}}",
                        },
                        {
                            "name": "bucket",
                            "value": "{{workflow.parameters.bucket}}",
                        },
                        {
                            "name": "registry",
                            "value": "{{workflow.parameters.registry}}",
                        },
                        {
                            "name": "build-version",
                            "value": "{{workflow.parameters.build-version}}",
                        },
                        {
                            "name": "use-spot",
                            "value": "{{workflow.parameters.use-spot}}",
                        },
                    ]
                },
            }
        )

    case_pipeline_template = {
        "name": "case-witnessed-pipeline",
        "inputs": {
            "parameters": [
                {"name": "case-id"},
                {"name": "project"},
            ]
        },
        "dag": {
            "failFast": False,
            "tasks": case_tasks,
        },
    }

    workflow["spec"]["templates"].append(case_pipeline_template)
    return yaml.dump(workflow, default_flow_style=False, width=200)


def submit_witnessed_analysis(
    source_experiment: str,
    cases: Optional[str] = None,
    reference: Optional[str] = None,
    pairs: Optional[str] = None,
    agents: Optional[str] = None,
    analysis_experiment: Optional[str] = None,
    analysis_model: str = "claude-sonnet-4-5-20250929",
    max_runtime_seconds: int = 3600,
    max_witness_time: int = 600,
    witness_time_fraction: float = 0.7,
    thinking_budget: Optional[int] = None,
    build_version: str = "latest",
    config_file: Optional[Path] = None,
    use_spot: bool = True,
    dry_run: bool = False,
) -> None:
    """Submit a witnessed analysis workflow."""
    gke_config = GKEConfig.load()
    if not gke_config.is_configured():
        echo_error("Not configured. Run: python -m cli setup")
        raise typer.Exit(1)

    if config_file:
        import json5

        with open(config_file) as f:
            config = json5.load(f)

        source_experiment = config.get("source_experiment", source_experiment)
        cases = cases or config.get("cases")
        reference = reference or config.get("reference")
        agents = agents or config.get("agents")
        if isinstance(agents, list):
            agents = ",".join(agents)
        if isinstance(cases, list):
            cases = ",".join(str(c) for c in cases)
        pairs = pairs or config.get("pairs")
        analysis_model = config.get("analysis_model", analysis_model)
        max_runtime_seconds = config.get("max_runtime_seconds", max_runtime_seconds)
        max_witness_time = config.get("max_witness_time", max_witness_time)
        witness_time_fraction = config.get(
            "witness_time_fraction", witness_time_fraction
        )
        thinking_budget = config.get("thinking_budget", thinking_budget)
        build_version = config.get("build_version", build_version)
        use_spot = config.get("use_spot", use_spot)

    if not source_experiment:
        echo_error("--source-experiment is required")
        raise typer.Exit(1)

    if not cases:
        echo_error("--cases is required")
        raise typer.Exit(1)

    if isinstance(cases, str):
        case_ids = parse_cases(cases)
    else:
        case_ids = cases

    try:
        pair_list = _resolve_pairs(reference, pairs, agents)
    except ValueError as e:
        echo_error(str(e))
        raise typer.Exit(1)

    if not pair_list:
        echo_error(
            "No pairs to analyze. Check --reference/--pairs and --agents."
        )
        raise typer.Exit(1)

    if not analysis_experiment:
        analysis_experiment = (
            f"witnessed-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
        )

    typer.echo("=" * 60)
    typer.echo("Witnessed Analysis Submission")
    typer.echo("=" * 60)
    typer.echo(f"Source experiment:   {source_experiment}")
    typer.echo(f"Analysis experiment: {analysis_experiment}")
    typer.echo(f"Cases:               {len(case_ids)}")
    typer.echo(f"Pairs:               {len(pair_list)}")
    for p1, p2 in pair_list:
        typer.echo(f"  - {p1} vs {p2}")
    typer.echo(f"Analysis model:      {analysis_model}")
    typer.echo(f"Max runtime:         {max_runtime_seconds}s")
    typer.echo(f"Max witness time:    {max_witness_time}s")
    typer.echo(f"Witness fraction:    {witness_time_fraction}")
    typer.echo(f"Total jobs:          {len(case_ids) * len(pair_list)}")
    typer.echo()

    analysis_config = {
        "max_runtime_seconds": max_runtime_seconds,
        "max_witness_time": max_witness_time,
        "witness_time_fraction": witness_time_fraction,
    }
    if thinking_budget:
        analysis_config["thinking_budget"] = thinking_budget

    base_workflow_path = (
        get_script_dir() / "argo" / "workflows" / "witnessed-analysis.yaml"
    )
    workflow_yaml = _generate_witnessed_workflow_yaml(
        base_workflow_path,
        pair_list,
        analysis_model,
        analysis_config,
    )

    cases_json = json.dumps(
        [
            {"case_id": str(c), "project": _get_project_for_case(c)}
            for c in case_ids
        ]
    )

    parameters = {
        "source-experiment": source_experiment,
        "analysis-experiment": analysis_experiment,
        "bucket": gke_config.bucket_name,
        "registry": gke_config.artifact_registry,
        "build-version": build_version,
        "cases-json": cases_json,
        "use-spot": str(use_spot).lower(),
    }

    from ..argo import apply_templates

    typer.echo("Applying Argo workflow templates...")
    templates_dir = get_script_dir() / "argo" / "templates"
    if not apply_templates(str(templates_dir)):
        echo_error("Failed to apply workflow templates.")
        raise typer.Exit(1)
    typer.echo()

    if dry_run:
        typer.echo("Dry run - would submit workflow with:")
        for key, value in parameters.items():
            if key == "cases-json":
                typer.echo(f"  {key}: [{len(case_ids)} cases]")
            else:
                typer.echo(f"  {key}: {value}")
        return

    typer.echo("Submitting witnessed analysis workflow...")
    temp_workflow_path = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".yaml", delete=False
        ) as temp_file:
            temp_file.write(workflow_yaml)
            temp_workflow_path = temp_file.name

        workflow_name = submit_workflow(temp_workflow_path, parameters)
    finally:
        if temp_workflow_path:
            try:
                Path(temp_workflow_path).unlink()
            except OSError:
                pass

    if workflow_name:
        typer.echo()
        typer.echo(f"Workflow submitted: {workflow_name}")
        typer.echo()
        typer.echo("Monitor:")
        typer.echo(f"  python -m cli status {workflow_name}")
        typer.echo(f"  python -m cli status {workflow_name} -w")
        typer.echo()
        typer.echo("Results will be at:")
        typer.echo(
            f"  gs://{gke_config.bucket_name}/analysis/witnessed-analysis/"
            f"{analysis_experiment}/"
        )
        typer.echo()
        typer.echo("Replay witnesses:")
        typer.echo(
            f"  python -m cli debug-vm launch <case-id> --type witness "
            f"-e {analysis_experiment} --patcher-1 <p1> --patcher-2 <p2>"
        )
    else:
        echo_error("Failed to submit workflow.")
        raise typer.Exit(1)
