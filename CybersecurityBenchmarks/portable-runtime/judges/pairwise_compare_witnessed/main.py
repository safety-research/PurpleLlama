#!/usr/bin/env python3
"""
Main entry point for the witnessed pairwise patch comparison analysis agent.

Runs inside ARVO containers. Sets up the workspace (worktrees, blinding,
binaries), then runs the Claude Code analyst agent which invokes witness
builders to produce standalone scripts proving each claim.

Usage:
    # Via AGENT_CONFIG env var (preferred, used by Argo template):
    AGENT_CONFIG='{"model":"claude-sonnet-4-5-20250929","max_runtime_seconds":3600}' \\
        python3 -m judges.pairwise_compare_witnessed.main \\
            --case-id 9180 \\
            --source-experiment fuzz1800_all_0212 \\
            --patcher-1 claudecode-claude-sonnet-4-5-20250929 \\
            --patcher-2 gt

    # Manual testing on debug-vm:
    python3 -m judges.pairwise_compare_witnessed.main \\
        --case-id 9180 \\
        --source-experiment fuzz1800_all_0212 \\
        --patcher-1 claudecode-claude-sonnet-4-5-20250929 \\
        --patcher-2 gt \\
        --model claude-sonnet-4-5-20250929 \\
        --output-dir /output \\
        --verbose
"""

import argparse
import asyncio
import json
import logging
import os
import sys
from pathlib import Path

from .claudecode.agent import WitnessAnalystAgent
from .setup import setup_workspace
from .types import WitnessStatus

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
LOG = logging.getLogger(__name__)


def parse_agent_config(args: argparse.Namespace) -> dict:
    """Parse analysis agent config from JSON or CLI flags.

    Priority: --agent-config flag > AGENT_CONFIG env var > individual flags.
    """
    agent_config_json = args.agent_config or os.environ.get("AGENT_CONFIG")

    if agent_config_json:
        try:
            config = json.loads(agent_config_json)
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON in agent config: {e}") from e

        return {
            "model": config.get("model", args.model),
            "max_turns": config.get("max_turns", 500),
            "max_runtime_seconds": config.get("max_runtime_seconds", 3600),
            "thinking_budget": config.get("thinking_budget"),
            "witness_time_fraction": config.get("witness_time_fraction", 0.7),
            "max_witness_time": config.get("max_witness_time", 600),
        }
    else:
        return {
            "model": args.model,
            "max_turns": args.max_turns,
            "max_runtime_seconds": args.max_runtime_seconds,
            "thinking_budget": args.thinking_budget,
            "witness_time_fraction": args.witness_time_fraction,
            "max_witness_time": args.max_witness_time,
        }


def print_summary(report) -> None:
    """Print a summary of the witnessed analysis result."""
    print("\n" + "=" * 60)
    print("Witnessed Patch Comparison Analysis Summary")
    print("=" * 60)
    print(f"Case ID:         {report.case_id}")
    print(f"Experiment:      {report.source_experiment}")
    print(f"Patcher 1:       {report.patcher_1}")
    print(f"Patcher 2:       {report.patcher_2}")
    print(f"Status:          {report.status}")
    print(f"Duration:        {report.duration_seconds:.1f}s")
    print(f"Vulnerability:   {report.vulnerability.crash_type}")
    print(f"Total claims:    {len(report.claims)}")
    print(f"  Confirmed:     {report.confirmed_count}")
    print(f"  Refuted:       {report.refuted_count}")
    print(f"  Unverifiable:  {report.unverifiable_count}")
    if report.conclusion:
        print(f"Conclusion:      {report.conclusion[:200]}")
    if report.error:
        print(f"Error:           {report.error}")
    print("=" * 60)


def main() -> int:
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Witnessed Pairwise Patch Comparison Analysis Agent",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument("--case-id", type=int, required=True, help="ARVO case ID")
    parser.add_argument(
        "--source-experiment",
        type=str,
        required=True,
        help="Source experiment ID (e.g. fuzz1800_all_0212)",
    )
    parser.add_argument(
        "--patcher-1",
        type=str,
        required=True,
        help="First patcher ID (agent-id or 'gt')",
    )
    parser.add_argument(
        "--patcher-2",
        type=str,
        required=True,
        help="Second patcher ID (agent-id or 'gt')",
    )

    parser.add_argument(
        "--output-dir",
        type=str,
        default="/output",
        help="Output directory for results (default: /output)",
    )
    parser.add_argument(
        "--model",
        type=str,
        default="claude-sonnet-4-5-20250929",
        help="Analysis LLM model",
    )
    parser.add_argument(
        "--max-turns",
        type=int,
        default=500,
        help="Max agentic loop turns (default: 500)",
    )
    parser.add_argument(
        "--max-runtime-seconds",
        type=int,
        default=3600,
        help="Max total runtime in seconds (default: 3600)",
    )
    parser.add_argument(
        "--thinking-budget",
        type=int,
        default=None,
        help="Extended thinking token budget (default: disabled)",
    )
    parser.add_argument(
        "--witness-time-fraction",
        type=float,
        default=0.7,
        help="Fraction of time budget for witness building (default: 0.7)",
    )
    parser.add_argument(
        "--max-witness-time",
        type=int,
        default=600,
        help="Max seconds per witness builder sub-agent (default: 600)",
    )
    parser.add_argument(
        "--agent-config",
        type=str,
        default=None,
        help="JSON config string (overrides individual flags)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Set up workspace but skip agent execution",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Enable verbose logging",
    )

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    try:
        agent_cfg = parse_agent_config(args)
    except ValueError as e:
        LOG.error(str(e))
        return 1

    if not args.dry_run and not os.environ.get("ANTHROPIC_API_KEY"):
        LOG.error("ANTHROPIC_API_KEY environment variable not set")
        return 1

    output_dir = Path(args.output_dir)

    LOG.info(
        f"Starting witnessed analysis: case {args.case_id}, "
        f"{args.patcher_1} vs {args.patcher_2}"
    )

    try:
        workspace = setup_workspace(
            patcher_1_id=args.patcher_1,
            patcher_2_id=args.patcher_2,
            output_dir=str(output_dir),
        )
    except Exception as e:
        LOG.exception(f"Workspace setup failed: {e}")
        return 1

    LOG.info("Workspace setup complete")

    agent = WitnessAnalystAgent(
        workspace=workspace,
        output_dir=output_dir,
        model=agent_cfg["model"],
        max_turns=agent_cfg["max_turns"],
        max_runtime_seconds=agent_cfg["max_runtime_seconds"],
        thinking_budget=agent_cfg.get("thinking_budget"),
        witness_time_fraction=agent_cfg.get("witness_time_fraction", 0.7),
        max_witness_time=agent_cfg.get("max_witness_time", 600),
        dry_run=args.dry_run,
    )

    agent.report.case_id = args.case_id
    agent.report.source_experiment = args.source_experiment

    try:
        report = asyncio.run(agent.run())
    except Exception as e:
        LOG.exception(f"Witnessed analysis agent failed: {e}")
        return 1

    print_summary(report)

    if report.status == WitnessStatus.FAILED.value and report.error:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
