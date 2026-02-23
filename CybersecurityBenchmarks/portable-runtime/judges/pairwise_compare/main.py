#!/usr/bin/env python3
"""
Main entry point for the blinded pairwise patch comparison analysis agent.

Runs inside ARVO containers. Sets up the workspace (worktrees, blinding,
binaries), then runs the Claude Code analysis agent to compare two patches.

Usage:
    # Via AGENT_CONFIG env var (preferred, used by Argo template):
    AGENT_CONFIG='{"model":"claude-sonnet-4-5-20250929","max_runtime_seconds":1800}' \\
        python3 -m judges.pairwise_compare.main \\
            --case-id 9180 \\
            --source-experiment fuzz1800_all_0212 \\
            --patcher-1 claudecode-claude-sonnet-4-5-20250929 \\
            --patcher-2 gt

    # Manual testing on debug-vm:
    python3 -m judges.pairwise_compare.main \\
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

from .claudecode.agent import PatchAnalysisAgent
from .setup import setup_workspace
from .types import AnalysisStatus

# Configure logging
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
            "max_turns": config.get("max_turns", 200),
            "max_runtime_seconds": config.get("max_runtime_seconds", 1800),
            "thinking_budget": config.get("thinking_budget"),
        }
    else:
        return {
            "model": args.model,
            "max_turns": args.max_turns,
            "max_runtime_seconds": args.max_runtime_seconds,
            "thinking_budget": args.thinking_budget,
        }


def print_summary(report) -> None:
    """Print a summary of the analysis result."""
    print("\n" + "=" * 60)
    print("Patch Comparison Analysis Summary")
    print("=" * 60)
    print(f"Case ID:        {report.case_id}")
    print(f"Experiment:     {report.source_experiment}")
    print(f"Patcher 1:      {report.patcher_1}")
    print(f"Patcher 2:      {report.patcher_2}")
    print(f"Status:         {report.status}")
    print(f"Duration:       {report.duration_seconds:.1f}s")
    print(f"Vulnerability:  {report.vulnerability.crash_type}")
    print(f"Similarity:     {report.comparison.similarity}")
    print(f"Simpler patch:  {report.comparison.simpler_patch}")
    print(
        f"Patch A:        {report.patch_a.approach_type} ({report.patch_a.correctness})"
    )
    print(
        f"Patch B:        {report.patch_b.approach_type} ({report.patch_b.correctness})"
    )
    if report.comparison.key_differences:
        print(f"Key diffs:      {len(report.comparison.key_differences)}")
    if report.test_results:
        print(f"Test results:   {len(report.test_results)}")
    if report.error:
        print(f"Error:          {report.error}")
    print("=" * 60)


def main() -> int:
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Blinded Pairwise Patch Comparison Analysis Agent",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    # Required parameters
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

    # Optional parameters
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
        default=200,
        help="Max agentic loop turns (default: 200)",
    )
    parser.add_argument(
        "--max-runtime-seconds",
        type=int,
        default=1800,
        help="Max active runtime in seconds (default: 1800)",
    )
    parser.add_argument(
        "--thinking-budget",
        type=int,
        default=None,
        help="Extended thinking token budget (default: disabled)",
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

    # Parse agent config
    try:
        agent_cfg = parse_agent_config(args)
    except ValueError as e:
        LOG.error(str(e))
        return 1

    # Check for API key (unless dry run)
    if not args.dry_run and not os.environ.get("ANTHROPIC_API_KEY"):
        LOG.error("ANTHROPIC_API_KEY environment variable not set")
        return 1

    output_dir = Path(args.output_dir)

    LOG.info(
        f"Starting patch comparison analysis: case {args.case_id}, "
        f"{args.patcher_1} vs {args.patcher_2}"
    )

    # 1. Set up workspace (worktrees, blinding, binaries)
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

    # 2. Create and run the analysis agent
    agent = PatchAnalysisAgent(
        workspace=workspace,
        output_dir=output_dir,
        model=agent_cfg["model"],
        max_turns=agent_cfg["max_turns"],
        max_runtime_seconds=agent_cfg["max_runtime_seconds"],
        thinking_budget=agent_cfg.get("thinking_budget"),
        dry_run=args.dry_run,
    )

    # Set identification fields
    agent.report.case_id = args.case_id
    agent.report.source_experiment = args.source_experiment

    try:
        report = asyncio.run(agent.run())
    except Exception as e:
        LOG.exception(f"Analysis agent failed: {e}")
        return 1

    # 3. Print summary
    print_summary(report)

    # Return 0 on graceful completion (even if report is partial)
    if report.status == AnalysisStatus.FAILED.value and report.error:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
