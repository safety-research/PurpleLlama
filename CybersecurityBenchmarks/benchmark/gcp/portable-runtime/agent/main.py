#!/usr/bin/env python3
# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

"""
Main entry point for ARVO agent harness.

This script runs inside ARVO containers to execute patching agents.
The agent is responsible for:
1. Analyzing the original crash/vulnerability
2. Generating a patch using LLM
3. Applying and verifying the patch
4. Saving results for collection

Fuzzing/evaluation is handled separately by the evaluation pipeline.

Usage:
    python3 -m agent.main --case-id 42 --agent autopatchbench --model claude-sonnet-4-20250514
    python3 -m agent.main --case-id 42 --agent autopatchbench --dry-run
"""

import argparse
import asyncio
import logging
import os
import sys
from pathlib import Path
from typing import Dict, Type

from .base import AgentResult, BaseAgent

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
LOG = logging.getLogger(__name__)


# Registry of available agents
AGENT_REGISTRY: Dict[str, Type[BaseAgent]] = {}


def register_agent(agent_class: Type[BaseAgent]) -> Type[BaseAgent]:
    """Decorator to register an agent class."""
    AGENT_REGISTRY[agent_class.AGENT_NAME] = agent_class
    return agent_class


def get_available_agents() -> Dict[str, Type[BaseAgent]]:
    """Get all available agents, loading them lazily."""
    if not AGENT_REGISTRY:
        # Import agents to trigger registration
        try:
            from .autopatchbench import AutoPatchBenchAgent
            AGENT_REGISTRY["autopatchbench"] = AutoPatchBenchAgent
        except ImportError as e:
            LOG.warning(f"Failed to import autopatchbench agent: {e}")

    return AGENT_REGISTRY


def create_agent(
    agent_name: str,
    case_id: int,
    output_dir: Path,
    model: str,
    dry_run: bool = False,
    max_retries: int = 10,
    **kwargs,
) -> BaseAgent:
    """
    Create an agent instance by name.

    Args:
        agent_name: Name of the agent to create
        case_id: ARVO case ID
        output_dir: Output directory for results
        model: LLM model to use
        dry_run: Skip LLM calls if True
        max_retries: Maximum retry attempts
        **kwargs: Additional agent-specific arguments

    Returns:
        Configured agent instance

    Raises:
        ValueError: If agent_name is not recognized
    """
    agents = get_available_agents()

    if agent_name not in agents:
        available = ", ".join(agents.keys())
        raise ValueError(f"Unknown agent: {agent_name}. Available: {available}")

    agent_class = agents[agent_name]

    return agent_class(
        case_id=case_id,
        output_dir=output_dir,
        model=model,
        dry_run=dry_run,
        max_retries=max_retries,
        **kwargs,
    )


async def run_agent(
    agent_name: str,
    case_id: int,
    output_dir: Path,
    model: str,
    dry_run: bool = False,
    max_retries: int = 10,
    **kwargs,
) -> AgentResult:
    """
    Run an agent and return the result.

    Args:
        agent_name: Name of the agent to run
        case_id: ARVO case ID
        output_dir: Output directory for results
        model: LLM model to use
        dry_run: Skip LLM calls if True
        max_retries: Maximum retry attempts
        **kwargs: Additional agent-specific arguments

    Returns:
        AgentResult containing the patching results
    """
    agent = create_agent(
        agent_name=agent_name,
        case_id=case_id,
        output_dir=output_dir,
        model=model,
        dry_run=dry_run,
        max_retries=max_retries,
        **kwargs,
    )

    return await agent.run()


def print_summary(result: AgentResult) -> None:
    """Print a summary of the agent result."""
    print("\n" + "=" * 60)
    print("Agent Result Summary")
    print("=" * 60)
    print(f"Case ID:        {result.case_id}")
    print(f"Agent:          {result.agent_name}")
    print(f"Model:          {result.model}")
    print(f"Duration:       {result.duration_seconds:.1f}s")
    print(f"Status:         {result.status.value}")
    print(f"Crash Type:     {result.original_crash_type}")
    print(f"Patch Generated: {result.patch_generated}")
    print(f"Build Success:  {result.build_success}")
    print(f"Crash Fixed:    {result.crash_fixed}")
    print(f"LLM Calls:      {result.llm_calls}")
    print(f"Tokens Used:    {result.llm_tokens_used}")
    if result.error:
        print(f"Error:          {result.error}")
    print("=" * 60)


def main() -> int:
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="ARVO Agent Harness - Run patching agents inside containers",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        "--case-id",
        type=int,
        required=True,
        help="ARVO case ID",
    )
    parser.add_argument(
        "--agent",
        type=str,
        default="autopatchbench",
        help="Agent to run (default: autopatchbench)",
    )
    parser.add_argument(
        "--model",
        type=str,
        default="claude-sonnet-4-20250514",
        help="Anthropic model to use (default: claude-sonnet-4-20250514)",
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        default="/tmp/results",
        help="Output directory for results (default: /tmp/results)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Run without making LLM calls",
    )
    parser.add_argument(
        "--max-retries",
        type=int,
        default=10,
        help="Maximum patch generation retries (default: 10)",
    )
    parser.add_argument(
        "--max-iterations",
        type=int,
        default=5,
        help="Maximum iterations per retry round (default: 5)",
    )
    parser.add_argument(
        "--stack-depth",
        type=int,
        default=5,
        help="Number of stack frames to include (default: 5)",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Enable verbose logging",
    )
    parser.add_argument(
        "--list-agents",
        action="store_true",
        help="List available agents and exit",
    )

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # List agents mode
    if args.list_agents:
        agents = get_available_agents()
        print("Available agents:")
        for name, agent_class in agents.items():
            print(f"  - {name}: {agent_class.__doc__.split('.')[0] if agent_class.__doc__ else 'No description'}")
        return 0

    # Check for API key (unless dry run)
    if not args.dry_run and not os.environ.get("ANTHROPIC_API_KEY"):
        LOG.error("ANTHROPIC_API_KEY environment variable not set")
        return 1

    # Create output directory
    output_dir = Path(args.output_dir) / f"case_{args.case_id}" / args.agent
    if args.model:
        output_dir = output_dir / args.model

    # Run agent
    LOG.info(f"Running {args.agent} agent for case {args.case_id}")

    try:
        result = asyncio.run(
            run_agent(
                agent_name=args.agent,
                case_id=args.case_id,
                output_dir=output_dir,
                model=args.model,
                dry_run=args.dry_run,
                max_retries=args.max_retries,
                max_iterations=args.max_iterations,
                stack_ctx_depth=args.stack_depth,
            )
        )
    except ValueError as e:
        LOG.error(str(e))
        return 1
    except Exception as e:
        LOG.exception(f"Agent failed with exception: {e}")
        return 1

    # Print summary
    print_summary(result)

    # Return appropriate exit code
    if result.is_success():
        return 0
    elif result.error or result.exception:
        return 1
    else:
        return 2  # Partial success (patch generated but didn't fix)


if __name__ == "__main__":
    sys.exit(main())
