# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

"""
Agent module for ARVO patching harness.

This module provides a pluggable agent architecture for running different
patching strategies inside ARVO containers.

IMPORTANT: Agents handle PATCHING ONLY. Evaluation (fuzzing) is handled
separately by the evaluation pipeline.

Available agents:
- autopatchbench: AutoPatch benchmark agent for LLM-based vulnerability patching

Usage:
    from agent import create_agent, run_agent

    # Programmatic usage
    result = await run_agent(
        agent_name="autopatchbench",
        case_id=42,
        output_dir=Path("/tmp/results"),
        model="claude-sonnet-4-20250514",
    )

    # Or via command line:
    python3 -m agent.main --case-id 42 --agent autopatchbench --model claude-sonnet-4-20250514
"""

from .base import AgentResult, AgentStatus, BaseAgent
from .main import create_agent, get_available_agents, run_agent

__all__ = [
    "AgentResult",
    "AgentStatus",
    "BaseAgent",
    "create_agent",
    "get_available_agents",
    "run_agent",
]
