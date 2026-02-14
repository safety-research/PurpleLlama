"""
Claude Code agent for blinded pairwise patch comparison analysis.

Runs a single agentic session with a time budget, producing a structured
AnalysisReport comparing two patches for the same vulnerability.
"""

import json
import logging
import os
import re
import time
from datetime import datetime
from pathlib import Path

from claude_agent_sdk import (
    AssistantMessage,
    ClaudeAgentOptions,
    ClaudeSDKClient,
    ResultMessage,
    ToolUseBlock,
)

from ..setup import WorkspaceInfo
from ..types import AnalysisReport, AnalysisStatus
from .permissions import restrict_analysis_writes
from .prompts import get_initial_prompt, get_system_prompt
from .tools import create_analysis_mcp_server

LOG = logging.getLogger(__name__)


class PatchAnalysisAgent:
    """Claude Code agent for blinded patch comparison analysis.

    Runs inside an ARVO -vul container with pre-configured worktrees
    and binaries. Produces a structured AnalysisReport comparing two
    patches.

    Configurable parameters (via constructor or AGENT_CONFIG JSON):
        model (str): LLM model name (default: claude-sonnet-4-5-20250929)
        max_turns (int): Max agentic loop iterations (default: 200)
        max_runtime_seconds (int): Max active runtime (default: 1800 = 30 min)
        thinking_budget (int): Extended thinking token budget (default: None)
    """

    def __init__(
        self,
        workspace: WorkspaceInfo,
        output_dir: Path,
        model: str | None = None,
        max_turns: int = 200,
        max_runtime_seconds: int = 1800,
        thinking_budget: int | None = None,
        dry_run: bool = False,
    ):
        self.workspace = workspace
        self.output_dir = Path(output_dir)
        self.model = model
        self.max_turns = max_turns
        self.max_runtime_seconds = max_runtime_seconds
        self.thinking_budget = thinking_budget
        self.dry_run = dry_run

        # Conversation log
        self._conversation_messages: list[dict] = []

        # Report (populated by parsing agent output)
        self.report = AnalysisReport(
            case_id=0,  # Set by caller
            source_experiment="",  # Set by caller
            patcher_1=workspace.blinding_key.patcher_1,
            patcher_2=workspace.blinding_key.patcher_2,
        )

        # CLI path
        self.cli_path = os.environ.get(
            "CLAUDE_CODE_CLI_PATH", "/agent-runtime/bin/claude"
        )

    async def run(self) -> AnalysisReport:
        """Run the analysis agent and return a structured report."""
        start_time = time.monotonic()
        self.report.status = AnalysisStatus.RUNNING.value

        try:
            if self.dry_run:
                LOG.info("Dry run -- skipping agent execution")
                self.report.status = AnalysisStatus.COMPLETED.value
                self._save_results()
                return self.report

            await self._run_agentic_session()

            self.report.duration_seconds = time.monotonic() - start_time

            if self.report.status != AnalysisStatus.FAILED.value:
                self.report.status = AnalysisStatus.COMPLETED.value

        except Exception as e:
            LOG.exception(f"Analysis agent failed: {e}")
            self.report.status = AnalysisStatus.FAILED.value
            self.report.error = str(e)
            self.report.duration_seconds = time.monotonic() - start_time

        self._save_results()
        return self.report

    async def _run_agentic_session(self) -> None:
        """Run the Claude Code agentic session."""
        session_start = time.monotonic()
        timeout_triggered = False

        # Create MCP server with analysis tools
        analysis_server = create_analysis_mcp_server()

        # Configure allowed tools
        allowed_tools = [
            "Read",
            "Write",
            "Edit",
            "Grep",
            "Glob",
            "Bash",
            "mcp__analysis__run_binary",
            "mcp__analysis__run_poc",
            "mcp__analysis__build_worktree",
            "mcp__analysis__diff_files",
        ]

        options = ClaudeAgentOptions(
            cli_path=self.cli_path,
            system_prompt=get_system_prompt(self.workspace),
            cwd="/workspace",
            allowed_tools=allowed_tools,
            mcp_servers={"analysis": analysis_server},
            can_use_tool=restrict_analysis_writes,
            permission_mode="default",
            max_turns=self.max_turns,
            model=self.model,
            max_thinking_tokens=self.thinking_budget,
        )

        initial_prompt = get_initial_prompt(self.workspace)
        LOG.info(
            f"Starting analysis session: max_turns={self.max_turns}, "
            f"max_runtime={self.max_runtime_seconds}s"
        )

        last_assistant_text = ""

        async with ClaudeSDKClient(options=options) as client:
            await client.query(initial_prompt)
            async for message in client.receive_response():
                self._process_message(message)

                # Accumulate assistant text for report extraction
                if isinstance(message, AssistantMessage):
                    for block in message.content:
                        if hasattr(block, "text") and block.text:
                            last_assistant_text += block.text

                # Check time budget
                elapsed = time.monotonic() - session_start
                if elapsed > self.max_runtime_seconds:
                    LOG.warning(f"Time budget exceeded: {elapsed:.1f}s. Interrupting.")
                    timeout_triggered = True
                    self.report.status = AnalysisStatus.TIMEOUT.value
                    await client.interrupt()
                    break

        session_elapsed = time.monotonic() - session_start
        LOG.info(
            f"Session complete: {session_elapsed:.1f}s"
            + (", TIMEOUT" if timeout_triggered else "")
        )

        # Extract structured report from the agent's final output
        self._extract_report(last_assistant_text)

    def _extract_report(self, text: str) -> None:
        """Extract the structured JSON report from the agent's output."""
        if not text:
            LOG.warning("No agent output to extract report from")
            return

        # Try to find a JSON block in the output
        json_match = re.search(r"```json\s*\n(.*?)\n\s*```", text, re.DOTALL)
        if json_match:
            json_str = json_match.group(1)
        else:
            # Try to find raw JSON object
            json_match = re.search(
                r"\{[^{}]*\"vulnerability\"[^{}]*\}", text, re.DOTALL
            )
            if json_match:
                json_str = json_match.group(0)
            else:
                LOG.warning("No JSON report found in agent output")
                self.report.full_report = text[-5000:]  # Save tail as fallback
                return

        try:
            data = json.loads(json_str)
            parsed = AnalysisReport.from_dict(data)

            # Merge parsed fields into our report (preserving identification fields)
            self.report.vulnerability = parsed.vulnerability
            self.report.patch_a = parsed.patch_a
            self.report.patch_b = parsed.patch_b
            self.report.comparison = parsed.comparison
            self.report.test_results = parsed.test_results
            self.report.differentiating_inputs = parsed.differentiating_inputs
            self.report.full_report = parsed.full_report

            LOG.info(
                f"Extracted report: similarity={self.report.comparison.similarity}, "
                f"patch_a={self.report.patch_a.approach_type}, "
                f"patch_b={self.report.patch_b.approach_type}"
            )
        except (json.JSONDecodeError, KeyError, AttributeError) as e:
            LOG.warning(f"Failed to parse JSON report: {e}")
            self.report.full_report = text[-5000:]

    def _process_message(self, message) -> None:
        """Process messages from Claude Code and accumulate conversation."""
        self._conversation_messages.append(self._serialize_message(message))

        if isinstance(message, AssistantMessage):
            for block in message.content:
                if isinstance(block, ToolUseBlock):
                    LOG.debug(f"Tool call: {block.name}")

        elif isinstance(message, ResultMessage):
            if hasattr(message, "total_cost_usd") and message.total_cost_usd:
                LOG.info(f"Total cost: ${message.total_cost_usd:.4f}")
            if hasattr(message, "duration_ms"):
                LOG.info(f"Duration: {message.duration_ms}ms")

    @staticmethod
    def _serialize_message(message) -> dict:
        """Serialize an SDK message to a JSON-compatible dict."""
        if hasattr(message, "model_dump"):
            return message.model_dump()
        if hasattr(message, "to_dict"):
            return message.to_dict()
        result = {"type": type(message).__name__}
        for attr in (
            "content",
            "role",
            "id",
            "name",
            "input",
            "text",
            "total_cost_usd",
            "duration_ms",
            "model",
        ):
            if hasattr(message, attr):
                val = getattr(message, attr)
                if val is not None:
                    result[attr] = val
        return result

    def _save_results(self) -> None:
        """Save analysis results to output directory."""
        self.output_dir.mkdir(parents=True, exist_ok=True)

        # Save structured report
        report_file = self.output_dir / "report.json"
        report_file.write_text(json.dumps(self.report.to_dict(), indent=2, default=str))
        LOG.info(f"Saved report to {report_file}")

        # Save markdown report
        if self.report.full_report:
            md_file = self.output_dir / "report.md"
            md_file.write_text(self.report.full_report)
            LOG.info(f"Saved markdown report to {md_file}")

        # Save conversation
        if self._conversation_messages:
            conv_file = self.output_dir / "conversation.json"
            conv_data = {
                "case_id": self.report.case_id,
                "source_experiment": self.report.source_experiment,
                "patcher_1": self.report.patcher_1,
                "patcher_2": self.report.patcher_2,
                "model": self.model,
                "status": self.report.status,
                "timing": {
                    "duration_seconds": self.report.duration_seconds,
                    "max_runtime_seconds": self.max_runtime_seconds,
                    "max_turns": self.max_turns,
                    "thinking_budget": self.thinking_budget,
                },
                "messages": self._conversation_messages,
            }
            conv_file.write_text(json.dumps(conv_data, indent=2, default=str))
            LOG.info(
                f"Saved conversation ({len(self._conversation_messages)} messages)"
            )
