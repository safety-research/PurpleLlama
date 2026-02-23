"""
Claude Code agent for witnessed pairwise patch comparison analysis.

Runs a single analyst agentic session that:
  1. Analyzes two patches (blinded as A/B)
  2. Forms testable claims about their differences
  3. Invokes witness-builder sub-agents via the run_witness MCP tool
  4. Reviews witness results and writes a final conclusion

The run_witness tool spawns separate CC sub-sessions under the hood,
but from the analyst's perspective they are just tool calls.
"""

import json
import logging
import os
import re
import subprocess
import tarfile
import time
from pathlib import Path

from claude_agent_sdk import (
    AssistantMessage,
    ClaudeAgentOptions,
    ResultMessage,
    ToolUseBlock,
)

from shared.api_retry import RetryEvent, resilient_sdk_session
from shared.retry_tracker import RetryTimeTracker
from judges.pairwise_compare.setup import WorkspaceInfo
from ..types import Claim, WitnessReport, WitnessStatus
from .permissions import restrict_witnessed_writes
from .prompts import get_analyst_initial_prompt, get_analyst_system_prompt
from .tools import create_witnessed_analysis_mcp_server

LOG = logging.getLogger(__name__)

WITNESSES_DIR = "/output/witnesses"


class WitnessAnalystAgent:
    """Claude Code agent for witnessed patch comparison analysis.

    Runs inside an ARVO -vul container with pre-configured worktrees
    and binaries. Drives the full witnessed analysis workflow in a
    single CC session.

    Configurable parameters (via constructor or AGENT_CONFIG JSON):
        model (str): LLM model name
        max_turns (int): Max agentic loop iterations (default: 500)
        max_runtime_seconds (int): Total runtime budget for the entire judge (default: 3600)
        thinking_budget (int): Extended thinking token budget (default: None)
        witness_time_fraction (float): Fraction of budget for witnesses (default: 0.7)
        max_witness_time (int): Per-claim budget covering generate-critique loop (default: 900)
        max_critic_time (int): Per-critic evaluation budget (default: 120)
        max_critic_attempts (int): Max generate-critique iterations per claim (default: 3)
    """

    def __init__(
        self,
        workspace: WorkspaceInfo,
        output_dir: Path,
        model: str | None = None,
        max_turns: int = 500,
        max_runtime_seconds: int = 3600,
        thinking_budget: int | None = None,
        witness_time_fraction: float = 0.7,
        max_witness_time: int = 900,
        max_critic_time: int = 120,
        max_critic_attempts: int = 3,
        dry_run: bool = False,
    ):
        self.workspace = workspace
        self.output_dir = Path(output_dir)
        self.model = model
        self.max_turns = max_turns
        self.max_runtime_seconds = max_runtime_seconds
        self.thinking_budget = thinking_budget
        self.witness_time_fraction = witness_time_fraction
        self.max_witness_time = max_witness_time
        self.max_critic_time = max_critic_time
        self.max_critic_attempts = max_critic_attempts
        self.dry_run = dry_run

        self._conversation_messages: list[dict] = []

        self.report = WitnessReport(
            case_id=0,
            source_experiment="",
            patcher_1=workspace.blinding_key.patcher_1,
            patcher_2=workspace.blinding_key.patcher_2,
        )

        self.cli_path = os.environ.get(
            "CLAUDE_CODE_CLI_PATH", "/agent-runtime/bin/claude"
        )

    async def run(self) -> WitnessReport:
        """Run the witnessed analysis and return the report."""
        start_time = time.monotonic()
        self.report.status = WitnessStatus.RUNNING.value

        try:
            if self.dry_run:
                LOG.info("Dry run -- skipping agent execution")
                self.report.status = WitnessStatus.COMPLETED.value
                self._save_results()
                return self.report

            await self._run_analyst_session()

            self.report.duration_seconds = time.monotonic() - start_time

            if self.report.status != WitnessStatus.FAILED.value:
                self.report.status = WitnessStatus.COMPLETED.value

        except Exception as e:
            LOG.exception(f"Witnessed analysis agent failed: {e}")
            self.report.status = WitnessStatus.FAILED.value
            self.report.error = str(e)
            self.report.duration_seconds = time.monotonic() - start_time

        self._save_results()
        return self.report

    async def _run_analyst_session(self) -> None:
        """Run the analyst CC session."""
        session_start = time.monotonic()
        timeout_triggered = False

        mcp_server = create_witnessed_analysis_mcp_server(
            cli_path=self.cli_path,
            model=self.model,
            thinking_budget=self.thinking_budget,
            max_witness_time=self.max_witness_time,
            max_critic_time=self.max_critic_time,
            max_critic_attempts=self.max_critic_attempts,
            patch_a_diff=self.workspace.patch_a_diff,
            patch_b_diff=self.workspace.patch_b_diff,
            permissions_callback=restrict_witnessed_writes,
            include_run_witness=True,
        )

        allowed_tools = [
            "Read",
            "Write",
            "Edit",
            "Grep",
            "Glob",
            "Bash",
            "mcp__witnessed__run_binary",
            "mcp__witnessed__run_poc",
            "mcp__witnessed__build_worktree",
            "mcp__witnessed__diff_files",
            "mcp__witnessed__compile_harness",
            "mcp__witnessed__run_witness",
        ]

        initial_prompt = get_analyst_initial_prompt(self.workspace)
        LOG.info(
            f"Starting witnessed analysis session: max_turns={self.max_turns}, "
            f"max_runtime={self.max_runtime_seconds}s"
        )

        last_assistant_text = ""
        retry_tracker = RetryTimeTracker()

        options = ClaudeAgentOptions(
            cli_path=self.cli_path,
            system_prompt=get_analyst_system_prompt(self.workspace),
            cwd="/workspace",
            allowed_tools=allowed_tools,
            mcp_servers={"witnessed": mcp_server},
            can_use_tool=restrict_witnessed_writes,
            permission_mode="default",
            max_turns=self.max_turns,
            model=self.model,
            max_thinking_tokens=self.thinking_budget,
            max_buffer_size=100 * 1024 * 1024,
            env={"CLAUDE_CODE_MAX_RETRIES": "500"},
            stderr=retry_tracker.handle_stderr_line,
        )

        async for item in resilient_sdk_session(
            options, initial_prompt, retry_tracker=retry_tracker,
        ):
            if isinstance(item, RetryEvent):
                last_assistant_text = ""
                timeout_triggered = False
                continue
            client, message = item

            retry_tracker.on_message_received()
            self._process_message(message)

            if isinstance(message, AssistantMessage):
                for block in message.content:
                    if hasattr(block, "text") and block.text:
                        last_assistant_text += block.text

            elapsed = time.monotonic() - session_start
            excluded = retry_tracker.get_excluded_seconds()
            active = elapsed - excluded
            if active > self.max_runtime_seconds:
                LOG.warning(
                    f"Time budget exceeded: {active:.1f}s active "
                    f"(excluded {excluded:.1f}s from {retry_tracker.get_retry_count()} retries). Interrupting."
                )
                timeout_triggered = True
                self.report.status = WitnessStatus.TIMEOUT.value
                await client.interrupt()
                break

        session_elapsed = time.monotonic() - session_start
        session_excluded = retry_tracker.get_excluded_seconds()
        LOG.info(
            f"Analyst session complete: {session_elapsed:.1f}s"
            + (f", {session_excluded:.1f}s excluded ({retry_tracker.get_retry_count()} retries)" if session_excluded > 0 else "")
            + (", TIMEOUT" if timeout_triggered else "")
        )

        self._extract_report(last_assistant_text)
        self._collect_witness_results()

    def _extract_report(self, text: str) -> None:
        """Extract the structured JSON report from the analyst's output."""
        if not text:
            LOG.warning("No agent output to extract report from")
            return

        json_match = re.search(r"```json\s*\n(.*?)\n\s*```", text, re.DOTALL)
        if json_match:
            json_str = json_match.group(1)
        else:
            json_match = re.search(
                r"\{[^{}]*\"claims\"[^{}]*\}", text, re.DOTALL
            )
            if json_match:
                json_str = json_match.group(0)
            else:
                LOG.warning("No JSON report found in agent output")
                self.report.full_report = text[-5000:]
                return

        try:
            data = json.loads(json_str)
            parsed = WitnessReport.from_dict(data)

            self.report.vulnerability = parsed.vulnerability
            self.report.patch_a = parsed.patch_a
            self.report.patch_b = parsed.patch_b
            self.report.claims = parsed.claims
            self.report.conclusion = parsed.conclusion
            self.report.full_report = parsed.full_report

            LOG.info(
                f"Extracted report: {len(self.report.claims)} claims, "
                f"{self.report.confirmed_count} confirmed, "
                f"{self.report.refuted_count} refuted, "
                f"{self.report.unverifiable_count} unverifiable"
            )
        except (json.JSONDecodeError, KeyError, AttributeError) as e:
            LOG.warning(f"Failed to parse JSON report: {e}")
            self.report.full_report = text[-5000:]

    def _collect_witness_results(self) -> None:
        """Scan the witnesses directory for result.json files and merge
        any witness outcomes not already captured in the report."""
        witnesses_path = Path(WITNESSES_DIR)
        if not witnesses_path.exists():
            return

        for claim_dir in sorted(witnesses_path.iterdir()):
            if not claim_dir.is_dir():
                continue
            result_file = claim_dir / "result.json"
            if not result_file.exists():
                continue

            try:
                result_data = json.loads(result_file.read_text())
            except (json.JSONDecodeError, OSError):
                continue

            claim_id = result_data.get("claim_id", claim_dir.name)

            matching = [c for c in self.report.claims if c.id == claim_id]
            if matching:
                claim = matching[0]
                if claim.status in ("pending", ""):
                    claim.status = result_data.get("status", claim.status)
                claim.witness_script = f"{claim_id}/witness.sh"
                claim.witness_output = (
                    result_data.get("stdout", "")
                    + result_data.get("stderr", "")
                )[:5000]
                claim.witness_exit_code = result_data.get("exit_code", -1)

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

        report_file = self.output_dir / "report.json"
        report_file.write_text(
            json.dumps(self.report.to_dict(), indent=2, default=str)
        )
        LOG.info(f"Saved report to {report_file}")

        if self.report.full_report:
            md_file = self.output_dir / "report.md"
            md_file.write_text(self.report.full_report)
            LOG.info(f"Saved markdown report to {md_file}")

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
                    "witness_time_fraction": self.witness_time_fraction,
                    "max_witness_time": self.max_witness_time,
                },
                "claims_summary": {
                    "total": len(self.report.claims),
                    "confirmed": self.report.confirmed_count,
                    "refuted": self.report.refuted_count,
                    "unverifiable": self.report.unverifiable_count,
                },
                "messages": self._conversation_messages,
            }
            conv_file.write_text(json.dumps(conv_data, indent=2, default=str))
            LOG.info(
                f"Saved conversation ({len(self._conversation_messages)} messages)"
            )

        # Create witnesses tarball for reproducibility
        witnesses_path = Path(WITNESSES_DIR)
        if witnesses_path.exists() and any(witnesses_path.iterdir()):
            tarball_path = self.output_dir / "witnesses.tar.gz"
            try:
                with tarfile.open(tarball_path, "w:gz") as tar:
                    tar.add(str(witnesses_path), arcname="witnesses")
                LOG.info(f"Created witnesses tarball: {tarball_path}")
            except Exception as e:
                LOG.warning(f"Failed to create witnesses tarball: {e}")
