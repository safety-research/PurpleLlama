"""
Claude Code AgentSDK-based patching agent.

Uses Claude Code's agentic capabilities to explore codebases, understand
vulnerability context, generate patches, and verify fixes -- significantly
more powerful than the baseline autopatchbench agent.
"""

import json
import logging
import os
import time

from claude_agent_sdk import (
    AssistantMessage,
    ClaudeAgentOptions,
    ClaudeSDKClient,
    ResultMessage,
    ToolUseBlock,
)

from ..base import AgentResult, AgentStatus, BaseAgent
from .permissions import restrict_file_writes
from .prompts import get_project_source_path, get_system_prompt
from shared.retry_tracker import RetryTimeTracker
from .tools import create_arvo_mcp_server

LOG = logging.getLogger(__name__)


class ClaudeCodeAgent(BaseAgent):
    """Claude Code AgentSDK-based patching agent.

    Uses Claude Code's agentic capabilities to:
    1. Explore the entire codebase (not just stack trace)
    2. Understand the vulnerability context
    3. Generate and apply patches
    4. Verify builds and fix

    Key differences from autopatchbench:
    - Uses full Claude Code agentic loop (not just LLM queries)
    - Can explore entire codebase, not limited to stack trace
    - Has access to Bash, Grep, Glob for deeper exploration
    - File writes restricted to /src/ only via can_use_tool callback

    Output interface is identical to autopatchbench:
    - result.json with patching results
    - rebuilt_binary for downstream fuzzing (via BaseAgent._save_binary_for_fuzzing)
    - patch.patch unified diff (via BaseAgent._generate_patch_diff)
    - conversation.json full structured interaction history (via _save_additional_results)

    Configurable parameters (flow through from AGENT_CONFIG JSON via **kwargs):
    - max_turns (int): Max agentic loop iterations, safety net (default: 500)
    - max_runtime_seconds (int): Max active runtime in seconds (default: 3600 = 1 hour)
        Time spent on API retries (529 overloaded) is excluded from this budget.
    - thinking_budget (int): Max tokens for extended thinking (default: None = disabled).
        When set, enables extended thinking with the specified token budget.
        Recommended values: 8000-32000 for most tasks. For Claude Opus 4.6, consider
        using higher values as it supports adaptive thinking.
    - enable_fuzzing (bool): Whether to expose the fork-mode fuzzer tool (default: False)
    - fuzz_duration (int): Seconds to run fork-mode fuzzing when enabled (default: 60)
    """

    AGENT_NAME = "claudecode"

    def __init__(
        self,
        case_id,
        output_dir,
        model=None,
        dry_run=False,
        max_retries=3,
        max_turns=500,
        max_runtime_seconds=3600,
        thinking_budget=None,
        enable_fuzzing=False,
        fuzz_duration=60,
        escalation_timeout=1800,
        **kwargs,
    ):
        super().__init__(case_id, output_dir, model, dry_run, max_retries)
        # These flow through from AGENT_CONFIG JSON via **kwargs
        self.max_turns = max_turns
        self.max_runtime_seconds = max_runtime_seconds
        self.thinking_budget = thinking_budget
        self.enable_fuzzing = enable_fuzzing
        self.fuzz_duration = fuzz_duration
        self.escalation_timeout = escalation_timeout

        # Full structured conversation log (serialized to conversation.json)
        self._conversation_messages: list[dict] = []

        # Retry time tracking (accumulated across all sessions within a run)
        self._total_excluded_retry_seconds: float = 0.0
        self._total_retry_count: int = 0

        # Get CLI path from environment or use default
        self.cli_path = os.environ.get(
            "CLAUDE_CODE_CLI_PATH", "/agent-runtime/bin/claude"
        )

    async def run(self) -> AgentResult:
        """Run the Claude Code agent patching pipeline.

        Gives the agent up to max_retries (default 10) fresh attempts to fix
        the crash, on par with the autopatchbench agents.  Each attempt starts
        a brand-new agentic session with a clean conversation and reverted
        source tree.
        """
        try:
            LOG.info(f"Starting ClaudeCode agent for case {self.case_id}")
            self.result.status = AgentStatus.RUNNING
            self.result.escalation_timeout = self.escalation_timeout

            # 0. Set up overlayfs for instant source revert between retries
            self._setup_overlays()

            # 1. Analyze crash output
            crash_output = self._analyze_crash()
            if not crash_output:
                self.result.status = AgentStatus.FAILED
                self.result.error = "Failed to reproduce crash"
                return self._finalize_and_save()

            if self.dry_run:
                LOG.info("Dry run - skipping agent execution")
                self.result.status = AgentStatus.SUCCESS
                return self._finalize_and_save()

            # 2. Retry loop — up to max_retries fresh agentic sessions
            for attempt in range(1, self.max_retries + 1):
                LOG.info(
                    f"Attempt {attempt}/{self.max_retries} for case {self.case_id}"
                )

                # Reset per-attempt state
                self.result.crash_fixed = False
                self.result.build_success = False

                # Revert source/build changes from previous attempt
                if attempt > 1:
                    self._reset_overlays()
                    self._conversation_messages.append(
                        {"type": "retry_separator", "attempt": attempt}
                    )

                success = await self._run_agentic_session(crash_output)

                if success:
                    self.result.status = AgentStatus.SUCCESS
                    LOG.info(
                        f"Agent succeeded on attempt "
                        f"{attempt}/{self.max_retries} — crash fixed!"
                    )
                    break
                else:
                    LOG.info(
                        f"Attempt {attempt}/{self.max_retries} failed — crash not fixed"
                    )

            # 3. Determine final status if no attempt succeeded
            if self.result.status != AgentStatus.SUCCESS:
                if self.result.patch_generated:
                    self.result.status = AgentStatus.PARTIAL
                    LOG.info(
                        f"All {self.max_retries} attempts exhausted — "
                        "partial (patch generated but crash not fixed)"
                    )
                else:
                    self.result.status = AgentStatus.FAILED
                    LOG.info(
                        f"All {self.max_retries} attempts exhausted — "
                        "no valid patch generated"
                    )

        except Exception as e:
            LOG.exception(f"Agent failed with exception: {e}")
            self.result.status = AgentStatus.FAILED
            self.result.exception = str(e)
        finally:
            # Capture binary and patch diff BEFORE tearing down overlays.
            # The overlay upper layer contains all source modifications; once
            # unmounted, `git diff` sees the pristine lower layer and returns
            # nothing.  _save_binary_for_fuzzing() also needs the patched
            # binary in /out/ which lives on the overlay.
            self._save_binary_for_fuzzing()
            self._generate_patch_diff()
            self._teardown_overlays()

        # Populate retry statistics in result
        self.result.excluded_retry_seconds = self._total_excluded_retry_seconds
        self.result.api_retry_count = self._total_retry_count

        return self._finalize_and_save()

    async def _run_agentic_session(self, crash_output: str) -> bool:
        """Run a single Claude Code agentic session.

        Returns True if the crash was fixed by the end of the session.

        Time budget enforcement:
        - Tracks wall-clock time and excludes API retry time (529 errors)
        - Interrupts the agent if active runtime exceeds max_runtime_seconds
        - max_turns serves as a safety net (should rarely be hit)
        """
        # Create retry tracker for this session
        retry_tracker = RetryTimeTracker()
        session_start = time.monotonic()
        timeout_triggered = False

        # Create custom MCP tools for ARVO operations
        arvo_server = create_arvo_mcp_server(self)

        # Configure Claude Code Agent with restrictions
        allowed_tools = [
            "Read",
            "Write",
            "Edit",
            "Grep",
            "Glob",
            "Bash",
            "mcp__arvo__build",
            "mcp__arvo__run_poc",
            "mcp__arvo__reset_source",
        ]
        if self.enable_fuzzing:
            allowed_tools.append("mcp__arvo__fuzz")

        options = ClaudeAgentOptions(
            cli_path=self.cli_path,
            system_prompt=get_system_prompt(),
            cwd="/src",
            allowed_tools=allowed_tools,
            mcp_servers={"arvo": arvo_server},
            can_use_tool=restrict_file_writes,
            permission_mode="default",
            max_turns=self.max_turns,
            model=self.model,
            max_thinking_tokens=self.thinking_budget,
            # 100 MB buffer — avoid JSON buffer overflow on long conversations
            # (SDK default is 1 MB, which large build outputs can exceed)
            max_buffer_size=100 * 1024 * 1024,
            # Stderr callback for API retry tracking
            stderr=retry_tracker.handle_stderr_line,
            # Allow CLI to retry through long API overload windows (default: 10)
            env={"CLAUDE_CODE_MAX_RETRIES": "500"},
        )

        # Run agentic loop with time budget enforcement
        initial_prompt = self._build_initial_prompt(crash_output)
        LOG.info(
            f"Starting agentic loop with max_turns={self.max_turns}, "
            f"max_runtime_seconds={self.max_runtime_seconds}"
        )

        async with ClaudeSDKClient(options=options) as client:
            await client.query(initial_prompt)
            async for message in client.receive_response():
                # Finalize any retry sequence when we receive a message
                retry_tracker.on_message_received()

                self._process_message(message)

                # Check time budget after each message
                elapsed = time.monotonic() - session_start
                excluded = retry_tracker.get_excluded_seconds()
                active_runtime = elapsed - excluded

                if active_runtime > self.max_runtime_seconds:
                    LOG.warning(
                        f"Time budget exceeded: {active_runtime:.1f}s active runtime "
                        f"(excluded {excluded:.1f}s from {retry_tracker.get_retry_count()} retries). "
                        f"Interrupting agent."
                    )
                    timeout_triggered = True
                    await client.interrupt()
                    break

        # Log session timing summary
        session_elapsed = time.monotonic() - session_start
        session_excluded = retry_tracker.get_excluded_seconds()
        session_active = session_elapsed - session_excluded
        LOG.info(
            f"Session complete: {session_elapsed:.1f}s elapsed, "
            f"{session_active:.1f}s active, "
            f"{session_excluded:.1f}s excluded ({retry_tracker.get_retry_count()} retries)"
            + (", TIMEOUT" if timeout_triggered else "")
        )

        # Accumulate retry stats across sessions
        self._total_excluded_retry_seconds += session_excluded
        self._total_retry_count += retry_tracker.get_retry_count()

        return self.result.crash_fixed

    def _analyze_crash(self) -> str | None:
        """Analyze the original crash using arvo command."""
        from .types import get_sanitizer_crash_type

        LOG.info("Analyzing original crash...")
        result = self._run_command(["arvo"], timeout=120)
        crash_output = result.stdout + result.stderr

        self.result.original_crash_output = crash_output
        self.result.original_crash_type = get_sanitizer_crash_type(crash_output)
        LOG.info(f"Detected crash type: {self.result.original_crash_type}")

        # Check if crash reproduced
        if "ERROR: AddressSanitizer" in crash_output or "SUMMARY:" in crash_output:
            return crash_output

        LOG.warning("Crash did not reproduce")
        return None

    def _build_initial_prompt(self, crash_output: str) -> str:
        """Build the initial prompt for the agentic loop."""
        source_path = get_project_source_path()
        return f"""A crash was detected in this project. Your task is to find and fix the vulnerability.

## Crash Output
```
{crash_output[:8000]}
```

## Your approach (follow the phases in your system prompt)

**Phase 1 — Hypothesize:** Read the crash output above. Before exploring ANY code, write down 2-4 hypotheses about what the root cause could be. Consider both the crash site AND upstream callers.

**Phase 2 — Investigate:** For each hypothesis, gather evidence from the code. Trace the data flow upstream from the crash. Check declarations, definitions, and symbols across files. Mark each hypothesis CONFIRMED or REJECTED.

**Phase 3 — Patch:** Fix the confirmed root cause with a minimal edit. You can only write to files in {source_path}/.

**Phase 4 — Verify:** Build with mcp__arvo__build, then test with mcp__arvo__run_poc. If the crash persists, your hypothesis was wrong — go back to Phase 1 with new hypotheses targeting a different subsystem. Do NOT retry the same approach.

Start with Phase 1: read the crash output and write your hypotheses.
"""

    def _process_message(self, message):
        """Process messages from Claude Code, update result, and accumulate history."""
        # Accumulate full message for conversation.json
        self._conversation_messages.append(self._serialize_message(message))

        if isinstance(message, AssistantMessage):
            for block in message.content:
                if isinstance(block, ToolUseBlock):
                    self.result.llm_calls += 1
                    # Track if patch was applied
                    if block.name in ["Edit", "Write"]:
                        self.result.patch_generated = True
                        file_path = block.input.get("file_path", "")
                        if file_path:
                            self.result.patched_file_path = file_path
                        LOG.debug(f"Patch applied to: {file_path}")

        elif isinstance(message, ResultMessage):
            if hasattr(message, "total_cost_usd") and message.total_cost_usd:
                LOG.info(f"Total cost: ${message.total_cost_usd:.4f}")
            if hasattr(message, "duration_ms"):
                LOG.info(f"Duration: {message.duration_ms}ms")

    @staticmethod
    def _serialize_message(message) -> dict:
        """Serialize an SDK message to a JSON-compatible dict."""
        # Use the SDK's built-in serialization if available
        if hasattr(message, "model_dump"):
            return message.model_dump()
        if hasattr(message, "to_dict"):
            return message.to_dict()
        # Fallback: extract what we can
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

    def _save_additional_results(self) -> None:
        """Save full structured conversation history as JSON."""
        if self._conversation_messages:
            conv_file = self.output_dir / "conversation.json"
            conv_data = {
                "case_id": self.result.case_id,
                "agent_name": self.AGENT_NAME,
                "agent_id": self.result.agent_id,
                "model": self.model,
                "status": self.result.status.value,
                # Time budget tracking
                "timing": {
                    "duration_seconds": self.result.duration_seconds,
                    "active_runtime_seconds": self.result.active_runtime_seconds,
                    "excluded_retry_seconds": self._total_excluded_retry_seconds,
                    "api_retry_count": self._total_retry_count,
                    "max_runtime_seconds": self.max_runtime_seconds,
                    "max_turns": self.max_turns,
                    "thinking_budget": self.thinking_budget,
                },
                "messages": self._conversation_messages,
            }
            conv_file.write_text(json.dumps(conv_data, indent=2, default=str))
            LOG.info(
                f"Saved conversation ({len(self._conversation_messages)} messages) "
                f"to {conv_file}"
            )
