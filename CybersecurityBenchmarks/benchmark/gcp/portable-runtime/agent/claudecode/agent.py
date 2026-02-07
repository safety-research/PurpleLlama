"""
Claude Code AgentSDK-based patching agent.

Uses Claude Code's agentic capabilities to explore codebases, understand
vulnerability context, generate patches, and verify fixes -- significantly
more powerful than the baseline autopatchbench agent.
"""

import json
import logging
import os

from claude_agent_sdk import (
    AssistantMessage,
    ClaudeAgentOptions,
    ClaudeSDKClient,
    ResultMessage,
    TextBlock,
    ToolResultBlock,
    ToolUseBlock,
)

from ..base import AgentResult, AgentStatus, BaseAgent
from .permissions import restrict_file_writes
from .prompts import ARVO_SYSTEM_PROMPT
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
    - max_turns (int): Max agentic loop iterations (default: 50)
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
        max_retries=10,
        max_turns=50,
        enable_fuzzing=False,
        fuzz_duration=60,
        **kwargs,
    ):
        super().__init__(case_id, output_dir, model, dry_run, max_retries)
        # These flow through from AGENT_CONFIG JSON via **kwargs
        self.max_turns = max_turns
        self.enable_fuzzing = enable_fuzzing
        self.fuzz_duration = fuzz_duration

        # Full structured conversation log (serialized to conversation.json)
        self._conversation_messages: list[dict] = []

        # Get CLI path from environment or use default
        self.cli_path = os.environ.get(
            "CLAUDE_CODE_CLI_PATH", "/agent-runtime/bin/claude"
        )

    async def run(self) -> AgentResult:
        """Run the Claude Code agent patching pipeline."""
        try:
            LOG.info(f"Starting ClaudeCode agent for case {self.case_id}")
            self.result.status = AgentStatus.RUNNING

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

            # 2. Create custom MCP tools for ARVO operations
            arvo_server = create_arvo_mcp_server(self)

            # 3. Configure Claude Code Agent with restrictions
            allowed_tools = [
                "Read",
                "Write",
                "Edit",
                "Grep",
                "Glob",
                "Bash",
                "mcp__arvo__build",
                "mcp__arvo__run_poc",
            ]
            if self.enable_fuzzing:
                allowed_tools.append("mcp__arvo__fuzz")

            options = ClaudeAgentOptions(
                cli_path=self.cli_path,
                system_prompt=ARVO_SYSTEM_PROMPT,
                cwd="/src",
                allowed_tools=allowed_tools,
                mcp_servers={"arvo": arvo_server},
                can_use_tool=restrict_file_writes,
                permission_mode="default",
                max_turns=self.max_turns,
                model=self.model,
            )

            # 4. Run agentic loop
            initial_prompt = self._build_initial_prompt(crash_output)
            LOG.info(f"Starting agentic loop with max_turns={self.max_turns}")

            async with ClaudeSDKClient(options=options) as client:
                await client.query(initial_prompt)
                async for message in client.receive_response():
                    self._process_message(message)

            # 5. Determine final status
            # (run_poc tool updates crash_fixed directly)
            if self.result.crash_fixed:
                self.result.status = AgentStatus.SUCCESS
                LOG.info("Agent completed successfully - crash fixed!")
            elif self.result.patch_generated:
                self.result.status = AgentStatus.PARTIAL
                LOG.info(
                    "Agent completed with partial success - "
                    "patch generated but crash not fixed"
                )
            else:
                self.result.status = AgentStatus.FAILED
                LOG.info("Agent failed - no valid patch generated")

        except Exception as e:
            LOG.exception(f"Agent failed with exception: {e}")
            self.result.status = AgentStatus.FAILED
            self.result.exception = str(e)

        # _finalize_and_save() calls _save_binary_for_fuzzing() and
        # _generate_patch_diff() which handle binary + patch output
        return self._finalize_and_save()

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
        return f"""A crash was detected in this project. Your task is to analyze and fix the vulnerability.

## Crash Output
```
{crash_output[:8000]}
```

## Instructions
1. First, understand the crash by analyzing the stack trace and error message
2. Explore the codebase to understand the context - don't limit yourself to stack trace functions
3. Identify the root cause of the vulnerability
4. Generate a minimal, correct patch
5. Apply the patch using the Edit tool (writes are restricted to /src/ only)
6. Build the project using the mcp__arvo__build tool
7. Test the fix using the mcp__arvo__run_poc tool (runs the PoC against the built binary)

IMPORTANT:
- You can only write to files in /src/ - other directories are read-only
- After successful verification, the task is complete

Start by analyzing the crash output and exploring the relevant source files.
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
                "messages": self._conversation_messages,
            }
            conv_file.write_text(json.dumps(conv_data, indent=2, default=str))
            LOG.info(
                f"Saved conversation ({len(self._conversation_messages)} messages) "
                f"to {conv_file}"
            )
