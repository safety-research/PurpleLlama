"""
GT Backporter agent: applies a known ground-truth fix to the vulnerable codebase.

Uses Claude Code to find and apply the exact patch from arvo_meta patch metadata,
handling line number differences between the fix commit and the older vul codebase.
Produces a "perfect single-fix" binary for fair fuzzing comparison.
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
from ..claudecode.permissions import restrict_file_writes
from ..claudecode.tools import create_arvo_mcp_server
from .prompts import GT_BACKPORTER_SYSTEM_PROMPT, build_backporter_prompt

LOG = logging.getLogger(__name__)


class GtBackporterAgent(BaseAgent):
    """Applies a known ground-truth patch to the vulnerable codebase.

    Unlike the claudecode agent which discovers and generates fixes, this agent
    receives the exact patch to apply. It uses Claude Code only to handle line
    number differences and minor code drift between the fix commit and the
    older vul codebase.

    Configurable parameters (via AGENT_CONFIG JSON):
    - max_turns (int): Max agentic loop iterations (default: 15)
    - patch_data (list[dict]): Patch hunks from arvo_meta/{id}-patch.json.
      Each hunk has: filename, patch (unified diff), summary
    """

    AGENT_NAME = "gtbackporter"

    def __init__(
        self,
        case_id,
        output_dir,
        model=None,
        dry_run=False,
        max_retries=1,
        max_turns=25,
        patch_data=None,
        **kwargs,
    ):
        super().__init__(case_id, output_dir, model, dry_run, max_retries)
        self.max_turns = max_turns
        self.patch_data = patch_data or []

        # Full structured conversation log
        self._conversation_messages: list[dict] = []

        # CLI path
        self.cli_path = os.environ.get(
            "CLAUDE_CODE_CLI_PATH", "/agent-runtime/bin/claude"
        )

        # If no patch_data in config, try loading from GCS or local file
        if not self.patch_data:
            self.patch_data = self._load_patch_data()

    def _load_patch_data(self) -> list[dict]:
        """Load patch data from local file or GCS.

        Checks in order:
        1. /agent-runtime/patches/{case_id}-patch.json (uploaded by submit CLI)
        2. GCS gs://{bucket}/patches/{case_id}-patch.json (via BUCKET env var)
        """
        import subprocess

        # Try local path first (mounted or pre-downloaded)
        local_path = f"/agent-runtime/patches/{self.case_id}-patch.json"
        if os.path.exists(local_path):
            LOG.info(f"Loading patch data from {local_path}")
            with open(local_path) as f:
                return json.load(f)

        # Try downloading from GCS via authenticated HTTP
        bucket = os.environ.get("BUCKET", "")
        if bucket:
            import subprocess
            import urllib.error
            import urllib.request

            gcs_url = (
                f"https://storage.googleapis.com/storage/v1/b/{bucket}"
                f"/o/patches%2F{self.case_id}-patch.json?alt=media"
            )
            # Get auth token from GKE metadata server
            try:
                token_req = urllib.request.Request(
                    "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
                    headers={"Metadata-Flavor": "Google"},
                )
                with urllib.request.urlopen(token_req, timeout=5) as resp:
                    token = json.loads(resp.read().decode())["access_token"]

                req = urllib.request.Request(
                    gcs_url,
                    headers={"Authorization": f"Bearer {token}"},
                )
                with urllib.request.urlopen(req, timeout=30) as resp:
                    data = json.loads(resp.read().decode())
                LOG.info(f"Downloaded patch data from GCS for case {self.case_id}")
                return data
            except urllib.error.HTTPError as e:
                LOG.warning(f"Patch not found in GCS (HTTP {e.code})")
            except Exception as e:
                LOG.warning(f"Failed to download patch from GCS: {e}")

        LOG.warning(f"No patch data found for case {self.case_id}")
        return []

    async def run(self) -> AgentResult:
        """Run the backporter pipeline: apply known patch + build."""
        try:
            LOG.info(f"Starting GT backporter for case {self.case_id}")
            self.result.status = AgentStatus.RUNNING

            if not self.patch_data:
                self.result.status = AgentStatus.FAILED
                self.result.error = "No patch_data in agent config"
                return self._finalize_and_save()

            if self.dry_run:
                LOG.info("Dry run - skipping agent execution")
                self.result.status = AgentStatus.SUCCESS
                return self._finalize_and_save()

            # Create MCP tools (build only -- no run_poc)
            arvo_server = create_arvo_mcp_server(self)

            # Tools: everything EXCEPT mcp__arvo__run_poc
            allowed_tools = [
                "Read",
                "Write",
                "Edit",
                "Grep",
                "Glob",
                "Bash",
                "mcp__arvo__build",
            ]

            options = ClaudeAgentOptions(
                cli_path=self.cli_path,
                system_prompt=GT_BACKPORTER_SYSTEM_PROMPT,
                cwd="/src",
                allowed_tools=allowed_tools,
                mcp_servers={"arvo": arvo_server},
                can_use_tool=restrict_file_writes,
                permission_mode="default",
                max_turns=self.max_turns,
                model=self.model,
                # 100 MB buffer — avoid JSON buffer overflow on long conversations
                max_buffer_size=100 * 1024 * 1024,
            )

            # Build the prompt from patch metadata
            initial_prompt = build_backporter_prompt(self.patch_data)
            LOG.info(
                f"Applying GT patch ({len(self.patch_data)} hunks) "
                f"with max_turns={self.max_turns}"
            )

            # Run agentic loop
            async with ClaudeSDKClient(options=options) as client:
                await client.query(initial_prompt)
                async for message in client.receive_response():
                    self._process_message(message)

            # Determine status based on whether a patch was applied and built
            if self.result.build_success:
                self.result.status = AgentStatus.SUCCESS
                # Mark crash_fixed=True since we applied the known fix
                # (actual verification happens in the fuzz step)
                self.result.crash_fixed = True
                LOG.info("GT backporter completed - patch applied and built")
            elif self.result.patch_generated:
                self.result.status = AgentStatus.PARTIAL
                LOG.info("GT backporter partial - patch applied but build failed")
            else:
                self.result.status = AgentStatus.FAILED
                LOG.info("GT backporter failed - could not apply patch")

        except Exception as e:
            LOG.exception(f"GT backporter failed: {e}")
            self.result.status = AgentStatus.FAILED
            self.result.exception = str(e)

        return self._finalize_and_save()

    def _process_message(self, message):
        """Process messages from Claude Code."""
        self._conversation_messages.append(self._serialize_message(message))

        if isinstance(message, AssistantMessage):
            for block in message.content:
                if isinstance(block, ToolUseBlock):
                    self.result.llm_calls += 1
                    if block.name in ["Edit", "Write"]:
                        self.result.patch_generated = True
                        file_path = block.input.get("file_path", "")
                        if file_path:
                            self.result.patched_file_path = file_path
                        LOG.debug(f"Patch applied to: {file_path}")
                    elif block.name == "mcp__arvo__build":
                        # Build will be tracked via tool result
                        pass

        elif isinstance(message, ResultMessage):
            if hasattr(message, "total_cost_usd") and message.total_cost_usd:
                LOG.info(f"Total cost: ${message.total_cost_usd:.4f}")

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

    def _save_additional_results(self) -> None:
        """Save conversation history."""
        if self._conversation_messages:
            conv_file = self.output_dir / "conversation.json"
            conv_data = {
                "case_id": self.result.case_id,
                "agent_name": self.AGENT_NAME,
                "agent_id": self.result.agent_id,
                "model": self.model,
                "status": self.result.status.value,
                "patch_data": self.patch_data,
                "messages": self._conversation_messages,
            }
            conv_file.write_text(json.dumps(conv_data, indent=2, default=str))
            LOG.info(
                f"Saved conversation ({len(self._conversation_messages)} messages) "
                f"to {conv_file}"
            )
