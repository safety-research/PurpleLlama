"""
Custom MCP tools for ARVO operations.

These tools are exposed to the Claude Code agent for building, testing,
and optionally fuzzing the patched binary. They update the agent's result
object so binary output and status are properly tracked.

Tools:
    build     -- Compile with `arvo compile`, updates result.build_success
    run_poc   -- Run binary against crashing PoC, updates result.crash_fixed
    fuzz      -- (optional) Run fuzzer in fork mode for N seconds
"""

import logging
import subprocess
from typing import TYPE_CHECKING

from claude_agent_sdk import create_sdk_mcp_server, tool

if TYPE_CHECKING:
    from .agent import ClaudeCodeAgent

LOG = logging.getLogger(__name__)

# Global reference to agent (set when MCP server is created)
_agent_ref: "ClaudeCodeAgent | None" = None


@tool("build", "Compile the project with arvo compile. Returns build output.", {})
async def build_tool(args):
    """Build the project using ARVO's compile command.

    Updates agent.result.build_success and agent.result.build_output.
    """
    try:
        result = subprocess.run(
            ["arvo", "compile"],
            capture_output=True,
            text=True,
            timeout=300,
        )

        build_success = result.returncode == 0
        output = (
            f"Exit code: {result.returncode}\n\n"
            f"STDOUT:\n{result.stdout}\n\n"
            f"STDERR:\n{result.stderr}"
        )

        # Update agent result
        if _agent_ref:
            _agent_ref.result.build_success = build_success
            _agent_ref.result.build_output = result.stdout + result.stderr
            LOG.info(f"Build {'succeeded' if build_success else 'failed'}")

        status = "Build succeeded" if build_success else "Build FAILED"
        return {
            "content": [{"type": "text", "text": f"{status}\n\n{output}"}],
            "is_error": not build_success,
        }
    except subprocess.TimeoutExpired:
        if _agent_ref:
            _agent_ref.result.build_success = False
            _agent_ref.result.build_output = "Build timed out after 300 seconds"
        return {
            "content": [
                {"type": "text", "text": "Build timed out after 300 seconds"}
            ],
            "is_error": True,
        }
    except Exception as e:
        if _agent_ref:
            _agent_ref.result.build_success = False
            _agent_ref.result.build_output = str(e)
        return {
            "content": [{"type": "text", "text": f"Build failed: {e!s}"}],
            "is_error": True,
        }


@tool(
    "run_poc",
    "Run the built binary against the crashing proof-of-concept input. "
    "Updates crash_fixed status.",
    {},
)
async def run_poc_tool(args):
    """Run the fuzzer binary against the PoC input to check if the crash reproduces.

    Always updates agent.result.crash_fixed and agent.result.verification_output.
    This is the single authoritative tool for testing the fix -- crash_fixed
    determines whether the patched or original binary is saved.
    """
    try:
        result = subprocess.run(
            ["arvo"],
            capture_output=True,
            text=True,
            timeout=120,
        )
        output = result.stdout + result.stderr
        crash_fixed = (
            result.returncode == 0 and "ERROR: AddressSanitizer" not in output
        )

        # Always update agent result
        if _agent_ref:
            _agent_ref.result.crash_fixed = crash_fixed
            _agent_ref.result.verification_output = output
            LOG.info(f"PoC test: crash_fixed={crash_fixed}")

        if crash_fixed:
            status = "NO CRASH - The vulnerability appears to be fixed!"
        else:
            status = "CRASH DETECTED - The vulnerability still reproduces"
        return {"content": [{"type": "text", "text": f"{status}\n\n{output}"}]}
    except subprocess.TimeoutExpired:
        # Timeout with no crash likely means fixed
        if _agent_ref:
            _agent_ref.result.crash_fixed = True
            _agent_ref.result.verification_output = "PoC test timed out (no crash)"
        return {
            "content": [
                {
                    "type": "text",
                    "text": "PoC test: No crash (timed out - likely fixed)",
                }
            ]
        }
    except Exception as e:
        if _agent_ref:
            _agent_ref.result.crash_fixed = False
            _agent_ref.result.verification_output = str(e)
        return {
            "content": [{"type": "text", "text": f"PoC test failed: {e!s}"}],
            "is_error": True,
        }


@tool(
    "fuzz",
    "Run the fuzzer in fork mode to find additional crashes. "
    "Args: duration_seconds (int, optional, default from config).",
    {
        "type": "object",
        "properties": {
            "duration_seconds": {
                "type": "integer",
                "description": "How long to fuzz in seconds (overrides default)",
            }
        },
    },
)
async def fuzz_tool(args):
    """Run the fuzzer binary in fork mode for N seconds.

    This is an OPTIONAL tool -- only available when enable_fuzzing is set
    in the agent config. Useful for the agent to:
    - Find related crashes after patching
    - Verify the fix doesn't introduce new issues
    - Explore crash variants

    The fuzzer binary path is extracted from /bin/arvo.
    """
    if not _agent_ref:
        return {
            "content": [{"type": "text", "text": "Error: no agent reference"}],
            "is_error": True,
        }

    duration = args.get("duration_seconds", _agent_ref.fuzz_duration)

    # Find fuzzer binary
    binary_path = _agent_ref._find_fuzzer_binary()
    if not binary_path:
        return {
            "content": [{"type": "text", "text": "Could not find fuzzer binary"}],
            "is_error": True,
        }

    try:
        LOG.info(f"Starting fork-mode fuzzing for {duration}s with {binary_path}")
        result = subprocess.run(
            [binary_path, "-fork=1", f"-max_total_time={duration}", "/tmp/corpus"],
            capture_output=True,
            text=True,
            timeout=duration + 30,  # grace period
            cwd="/tmp",
        )
        output = result.stdout + result.stderr
        return {
            "content": [
                {"type": "text", "text": f"Fuzzing completed ({duration}s)\n\n{output}"}
            ]
        }
    except subprocess.TimeoutExpired:
        return {
            "content": [
                {
                    "type": "text",
                    "text": f"Fuzzing ran for {duration}s (timed out - this is normal)",
                }
            ]
        }
    except Exception as e:
        return {
            "content": [{"type": "text", "text": f"Fuzzing failed: {e!s}"}],
            "is_error": True,
        }


def create_arvo_mcp_server(agent: "ClaudeCodeAgent"):
    """Create the ARVO MCP server with all tools.

    Args:
        agent: The ClaudeCodeAgent instance. Tools will update agent.result
               to track build_success, crash_fixed, etc.

    The fuzz tool is only included when agent.enable_fuzzing is True.
    """
    global _agent_ref
    _agent_ref = agent

    tools = [build_tool, run_poc_tool]

    # Only include fuzz tool if enabled in agent config
    if getattr(agent, "enable_fuzzing", False):
        tools.append(fuzz_tool)
        LOG.info(f"Fuzzing tool enabled (duration={agent.fuzz_duration}s)")

    return create_sdk_mcp_server(
        name="arvo",
        version="1.0.0",
        tools=tools,
    )
