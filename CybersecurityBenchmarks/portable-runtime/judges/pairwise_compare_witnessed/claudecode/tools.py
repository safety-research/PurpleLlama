"""
Custom MCP tools for the witnessed analysis agent.

Includes all tools from the analysis module (run_binary, run_poc,
build_worktree, diff_files) plus:
    compile_harness -- Compile a custom C/C++ harness
    run_witness     -- Spawn a witness-builder CC sub-agent (the key tool)

The run_witness tool is created via a factory function that captures
the ClaudeSDKClient configuration so it can spawn sub-sessions.
"""

import asyncio
import json
import logging
import os
import re
import shutil
import subprocess
import time
import uuid

from claude_agent_sdk import (
    AssistantMessage,
    ClaudeAgentOptions,
    create_sdk_mcp_server,
    tool,
)

from shared.api_retry import RetryEvent, resilient_sdk_session
from shared.retry_tracker import RetryTimeTracker

LOG = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Output truncation (same pattern as judges/pairwise_compare/claudecode/tools.py)
# ---------------------------------------------------------------------------
MAX_OUTPUT_CHARS = 200_000
HEAD_LINES = 100
TAIL_LINES = 200


def truncate_output(
    text: str,
    max_chars: int = MAX_OUTPUT_CHARS,
    head_lines: int = HEAD_LINES,
    tail_lines: int = TAIL_LINES,
    file_hint: str | None = None,
) -> str:
    """Truncate large output, keeping first and last lines."""
    if len(text) <= max_chars:
        return text

    lines = text.splitlines(keepends=True)
    hint = f" {file_hint}" if file_hint else ""

    if len(lines) <= head_lines + tail_lines:
        return (
            text[:max_chars]
            + f"\n\n... [truncated — {len(text) - max_chars} chars omitted.{hint}] ..."
        )

    head = lines[:head_lines]
    tail = lines[-tail_lines:]
    omitted = len(lines) - head_lines - tail_lines
    marker = (
        f"\n\n... [{omitted} lines omitted — output too large ({len(text)} chars)."
        f"{hint}] ...\n\n"
    )
    result = "".join(head) + marker + "".join(tail)
    if len(result) > max_chars:
        result = result[:max_chars] + "\n\n... [truncated] ..."
    return result


# ---------------------------------------------------------------------------
# Log-file helpers
# ---------------------------------------------------------------------------
TOOL_LOG_DIR = "/tmp/tool_logs"


def _write_log_files(prefix: str, stdout: str, stderr: str) -> tuple[str, str]:
    """Write stdout and stderr to separate log files."""
    log_id = uuid.uuid4().hex[:8]
    os.makedirs(TOOL_LOG_DIR, exist_ok=True)
    stdout_path = f"{TOOL_LOG_DIR}/{prefix}_{log_id}_stdout.log"
    stderr_path = f"{TOOL_LOG_DIR}/{prefix}_{log_id}_stderr.log"
    for path, content in ((stdout_path, stdout), (stderr_path, stderr)):
        try:
            with open(path, "w") as f:
                f.write(content)
        except OSError as e:
            LOG.warning(f"Failed to write log file {path}: {e}")
    return stdout_path, stderr_path


# ---------------------------------------------------------------------------
# Binary / worktree resolution
# ---------------------------------------------------------------------------
BINARY_MAP = {
    "original": "/binaries/original",
    "patch-a": "/binaries/patch-a",
    "patch-b": "/binaries/patch-b",
}

WORKTREE_MAP = {
    "patch-a": "/workspace/patch-a",
    "patch-b": "/workspace/patch-b",
    "original": "/src",
}

WITNESSES_DIR = "/output/witnesses"


# ---------------------------------------------------------------------------
# Shared tools (used by both analyst and witness builders)
# ---------------------------------------------------------------------------


@tool(
    "run_binary",
    "Run a binary (original, patch-a, or patch-b) with a given input file. "
    "Returns stdout/stderr including any sanitizer output.",
    {
        "type": "object",
        "properties": {
            "binary": {
                "type": "string",
                "enum": ["original", "patch-a", "patch-b"],
                "description": "Which binary to run",
            },
            "input_file": {
                "type": "string",
                "description": "Path to the input file to feed to the binary",
            },
        },
        "required": ["binary", "input_file"],
    },
)
async def run_binary_tool(args):
    """Run a fuzzer binary with a given input file."""
    binary_name = args.get("binary", "")
    input_file = args.get("input_file", "")

    binary_path = BINARY_MAP.get(binary_name)
    if not binary_path:
        return {
            "content": [
                {
                    "type": "text",
                    "text": f"Unknown binary: {binary_name}. Use: original, patch-a, or patch-b",
                }
            ],
            "is_error": True,
        }

    if not os.path.exists(binary_path):
        return {
            "content": [{"type": "text", "text": f"Binary not found at {binary_path}"}],
            "is_error": True,
        }

    if not os.path.exists(input_file):
        return {
            "content": [
                {"type": "text", "text": f"Input file not found: {input_file}"}
            ],
            "is_error": True,
        }

    try:
        result = subprocess.run(
            [binary_path, input_file],
            capture_output=True,
            text=True,
            timeout=120,
        )
        raw_output = result.stdout + result.stderr

        stdout_path, stderr_path = _write_log_files(
            f"run_{binary_name}", result.stdout, result.stderr
        )
        file_hint = (
            f"Full stdout saved to {stdout_path} and stderr to {stderr_path}"
            f" — use Read or Grep to inspect them."
        )
        output = truncate_output(raw_output, file_hint=file_hint)

        has_crash = (
            "ERROR: AddressSanitizer" in raw_output
            or "SUMMARY:" in raw_output
            or result.returncode != 0
        )
        status = "CRASH DETECTED" if has_crash else "NO CRASH"

        return {
            "content": [
                {
                    "type": "text",
                    "text": f"[{binary_name}] {status} (exit code: {result.returncode})\n\n{output}",
                }
            ]
        }
    except subprocess.TimeoutExpired:
        return {
            "content": [
                {
                    "type": "text",
                    "text": f"[{binary_name}] Timed out after 120s (no crash)",
                }
            ]
        }
    except Exception as e:
        return {
            "content": [{"type": "text", "text": f"[{binary_name}] Failed: {e!s}"}],
            "is_error": True,
        }


@tool(
    "run_poc",
    "Run the PoC crash input (/tmp/poc) against a specific binary to check "
    "if the crash reproduces.",
    {
        "type": "object",
        "properties": {
            "binary": {
                "type": "string",
                "enum": ["original", "patch-a", "patch-b"],
                "description": "Which binary to test",
            },
        },
        "required": ["binary"],
    },
)
async def run_poc_tool(args):
    """Run the PoC against a specific binary."""
    binary_name = args.get("binary", "")
    binary_path = BINARY_MAP.get(binary_name)
    if not binary_path:
        return {
            "content": [
                {
                    "type": "text",
                    "text": f"Unknown binary: {binary_name}. Use: original, patch-a, or patch-b",
                }
            ],
            "is_error": True,
        }

    if not os.path.exists(binary_path):
        return {
            "content": [{"type": "text", "text": f"Binary not found at {binary_path}"}],
            "is_error": True,
        }

    poc_path = "/tmp/poc"
    if not os.path.exists(poc_path):
        return {
            "content": [{"type": "text", "text": "PoC file not found at /tmp/poc"}],
            "is_error": True,
        }

    try:
        result = subprocess.run(
            [binary_path, poc_path],
            capture_output=True,
            text=True,
            timeout=120,
        )
        raw_output = result.stdout + result.stderr

        stdout_path, stderr_path = _write_log_files(
            f"poc_{binary_name}", result.stdout, result.stderr
        )
        file_hint = f"Full output saved to {stdout_path} and {stderr_path}"
        output = truncate_output(raw_output, file_hint=file_hint)

        crash_detected = (
            "ERROR: AddressSanitizer" in raw_output
            or "SUMMARY:" in raw_output
            or result.returncode != 0
        )

        if crash_detected:
            status = "CRASH DETECTED — the vulnerability still reproduces"
        else:
            status = "NO CRASH — the vulnerability appears to be fixed"

        return {
            "content": [
                {
                    "type": "text",
                    "text": f"[{binary_name}] {status}\n\n{output}",
                }
            ]
        }
    except subprocess.TimeoutExpired:
        return {
            "content": [
                {
                    "type": "text",
                    "text": f"[{binary_name}] PoC timed out (no crash — likely fixed)",
                }
            ]
        }
    except Exception as e:
        return {
            "content": [
                {"type": "text", "text": f"[{binary_name}] PoC test failed: {e!s}"}
            ],
            "is_error": True,
        }


@tool(
    "build_worktree",
    "Compile the project from a specific worktree (patch-a or patch-b). "
    "Uses rsync to temporarily swap /src/ content, runs arvo compile, "
    "then restores. The rebuilt binary is placed in /binaries/.",
    {
        "type": "object",
        "properties": {
            "worktree": {
                "type": "string",
                "enum": ["patch-a", "patch-b"],
                "description": "Which worktree to build from",
            },
        },
        "required": ["worktree"],
    },
)
async def build_worktree_tool(args):
    """Build the project from a worktree using rsync swap."""
    worktree_name = args.get("worktree", "")
    worktree_path = WORKTREE_MAP.get(worktree_name)

    if not worktree_path or worktree_name == "original":
        return {
            "content": [
                {
                    "type": "text",
                    "text": f"Invalid worktree: {worktree_name}. Use: patch-a or patch-b",
                }
            ],
            "is_error": True,
        }

    binary_dest = BINARY_MAP.get(worktree_name, f"/binaries/{worktree_name}")

    LOG.info(f"Building from worktree: {worktree_name} at {worktree_path}")

    try:
        subprocess.run(
            [
                "rsync",
                "-a",
                "--delete",
                "--exclude=.git",
                f"{worktree_path}/",
                "/src/",
            ],
            capture_output=True,
            text=True,
            timeout=120,
        )

        build_result = subprocess.run(
            ["arvo", "compile"],
            capture_output=True,
            text=True,
            timeout=1800,
        )

        build_success = build_result.returncode == 0

        stdout_path, stderr_path = _write_log_files(
            f"build_{worktree_name}", build_result.stdout, build_result.stderr
        )
        file_hint = f"Full stdout saved to {stdout_path} and stderr to {stderr_path}"

        full_output = (
            f"Exit code: {build_result.returncode}\n\n"
            f"STDOUT:\n{build_result.stdout}\n\n"
            f"STDERR:\n{build_result.stderr}"
        )
        output = truncate_output(full_output, file_hint=file_hint)

        if build_success:
            arvo_script = "/bin/arvo"
            binary_path = None
            if os.path.exists(arvo_script):
                content = open(arvo_script).read()
                match = re.search(r"(/out/[\w\-\.]+)\s+/tmp/(poc|corpus)", content)
                if match:
                    binary_path = match.group(1)

            if binary_path and os.path.exists(binary_path):
                shutil.copy2(binary_path, binary_dest)
                os.chmod(binary_dest, 0o755)
                LOG.info(f"Updated binary for {worktree_name}: {binary_dest}")

        subprocess.run(
            ["git", "checkout", "--", "."],
            capture_output=True,
            text=True,
            cwd="/src",
            timeout=60,
        )

        status = "Build succeeded" if build_success else "Build FAILED"
        return {
            "content": [
                {
                    "type": "text",
                    "text": f"[{worktree_name}] {status}\n\n{output}",
                }
            ],
            "is_error": not build_success,
        }

    except subprocess.TimeoutExpired:
        subprocess.run(
            ["git", "checkout", "--", "."],
            capture_output=True,
            text=True,
            cwd="/src",
            timeout=60,
        )
        return {
            "content": [
                {
                    "type": "text",
                    "text": f"[{worktree_name}] Build timed out after 30 minutes",
                }
            ],
            "is_error": True,
        }
    except Exception as e:
        subprocess.run(
            ["git", "checkout", "--", "."],
            capture_output=True,
            text=True,
            cwd="/src",
            timeout=60,
        )
        return {
            "content": [
                {
                    "type": "text",
                    "text": f"[{worktree_name}] Build failed: {e!s}",
                }
            ],
            "is_error": True,
        }


@tool(
    "diff_files",
    "Diff a file across worktrees. Compare the same file path between "
    "original, patch-a, and/or patch-b source trees.",
    {
        "type": "object",
        "properties": {
            "file_path": {
                "type": "string",
                "description": "Relative file path within the source tree (e.g. src/foo.c)",
            },
            "tree_a": {
                "type": "string",
                "enum": ["original", "patch-a", "patch-b"],
                "description": "First tree to compare",
            },
            "tree_b": {
                "type": "string",
                "enum": ["original", "patch-a", "patch-b"],
                "description": "Second tree to compare",
            },
        },
        "required": ["file_path", "tree_a", "tree_b"],
    },
)
async def diff_files_tool(args):
    """Diff a file across two source trees."""
    file_path = args.get("file_path", "")
    tree_a = args.get("tree_a", "")
    tree_b = args.get("tree_b", "")

    root_a = WORKTREE_MAP.get(tree_a)
    root_b = WORKTREE_MAP.get(tree_b)

    if not root_a or not root_b:
        return {
            "content": [
                {
                    "type": "text",
                    "text": "Invalid tree names. Use: original, patch-a, patch-b",
                }
            ],
            "is_error": True,
        }

    path_a = os.path.join(root_a, file_path)
    path_b = os.path.join(root_b, file_path)

    if not os.path.exists(path_a):
        return {
            "content": [
                {"type": "text", "text": f"File not found in {tree_a}: {path_a}"}
            ],
            "is_error": True,
        }
    if not os.path.exists(path_b):
        return {
            "content": [
                {"type": "text", "text": f"File not found in {tree_b}: {path_b}"}
            ],
            "is_error": True,
        }

    try:
        result = subprocess.run(
            ["diff", "-u", path_a, path_b],
            capture_output=True,
            text=True,
            timeout=30,
        )

        if result.returncode == 0:
            return {
                "content": [
                    {
                        "type": "text",
                        "text": f"Files are identical between {tree_a} and {tree_b}: {file_path}",
                    }
                ]
            }

        output = truncate_output(result.stdout)
        return {
            "content": [
                {
                    "type": "text",
                    "text": f"Diff of {file_path} ({tree_a} vs {tree_b}):\n\n{output}",
                }
            ]
        }
    except Exception as e:
        return {
            "content": [{"type": "text", "text": f"Diff failed: {e!s}"}],
            "is_error": True,
        }


@tool(
    "compile_harness",
    "Compile a custom C/C++ harness file from /workspace/ or /tmp/. "
    "Uses the container's toolchain (clang/gcc) with optional flags.",
    {
        "type": "object",
        "properties": {
            "source_file": {
                "type": "string",
                "description": "Path to the source file (e.g. /workspace/witnesses/harness.c)",
            },
            "output_binary": {
                "type": "string",
                "description": "Path for the compiled binary (e.g. /tmp/harness)",
            },
            "flags": {
                "type": "string",
                "description": "Additional compiler flags (e.g. '-I/src/include -lz -fsanitize=address')",
                "default": "",
            },
        },
        "required": ["source_file", "output_binary"],
    },
)
async def compile_harness_tool(args):
    """Compile a custom C/C++ harness."""
    source_file = args.get("source_file", "")
    output_binary = args.get("output_binary", "")
    flags = args.get("flags", "")

    if not os.path.exists(source_file):
        return {
            "content": [
                {"type": "text", "text": f"Source file not found: {source_file}"}
            ],
            "is_error": True,
        }

    compiler = "gcc"
    if source_file.endswith((".cpp", ".cc", ".cxx")):
        compiler = "g++"
    for candidate in ["clang", "clang++"]:
        if shutil.which(candidate):
            compiler = candidate if source_file.endswith(".c") else "clang++"
            break

    cmd = [compiler, "-o", output_binary, source_file, "-g"]
    if flags:
        cmd.extend(flags.split())

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300,
        )

        stdout_path, stderr_path = _write_log_files(
            "compile_harness", result.stdout, result.stderr
        )
        file_hint = f"Full output saved to {stdout_path} and {stderr_path}"

        full_output = result.stdout + result.stderr
        output = truncate_output(full_output, file_hint=file_hint)

        if result.returncode == 0:
            return {
                "content": [
                    {
                        "type": "text",
                        "text": f"Compilation succeeded: {output_binary}\n"
                        f"Command: {' '.join(cmd)}\n\n{output}",
                    }
                ]
            }
        else:
            return {
                "content": [
                    {
                        "type": "text",
                        "text": f"Compilation FAILED (exit {result.returncode})\n"
                        f"Command: {' '.join(cmd)}\n\n{output}",
                    }
                ],
                "is_error": True,
            }
    except subprocess.TimeoutExpired:
        return {
            "content": [
                {"type": "text", "text": "Compilation timed out after 5 minutes"}
            ],
            "is_error": True,
        }
    except Exception as e:
        return {
            "content": [{"type": "text", "text": f"Compilation failed: {e!s}"}],
            "is_error": True,
        }


# ---------------------------------------------------------------------------
# Witness critic: evaluates witness scripts for validity
# ---------------------------------------------------------------------------


async def _run_witness_critic(
    cli_path: str,
    model: str | None,
    thinking_budget: int | None,
    max_critic_time: int,
    claim_id: str,
    claim_text: str,
    category: str,
    witness_script_content: str,
    script_output: str,
    script_exit_code: int,
    patch_a_diff: str,
    patch_b_diff: str,
    permissions_callback,
) -> dict:
    """Run the witness critic agent and return its verdict.

    Returns dict with keys: verdict ("ACCEPT"/"REVISE"/"REJECT"),
    feedback (str), reachability/correctness/soundness details.
    On error or timeout, defaults to ACCEPT (fail-open).
    """
    from .prompts import get_witness_critic_initial_prompt, get_witness_critic_system_prompt

    critic_system = get_witness_critic_system_prompt()
    critic_initial = get_witness_critic_initial_prompt(
        claim_id=claim_id,
        claim_text=claim_text,
        category=category,
        witness_script=witness_script_content,
        script_output=script_output,
        script_exit_code=script_exit_code,
        patch_a_diff=patch_a_diff,
        patch_b_diff=patch_b_diff,
    )

    critic_mcp = create_sdk_mcp_server(
        name="witnessed",
        version="1.0.0",
        tools=[],
    )

    critic_retry_tracker = RetryTimeTracker()

    options = ClaudeAgentOptions(
        cli_path=cli_path,
        system_prompt=critic_system,
        cwd="/workspace",
        allowed_tools=["Read", "Grep", "Glob", "Bash"],
        mcp_servers={"witnessed": critic_mcp},
        can_use_tool=permissions_callback,
        permission_mode="default",
        max_turns=50,
        model=model,
        max_thinking_tokens=thinking_budget,
        max_buffer_size=50 * 1024 * 1024,
        stderr=critic_retry_tracker.handle_stderr_line,
        env={"CLAUDE_CODE_MAX_RETRIES": "500"},
    )

    last_text = ""
    start = time.monotonic()

    try:
        async for item in resilient_sdk_session(
            options, critic_initial, retry_tracker=critic_retry_tracker,
        ):
            if isinstance(item, RetryEvent):
                last_text = ""
                continue
            client, message = item

            elapsed = time.monotonic() - start
            excluded = critic_retry_tracker.get_excluded_seconds()
            active = elapsed - excluded
            if active > max_critic_time:
                LOG.warning(f"Critic for {claim_id} timed out at {active:.1f}s active")
                await client.interrupt()
                break
            if isinstance(message, AssistantMessage):
                for block in message.content:
                    if hasattr(block, "text"):
                        last_text = block.text
    except Exception as e:
        LOG.warning(f"Critic for {claim_id} failed: {e}")
        return {"verdict": "ACCEPT", "feedback": f"Critic error: {e}"}

    elapsed = time.monotonic() - start
    LOG.info(f"Critic for {claim_id} finished in {elapsed:.1f}s")

    # Parse JSON verdict from the critic's last message
    json_match = re.search(r"```json\s*(\{.*?\})\s*```", last_text, re.DOTALL)
    if not json_match:
        LOG.warning(f"Critic for {claim_id} did not produce JSON verdict, defaulting to ACCEPT")
        return {"verdict": "ACCEPT", "feedback": "Critic did not produce structured verdict"}

    try:
        verdict_data = json.loads(json_match.group(1))
        verdict = verdict_data.get("verdict", "ACCEPT").upper()
        if verdict not in ("ACCEPT", "REVISE", "REJECT"):
            verdict = "ACCEPT"
        verdict_data["verdict"] = verdict
        return verdict_data
    except json.JSONDecodeError:
        LOG.warning(f"Critic for {claim_id} produced invalid JSON, defaulting to ACCEPT")
        return {"verdict": "ACCEPT", "feedback": "Critic produced invalid JSON"}


# ---------------------------------------------------------------------------
# run_witness: sub-agent spawner (created via factory)
# ---------------------------------------------------------------------------


def _make_run_witness_tool(
    cli_path: str,
    model: str | None,
    thinking_budget: int | None,
    max_witness_time: int,
    max_critic_time: int,
    max_critic_attempts: int,
    patch_a_diff: str,
    patch_b_diff: str,
    permissions_callback,
):
    """Create the run_witness tool with captured configuration.

    This factory captures the ClaudeSDKClient settings so the tool can
    spawn witness-builder and witness-critic sub-sessions in a loop.
    """
    from .prompts import get_witness_builder_initial_prompt, get_witness_builder_system_prompt

    witness_system_prompt = get_witness_builder_system_prompt()
    witness_tools = [
        run_binary_tool,
        run_poc_tool,
        build_worktree_tool,
        diff_files_tool,
        compile_harness_tool,
    ]

    async def _run_builder(
        claim_id: str,
        claim_text: str,
        category: str,
        test_strategy: str,
        time_budget: float,
        critic_feedback: str | None = None,
    ) -> tuple[str | None, float]:
        """Run the witness builder sub-agent.

        Returns (error_string_or_None, elapsed_seconds).
        """
        witness_mcp_server = create_sdk_mcp_server(
            name="witnessed",
            version="1.0.0",
            tools=witness_tools,
        )

        options = ClaudeAgentOptions(
            cli_path=cli_path,
            system_prompt=witness_system_prompt,
            cwd="/workspace",
            allowed_tools=[
                "Read", "Write", "Edit", "Grep", "Glob", "Bash",
                "mcp__witnessed__run_binary",
                "mcp__witnessed__run_poc",
                "mcp__witnessed__build_worktree",
                "mcp__witnessed__diff_files",
                "mcp__witnessed__compile_harness",
            ],
            mcp_servers={"witnessed": witness_mcp_server},
            can_use_tool=permissions_callback,
            permission_mode="default",
            max_turns=200,
            model=model,
            max_thinking_tokens=thinking_budget,
            max_buffer_size=100 * 1024 * 1024,
            env={"CLAUDE_CODE_MAX_RETRIES": "500"},
        )

        initial_prompt = get_witness_builder_initial_prompt(
            claim_id=claim_id,
            claim_text=claim_text,
            category=category,
            test_strategy=test_strategy,
            patch_a_diff=patch_a_diff,
            patch_b_diff=patch_b_diff,
            critic_feedback=critic_feedback,
        )

        start = time.monotonic()
        error = None
        builder_retry_tracker = RetryTimeTracker()
        options.stderr = builder_retry_tracker.handle_stderr_line

        try:
            async for item in resilient_sdk_session(
                options, initial_prompt, retry_tracker=builder_retry_tracker,
            ):
                if isinstance(item, RetryEvent):
                    error = None
                    continue
                client, message = item

                elapsed = time.monotonic() - start
                excluded = builder_retry_tracker.get_excluded_seconds()
                active = elapsed - excluded
                if active > time_budget:
                    LOG.warning(f"Builder {claim_id} timed out at {active:.1f}s active")
                    await client.interrupt()
                    break
        except Exception as e:
            error = str(e)
            LOG.exception(f"Builder {claim_id} failed: {e}")

        return error, time.monotonic() - start

    def _run_script(witness_script: str) -> dict:
        """Execute the witness script and return result data."""
        if not os.path.exists(witness_script):
            return {
                "status": "unverifiable",
                "error": "Witness script was not produced",
                "exit_code": -1,
                "stdout": "",
                "stderr": "",
            }

        os.chmod(witness_script, 0o755)
        LOG.info(f"Running witness script: {witness_script}")
        try:
            run_result = subprocess.run(
                ["bash", witness_script],
                capture_output=True,
                text=True,
                timeout=300,
            )
            status = "confirmed" if run_result.returncode == 0 else "refuted"
            return {
                "status": status,
                "exit_code": run_result.returncode,
                "stdout": run_result.stdout,
                "stderr": run_result.stderr,
            }
        except subprocess.TimeoutExpired:
            return {
                "status": "timeout",
                "exit_code": -1,
                "stdout": "",
                "stderr": "Witness script timed out after 5 minutes",
            }
        except Exception as e:
            return {
                "status": "error",
                "exit_code": -1,
                "stdout": "",
                "stderr": str(e),
            }

    @tool(
        "run_witness",
        "Spawn a witness-builder sub-agent to produce a standalone script "
        "proving a specific claim. A critic agent validates the witness for "
        "reachability, correctness, and soundness. Returns the final result "
        "(confirmed / refuted / unverifiable / error).",
        {
            "type": "object",
            "properties": {
                "claim_id": {
                    "type": "string",
                    "description": "Unique claim ID (e.g. claim_1)",
                },
                "claim": {
                    "type": "string",
                    "description": "The specific assertion to prove",
                },
                "category": {
                    "type": "string",
                    "enum": [
                        "new_crash",
                        "incomplete_fix",
                        "behavioral_divergence",
                        "latent_portability_bug",
                        "build_robustness",
                        "unnecessary_code",
                        "performance_regression",
                    ],
                    "description": "Category of the claim",
                },
                "test_strategy": {
                    "type": "string",
                    "description": "How to approach proving this claim",
                },
            },
            "required": ["claim_id", "claim", "category", "test_strategy"],
        },
    )
    async def run_witness_tool(args):
        claim_id = args.get("claim_id", "")
        claim_text = args.get("claim", "")
        category = args.get("category", "")
        test_strategy = args.get("test_strategy", "")

        claim_dir = f"{WITNESSES_DIR}/{claim_id}"
        os.makedirs(claim_dir, exist_ok=True)
        witness_script = f"{claim_dir}/witness.sh"

        LOG.info(f"Starting witness pipeline for {claim_id}: {claim_text[:80]}...")

        overall_start = time.monotonic()
        result_data = {"claim_id": claim_id}
        critic_feedback = None

        for attempt in range(max_critic_attempts):
            elapsed_total = time.monotonic() - overall_start
            remaining = max_witness_time - elapsed_total
            if remaining < 60:
                LOG.warning(f"Witness {claim_id}: time budget exhausted after {attempt} attempts")
                break

            # --- Step 1: Builder produces/revises the witness script ---
            attempt_label = f"(attempt {attempt + 1}/{max_critic_attempts})"
            if critic_feedback:
                LOG.info(f"Builder {claim_id} {attempt_label} with critic feedback")
            else:
                LOG.info(f"Builder {claim_id} {attempt_label}")

            builder_budget = remaining - max_critic_time - 30
            builder_error, builder_elapsed = await _run_builder(
                claim_id=claim_id,
                claim_text=claim_text,
                category=category,
                test_strategy=test_strategy,
                time_budget=max(builder_budget, 120),
                critic_feedback=critic_feedback,
            )
            LOG.info(f"Builder {claim_id} finished in {builder_elapsed:.1f}s")

            if builder_error:
                result_data.update({
                    "status": "error",
                    "error": builder_error,
                    "exit_code": -1,
                    "stdout": "",
                    "stderr": builder_error,
                })
                break

            # --- Step 2: Run the witness script ---
            script_result = _run_script(witness_script)
            result_data.update(script_result)

            if script_result["status"] in ("unverifiable", "error", "timeout"):
                break

            # --- Step 3: Critic evaluates ---
            elapsed_total = time.monotonic() - overall_start
            if elapsed_total + 30 > max_witness_time:
                LOG.info(f"Critic {claim_id}: skipping, no time remaining")
                break

            script_content = ""
            try:
                with open(witness_script) as f:
                    script_content = f.read()
            except OSError:
                pass

            script_output = script_result.get("stdout", "") + script_result.get("stderr", "")

            LOG.info(f"Running critic for {claim_id} {attempt_label}")
            verdict = await _run_witness_critic(
                cli_path=cli_path,
                model=model,
                thinking_budget=thinking_budget,
                max_critic_time=max_critic_time,
                claim_id=claim_id,
                claim_text=claim_text,
                category=category,
                witness_script_content=script_content,
                script_output=script_output,
                script_exit_code=script_result.get("exit_code", -1),
                patch_a_diff=patch_a_diff,
                patch_b_diff=patch_b_diff,
                permissions_callback=permissions_callback,
            )

            verdict_str = verdict.get("verdict", "ACCEPT")
            feedback = verdict.get("feedback", "")
            LOG.info(f"Critic verdict for {claim_id}: {verdict_str}")

            # Save critic verdict
            try:
                critic_file = f"{claim_dir}/critic_attempt_{attempt + 1}.json"
                with open(critic_file, "w") as f:
                    json.dump(verdict, f, indent=2)
            except OSError:
                pass

            if verdict_str == "ACCEPT":
                result_data["critic_accepted"] = True
                break
            elif verdict_str == "REJECT":
                LOG.info(f"Critic rejected {claim_id} as unfixable: {feedback[:200]}")
                result_data["status"] = "unverifiable"
                result_data["error"] = f"Critic rejected: {feedback[:500]}"
                result_data["critic_rejected"] = True
                break
            else:
                critic_feedback = feedback
                LOG.info(f"Critic requested revision for {claim_id}: {feedback[:200]}")
                continue

        total_elapsed = time.monotonic() - overall_start
        result_data["duration_seconds"] = round(total_elapsed, 1)

        # Save result.json
        try:
            with open(f"{claim_dir}/result.json", "w") as f:
                json.dump(result_data, f, indent=2)
        except OSError as e:
            LOG.warning(f"Failed to save result.json: {e}")

        # Build response for the analyst
        status = result_data.get("status", "error")
        summary_parts = [
            f"**Witness result for {claim_id}**: {status.upper()}",
            f"Duration: {result_data['duration_seconds']}s",
        ]

        if result_data.get("critic_rejected"):
            summary_parts.append(f"Critic rejected: {result_data.get('error', '')}")
        elif result_data.get("critic_accepted"):
            summary_parts.append("Critic: ACCEPTED (reachability, correctness, soundness verified)")

        if status == "confirmed":
            summary_parts.append(f"Exit code: {result_data['exit_code']}")
            output_preview = truncate_output(
                result_data.get("stdout", "") + result_data.get("stderr", ""),
                max_chars=3000,
            )
            summary_parts.append(f"Script output:\n{output_preview}")
            summary_parts.append(f"Witness script saved to: {witness_script}")
        elif status == "refuted":
            summary_parts.append(f"Exit code: {result_data['exit_code']}")
            output_preview = truncate_output(
                result_data.get("stdout", "") + result_data.get("stderr", ""),
                max_chars=3000,
            )
            summary_parts.append(
                f"The witness script did NOT confirm the claim.\n"
                f"Script output:\n{output_preview}"
            )
        elif status == "unverifiable":
            summary_parts.append(
                result_data.get("error", "The witness builder could not produce a valid script.")
            )
        elif status in ("error", "timeout"):
            summary_parts.append(
                f"Error: {result_data.get('error', result_data.get('stderr', ''))}"
            )

        return {
            "content": [
                {"type": "text", "text": "\n".join(summary_parts)}
            ]
        }

    return run_witness_tool


# ---------------------------------------------------------------------------
# MCP server factory
# ---------------------------------------------------------------------------


def create_witnessed_analysis_mcp_server(
    cli_path: str,
    model: str | None,
    thinking_budget: int | None,
    max_witness_time: int,
    max_critic_time: int = 120,
    max_critic_attempts: int = 3,
    patch_a_diff: str = "",
    patch_b_diff: str = "",
    permissions_callback=None,
    include_run_witness: bool = True,
):
    """Create the MCP server with all witnessed analysis tools.

    Args:
        cli_path: Path to the Claude Code CLI binary.
        model: LLM model name for witness builder sub-agents.
        thinking_budget: Extended thinking token budget.
        max_witness_time: Max seconds per witness claim (full generate-critique loop).
        max_critic_time: Max seconds per critic evaluation.
        max_critic_attempts: Max generate-critique loop iterations per claim.
        patch_a_diff: Unified diff for Patch A (passed to witness builders).
        patch_b_diff: Unified diff for Patch B (passed to witness builders).
        permissions_callback: Permission callback for tool access control.
        include_run_witness: If False, exclude run_witness (for sub-agents).
    """
    tools = [
        run_binary_tool,
        run_poc_tool,
        build_worktree_tool,
        diff_files_tool,
        compile_harness_tool,
    ]

    if include_run_witness:
        witness_tool = _make_run_witness_tool(
            cli_path=cli_path,
            model=model,
            thinking_budget=thinking_budget,
            max_witness_time=max_witness_time,
            max_critic_time=max_critic_time,
            max_critic_attempts=max_critic_attempts,
            patch_a_diff=patch_a_diff,
            patch_b_diff=patch_b_diff,
            permissions_callback=permissions_callback,
        )
        tools.append(witness_tool)

    return create_sdk_mcp_server(
        name="witnessed",
        version="1.0.0",
        tools=tools,
    )
