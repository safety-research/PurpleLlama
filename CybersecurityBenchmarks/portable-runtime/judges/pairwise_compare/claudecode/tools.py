"""
Custom MCP tools for the patch comparison analysis agent.

Tools:
    run_binary      -- Run a binary (original, patch-a, patch-b) with a given input
    run_poc         -- Run the PoC against a specific binary
    build_worktree  -- Compile the project from a specific worktree
    diff_files      -- Diff a file across worktrees
"""

import logging
import os
import shutil
import subprocess
import uuid

from claude_agent_sdk import create_sdk_mcp_server, tool

LOG = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Output truncation (same pattern as agent/claudecode/tools.py)
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
# Binary resolution
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


# ---------------------------------------------------------------------------
# Tools
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
    "Uses overlayfs to temporarily mount the worktree as /src/, runs "
    "arvo compile, then restores. The rebuilt binary is placed in /binaries/.",
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
    """Build the project from a worktree using overlayfs swap."""
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
        # Strategy: temporarily swap /src content with worktree content using
        # bind mount. This avoids modifying /src permanently.
        # Save original /src state, replace with worktree, build, restore.

        # 1. Create a backup bind mount of original /src
        backup_dir = "/tmp/src_backup"
        os.makedirs(backup_dir, exist_ok=True)

        # Copy the worktree contents over /src (keeping .git intact)
        # Use rsync to efficiently sync, excluding .git
        result = subprocess.run(
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
        if result.returncode != 0:
            # rsync not available, fall back to manual approach
            LOG.info("rsync not available, falling back to cp")
            # This is less ideal but works
            pass

        # 2. Build
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

        # 3. If build succeeded, copy the binary
        if build_success:
            # Find the built binary
            import re

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

        # 4. Restore original source by checking out from git
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
        # Restore /src on timeout
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
        # Restore /src on error
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
                    "text": f"Invalid tree names. Use: original, patch-a, patch-b",
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


def create_analysis_mcp_server():
    """Create the analysis MCP server with all tools."""
    return create_sdk_mcp_server(
        name="analysis",
        version="1.0.0",
        tools=[run_binary_tool, run_poc_tool, build_worktree_tool, diff_files_tool],
    )
