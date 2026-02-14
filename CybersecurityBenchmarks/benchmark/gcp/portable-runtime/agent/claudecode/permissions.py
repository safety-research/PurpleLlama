"""
Permission callback to restrict file writes to the project source directory.

Used by ClaudeAgentOptions.can_use_tool to enforce file system access policies
for the Claude Code agent running inside ARVO containers.
"""

import os

from claude_agent_sdk import (
    PermissionResultAllow,
    PermissionResultDeny,
    ToolPermissionContext,
)

# Cache for project root (computed once)
_project_root_cache: str | None = None


def _get_project_root() -> str:
    """Get the project root directory, caching the result.

    Uses PROJECT_ROOT or PROJECT env vars if set, otherwise falls back to /src.
    This matches the logic in tools.py _find_project_root().
    """
    global _project_root_cache
    if _project_root_cache is not None:
        return _project_root_cache

    src_dir = os.environ.get("SRC", "/src")

    # Method 1: Explicit PROJECT_ROOT env var
    project_root = os.environ.get("PROJECT_ROOT")
    if project_root and os.path.isdir(project_root):
        _project_root_cache = project_root
        return _project_root_cache

    # Method 2: Use PROJECT env var from metadata
    project = os.environ.get("PROJECT")
    if project:
        candidate = os.path.join(src_dir, project)
        if os.path.isdir(candidate):
            _project_root_cache = candidate
            return _project_root_cache

    # Fallback: use /src (broad permission)
    _project_root_cache = src_dir
    return _project_root_cache


def get_allowed_write_paths() -> list[str]:
    """Get the list of paths where the agent is allowed to write."""
    project_root = _get_project_root()
    # Allow writes to the project root and its contents
    return [project_root + "/", project_root]


async def restrict_file_writes(
    tool_name: str,
    input_data: dict,
    context: ToolPermissionContext,
) -> PermissionResultAllow | PermissionResultDeny:
    """Permission callback to restrict file writes to the project source directory.

    Uses PROJECT_ROOT or PROJECT env var to determine the allowed write path.
    This ensures the agent can only modify source code within the specific project,
    not other projects in /src/ or system files.

    Args:
        tool_name: Name of the tool being called (e.g., "Write", "Edit", "Bash")
        input_data: Tool input parameters
        context: Permission context from the SDK

    Returns:
        PermissionResultAllow or PermissionResultDeny
    """
    # Always allow read-only operations
    if tool_name in ["Read", "Glob", "Grep"]:
        return PermissionResultAllow()

    # Restrict Write/Edit to project source directory only
    if tool_name in ["Write", "Edit", "MultiEdit"]:
        file_path = input_data.get("file_path", "")

        # Normalize path
        if not file_path.startswith("/"):
            file_path = f"/src/{file_path}"

        # Check if path is within allowed directories
        allowed_paths = get_allowed_write_paths()
        is_allowed = any(file_path.startswith(allowed) for allowed in allowed_paths)

        if not is_allowed:
            project_root = _get_project_root()
            return PermissionResultDeny(
                message=f"Write access denied: {file_path}. Only {project_root}/ is writable."
            )

        return PermissionResultAllow()

    # Restrict Bash commands that could write outside /src
    if tool_name == "Bash":
        command = input_data.get("command", "")

        # Block dangerous commands
        dangerous_patterns = [
            "rm -rf /",
            "chmod 777",
            "> /etc/",
            "> /usr/",
            "> /bin/",
            "dd if=",
        ]

        for pattern in dangerous_patterns:
            if pattern in command:
                return PermissionResultDeny(
                    message=f"Dangerous command blocked: {pattern}"
                )

        return PermissionResultAllow()

    # Allow MCP tools (our custom ARVO tools)
    if tool_name.startswith("mcp__arvo__"):
        return PermissionResultAllow()

    # Default: allow other tools
    return PermissionResultAllow()
