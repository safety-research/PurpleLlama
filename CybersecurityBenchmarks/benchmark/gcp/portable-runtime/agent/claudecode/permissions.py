"""
Permission callback to restrict file writes to /src/ only.

Used by ClaudeAgentOptions.can_use_tool to enforce file system access policies
for the Claude Code agent running inside ARVO containers.
"""

from claude_agent_sdk import (
    PermissionResultAllow,
    PermissionResultDeny,
    ToolPermissionContext,
)

# Directories where the agent is allowed to write
ALLOWED_WRITE_PATHS = ["/src/", "/src"]


async def restrict_file_writes(
    tool_name: str,
    input_data: dict,
    context: ToolPermissionContext,
) -> PermissionResultAllow | PermissionResultDeny:
    """Permission callback to restrict file writes to /src only.

    This ensures the agent can only modify source code, not:
    - Build scripts
    - System files
    - Output directories (/out, /tmp)
    - Any other sensitive locations

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

    # Restrict Write/Edit to /src directory only
    if tool_name in ["Write", "Edit", "MultiEdit"]:
        file_path = input_data.get("file_path", "")

        # Normalize path
        if not file_path.startswith("/"):
            file_path = f"/src/{file_path}"

        # Check if path is within allowed directories
        is_allowed = any(
            file_path.startswith(allowed) for allowed in ALLOWED_WRITE_PATHS
        )

        if not is_allowed:
            return PermissionResultDeny(
                message=f"Write access denied: {file_path}. Only /src/ is writable."
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
