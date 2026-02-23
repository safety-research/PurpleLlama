"""
Permission callback for the analysis agent.

Allows writes to /workspace/*, /tmp/*, and /output/ but blocks writes
to /src/ (the original source must remain pristine) and system paths.
"""

from claude_agent_sdk import (
    PermissionResultAllow,
    PermissionResultDeny,
    ToolPermissionContext,
)

# Paths the analysis agent is allowed to write to
ALLOWED_WRITE_PREFIXES = [
    "/workspace/",
    "/tmp/",
    "/output/",
]

# Paths that must never be written to
BLOCKED_WRITE_PREFIXES = [
    "/src/",  # Original source must stay pristine
    "/etc/",
    "/usr/",
    "/bin/",
    "/sbin/",
]


async def restrict_analysis_writes(
    tool_name: str,
    input_data: dict,
    context: ToolPermissionContext,
) -> PermissionResultAllow | PermissionResultDeny:
    """Permission callback for the analysis agent.

    Read operations are always allowed. Write operations are restricted
    to /workspace/, /tmp/, and /output/. The original source at /src/
    is read-only to preserve the pristine state for comparison.
    """
    # Always allow read-only operations
    if tool_name in ["Read", "Glob", "Grep"]:
        return PermissionResultAllow()

    # Restrict Write/Edit to allowed paths
    if tool_name in ["Write", "Edit", "MultiEdit"]:
        file_path = input_data.get("file_path", "")

        # Check blocked paths first
        for prefix in BLOCKED_WRITE_PREFIXES:
            if file_path.startswith(prefix):
                return PermissionResultDeny(
                    message=f"Write denied: {file_path}. "
                    f"The original source at /src/ is read-only. "
                    f"You may write to /workspace/ or /tmp/ instead."
                )

        # Check allowed paths
        is_allowed = any(
            file_path.startswith(prefix) for prefix in ALLOWED_WRITE_PREFIXES
        )
        if not is_allowed:
            return PermissionResultDeny(
                message=f"Write denied: {file_path}. "
                f"Allowed paths: {', '.join(ALLOWED_WRITE_PREFIXES)}"
            )

        return PermissionResultAllow()

    # Restrict Bash: block dangerous commands
    if tool_name == "Bash":
        command = input_data.get("command", "")
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

    # Allow MCP tools (our custom analysis tools)
    if tool_name.startswith("mcp__analysis__"):
        return PermissionResultAllow()

    # Default: allow
    return PermissionResultAllow()
