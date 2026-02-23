"""
Permission callback for the witnessed analysis agent.

Allows writes to /workspace/*, /tmp/*, and /output/ but blocks writes
to /src/ (the original source must remain pristine) and system paths.

Identical policy to judges/pairwise_compare/claudecode/permissions.py.
"""

from claude_agent_sdk import (
    PermissionResultAllow,
    PermissionResultDeny,
    ToolPermissionContext,
)

ALLOWED_WRITE_PREFIXES = [
    "/workspace/",
    "/tmp/",
    "/output/",
]

BLOCKED_WRITE_PREFIXES = [
    "/src/",
    "/etc/",
    "/usr/",
    "/bin/",
    "/sbin/",
]


async def restrict_witnessed_writes(
    tool_name: str,
    input_data: dict,
    context: ToolPermissionContext,
) -> PermissionResultAllow | PermissionResultDeny:
    """Permission callback for the witnessed analysis agents.

    Read operations are always allowed. Write operations are restricted
    to /workspace/, /tmp/, and /output/. The original source at /src/
    is read-only to preserve the pristine state for comparison.
    """
    if tool_name in ["Read", "Glob", "Grep"]:
        return PermissionResultAllow()

    if tool_name in ["Write", "Edit", "MultiEdit"]:
        file_path = input_data.get("file_path", "")

        for prefix in BLOCKED_WRITE_PREFIXES:
            if file_path.startswith(prefix):
                return PermissionResultDeny(
                    message=f"Write denied: {file_path}. "
                    f"The original source at /src/ is read-only. "
                    f"You may write to /workspace/ or /tmp/ instead."
                )

        is_allowed = any(
            file_path.startswith(prefix) for prefix in ALLOWED_WRITE_PREFIXES
        )
        if not is_allowed:
            return PermissionResultDeny(
                message=f"Write denied: {file_path}. "
                f"Allowed paths: {', '.join(ALLOWED_WRITE_PREFIXES)}"
            )

        return PermissionResultAllow()

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

    if tool_name.startswith("mcp__witnessed__"):
        return PermissionResultAllow()

    return PermissionResultAllow()
