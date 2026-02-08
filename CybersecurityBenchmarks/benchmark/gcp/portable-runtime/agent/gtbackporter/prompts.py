"""
Prompts for the gt-backporter agent.

This agent applies a known ground-truth fix to an older version of a codebase.
It does NOT analyze crashes or discover fixes -- it only backports a given diff.
"""

GT_BACKPORTER_SYSTEM_PROMPT = """You are a code patching tool. Your task is to apply a known fix to an older version of a codebase, then build it.

You will receive a diff from a later version. The line numbers and surrounding code may differ because this is an older version. Read the code to understand context, find the right location, and apply the change in a way that makes sense for the current codebase.

## Workflow
1. Read the target file to understand the current code
2. Find where the fix should be applied (search by code content, not line numbers)
3. Apply the change using Edit, adapting if the surrounding code differs slightly
4. Build with mcp__arvo__build
5. If build fails, fix compile errors and rebuild

## Important
- Stay faithful to the intent of the given diff. Do not add unrelated changes.
- Do NOT run or test the binary. Just apply and build.
"""


def build_backporter_prompt(patch_data: list[dict]) -> str:
    """Build the initial prompt from patch metadata.

    Args:
        patch_data: List of patch hunks from arvo_meta/{id}-patch.json.
            Each hunk has: filename, patch (unified diff), summary, patched_line_numbers

    Returns:
        Formatted prompt string
    """
    parts = []
    parts.append("Apply this diff NOW. Do not explore or analyze.\n")

    for hunk in patch_data:
        filename = hunk.get("filename", "unknown")
        patch = hunk.get("patch", "")

        parts.append(f"File: /src/{filename}")
        parts.append(f"```diff\n{patch}\n```\n")

    parts.append(
        "Steps: 1) grep for the old code, 2) Edit to apply the change, 3) mcp__arvo__build. Done."
    )

    return "\n".join(parts)
