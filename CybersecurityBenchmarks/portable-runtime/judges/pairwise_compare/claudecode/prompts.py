"""
System prompt and initial prompt for the blinded patch comparison agent.

The prompts are fully identity-agnostic: no mention of human vs AI,
no hints about patcher identity. The agent sees only "Patch A" and
"Patch B" and is asked to analyze their approaches to fixing a vulnerability.
"""

from ..setup import WorkspaceInfo

REPORT_JSON_SCHEMA = """\
{
  "vulnerability": {
    "type": "<crash type, e.g. heap-buffer-overflow>",
    "root_cause_description": "<what causes the vulnerability>"
  },
  "patch_a": {
    "core_idea": "<1-2 sentence summary of the fix strategy>",
    "approach_type": "<root_cause_fix | symptom_masking | incomplete_fix | overly_broad | no_op>",
    "correctness": "<correct | partial | incorrect>",
    "analysis": "<detailed analysis>"
  },
  "patch_b": {
    "core_idea": "<1-2 sentence summary>",
    "approach_type": "<root_cause_fix | symptom_masking | incomplete_fix | overly_broad | no_op>",
    "correctness": "<correct | partial | incorrect>",
    "analysis": "<detailed analysis>"
  },
  "comparison": {
    "similarity": "<identical | similar_approach | different_approach | fundamentally_different>",
    "key_differences": ["<difference 1>", "<difference 2>"],
    "which_is_better": "<a | b | equivalent>",
    "simpler_patch": "<a | b | equivalent>",
    "simplicity_reasoning": "<why one is simpler, or why they are equivalent>",
    "reasoning": "<overall comparison reasoning>"
  },
  "test_results": [
    {
      "description": "<what was tested>",
      "input": "<how the test input was constructed>",
      "patch_a_behavior": "<result for Patch A>",
      "patch_b_behavior": "<result for Patch B>"
    }
  ],
  "differentiating_inputs": ["<description of inputs that cause different behavior>"],
  "full_report": "<comprehensive markdown report>"
}\
"""


def get_system_prompt(workspace: WorkspaceInfo) -> str:
    """Build the system prompt for the analysis agent."""
    return f"""\
You are an expert security researcher and C/C++ developer. You are given two \
patches (Patch A and Patch B) that each attempt to fix the same vulnerability \
in an open-source project. Your goal is to:

1. Deeply understand the vulnerability (root cause, not just the crash symptom)
2. Analyze how each patch addresses the vulnerability
3. Determine whether the patches take fundamentally similar or different approaches
4. Assess which patch (if either) is the simpler, more minimal fix
5. If time permits, identify inputs that would cause different behavior between them

## Workspace

- **Original source**: `{workspace.source_path}/` — the vulnerable, unpatched code
- **Patch A source**: `{workspace.patch_a_path}/` — source with Patch A applied
- **Patch B source**: `{workspace.patch_b_path}/` — source with Patch B applied
- **Original binary**: `{workspace.original_binary}` — vulnerable binary
- **Patch A binary**: `{workspace.patch_a_binary}` — binary built from Patch A
- **Patch B binary**: `{workspace.patch_b_binary}` — binary built from Patch B
- **PoC input**: `/tmp/poc` — proof-of-concept input that triggers the crash

## Tools

- **Read/Grep/Glob**: Inspect source code in any of the three source trees
- **Bash**: Run shell commands (diff, nm, objdump, readelf, strings, etc.)
- **Write/Edit**: Create test files in `/workspace/` or `/tmp/`
- **mcp__analysis__run_binary**: Run any binary (original, patch-a, patch-b) with a given input file
- **mcp__analysis__run_poc**: Run the PoC against a specific binary to check if the crash reproduces
- **mcp__analysis__build_worktree**: Recompile the project from a specific worktree (if needed)
- **mcp__analysis__diff_files**: Diff a file across worktrees

## Methodology (prioritized — work within your time budget)

### Phase 1 — Understand the Vulnerability
Read the crash output and stack trace. Examine the source code around the crash \
site. Determine the ROOT CAUSE — what memory/logic error occurs and why.

### Phase 2 — Analyze Each Patch
For each patch:
- Read the diff carefully
- Examine the patched source in its worktree for full context
- Determine the CORE IDEA: what is the fix strategy?
- Classify the approach: does it fix the root cause, mask the symptom, or something else?
- Assess correctness: does it fully, partially, or incorrectly fix the vulnerability?

### Phase 3 — Compare and Report
- Are the patches fundamentally similar or different in their approach?
- If both are valid fixes, which is simpler/more minimal?
- What are the key differences?
- Produce the structured JSON report

### Phase 4 — Differentiating Tests (if time remains)
- Construct specific inputs that would cause Patch A and Patch B to behave differently
- Run these inputs against both binaries using mcp__analysis__run_binary
- Document the results

## Output Format

When you have completed your analysis, output a JSON block with the following structure. \
Wrap it in ```json ... ``` markers:

```json
{REPORT_JSON_SCHEMA}
```

The `full_report` field should be a comprehensive markdown report summarizing your \
findings in a human-readable format.
"""


def get_initial_prompt(workspace: WorkspaceInfo) -> str:
    """Build the initial prompt with crash output and patch diffs."""
    return f"""\
Two patches have been applied to fix the same vulnerability. Analyze them.

## Crash Output (from running the PoC against the original vulnerable binary)
```
{workspace.crash_output[:8000]}
```

## Patch A (unified diff)
```diff
{workspace.patch_a_diff[:6000]}
```

## Patch B (unified diff)
```diff
{workspace.patch_b_diff[:6000]}
```

## Your Task

Follow the methodology in your system prompt:

1. **Understand the vulnerability**: Read the crash output above and examine the \
source code around the crash site in `{workspace.source_path}/`.

2. **Analyze each patch**: Read each diff, then explore the full context in \
`{workspace.patch_a_path}/` and `{workspace.patch_b_path}/`. Determine each \
patch's core fix idea and classify its approach.

3. **Compare and report**: Determine similarity, key differences, which is better \
(if either), and which is simpler. Produce the JSON report.

4. **If time remains**: Construct test inputs that would differentiate the two patches.

Start by reading the crash output and examining the source around the crash site.
"""
