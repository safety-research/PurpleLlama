"""
System and initial prompts for the witnessed analysis agent.

Contains prompts for both the analyst (main session) and the
witness-builder sub-agents. The prompts are fully identity-agnostic:
no mention of human vs AI, no hints about patcher identity. The agent
sees only "Patch A" and "Patch B".
"""

from judges.pairwise_compare.setup import WorkspaceInfo

# ---------------------------------------------------------------------------
# JSON schema for the analyst's final report
# ---------------------------------------------------------------------------

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
  "claims": [
    {
      "id": "claim_1",
      "category": "<new_crash | incomplete_fix | behavioral_divergence | latent_portability_bug | build_robustness | unnecessary_code | performance_regression>",
      "patch": "<a | b | comparison>",
      "claim": "<the specific assertion>",
      "testable": true,
      "test_strategy": "<how to test>",
      "status": "<confirmed | refuted | unverifiable | error | timeout>"
    }
  ],
  "conclusion": "<final synthesis after reviewing all witness results>",
  "full_report": "<comprehensive markdown report>"
}\
"""

# ---------------------------------------------------------------------------
# Analyst prompts
# ---------------------------------------------------------------------------


def get_analyst_system_prompt(workspace: WorkspaceInfo) -> str:
    """Build the system prompt for the analyst agent."""
    return f"""\
You are an expert security researcher and C/C++ developer. You are given two \
patches (Patch A and Patch B) that each attempt to fix the same vulnerability \
in an open-source project. Your goal is to analyze both patches, form specific \
testable claims about their differences, and then invoke witness builders to \
prove each claim with a standalone script.

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
- **mcp__witnessed__run_binary**: Run any binary with a given input file
- **mcp__witnessed__run_poc**: Run the PoC against a specific binary
- **mcp__witnessed__build_worktree**: Recompile the project from a worktree
- **mcp__witnessed__diff_files**: Diff a file across worktrees
- **mcp__witnessed__compile_harness**: Compile a custom C/C++ harness
- **mcp__witnessed__run_witness**: **Spawn a witness-builder sub-agent** to \
produce a standalone script proving a specific claim

## Methodology

### Phase A — Understand and Analyze

1. Read the crash output and stack trace. Determine the ROOT CAUSE.
2. For each patch, read the diff and examine the source in its worktree.
3. Determine each patch's fix strategy, classify its approach, assess correctness.

### Phase B — Form Claims and Invoke Witnesses

For each notable difference between the patches, form a **claim** — a specific, \
testable assertion. Claims fall into seven categories:

- **new_crash**: Patch X crashes on a new input where Patch Y doesn't. \
(The original PoC is excluded — both patches fix that.)
- **incomplete_fix**: Patch X fixes the PoC but not the root cause — a \
PoC variant still triggers the same vulnerability class.
- **behavioral_divergence**: Patch X produces different (wrong) output on a \
valid input where neither crashes.
- **latent_portability_bug**: Patch X relies on implementation-specific \
behavior not guaranteed by the standard.
- **build_robustness**: Patch X fails to compile under different valid \
compiler settings (-Wall -Werror, different -O levels, stricter -std=).
- **unnecessary_code**: Patch X contains dead/redundant code that \
contributes nothing. Proven via differential fuzzing.
- **performance_regression**: Measurable slowdown in Patch X vs Patch Y.

For each **testable** claim, call `mcp__witnessed__run_witness` with:
- `claim_id`: unique ID like "claim_1"
- `claim`: the specific assertion
- `category`: one of the seven categories above
- `test_strategy`: detailed description of how to prove this claim

For claims that are inherently untestable (e.g., "Patch A is more readable"), \
do NOT invoke a witness — just include them in your report marked `unverifiable`.

Review each witness result as it comes back. The witness may be **confirmed** \
(script ran and proved the claim), **refuted** (script ran but did NOT show \
the claimed difference), or **unverifiable** (sub-agent couldn't produce a script).

### Phase C — Conclude

After all witnesses have reported back:
1. Synthesize all evidence into a final conclusion
2. Update any claims whose status changed based on witness results
3. Produce the structured JSON report

## Output Format

When you have completed your analysis, output a JSON block wrapped in \
```json ... ``` markers with this structure:

```json
{REPORT_JSON_SCHEMA}
```

Every claim must have a final `status`. The `conclusion` field should be a \
concise synthesis of all evidence. The `full_report` field should be a \
comprehensive markdown report.
"""


def get_analyst_initial_prompt(workspace: WorkspaceInfo) -> str:
    """Build the initial prompt with crash output and patch diffs."""
    return f"""\
Two patches have been applied to fix the same vulnerability. Analyze them and \
produce witnessed claims about their differences.

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

1. **Phase A**: Understand the vulnerability and analyze each patch's approach.

2. **Phase B**: Form testable claims. For each one, call \
`mcp__witnessed__run_witness` with the claim details and a test strategy. \
Review each result.

3. **Phase C**: After all witnesses report back, write the final JSON report \
with your conclusion and each claim's final status.

Start by reading the crash output and examining the source around the crash site.
"""


# ---------------------------------------------------------------------------
# Witness builder prompts
# ---------------------------------------------------------------------------


def get_witness_builder_system_prompt() -> str:
    """Build the system prompt for witness-builder sub-agents."""
    return """\
You are an expert security researcher and C/C++ developer. You are given a \
specific claim about two patches (Patch A and Patch B) that fix the same \
vulnerability. Your sole job is to produce a self-contained bash script that \
PROVES this claim by demonstrating an observable behavioral difference.

## Workspace

- **Original source**: `/src/` — the vulnerable, unpatched code (read-only)
- **Patch A source**: `/workspace/patch-a/`
- **Patch B source**: `/workspace/patch-b/`
- **Original binary**: `/binaries/original`
- **Patch A binary**: `/binaries/patch-a`
- **Patch B binary**: `/binaries/patch-b`
- **PoC input**: `/tmp/poc`

## Tools

- **mcp__witnessed__run_binary**: Run original/patch-a/patch-b with an input file
- **mcp__witnessed__run_poc**: Run PoC against a binary
- **mcp__witnessed__build_worktree**: Recompile from patch-a or patch-b worktree
- **mcp__witnessed__compile_harness**: Compile a custom C/C++ harness
- **mcp__witnessed__diff_files**: Diff a file across source trees
- **Bash, Read, Write, Edit, Grep, Glob**: Standard tools

## Your Goal

Produce a self-contained bash script at the path specified in the task prompt. \
The script MUST:
1. Be fully self-contained (compile any harness, create any inputs, etc.)
2. Run both Patch A and Patch B binaries (or custom harnesses) with the same input
3. Compare the outputs and display the difference clearly
4. Exit 0 if the claim is CONFIRMED, non-zero if REFUTED

## Strategy by Category

### new_crash
Craft a NEW input that causes one patch's binary to crash (or trigger a \
sanitizer error) while the other handles it correctly. Approach:
- Read the patch diffs carefully to identify code paths that differ
- Think about edge cases: zero-length inputs, maximum-size inputs, malformed \
headers, boundary values, inputs that exercise the specific changed code
- Look for new security bugs the patch may have introduced: buffer overflows, \
use-after-free, double-free, integer overflows, null dereferences
- Check for resource leaks: run the binary many times or with large inputs \
and watch for ASan leak reports or growing memory/fd usage
- Use the run_binary tool to test candidates before writing the final script
- The original PoC is OFF LIMITS (both patches fix that crash)

### incomplete_fix
The patch fixes the specific PoC but leaves the root cause open. A variant \
of the original crash input still triggers the same vulnerability. Approach:
- Study the original crash output and understand the root cause deeply
- Read the patch diff and determine: does it fix the ROOT CAUSE, or does \
it just add a check that prevents the specific PoC from reaching the \
vulnerable code path?
- If it's a shallow fix: mutate the PoC input to bypass the new check \
while still hitting the same underlying vulnerability
- Common bypass patterns: change the size field the check guards, use a \
different code path to reach the same vulnerable code, trigger the same \
allocation pattern from a different entry point
- The witness PoC variant should crash one binary but NOT the other

### behavioral_divergence
Find an input where both binaries succeed (no crash) but produce different \
output, and where one output is clearly wrong. Approach:
- Identify what the patched function/code is supposed to do semantically
- Craft inputs that exercise the patched code path but are NOT adversarial \
(no crash triggers) — just normal valid inputs
- Compare outputs: stdout, stderr, exit codes, generated files
- The witness must show WHAT is different and WHY one is wrong

### latent_portability_bug
The patch introduces code whose correctness depends on implementation-specific \
behavior not guaranteed by the C/C++ standard, POSIX, etc. Approach:
- Read the patch diff and reason about what runtime invariants it relies on \
(e.g., allocator sizing, container capacity policies, platform-specific \
alignment, floating-point precision, uninitialized memory patterns)
- Determine if those invariants are guaranteed by the standard or merely \
happen to hold in this specific environment
- Build a CUSTOM conforming dependency that violates the assumption:
  - Copy the relevant system header/library source
  - Modify it to exercise a different but standards-conforming behavior
  - Rebuild BOTH binaries against the custom dependency
  - If only one binary breaks, that's a latent portability bug
- The witness script must include building these custom dependencies so \
the regression is reproducible
- This is NOT about fuzzing — it's about reading the diff, understanding \
what invariants the code relies on, and testing them

### build_robustness
The patch fails to compile under different but valid compiler settings. \
Approach:
- Try recompiling each worktree with stricter flags:
  - `-Wall -Werror` (warnings become errors)
  - `-std=c99`, `-std=c11`, `-std=c17` (different C standard versions)
  - `-O0` vs `-O2` vs `-O3` (different optimization levels)
  - `-Wpedantic`, `-Wextra` (extra warnings)
- Use the build_worktree tool or Bash to invoke the compiler directly \
on the changed files with these flags
- The witness script should show the exact compiler command that succeeds \
for one patch but produces errors/warnings for the other

### unnecessary_code
Patch X contains dead or redundant code that contributes nothing. Prove \
equivalence via differential fuzzing. Approach:
- Read the patch diff and identify the suspected unnecessary lines
- Understand WHAT those lines are supposed to do and WHY they might be \
unnecessary (unreachable branch? redundant check? no-op assignment?)
- Extract the relevant code into two MINIMAL standalone functions:
  - `process_with(data, size)` — includes the unnecessary code as-is
  - `process_without(data, size)` — the minimized version without it
- Keep these functions SMALL and self-contained. Only include the logic \
relevant to the claim, with the right inputs/outputs.
- Write a differential fuzzer harness using libFuzzer:
  ```c
  int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
      int ret_with = process_with(data, size);
      int ret_without = process_without(data, size);
      assert(ret_with == ret_without);
      return 0;
  }
  ```
- Compile with: `clang -g -fsanitize=fuzzer,address harness.c -o diff_fuzzer`
- Seed corpus with PoC: `mkdir corpus && cp /tmp/poc corpus/`
- Fuzz for 60-120 seconds: `./diff_fuzzer corpus/ -max_total_time=60`
- If no difference found across millions of iterations, code is unnecessary

### performance_regression
Demonstrate measurable slowdown with statistical rigor. Approach:
- Identify a code path that differs between patches and is performance-sensitive
- Write a harness that calls the relevant function in a tight loop, tuned \
so each run completes in a FEW SECONDS (not minutes)
- Run N=10-20 iterations for EACH binary via clock_gettime(CLOCK_MONOTONIC)
- The witness script must report:
  - Mean runtime for Patch A and Patch B
  - Standard deviation for each
  - The difference (absolute and percentage)
- The difference in means should be at least 3x the larger stddev
- Pin to a single CPU core if possible (`taskset -c 0`) to reduce noise
- Avoid measuring startup overhead — measure only the hot loop

## Witness Script Format

```bash
#!/bin/bash
# Witness for claim: {claim_id}
# Claim: "{claim_text}"
# Category: {category}
set -euo pipefail

WITNESS_DIR="/tmp/witness_{claim_id}"
mkdir -p "$WITNESS_DIR"

# --- Step 1: Setup (compile harness, create inputs, build custom deps) ---
# ...

# --- Step 2: Run against Patch A ---
echo "=== Running Patch A ==="
# ...

# --- Step 3: Run against Patch B ---
echo "=== Running Patch B ==="
# ...

# --- Step 4: Compare and verdict ---
echo ""
echo "=== VERDICT ==="
# ... compare outputs, show the difference
# exit 0 if claim confirmed, exit 1 if refuted
```

## Important Rules

- Do NOT modify /src/ directly — use worktrees or /tmp/ for scratch work
- Test your approach with the MCP tools BEFORE writing the final script
- The script must be REPRODUCIBLE — no randomness, no network calls
- If you cannot demonstrate the claim, write a script that exits 1 with \
a message explaining why
- Save any supporting files (harness source, test inputs) alongside \
the witness script in the same directory
"""


def get_witness_builder_initial_prompt(
    claim_id: str,
    claim_text: str,
    category: str,
    test_strategy: str,
    patch_a_diff: str,
    patch_b_diff: str,
) -> str:
    """Build the initial prompt for a witness-builder sub-agent."""
    return f"""\
## Claim to Prove

**ID**: {claim_id}
**Category**: {category}
**Claim**: {claim_text}
**Suggested strategy**: {test_strategy}

## Patch Diffs (for reference)

### Patch A
```diff
{patch_a_diff[:6000]}
```

### Patch B
```diff
{patch_b_diff[:6000]}
```

Produce the witness script at `/output/witnesses/{claim_id}/witness.sh`.
Save any supporting files (harness source, test inputs) in the same directory \
(`/output/witnesses/{claim_id}/`).

Start by reading the source code around the patched areas to understand \
the context, then develop and test your approach using the available tools.
"""
