#!/usr/bin/env python3
"""
Classify fix strategy patterns across patch comparison analysis results.

For each case, reads the judge's analysis report and uses Claude Opus to
classify whether the case matches the "GT validates upstream, LLM fixes
symptom downstream" pattern.

Output: JSON file mapping case_id -> {label, confidence, one_line}

Usage:
    python classify_fix_strategy.py \
        --analysis-dir /tmp/analysis-results/analysis-20260213-133233 \
        --output /tmp/classifications.json \
        [--agent-id claudecode-claude-opus-4-6] \
        [--model claude-opus-4-6-20250929] \
        [--max-concurrent 10]
"""

import argparse
import asyncio
import json
import sys
from pathlib import Path

import anthropic


CLASSIFICATION_PROMPT = """\
You are classifying vulnerability patches. A judge has analyzed two patches \
(Patch A and Patch B) for the same vulnerability. One patch is from a human \
developer (ground truth / GT) and one is from an LLM agent. The blinding key \
tells you which is which.

Determine which category this case falls into:

1. **gt_upstream_llm_downstream**: GT fixes the root cause via upstream input \
validation (rejects, clamps, or sanitizes bad input BEFORE it propagates to \
the crash site). The LLM agent instead fixes the symptom downstream (enlarges \
buffers, adds defensive guards at the crash site, handles bad state after it \
already exists). This includes cases where GT corrects a wrong constant/size \
calculation while LLM just makes the buffer bigger.

2. **both_similar**: Both patches use essentially the same strategy (both \
validate upstream, or both fix downstream, or both make the same core change).

3. **llm_better_strategy**: The LLM agent actually has a better or more \
principled fix strategy than GT.

4. **other**: Doesn't clearly fit any of the above patterns (e.g. both are \
wrong, or the difference is about something else entirely).

Here is the judge's analysis:

## Blinding Key
{blinding}

## Vulnerability
Type: {vuln_type}
Root cause: {root_cause}

## Patch Analysis (from the judge)

### {pa_label}
- Approach: {pa_approach}
- Correctness: {pa_correctness}
- Core idea: {pa_core_idea}
- Analysis: {pa_analysis}

### {pb_label}
- Approach: {pb_approach}
- Correctness: {pb_correctness}
- Core idea: {pb_core_idea}
- Analysis: {pb_analysis}

## Comparison (from the judge)
Similarity: {similarity}
Which is better: {which_better}
Reasoning: {reasoning}

---

Respond with ONLY a JSON object (no markdown, no explanation outside the JSON):
{{"label": "gt_upstream_llm_downstream" or "both_similar" or "llm_better_strategy" or "other", "confidence": "high" or "low", "one_line": "brief one-sentence explanation"}}"""


async def classify_case(
    client: anthropic.AsyncAnthropic,
    case_id: str,
    report: dict,
    blinding: dict,
    model: str,
    semaphore: asyncio.Semaphore,
) -> tuple[str, dict]:
    """Classify a single case. Returns (case_id, classification_dict)."""
    pa_patcher = blinding.get("patch_a_patcher", "unknown")
    pb_patcher = blinding.get("patch_b_patcher", "unknown")

    vuln = report.get("vulnerability", {})
    pa = report.get("patch_a", {})
    pb = report.get("patch_b", {})
    comp = report.get("comparison", {})

    # Unblind "which is better"
    wb = comp.get("which_is_better", "equivalent")
    if wb == "a":
        which_better = pa_patcher
    elif wb == "b":
        which_better = pb_patcher
    else:
        which_better = "equivalent"

    prompt = CLASSIFICATION_PROMPT.format(
        blinding=f"Patch A = {pa_patcher}, Patch B = {pb_patcher}",
        vuln_type=vuln.get("type", "unknown"),
        root_cause=vuln.get("root_cause_description", "unknown"),
        pa_label=f"Patch A ({pa_patcher})",
        pa_approach=pa.get("approach_type", "unknown"),
        pa_correctness=pa.get("correctness", "unknown"),
        pa_core_idea=pa.get("core_idea", ""),
        pa_analysis=pa.get("analysis", ""),
        pb_label=f"Patch B ({pb_patcher})",
        pb_approach=pb.get("approach_type", "unknown"),
        pb_correctness=pb.get("correctness", "unknown"),
        pb_core_idea=pb.get("core_idea", ""),
        pb_analysis=pb.get("analysis", ""),
        similarity=comp.get("similarity", "unknown"),
        which_better=which_better,
        reasoning=comp.get("reasoning", ""),
    )

    async with semaphore:
        try:
            response = await client.messages.create(
                model=model,
                max_tokens=256,
                messages=[{"role": "user", "content": prompt}],
            )
            text = response.content[0].text.strip()

            # Parse JSON from response (handle potential markdown wrapping)
            if text.startswith("```"):
                text = text.split("\n", 1)[1].rsplit("```", 1)[0].strip()

            result = json.loads(text)
            return case_id, {
                "label": result.get("label", "other"),
                "confidence": result.get("confidence", "low"),
                "one_line": result.get("one_line", ""),
            }
        except json.JSONDecodeError as e:
            print(f"  [{case_id}] JSON parse error: {e} -- raw: {text[:200]}", file=sys.stderr)
            return case_id, {"label": "other", "confidence": "low", "one_line": f"parse error: {text[:100]}"}
        except Exception as e:
            print(f"  [{case_id}] API error: {e}", file=sys.stderr)
            return case_id, {"label": "other", "confidence": "low", "one_line": f"error: {str(e)[:100]}"}


async def run_all(
    analysis_dir: Path,
    agent_id: str,
    model: str,
    max_concurrent: int,
) -> dict[str, dict]:
    """Classify all cases and return results dict."""
    pair_suffix = f"{agent_id}-vs-gt"
    client = anthropic.AsyncAnthropic()
    semaphore = asyncio.Semaphore(max_concurrent)

    tasks = []
    for case_dir in sorted(
        analysis_dir.iterdir(),
        key=lambda d: int(d.name) if d.name.isdigit() else 0,
    ):
        if not case_dir.is_dir():
            continue
        pair_dir = case_dir / pair_suffix
        report_path = pair_dir / "report.json"
        bk_path = pair_dir / "blinding_key.json"
        if not report_path.exists() or not bk_path.exists():
            continue

        with open(report_path) as f:
            report = json.load(f)
        with open(bk_path) as f:
            blinding = json.load(f)

        tasks.append(classify_case(client, case_dir.name, report, blinding, model, semaphore))

    print(f"Classifying {len(tasks)} cases with {model} (max {max_concurrent} concurrent)...", file=sys.stderr)

    results = {}
    done = 0
    for coro in asyncio.as_completed(tasks):
        case_id, classification = await coro
        results[case_id] = classification
        done += 1
        label = classification["label"]
        conf = classification["confidence"]
        print(f"  [{done}/{len(tasks)}] {case_id}: {label} ({conf}) -- {classification['one_line'][:80]}", file=sys.stderr)

    return results


def main():
    parser = argparse.ArgumentParser(description="Classify fix strategy patterns")
    parser.add_argument("--analysis-dir", required=True, type=Path, help="Analysis results directory")
    parser.add_argument("--output", "-o", required=True, type=Path, help="Output JSON file")
    parser.add_argument("--agent-id", default="claudecode-claude-opus-4-6", help="Agent ID")
    parser.add_argument("--model", default="claude-opus-4-6-20250929", help="Classification model")
    parser.add_argument("--max-concurrent", type=int, default=10, help="Max concurrent API calls")
    args = parser.parse_args()

    results = asyncio.run(run_all(args.analysis_dir, args.agent_id, args.model, args.max_concurrent))

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with open(args.output, "w") as f:
        json.dump(results, f, indent=2)

    # Summary
    from collections import Counter
    counts = Counter(r["label"] for r in results.values())
    print(f"\nClassification summary ({len(results)} cases):", file=sys.stderr)
    for label, count in counts.most_common():
        print(f"  {label}: {count}", file=sys.stderr)
    print(f"\nSaved to {args.output}", file=sys.stderr)


if __name__ == "__main__":
    main()
