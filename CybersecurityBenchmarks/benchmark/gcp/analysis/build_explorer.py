#!/usr/bin/env python3
"""
Build an interactive HTML explorer for patch comparison analysis results.

Generates a self-contained HTML page with:
- Summary charts (embedded as base64 PNG)
- Sortable, filterable table of all cases
- Per-case detail view with Judge Analysis, Agent Patch, GT Patch, LLM Transcript
- Dirty-repo case filtering (optional)

Usage:
    python build_explorer.py \
        --analysis-dir /tmp/analysis/analysis-20260213-133233 \
        --artifacts-dir /tmp/explorer-staging \
        --agent-id claudecode-claude-opus-4-6 \
        --output /tmp/analysis_explorer.html \
        [--image-audit /tmp/image-audit]
"""

import argparse
import base64
import io
import json
import re
import sys
from collections import Counter
from pathlib import Path


# ---------------------------------------------------------------------------
# Data loading
# ---------------------------------------------------------------------------

def load_dirty_cases(audit_dir: str | None) -> set[str]:
    """Load set of case IDs with dirty (modified tracked files) git repos."""
    if not audit_dir:
        return set()
    audit_path = Path(audit_dir)
    if not audit_path.exists():
        return set()

    dirty = set()
    for case_dir in audit_path.iterdir():
        if not case_dir.is_dir():
            continue
        for img_type in ["vul", "fix"]:
            jp = case_dir / f"{img_type}.json"
            if not jp.exists():
                continue
            raw = re.sub(r"^\s+", "", jp.read_text(), flags=re.MULTILINE)
            try:
                d = json.loads(raw)
            except json.JSONDecodeError:
                continue
            modified = d.get("modified_files", "").strip()
            status = d.get("git_status", "")
            has_tracked = bool(modified)
            if not has_tracked:
                for entry in status.split("|"):
                    entry = entry.strip()
                    if entry and not entry.startswith("??"):
                        has_tracked = True
                        break
            if has_tracked:
                dirty.add(case_dir.name)
    return dirty


def load_gt_patch(gt_patch_path: Path) -> str:
    """Load and format GT patch from ARVO metadata JSON."""
    if not gt_patch_path.exists():
        return ""
    try:
        gt_data = json.loads(gt_patch_path.read_text())
        parts = []
        for entry in gt_data:
            fn = entry.get("filename", "")
            patch_text = entry.get("patch", "")
            if patch_text:
                parts.append(f"--- a/{fn}\n+++ b/{fn}\n{patch_text}")
        return "\n".join(parts) if parts else json.dumps(gt_data, indent=2)
    except Exception:
        return gt_patch_path.read_text()


def parse_conversation(conv_path: Path) -> str:
    """Extract assistant reasoning from SDK conversation JSON."""
    if not conv_path.exists():
        return ""
    try:
        conv = json.loads(conv_path.read_text())
        msgs = conv.get("messages", [])
        parts = []
        for msg in msgs:
            mt = msg.get("type", "")
            content = msg.get("content", [])
            if isinstance(content, str):
                content = [content]
            for block in content:
                s = str(block)
                if mt == "AssistantMessage" and "TextBlock(text=" in s:
                    text = s.split("TextBlock(text=", 1)[1]
                    if text.startswith('"'):
                        text = text[1:]
                        end = text.rfind('")')
                        text = text[:end] if end > 0 else text
                    elif text.startswith("'"):
                        text = text[1:]
                        end = text.rfind("')")
                        text = text[:end] if end > 0 else text
                    try:
                        text = text.encode().decode("unicode_escape", errors="replace")
                    except Exception:
                        pass
                    if len(text.strip()) > 50:
                        parts.append(text.strip())
                elif mt == "AssistantMessage" and "ToolUseBlock" in s:
                    name = (
                        s.split("name='")[1].split("'")[0] if "name='" in s else "?"
                    )
                    if name in (
                        "Edit",
                        "Write",
                        "mcp__arvo__build",
                        "mcp__arvo__run_poc",
                        "mcp__arvo__reset_source",
                    ):
                        parts.append(f"[Tool: {name}]")
        return "\n\n---\n\n".join(parts[:50])
    except Exception:
        return "(Error parsing conversation)"


def compute_patch_stats(patch_text: str) -> dict:
    """Compute line changes, hunks, and file changes from a unified diff."""
    if not patch_text.strip():
        return {"lines": 0, "hunks": 0, "files": 0}

    additions = 0
    deletions = 0
    hunks = 0
    files = set()

    for line in patch_text.splitlines():
        if line.startswith("--- a/") or line.startswith("--- "):
            pass  # header
        elif line.startswith("+++ b/") or line.startswith("+++ "):
            fn = line.split("+++ ", 1)[1]
            if fn.startswith("b/"):
                fn = fn[2:]
            files.add(fn)
        elif line.startswith("@@"):
            hunks += 1
        elif line.startswith("+") and not line.startswith("+++"):
            additions += 1
        elif line.startswith("-") and not line.startswith("---"):
            deletions += 1
        elif line.startswith("diff --git"):
            parts = line.split(" b/", 1)
            if len(parts) > 1:
                files.add(parts[1])

    return {
        "lines": additions + deletions,
        "hunks": hunks,
        "files": len(files),
    }


def _load_project_map(meta_dir: Path | None) -> dict[str, str]:
    """Load case_id -> project name mapping from arvo_meta."""
    if not meta_dir or not meta_dir.exists():
        return {}
    projects = {}
    for mp in meta_dir.glob("*-meta.json"):
        try:
            cid = mp.name.split("-meta.json")[0]
            m = json.loads(mp.read_text())
            projects[cid] = m.get("arvo_metadata", {}).get("project", "")
        except Exception:
            pass
    return projects


def load_cases(
    analysis_dir: Path,
    artifacts_dir: Path,
    agent_id: str,
    dirty_cases: set[str],
    meta_dir: Path | None = None,
) -> list[dict]:
    """Load all case data from analysis reports and artifacts."""
    pair_suffix = f"{agent_id}-vs-gt"
    project_map = _load_project_map(meta_dir)
    cases = []

    for case_dir in sorted(
        analysis_dir.iterdir(),
        key=lambda d: int(d.name) if d.name.isdigit() else 0,
    ):
        if not case_dir.is_dir():
            continue
        cid = case_dir.name
        pair_dir = case_dir / pair_suffix
        if not pair_dir.exists():
            continue

        # Load report + blinding key
        report_path = pair_dir / "report.json"
        bk_path = pair_dir / "blinding_key.json"
        if not report_path.exists():
            continue
        with open(report_path) as f:
            report = json.load(f)
        with open(bk_path) as f:
            bk = json.load(f)

        pa = bk["patch_a_patcher"]
        pb = bk["patch_b_patcher"]
        opus_key = "patch_a" if pa == agent_id else "patch_b"
        gt_key = "patch_a" if pa == "gt" else "patch_b"
        opus_info = report.get(opus_key, {})
        gt_info = report.get(gt_key, {})
        comp = report.get("comparison", {})

        # Unblind "better"
        bb = comp.get("which_is_better", "equivalent")
        better = pa if bb == "a" else (pb if bb == "b" else "equivalent")
        better_disp = (
            "Opus" if agent_id in better else ("GT" if better == "gt" else "Equivalent")
        )

        # Agent patch
        agent_patch = ""
        pp = artifacts_dir / cid / "agent_patch.patch"
        if pp.exists():
            agent_patch = pp.read_text()

        # GT patch
        gt_patch = load_gt_patch(artifacts_dir / cid / "gt_patch.json")

        # Conversation
        conv_text = parse_conversation(artifacts_dir / cid / "conversation.json")

        # Judge report
        rp = pair_dir / "report.md"
        judge_md = rp.read_text() if rp.exists() else report.get("full_report", "")

        # Fuzzing results (unique crashes and regressions)
        opus_unique = 0
        opus_regressions = 0
        gt_unique = 0
        gt_regressions = 0

        for fuzz_agent, prefix in [(agent_id, "opus"), ("gt", "gt")]:
            fuzz_path = artifacts_dir / cid / f"{fuzz_agent}_fuzz.json"
            if fuzz_path.exists():
                try:
                    fdata = json.loads(fuzz_path.read_text())
                    uc = fdata.get("unique_crashes", 0)
                    if prefix == "opus":
                        opus_unique = uc
                    else:
                        gt_unique = uc
                except Exception:
                    pass

            reg_path = artifacts_dir / cid / f"{fuzz_agent}_regression.json"
            if reg_path.exists():
                try:
                    rdata = json.loads(reg_path.read_text())
                    regs = rdata.get("regressions", 0)
                    if prefix == "opus":
                        opus_regressions = regs
                    else:
                        gt_regressions = regs
                except Exception:
                    pass

        # Patch complexity stats
        opus_stats = compute_patch_stats(agent_patch)
        gt_stats = compute_patch_stats(gt_patch)

        cases.append(
            {
                "id": cid,
                "dirty": cid in dirty_cases,
                "opus_correct": opus_info.get("correctness", "unknown"),
                "gt_correct": gt_info.get("correctness", "unknown"),
                "similarity": comp.get("similarity", "unknown"),
                "better": better_disp,
                "opus_approach": opus_info.get("approach_type", "unknown"),
                "gt_approach": gt_info.get("approach_type", "unknown"),
                "opus_patch": agent_patch,
                "gt_patch": gt_patch,
                "conversation": conv_text,
                "judge_report": judge_md,
                "vuln_type": report.get("vulnerability", {}).get("type", ""),
                "project": project_map.get(cid, ""),
                "blinding": f"Patch A = {pa}, Patch B = {pb}",
                "opus_unique_crashes": opus_unique,
                "opus_regressions": opus_regressions,
                "gt_unique_crashes": gt_unique,
                "gt_regressions": gt_regressions,
                "opus_lines": opus_stats["lines"],
                "opus_hunks": opus_stats["hunks"],
                "opus_files": opus_stats["files"],
                "gt_lines": gt_stats["lines"],
                "gt_hunks": gt_stats["hunks"],
                "gt_files": gt_stats["files"],
            }
        )
    return cases


# ---------------------------------------------------------------------------
# Chart generation
# ---------------------------------------------------------------------------

def generate_chart_b64(cases: list[dict], agent_label: str) -> str:
    """Generate summary charts and return as base64-encoded PNG."""
    try:
        import matplotlib

        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        import numpy as np
    except ImportError:
        print("WARNING: matplotlib not installed, skipping charts", file=sys.stderr)
        return ""

    completed = [c for c in cases if not c["dirty"]]
    if not completed:
        completed = cases

    fig, axes = plt.subplots(2, 2, figsize=(16, 12))
    fig.suptitle(
        f"Patch Comparison: {agent_label} vs Ground Truth\n({len(completed)} cases)",
        fontsize=14,
        fontweight="bold",
    )

    sim_colors = {
        "identical": "#2ecc71",
        "similar_approach": "#3498db",
        "different_approach": "#f39c12",
        "fundamentally_different": "#e74c3c",
    }

    # 1. Similarity pie
    ax = axes[0, 0]
    sim_counts = Counter(c["similarity"] for c in completed)
    labels = ["identical", "similar_approach", "different_approach", "fundamentally_different"]
    sizes = [sim_counts.get(s, 0) for s in labels]
    display = [s.replace("_", " ").title() for s in labels]
    colors = [sim_colors[s] for s in labels]
    nz = [(l, s, c) for l, s, c in zip(display, sizes, colors) if s > 0]
    if nz:
        nl, ns, nc = zip(*nz)
        ax.pie(ns, labels=nl, colors=nc, autopct=lambda p: f"{p:.0f}%\n({int(round(p/100*sum(ns)))})" if p > 3 else "", startangle=90, textprops={"fontsize": 10})
    ax.set_title("Patch Similarity", fontsize=12, fontweight="bold")

    # 2. Which is better
    ax = axes[0, 1]
    better_counts = Counter(c["better"] for c in completed)
    bl = ["Opus", "Equivalent", "GT"]
    bv = [better_counts.get(b, 0) for b in bl]
    bc = ["#8e44ad", "#95a5a6", "#27ae60"]
    bars = ax.bar(bl, bv, color=bc, width=0.6)
    for bar, val in zip(bars, bv):
        if val > 0:
            ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.5, f"{val} ({val/len(completed)*100:.0f}%)", ha="center", va="bottom", fontweight="bold", fontsize=11)
    ax.set_title("Which Patch is Better?", fontsize=12, fontweight="bold")
    ax.set_ylabel("Cases")
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)

    # 3. Correctness
    ax = axes[1, 0]
    corr_levels = ["correct", "partial", "incorrect", "unknown"]
    x = np.arange(len(corr_levels))
    w = 0.35
    oc = Counter(c["opus_correct"] for c in completed)
    gc = Counter(c["gt_correct"] for c in completed)
    b1 = ax.bar(x - w / 2, [oc.get(c, 0) for c in corr_levels], w, label=agent_label, color="#8e44ad", alpha=0.85)
    b2 = ax.bar(x + w / 2, [gc.get(c, 0) for c in corr_levels], w, label="Ground Truth", color="#27ae60", alpha=0.85)
    for bs in [b1, b2]:
        for bar in bs:
            h = bar.get_height()
            if h > 0:
                ax.text(bar.get_x() + bar.get_width() / 2, h + 0.3, str(int(h)), ha="center", va="bottom", fontsize=10)
    ax.set_xticks(x)
    ax.set_xticklabels([c.title() for c in corr_levels])
    ax.set_title("Patch Correctness", fontsize=12, fontweight="bold")
    ax.set_ylabel("Cases")
    ax.legend()
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)

    # 4. Approach types
    ax = axes[1, 1]
    approaches = ["root_cause_fix", "symptom_masking", "incomplete_fix", "overly_broad", "no_op"]
    x = np.arange(len(approaches))
    oa = Counter(c["opus_approach"] for c in completed)
    ga = Counter(c["gt_approach"] for c in completed)
    b1 = ax.bar(x - w / 2, [oa.get(a, 0) for a in approaches], w, label=agent_label, color="#8e44ad", alpha=0.85)
    b2 = ax.bar(x + w / 2, [ga.get(a, 0) for a in approaches], w, label="Ground Truth", color="#27ae60", alpha=0.85)
    for bs in [b1, b2]:
        for bar in bs:
            h = bar.get_height()
            if h > 0:
                ax.text(bar.get_x() + bar.get_width() / 2, h + 0.3, str(int(h)), ha="center", va="bottom", fontsize=10)
    ax.set_xticks(x)
    ax.set_xticklabels([a.replace("_", "\n") for a in approaches], fontsize=9)
    ax.set_title("Patch Approach Type", fontsize=12, fontweight="bold")
    ax.set_ylabel("Cases")
    ax.legend()
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)

    plt.tight_layout()
    buf = io.BytesIO()
    plt.savefig(buf, format="png", dpi=150, bbox_inches="tight")
    buf.seek(0)
    b64 = base64.b64encode(buf.read()).decode("ascii")
    plt.close()
    return b64


# ---------------------------------------------------------------------------
# HTML generation
# ---------------------------------------------------------------------------

def build_html(cases: list[dict], chart_b64: str, agent_label: str) -> str:
    """Build the self-contained HTML explorer page."""
    data_json = json.dumps(cases, ensure_ascii=True)

    chart_section = ""
    if chart_b64:
        chart_section = f'''<div class="chart-section">
  <div class="chart-toggle open" onclick="this.classList.toggle('open'); this.nextElementSibling.classList.toggle('open');">
    <span class="arrow">&#9654;</span> Summary Charts (click to collapse)
  </div>
  <div class="chart-img-wrap open">
    <img src="data:image/png;base64,{chart_b64}" alt="Summary Charts">
  </div>
</div>'''

    return f'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Patch Analysis: {agent_label} vs Ground Truth</title>
<style>
* {{ box-sizing: border-box; margin: 0; padding: 0; }}
body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: #f5f6fa; color: #2c3e50; }}
.header {{ background: #2c3e50; color: white; padding: 20px 30px; }}
.header h1 {{ font-size: 20px; }}
.header .stats {{ margin-top: 8px; font-size: 14px; opacity: 0.9; }}
.header .stats span {{ margin-right: 20px; }}
.controls {{ padding: 10px 30px; background: #ecf0f1; border-bottom: 1px solid #bdc3c7; display: flex; gap: 15px; align-items: center; flex-wrap: wrap; }}
.controls label {{ font-size: 13px; }}
.controls select, .controls input {{ font-size: 13px; padding: 4px 8px; }}
.container {{ max-width: 1400px; margin: 0 auto; padding: 20px; }}
table {{ width: 100%; border-collapse: collapse; background: white; border-radius: 8px; overflow: hidden; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }}
th {{ background: #34495e; color: white; padding: 10px 14px; text-align: center; font-size: 13px; cursor: pointer; position: sticky; top: 0; z-index: 10; user-select: none; }}
th:hover {{ background: #4a6a8a; }}
th .sort-arrow {{ font-size: 10px; margin-left: 4px; opacity: 0.6; }}
th .sort-arrow.active {{ opacity: 1; }}
td {{ padding: 8px 14px; text-align: center; border-bottom: 1px solid #ecf0f1; font-size: 13px; }}
tr.dirty {{ opacity: 0.5; }}
tr.case-row {{ cursor: pointer; }}
tr.case-row:hover {{ background: #eaf2f8; }}
.tag {{ padding: 2px 8px; border-radius: 4px; font-size: 12px; font-weight: 500; }}
.tag-correct {{ background: #d5f5e3; color: #1e8449; }}
.tag-partial {{ background: #fdebd0; color: #b7950b; }}
.tag-incorrect {{ background: #f5b7b1; color: #922b21; }}
.tag-unknown {{ background: #f2f3f4; color: #7f8c8d; }}
.tag-opus {{ background: #d6eaf8; color: #21618c; }}
.tag-gt {{ background: #fef9e7; color: #7d6608; }}
.tag-equiv {{ background: #f2f3f4; color: #7f8c8d; }}
.tag-identical {{ background: #d5f5e3; }}
.tag-similar {{ background: #d6eaf8; }}
.tag-different {{ background: #fdebd0; }}
.tag-fundamental {{ background: #f5b7b1; }}
.dirty-badge {{ background: #e74c3c; color: white; padding: 1px 6px; border-radius: 3px; font-size: 10px; margin-left: 5px; }}
.chart-section {{ background: white; border-radius: 8px; margin: 20px auto; max-width: 1400px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); overflow: hidden; }}
.chart-toggle {{ padding: 12px 20px; cursor: pointer; font-size: 14px; font-weight: 500; color: #2c3e50; display: flex; align-items: center; gap: 8px; border-bottom: 1px solid #ecf0f1; }}
.chart-toggle:hover {{ background: #f8f9fa; }}
.chart-toggle .arrow {{ transition: transform 0.2s; }}
.chart-toggle.open .arrow {{ transform: rotate(90deg); }}
.chart-img-wrap {{ display: none; padding: 10px; text-align: center; }}
.chart-img-wrap.open {{ display: block; }}
.chart-img-wrap img {{ max-width: 100%; height: auto; }}
#detail-overlay {{ display: none; position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: #f5f6fa; z-index: 100; overflow-y: auto; }}
#detail-overlay.active {{ display: block; }}
.detail-header {{ background: #2c3e50; color: white; padding: 15px 30px; display: flex; align-items: center; gap: 20px; position: sticky; top: 0; z-index: 10; }}
.detail-header .back-btn {{ background: rgba(255,255,255,0.15); border: 1px solid rgba(255,255,255,0.3); color: white; padding: 6px 16px; border-radius: 5px; cursor: pointer; font-size: 14px; }}
.detail-header .back-btn:hover {{ background: rgba(255,255,255,0.25); }}
.detail-header h2 {{ font-size: 18px; }}
.detail-header .meta {{ font-size: 13px; opacity: 0.85; display: flex; gap: 15px; margin-left: auto; }}
.detail-body {{ max-width: 1200px; margin: 0 auto; padding: 20px 30px; }}
.tabs {{ display: flex; border-bottom: 2px solid #ddd; margin-bottom: 20px; background: white; border-radius: 8px 8px 0 0; padding: 0 10px; }}
.tab {{ padding: 12px 24px; cursor: pointer; font-size: 14px; font-weight: 500; border-bottom: 3px solid transparent; margin-bottom: -2px; color: #7f8c8d; transition: all 0.15s; }}
.tab:hover {{ color: #2c3e50; background: #f8f9fa; }}
.tab.active {{ color: #2980b9; border-bottom-color: #2980b9; }}
.tab-panel {{ display: none; background: white; border-radius: 0 0 8px 8px; padding: 25px; box-shadow: 0 1px 3px rgba(0,0,0,0.08); }}
.tab-panel.active {{ display: block; }}
pre {{ background: #1e1e1e; color: #d4d4d4; padding: 18px; border-radius: 6px; overflow-x: auto; font-size: 13px; line-height: 1.6; white-space: pre-wrap; word-wrap: break-word; max-height: 80vh; overflow-y: auto; }}
pre .diff-add {{ color: #6a9955; }}
pre .diff-del {{ color: #f44747; }}
pre .diff-hunk {{ color: #569cd6; }}
.markdown {{ line-height: 1.7; font-size: 14px; }}
.markdown h1 {{ font-size: 22px; margin: 20px 0 10px; border-bottom: 1px solid #ecf0f1; padding-bottom: 5px; }}
.markdown h2 {{ font-size: 18px; margin: 18px 0 8px; }}
.markdown h3 {{ font-size: 15px; margin: 15px 0 6px; }}
.markdown p {{ margin: 8px 0; }}
.markdown code {{ background: #ecf0f1; padding: 2px 5px; border-radius: 3px; font-size: 12px; }}
.markdown pre {{ margin: 12px 0; }}
.markdown pre code {{ background: none; padding: 0; }}
.markdown ul, .markdown ol {{ margin: 8px 0; padding-left: 25px; }}
.markdown li {{ margin: 4px 0; }}
.markdown hr {{ border: none; border-top: 1px solid #ddd; margin: 20px 0; }}
.nav-btns {{ display: flex; gap: 10px; margin-top: 20px; }}
.nav-btns button {{ padding: 8px 20px; border: 1px solid #bdc3c7; background: white; border-radius: 5px; cursor: pointer; font-size: 13px; }}
.nav-btns button:hover {{ background: #ecf0f1; }}
.nav-btns button:disabled {{ opacity: 0.4; cursor: default; }}
</style>
</head>
<body>
<div id="table-view">
<div class="header">
  <h1>Patch Comparison Analysis: {agent_label} vs Ground Truth</h1>
  <div class="stats" id="stats"></div>
</div>
<div class="controls">
  <label>Filter: <select id="filter-better"><option value="all">All</option><option value="Opus">Agent better</option><option value="GT">GT better</option><option value="Equivalent">Equivalent</option></select></label>
  <label>Correctness: <select id="filter-correct"><option value="all">All</option><option value="both-correct">Both correct</option><option value="opus-only">Agent correct, GT not</option><option value="gt-only">GT correct, Agent not</option></select></label>
  <label>Strategy: <select id="filter-strategy"><option value="all">All</option><option value="gt_upstream_llm_downstream">GT upstream / LLM downstream</option><option value="llm_better_strategy">LLM better strategy</option><option value="both_similar">Both similar</option><option value="other">Other</option></select></label>
  <label><input type="checkbox" id="hide-dirty" checked> Hide dirty-repo cases</label>
  <label>Search: <input type="text" id="search" placeholder="case ID..." size="10"></label>
</div>
{chart_section}
<div class="container">
<table>
<thead><tr>
  <th data-col="id">Case <span class="sort-arrow"></span></th>
  <th data-col="project">Project <span class="sort-arrow"></span></th>
  <th data-col="vuln_type">Vuln Type <span class="sort-arrow"></span></th>
  <th data-col="opus_correct">Agent Correct <span class="sort-arrow"></span></th>
  <th data-col="gt_correct">GT Correct <span class="sort-arrow"></span></th>
  <th data-col="similarity">Similarity <span class="sort-arrow"></span></th>
  <th data-col="better">Better <span class="sort-arrow"></span></th>
  <th data-col="fix_strategy">Fix Strategy <span class="sort-arrow"></span></th>
  <th data-col="opus_unique_crashes">Agent Crashes <span class="sort-arrow"></span></th>
  <th data-col="gt_unique_crashes">GT Crashes <span class="sort-arrow"></span></th>
  <th data-col="opus_regressions">Agent Regs <span class="sort-arrow"></span></th>
  <th data-col="gt_regressions">GT Regs <span class="sort-arrow"></span></th>
  <th data-col="opus_lines">Agent Lines <span class="sort-arrow"></span></th>
  <th data-col="gt_lines">GT Lines <span class="sort-arrow"></span></th>
  <th data-col="opus_hunks">Agent Hunks <span class="sort-arrow"></span></th>
  <th data-col="opus_files">Agent Files <span class="sort-arrow"></span></th>
  <th data-col="proximity">Proximity <span class="sort-arrow"></span></th>
</tr></thead>
<tbody id="tbody"></tbody>
</table>
</div>
</div>
<div id="detail-overlay">
  <div class="detail-header">
    <button class="back-btn" onclick="closeDetail()">&larr; Back to table</button>
    <h2 id="detail-title"></h2>
    <div class="meta" id="detail-meta"></div>
  </div>
  <div class="detail-body">
    <div class="tabs" id="detail-tabs"></div>
    <div id="detail-panels"></div>
    <div class="nav-btns">
      <button id="prev-btn" onclick="navCase(-1)">&larr; Previous case</button>
      <button id="next-btn" onclick="navCase(1)">Next case &rarr;</button>
    </div>
  </div>
</div>
<script>
const DATA = {data_json};
let sortCol = null, sortDir = 1, currentFiltered = [], currentDetailIdx = -1;
const CO = {{correct:0,partial:1,incorrect:2,unknown:3}};
const SO = {{identical:0,similar_approach:1,different_approach:2,fundamentally_different:3,unknown:4}};
const BO = {{Opus:0,Equivalent:1,GT:2}};
function sv(c,col) {{
  if(col==='id') return parseInt(c.id);
  if(col==='opus_correct') return CO[c.opus_correct]??9;
  if(col==='gt_correct') return CO[c.gt_correct]??9;
  if(col==='similarity') return SO[c.similarity]??9;
  if(col==='better') return BO[c.better]??9;
  if(col==='project') return c.project||'zzz';
  if(col==='vuln_type') return c.vuln_type||'zzz';
  if(col==='opus_unique_crashes') return c.opus_unique_crashes||0;
  if(col==='gt_unique_crashes') return c.gt_unique_crashes||0;
  if(col==='opus_regressions') return c.opus_regressions||0;
  if(col==='gt_regressions') return c.gt_regressions||0;
  if(col==='fix_strategy') return c.fix_strategy||'zzz';
  if(col==='opus_lines') return c.opus_lines||0;
  if(col==='gt_lines') return c.gt_lines||0;
  if(col==='opus_hunks') return c.opus_hunks||0;
  if(col==='opus_files') return c.opus_files||0;
  if(col==='proximity') {{ const po={{'same_line':0,'same_function':1,'same_file_diff_function':2,'different_file':3,'unknown':4}}; return po[c.proximity]||4; }}
  return '';
}}
function esc(s){{ const d=document.createElement('div'); d.textContent=s; return d.innerHTML; }}
function colorDiff(t){{ return esc(t).split('\\n').map(l=>{{
  if(l.startsWith('+')&&!l.startsWith('+++')) return '<span class="diff-add">'+l+'</span>';
  if(l.startsWith('-')&&!l.startsWith('---')) return '<span class="diff-del">'+l+'</span>';
  if(l.startsWith('@@')) return '<span class="diff-hunk">'+l+'</span>';
  return l;
}}).join('\\n'); }}
function md(s){{ if(!s) return '<p style="color:#999">(empty)</p>'; let h=esc(s);
  h=h.replace(/```([\\s\\S]*?)```/g,'<pre><code>$1</code></pre>');
  h=h.replace(/`([^`]+)`/g,'<code>$1</code>');
  h=h.replace(/^### (.+)$/gm,'<h3>$1</h3>');
  h=h.replace(/^## (.+)$/gm,'<h2>$1</h2>');
  h=h.replace(/^# (.+)$/gm,'<h1>$1</h1>');
  h=h.replace(/\\*\\*(.+?)\\*\\*/g,'<strong>$1</strong>');
  h=h.replace(/^- (.+)$/gm,'<li>$1</li>');
  h=h.replace(/^\\d+\\. (.+)$/gm,'<li>$1</li>');
  h=h.replace(/---/g,'<hr>');
  h=h.replace(/\\n\\n/g,'</p><p>');
  return '<p>'+h+'</p>';
}}
function tc(t,v){{ if(t==='correct') return 'tag-'+v; if(t==='better') return v==='Opus'?'tag-opus':v==='GT'?'tag-gt':'tag-equiv'; if(t==='sim'){{ if(v==='identical') return 'tag-identical'; if(v==='similar_approach') return 'tag-similar'; if(v==='different_approach') return 'tag-different'; return 'tag-fundamental'; }} return ''; }}
function sl(v){{ return v.replace(/_/g,' ').replace(/\\b\\w/g,l=>l.toUpperCase()); }}
function openDetail(idx){{ currentDetailIdx=idx; const c=currentFiltered[idx];
  document.getElementById('detail-title').textContent='Case '+c.id+' ('+c.vuln_type+')';
  document.getElementById('detail-meta').innerHTML='<span class="tag '+tc('correct',c.opus_correct)+'">Agent: '+c.opus_correct+'</span><span class="tag '+tc('correct',c.gt_correct)+'">GT: '+c.gt_correct+'</span><span class="tag '+tc('sim',c.similarity)+'">'+sl(c.similarity)+'</span><span class="tag '+tc('better',c.better)+'">Better: '+c.better+'</span><span style="font-size:12px;opacity:0.8">Crashes: Agent='+c.opus_unique_crashes+' GT='+c.gt_unique_crashes+' | Regs: Agent='+c.opus_regressions+' GT='+c.gt_regressions+' | Patch: Agent='+c.opus_lines+'L/'+c.opus_hunks+'H/'+c.opus_files+'F GT='+c.gt_lines+'L/'+c.gt_hunks+'H/'+c.gt_files+'F</span>'+(c.dirty?'<span class="dirty-badge">dirty repo</span>':'');
  const tabs=[{{id:'judge',label:'Judge Analysis'}},{{id:'agent-patch',label:'Agent Patch'}},{{id:'gt-patch',label:'GT Patch'}},{{id:'transcript',label:'LLM Transcript'}}];
  document.getElementById('detail-tabs').innerHTML=tabs.map((t,i)=>'<div class="tab'+(i===0?' active':'')+'" data-tab="'+t.id+'">'+t.label+'</div>').join('');
  const blindBanner='<div style="background:#eaf2f8;border:1px solid #aed6f1;border-radius:6px;padding:10px 15px;margin-bottom:15px;font-size:13px;"><strong>Blinding:</strong> '+esc(c.blinding)+' &mdash; The judge saw blinded Patch A / Patch B labels, not the actual patcher names.</div>';
  document.getElementById('detail-panels').innerHTML='<div class="tab-panel active" id="p-judge">'+blindBanner+'<div class="markdown">'+md(c.judge_report)+'</div></div><div class="tab-panel" id="p-agent-patch"><pre>'+colorDiff(c.opus_patch||'(no patch)')+'</pre></div><div class="tab-panel" id="p-gt-patch"><pre>'+colorDiff(c.gt_patch||'(no GT patch)')+'</pre></div><div class="tab-panel" id="p-transcript"><div class="markdown">'+md(c.conversation||'(no transcript)')+'</div></div>';
  document.querySelectorAll('#detail-tabs .tab').forEach(tab=>{{ tab.onclick=()=>{{ document.querySelectorAll('#detail-tabs .tab').forEach(t=>t.classList.remove('active')); document.querySelectorAll('.tab-panel').forEach(p=>p.classList.remove('active')); tab.classList.add('active'); document.getElementById('p-'+tab.dataset.tab).classList.add('active'); }}; }});
  document.getElementById('prev-btn').disabled=idx===0;
  document.getElementById('next-btn').disabled=idx===currentFiltered.length-1;
  document.getElementById('detail-overlay').classList.add('active');
  document.getElementById('detail-overlay').scrollTop=0;
}}
function closeDetail(){{ document.getElementById('detail-overlay').classList.remove('active'); }}
function navCase(dir){{ const n=currentDetailIdx+dir; if(n>=0&&n<currentFiltered.length) openDetail(n); }}
document.addEventListener('keydown',e=>{{ if(!document.getElementById('detail-overlay').classList.contains('active')) return; if(e.key==='Escape') closeDetail(); if(e.key==='ArrowLeft') navCase(-1); if(e.key==='ArrowRight') navCase(1); }});
document.querySelectorAll('th[data-col]').forEach(th=>{{ th.onclick=()=>{{ const col=th.dataset.col; if(sortCol===col) sortDir*=-1; else {{ sortCol=col; sortDir=1; }} document.querySelectorAll('th .sort-arrow').forEach(a=>{{ a.textContent=''; a.classList.remove('active'); }}); th.querySelector('.sort-arrow').textContent=sortDir===1?'\\u25B2':'\\u25BC'; th.querySelector('.sort-arrow').classList.add('active'); render(); }}; }});
function render(){{ const bF=document.getElementById('filter-better').value, cF=document.getElementById('filter-correct').value, hD=document.getElementById('hide-dirty').checked, sr=document.getElementById('search').value.trim();
  const sF=document.getElementById('filter-strategy').value;
  currentFiltered=DATA.filter(c=>{{ if(hD&&c.dirty) return false; if(sr&&!c.id.includes(sr)) return false; if(bF!=='all'&&c.better!==bF) return false; if(sF!=='all'&&(c.fix_strategy||'')!==sF) return false; if(cF==='both-correct'&&!(c.opus_correct==='correct'&&c.gt_correct==='correct')) return false; if(cF==='opus-only'&&!(c.opus_correct==='correct'&&c.gt_correct!=='correct')) return false; if(cF==='gt-only'&&!(c.gt_correct==='correct'&&c.opus_correct!=='correct')) return false; return true; }});
  if(sortCol) currentFiltered.sort((a,b)=>{{ const va=sv(a,sortCol),vb=sv(b,sortCol); if(typeof va==='number'&&typeof vb==='number') return (va-vb)*sortDir; return String(va).localeCompare(String(vb))*sortDir; }});
  const n=currentFiltered.length, ob=currentFiltered.filter(c=>c.better==='Opus').length, gb=currentFiltered.filter(c=>c.better==='GT').length, eq=currentFiltered.filter(c=>c.better==='Equivalent').length, oc=currentFiltered.filter(c=>c.opus_correct==='correct').length, gc=currentFiltered.filter(c=>c.gt_correct==='correct').length;
  document.getElementById('stats').innerHTML=`<span>Showing: ${{n}} cases</span><span>Agent better: ${{ob}} (${{n?Math.round(ob/n*100):0}}%)</span><span>GT better: ${{gb}} (${{n?Math.round(gb/n*100):0}}%)</span><span>Equivalent: ${{eq}} (${{n?Math.round(eq/n*100):0}}%)</span><span>Agent correct: ${{oc}}/${{n}}</span><span>GT correct: ${{gc}}/${{n}}</span>`;
  const tbody=document.getElementById('tbody'); tbody.innerHTML='';
  currentFiltered.forEach((c,idx)=>{{ const tr=document.createElement('tr'); tr.className='case-row'+(c.dirty?' dirty':'');
    const fs=c.fix_strategy||''; const fsc=fs==='gt_upstream_llm_downstream'?'tag-different':fs==='llm_better_strategy'?'tag-opus':fs==='both_similar'?'tag-identical':'tag-unknown'; const fsl=fs==='gt_upstream_llm_downstream'?'GT upstream':fs==='llm_better_strategy'?'LLM better':fs==='both_similar'?'Similar':'other';
    tr.innerHTML=`<td><b>${{c.id}}</b>${{c.dirty?'<span class="dirty-badge">dirty</span>':''}}</td><td>${{c.project||''}}</td><td>${{c.vuln_type}}</td><td><span class="tag ${{tc('correct',c.opus_correct)}}">${{c.opus_correct}}</span></td><td><span class="tag ${{tc('correct',c.gt_correct)}}">${{c.gt_correct}}</span></td><td><span class="tag ${{tc('sim',c.similarity)}}">${{sl(c.similarity)}}</span></td><td><span class="tag ${{tc('better',c.better)}}">${{c.better}}</span></td><td><span class="tag ${{fsc}}" title="${{c.fix_strategy_note||''}}">${{fsl}}</span></td><td style="color:${{c.opus_unique_crashes>0?'#e74c3c':'#27ae60'}}">${{c.opus_unique_crashes}}</td><td style="color:${{c.gt_unique_crashes>0?'#e74c3c':'#27ae60'}}">${{c.gt_unique_crashes}}</td><td style="color:${{c.opus_regressions>0?'#e74c3c':'#888'}}">${{c.opus_regressions}}</td><td style="color:${{c.gt_regressions>0?'#e74c3c':'#888'}}">${{c.gt_regressions}}</td><td>${{c.opus_lines}}</td><td>${{c.gt_lines}}</td><td>${{c.opus_hunks}}</td><td>${{c.opus_files}}</td><td><span class="tag ${{c.proximity==='same_line'?'tag-correct':c.proximity==='same_function'?'tag-similar':c.proximity==='different_file'?'tag-different':'tag-unknown'}}" title="${{(c.gt_patch_loc||'')+' -> '+(c.crash_loc||'')}}">${{c.proximity==='same_line'?'same line':c.proximity==='same_function'?'same func':c.proximity==='same_file_diff_function'?'same file':c.proximity==='different_file'?'diff file':'?'}}</span></td>`;
    tr.onclick=()=>openDetail(idx); tbody.appendChild(tr); }});
}}
document.getElementById('filter-better').onchange=render;
document.getElementById('filter-correct').onchange=render;
document.getElementById('filter-strategy').onchange=render;
document.getElementById('hide-dirty').onchange=render;
document.getElementById('search').oninput=render;
render();
</script>
</body>
</html>'''


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Build patch analysis HTML explorer")
    parser.add_argument("--analysis-dir", required=True, help="Path to analysis results directory")
    parser.add_argument("--artifacts-dir", required=True, help="Path to staging directory with agent patches, GT patches, conversations")
    parser.add_argument("--agent-id", default="claudecode-claude-opus-4-6", help="Agent ID being compared to GT")
    parser.add_argument("--agent-label", default=None, help="Display name for agent (default: derived from agent-id)")
    parser.add_argument("--output", "-o", required=True, help="Output HTML file path")
    parser.add_argument("--image-audit", default=None, help="Path to image-audit results for dirty-repo filtering")
    parser.add_argument("--classifications", default=None, help="Path to classifications.json from classify_fix_strategy.py")
    parser.add_argument("--distances", default=None, help="Path to patch_crash_distances.json")
    parser.add_argument("--meta-dir", default=None, help="Path to arvo_meta directory for project names")
    parser.add_argument("--no-charts", action="store_true", help="Skip chart generation")
    args = parser.parse_args()

    agent_label = args.agent_label or args.agent_id.replace("claudecode-", "Claude ").replace("-", " ").title()

    print(f"Loading dirty cases from {args.image_audit}...")
    dirty_cases = load_dirty_cases(args.image_audit)
    print(f"  {len(dirty_cases)} dirty cases")

    print(f"Loading cases from {args.analysis_dir}...")
    meta_dir = Path(args.meta_dir) if args.meta_dir else None
    cases = load_cases(Path(args.analysis_dir), Path(args.artifacts_dir), args.agent_id, dirty_cases, meta_dir=meta_dir)
    print(f"  {len(cases)} cases loaded")

    # Merge classifications if provided
    if args.classifications:
        cls_path = Path(args.classifications)
        if cls_path.exists():
            with open(cls_path) as f:
                classifications = json.load(f)
            for case in cases:
                cls = classifications.get(case["id"], {})
                case["fix_strategy"] = cls.get("label", "")
                case["fix_strategy_note"] = cls.get("one_line", "")
                case["fix_strategy_confidence"] = cls.get("confidence", "")
            n_classified = sum(1 for c in cases if c.get("fix_strategy"))
            print(f"  Merged {n_classified} classifications")

    # Merge distances if provided
    if args.distances:
        dist_path = Path(args.distances)
        if dist_path.exists():
            with open(dist_path) as f:
                dist_data = json.load(f)
            for case in cases:
                d = dist_data.get(case["id"], {})
                case["proximity"] = d.get("proximity", "unknown")
                case["gt_patch_loc"] = d.get("gt_patch_location", "")
                case["crash_loc"] = d.get("crash_location", "")
                # Also keep numeric distance if available
                if d.get("type") == "same_file":
                    case["patch_crash_dist"] = d.get("line_distance", -1)
                else:
                    case["patch_crash_dist"] = -1
            n_prox = sum(1 for c in cases if c.get("proximity", "unknown") != "unknown")
            print(f"  Merged {n_prox} proximity classifications")

    chart_b64 = ""
    if not args.no_charts:
        print("Generating charts...")
        chart_b64 = generate_chart_b64(cases, agent_label)

    print(f"Building HTML...")
    html = build_html(cases, chart_b64, agent_label)

    Path(args.output).write_text(html)
    size_mb = Path(args.output).stat().st_size / 1024 / 1024
    print(f"Wrote {args.output} ({size_mb:.1f} MB, {len(cases)} cases)")


if __name__ == "__main__":
    main()
