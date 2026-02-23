---
name: build-analysis-explorer
description: Build an interactive HTML explorer for ARVO patch comparison analysis results. Use when the user wants to visualize analysis results, build a results dashboard, generate an analysis table, or compare agent patches vs ground truth across cases.
---

# Build Analysis Explorer

Generate a self-contained HTML page that displays patch comparison analysis results as an interactive table with per-case detail views, summary charts, and filtering.

## Quick Start

Use the download script to fetch all artifacts and build explorers in one command:

```bash
# From CybersecurityBenchmarks/ directory
python analysis/download_analysis.py <analysis-experiment> --build --open
```

This auto-detects the source experiment, agents, and cases from the analysis reports.

## Examples

```bash
# Download + build + open all agent explorers
python analysis/download_analysis.py analysis-20260222-214329 --build --open

# Just download (no build)
python analysis/download_analysis.py analysis-20260222-214329

# Reuse previously downloaded data
python analysis/download_analysis.py analysis-20260222-214329 \
    --local /tmp/explorer-analysis-20260222-214329 --build --open

# Custom output directory
python analysis/download_analysis.py analysis-20260222-214329 \
    --output-dir /tmp/my-analysis --build

# With extra build_explorer.py options
python analysis/download_analysis.py analysis-20260222-214329 --build \
    --build-args --image-audit /tmp/image-audit --classifications /tmp/cls.json
```

## What It Does

1. **Downloads from GCS** (3 rsync operations):
   - Analysis reports from `gs://BUCKET/analysis/patch-comparison/<analysis-experiment>/`
   - Agent patches + conversations from `gs://BUCKET/results/<source-experiment>/`
   - GT patches from `gs://BUCKET/patches/`

2. **Auto-detects** source experiment (from report.json) and agent IDs (from directory structure)

3. **Stages per-agent artifacts** into the layout `build_explorer.py` expects (using symlinks)

4. **Builds HTML explorers** (one per agent) if `--build` is passed

## Finding the Analysis Experiment ID

List available analysis experiments:
```bash
gsutil ls gs://$(python3 -c "import json; print(json.load(open('benchmark/gcp/.gke-config.json'))['bucket_name'])")/analysis/patch-comparison/
```

## Manual Build (Advanced)

If you need fine-grained control, run `build_explorer.py` directly:

```bash
python3 analysis/build_explorer.py \
  --analysis-dir "$STAGING/analysis" \
  --artifacts-dir "$STAGING/per-agent/$AGENT_ID" \
  --agent-id "$AGENT_ID" \
  --output "$OUTPUT_PATH" \
  --image-audit "/tmp/image-audit"  # optional
```

## HTML Features

The generated page includes:
- Summary charts (similarity pie, "which is better" bar, correctness comparison, approach types)
- Sortable table (click headers) with color-coded tags
- Filters: by "better", by correctness, hide dirty repos, search by case ID
- Full-page detail view on row click with 4 tabs: Judge Analysis, Agent Patch, GT Patch, LLM Transcript
- Keyboard nav: Escape to close, Left/Right arrows between cases
- Diff syntax coloring (green additions, red deletions, blue hunks)
- Stats bar updating live with filter changes

## Key Design Points

- **Self-contained**: All data (JSON, base64 charts) embedded in a single HTML file
- **GT patch format**: ARVO metadata uses `{"filename": "...", "patch": "..."}` array -- the `patch` field has the actual diff hunks
- **Conversation parsing**: Agent conversations use SDK message format with `TextBlock(text=...)` and `ToolUseBlock(...)` string representations
- **Blinding**: Reports use Patch A/B -- unblind via `blinding_key.json` which maps `patch_a_patcher` and `patch_b_patcher`
- **Dirty repo filtering**: If image-audit data exists, cases with modified tracked files (not just `??` untracked) are flagged and hidden by default
