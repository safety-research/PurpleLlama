---
name: build-analysis-explorer
description: Build an interactive HTML explorer for ARVO patch comparison analysis results. Use when the user wants to visualize analysis results, build a results dashboard, generate an analysis table, or compare agent patches vs ground truth across cases.
---

# Build Analysis Explorer

Generate a self-contained HTML page that displays patch comparison analysis results as an interactive table with per-case detail views, summary charts, and filtering.

## Required Inputs

The user must provide (or you infer from context):

| Input | Description | Example |
|-------|-------------|---------|
| `analysis_experiment` | Analysis experiment ID (GCS path segment) | `analysis-20260213-133233` |
| `source_experiment` | Source patching experiment ID | `fuzz1800_all_0213_3` |
| `agent_id` | Agent being compared to GT | `claudecode-claude-opus-4-6` |
| `cases_config` | Config file with cases list | `benchmark/gcp/configs/new_vul_all.json` |
| `output_path` | Where to save the HTML | `/tmp/analysis_explorer.html` |

Optional:
| Input | Description | Default |
|-------|-------------|---------|
| `image_audit_path` | Local path to image-audit results (for dirty-repo filtering) | `None` (no filtering) |
| `bucket` | GCS bucket name | Read from `.gke-config.json` |

## Steps

### 1. Download artifacts from GCS

```bash
BUCKET=$(python3 -c "import json; print(json.load(open('benchmark/gcp/.gke-config.json'))['bucket_name'])")
```

Download three types of artifacts per case to a local staging dir:

```bash
STAGING=/tmp/explorer-staging
# For each case_id:
gsutil cp "gs://$BUCKET/results/$SOURCE_EXP/$CASE_ID/$AGENT_ID/patch.patch" "$STAGING/$CASE_ID/agent_patch.patch"
gsutil cp "gs://$BUCKET/results/$SOURCE_EXP/$CASE_ID/$AGENT_ID/conversation.json" "$STAGING/$CASE_ID/conversation.json"
gsutil cp "gs://$BUCKET/patches/$CASE_ID-patch.json" "$STAGING/$CASE_ID/gt_patch.json"
```

Analysis reports are at:
```bash
gsutil -m rsync -r "gs://$BUCKET/analysis/patch-comparison/$ANALYSIS_EXP/" "$STAGING/analysis/"
```

### 2. Generate the HTML

Run the generator script, passing all parameters:

```bash
python3 benchmark/gcp/analysis/build_explorer.py \
  --analysis-dir "$STAGING/analysis" \
  --artifacts-dir "$STAGING" \
  --agent-id "$AGENT_ID" \
  --output "$OUTPUT_PATH" \
  --image-audit "/tmp/image-audit"  # optional
```

If `build_explorer.py` doesn't exist yet, create it following the template in [explorer-template.md](explorer-template.md).

### 3. Open the result

```bash
open "$OUTPUT_PATH"
```

## Key Design Points

- **Self-contained**: All data (JSON, base64 charts) embedded in a single HTML file
- **GT patch format**: ARVO metadata uses `{"filename": "...", "patch": "..."}` array -- the `patch` field has the actual diff hunks
- **Conversation parsing**: Agent conversations use SDK message format with `TextBlock(text=...)` and `ToolUseBlock(...)` string representations
- **Blinding**: Reports use Patch A/B -- unblind via `blinding_key.json` which maps `patch_a_patcher` and `patch_b_patcher`
- **Dirty repo filtering**: If image-audit data exists, cases with modified tracked files (not just `??` untracked) are flagged and hidden by default

## HTML Features

The generated page includes:
- Summary charts (similarity pie, "which is better" bar, correctness comparison, approach types)
- Sortable table (click headers) with color-coded tags
- Filters: by "better", by correctness, hide dirty repos, search by case ID
- Full-page detail view on row click with 4 tabs: Judge Analysis, Agent Patch, GT Patch, LLM Transcript
- Keyboard nav: Escape to close, Left/Right arrows between cases
- Diff syntax coloring (green additions, red deletions, blue hunks)
- Stats bar updating live with filter changes
