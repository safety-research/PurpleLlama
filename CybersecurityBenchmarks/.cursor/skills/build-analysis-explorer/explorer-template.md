# Explorer Template Reference

The reusable script is at `analysis/build_explorer.py`.

## Quick Start

```bash
# 1. Set variables
BUCKET=$(python3 -c "import json; print(json.load(open('.gke-config.json'))['bucket_name'])")
ANALYSIS_EXP="analysis-20260213-133233"
SOURCE_EXP="fuzz1800_all_0213_3"
AGENT_ID="claudecode-claude-opus-4-6"
STAGING=/tmp/explorer-staging

# 2. Download artifacts
mkdir -p $STAGING
gsutil -m rsync -r "gs://$BUCKET/analysis/patch-comparison/$ANALYSIS_EXP/" "$STAGING/analysis/"

CASES=$(python3 -c "import json; print(' '.join(str(c) for c in json.load(open('configs/new_vul_all.json'))['cases']))")
for cid in $CASES; do
  mkdir -p $STAGING/$cid
  gsutil -q cp "gs://$BUCKET/results/$SOURCE_EXP/$cid/$AGENT_ID/patch.patch" "$STAGING/$cid/agent_patch.patch" 2>/dev/null &
  gsutil -q cp "gs://$BUCKET/results/$SOURCE_EXP/$cid/$AGENT_ID/conversation.json" "$STAGING/$cid/conversation.json" 2>/dev/null &
  gsutil -q cp "gs://$BUCKET/patches/$cid-patch.json" "$STAGING/$cid/gt_patch.json" 2>/dev/null &
done
wait

# 3. (Optional) Download image-audit results for dirty-repo filtering
gsutil -m rsync -r "gs://$BUCKET/image-audit/" /tmp/image-audit/

# 4. Generate HTML
python3 analysis/build_explorer.py \
  --analysis-dir "$STAGING/analysis" \
  --artifacts-dir "$STAGING" \
  --agent-id "$AGENT_ID" \
  --agent-label "Claude Opus 4.6" \
  --output /tmp/analysis_explorer.html \
  --image-audit /tmp/image-audit

# 5. Open
open /tmp/analysis_explorer.html
```

## Plugging in Different Runs

To use a different experiment or agent, change these variables:

| Variable | What to Change |
|----------|---------------|
| `ANALYSIS_EXP` | The analysis experiment ID (from `submit-analysis` output) |
| `SOURCE_EXP` | The patching experiment that produced the agent results |
| `AGENT_ID` | The agent ID (e.g. `claudecode-claude-sonnet-4-5`, `claudecode-claude-haiku-4-5`) |
| `--agent-label` | Display name shown in the HTML header and charts |
| Cases config | Change `new_vul_all.json` to your config file |

## Artifact Layout Expected

```
$STAGING/
├── analysis/                    # From gs://bucket/analysis/patch-comparison/EXP/
│   ├── {case_id}/
│   │   └── {agent_id}-vs-gt/
│   │       ├── report.json      # Structured analysis report
│   │       ├── report.md        # Markdown report (optional)
│   │       └── blinding_key.json
│   └── ...
├── {case_id}/
│   ├── agent_patch.patch        # From results/EXP/CASE/AGENT/patch.patch
│   ├── conversation.json        # From results/EXP/CASE/AGENT/conversation.json
│   └── gt_patch.json            # From patches/CASE-patch.json
└── ...
```
