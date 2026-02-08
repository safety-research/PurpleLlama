---
name: manage-markers
description: Manage _SUCCESS markers in ARVO benchmark experiments. Use when the user wants to list, delete, or reset success markers to re-run specific agents, cases, or entire experiments. Also use when the user mentions clearing results, resetting runs, or re-running jobs.
---

# Manage ARVO Experiment Markers

ARVO workflows use `_SUCCESS` markers in GCS to skip already-completed work. Each case+agent combination has two markers:

- `results/{experiment}/{case}/{agent}/patch/_SUCCESS` — patch step completed
- `results/{experiment}/{case}/{agent}/_SUCCESS` — fuzz step completed

Deleting these markers causes the workflow to re-run those steps on the next submission.

## GCS Path Structure

```
gs://{bucket}/results/{experiment_id}/{case_id}/{agent_id}/patch/_SUCCESS
gs://{bucket}/results/{experiment_id}/{case_id}/{agent_id}/_SUCCESS
```

The bucket is read from `benchmark/gcp/.gke-config.json` (`bucket_name` field).

## Commands

All commands require `network` permissions for `gsutil`.

### List all markers for an experiment

```bash
BUCKET=$(python3 -c "import json; print(json.load(open('benchmark/gcp/.gke-config.json'))['bucket_name'])")
gsutil ls -r "gs://$BUCKET/results/{experiment_id}/**/_SUCCESS"
```

### List markers filtered by agent pattern

```bash
gsutil ls -r "gs://$BUCKET/results/{experiment_id}/**/_SUCCESS" | grep {agent_pattern}
```

### Delete markers for specific agents (re-run both patch and fuzz)

```bash
gsutil ls -r "gs://$BUCKET/results/{experiment_id}/**/_SUCCESS" \
  | grep {agent_pattern} \
  | gsutil -m rm -I
```

### Delete only patch markers (re-run patch, which cascades to fuzz)

```bash
gsutil ls -r "gs://$BUCKET/results/{experiment_id}/**/patch/_SUCCESS" \
  | grep {agent_pattern} \
  | gsutil -m rm -I
```

### Delete only fuzz markers (re-run fuzz only, keep existing patches)

```bash
gsutil ls -r "gs://$BUCKET/results/{experiment_id}/**/_SUCCESS" \
  | grep {agent_pattern} \
  | grep -v "/patch/" \
  | gsutil -m rm -I
```

### Delete markers for a single case + agent

```bash
gsutil rm "gs://$BUCKET/results/{experiment_id}/{case_id}/{agent_id}/patch/_SUCCESS"
gsutil rm "gs://$BUCKET/results/{experiment_id}/{case_id}/{agent_id}/_SUCCESS"
```

## Safety Notes

- GT markers (`gt/_SUCCESS`) should generally be preserved since GT results don't change across re-runs.
- Always list markers before deleting to verify scope. Pipe to `wc -l` to count.
