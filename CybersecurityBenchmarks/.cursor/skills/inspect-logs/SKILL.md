---
name: inspect-logs
description: Inspect GKE/Argo workflow logs for debugging failures, viewing LLM transcripts, and understanding rescheduling. Use when the user asks about logs, job failures, OOMKilled, evictions, pod errors, conversation history, or wants to debug a workflow run.
---

# Inspect ARVO Workflow Logs

Debug workflow failures, inspect LLM transcripts, and understand pod rescheduling.

## Config

```bash
BUCKET=$(python3 -c "import json; print(json.load(open('benchmark/gcp/.gke-config.json'))['bucket_name'])")
```

- Project: `fellows-safety-research`
- Cluster: `camyang-arvo-cluster`
- Namespace: `argo`

## 1. Finding Pods in a Workflow

Pod names are opaque hashes (e.g., `arvo-benchmark-hmj9b-patch-case-1679507585`). Structured info is in the `workflows.argoproj.io/node-name` annotation:

```
{wf}.process-cases({idx}:case_id:{id},project:{proj}).{step}-{agent}({retry})
```

- Pod name prefixes: `patch-case-`, `fuzz-case-`, `build-case-`, `check-completion-`
- Annotation encodes: case_id, project, step, agent, model, retry index

### Filter by status

```bash
kubectl get pods -n argo -l workflows.argoproj.io/workflow={wf} --field-selector=status.phase=Failed
```

### Filter by case ID or agent (via annotation)

```bash
kubectl get pods -n argo -l workflows.argoproj.io/workflow={wf} -o json \
  | jq -r '.items[] | select(.metadata.annotations["workflows.argoproj.io/node-name"] | test("case_id:{id}")) | .metadata.name'
```

### Filter by template type

```bash
kubectl get pods -n argo -l workflows.argoproj.io/workflow={wf} -o json \
  | jq -r '.items[] | select(.metadata.name | test("patch-case")) | "\(.metadata.name) \(.status.phase)"'
```

### List failed pods with reasons

```bash
kubectl get pods -n argo -l workflows.argoproj.io/workflow={wf} --field-selector=status.phase=Failed -o json \
  | jq -r '.items[] | "\(.metadata.name) | \(.status.containerStatuses[0].state.terminated.reason // "unknown") | exit=\(.status.containerStatuses[0].state.terminated.exitCode // "n/a")"'
```

## 2. Cloud Logging (Primary Debugging Tool)

Persists after pod cleanup. Captures all containers and K8s events.

### Container logs

```bash
gcloud logging read '
  resource.type="k8s_container"
  AND resource.labels.namespace_name="argo"
  AND labels."k8s-pod/workflows_argoproj_io/workflow"="{wf}"
  AND resource.labels.container_name="main"
' --limit=100 --format=json | jq -r '.[] | "\(.timestamp) \(.textPayload // .jsonPayload.message // "")"'
```

- Add `AND severity>="ERROR"` to filter errors only
- Change `container_name` to `wait` or `fetch-runtime` to see sidecar/init logs
- Add `AND resource.labels.pod_name="{pod}"` to scope to one pod
- Add `AND timestamp>="YYYY-MM-DDTHH:MM:SSZ"` to narrow time range

### K8s events (why jobs fail/reschedule)

```bash
gcloud logging read '
  logName="projects/fellows-safety-research/logs/events"
  AND resource.labels.cluster_name="camyang-arvo-cluster"
  AND jsonPayload.involvedObject.name=~"{wf}"
  AND jsonPayload.reason=~"OOM|Kill|Evict|Failed|BackOff"
' --limit=50 --format=json \
  | jq '.[] | {timestamp, reason: .jsonPayload.reason, pod: .jsonPayload.involvedObject.name, message: .jsonPayload.message}'
```

- Common reasons: `OOMKilling`, `TaintManagerEviction` (spot preemption), `FailedScheduling`, `BackOff`, `Killing`

### Console UI

`https://console.cloud.google.com/logs/query?project=fellows-safety-research`

## 3. kubectl (Live Pods Only)

- `kubectl describe pod {pod} -n argo` -- events, exit reasons, resource limits
- `kubectl logs {pod} -n argo --previous` -- logs from previous terminated container
- `kubectl get events -n argo --sort-by='.lastTimestamp' | tail -50` -- recent events
- Note: only works while pods exist; GKE garbage-collects completed pods

## 4. LLM Transcripts (GCS Artifacts)

Not available via Cloud Logging. Fetch directly from GCS:

```bash
gsutil cat "gs://$BUCKET/results/{experiment}/{case}/{agent}/conversation.json" | jq .
gsutil cat "gs://$BUCKET/results/{experiment}/{case}/{agent}/result.json" | jq .
gsutil cat "gs://$BUCKET/results/{experiment}/{case}/{agent}/chat.md"
```

### Recovering overwritten files (Argo retries)

GCS versioning is enabled (20 noncurrent versions kept). When a retry overwrites artifacts:

```bash
# List all versions of a file
gsutil ls -la "gs://$BUCKET/results/{experiment}/{case}/{agent}/conversation.json"

# Fetch a specific old version by generation number
gsutil cp "gs://$BUCKET/results/{experiment}/{case}/{agent}/conversation.json#{generation}" ./conversation_old.json
```

## 5. GCS Archived Logs (Backup)

- Path: `gs://$BUCKET/argo-logs/YYYY/MM/DD/{wf}/{pod}/main.log`
- Only captures main container stdout
- Useful when Cloud Logging retention (30 days) has expired

```bash
# List all archived logs for a workflow
gsutil ls "gs://$BUCKET/argo-logs/*/*/*/{wf}/"

# Read a specific pod's log
gsutil cat "gs://$BUCKET/argo-logs/*/*/*/{wf}/{pod}/main.log"

# Filter to patch pods only
gsutil ls "gs://$BUCKET/argo-logs/*/*/*/{wf}/" | grep patch-case
```

## 6. Argo-Server Node Status

For workflows with compressed or offloaded nodes (large workflows), use the argo-server proxy to get full node status including retry history:

```python
# From benchmark/gcp/ directory
from cli.argo import run_argo_via_server
result = run_argo_via_server(["get", "{wf}", "-n", "argo", "-o", "json"])
```

- Node status includes: displayName, phase, message, retry history, inputs/outputs
- Required when `kubectl get workflow` shows `compressedNodes` or `offloadNodeStatusVersion`
- Failed nodes have `message` field with error details (e.g., `main: OOMKilled (exit code 137)`)
- Retry nodes have `nodeFlag: {"retried": true}` and sibling nodes with `(1)`, `(2)` suffixes

## Common Failure Types

| Error | Cause | Retried? |
|-------|-------|----------|
| `main: OOMKilled (exit code 137)` | Container exceeded memory limit | Yes (escalates to 13G) |
| `Pod was terminated in response to imminent node shutdown` | Spot VM preemption | Yes |
| `pod deleted` | Node scale-down or preemption | Yes |
| `main: Error (exit code 1)` | Agent runtime error (check logs) | Yes |
| `Pod was active on the node longer than the specified deadline` | `activeDeadlineSeconds` hit | No (check-completion pods lack retry) |
