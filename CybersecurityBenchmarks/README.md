# ARVO Benchmark Infrastructure (Argo/GKE)

Run ARVO benchmarks on GKE with Argo Workflows for orchestration.

## Features

- **Memoization**: Cached tasks skip automatically (zero cost for re-runs)
- **Fine-grained DAG**: Per-case dependencies, parallel execution
- **Spot VMs**: 60-90% cost savings with GKE Spot node pools
- **Argo UI**: Web dashboard for monitoring and debugging

## Architecture

```
┌─────────────────────────────────────────┐
│           Argo Controller               │
│  - Evaluates DAG                        │
│  - Checks memoization cache             │
│  - Schedules only needed pods           │
└─────────────────────────────────────────┘
                    │
    ┌───────────────┼───────────────┐
    ▼               ▼               ▼
┌─────────┐   ┌─────────┐     ┌─────────┐
│ Case 1  │   │ Case 2  │     │ Case N  │
│         │   │         │     │         │
│ build   │   │ build   │     │ build   │
│   ↓     │   │   ↓     │     │   ↓     │
│ patch   │   │ patch   │     │ patch   │
│   ↓     │   │   ↓     │ ... │   ↓     │
│ fuzz    │   │ fuzz    │     │ fuzz    │
│         │   │         │     │         │
│ gt-fuzz │   │ gt-fuzz │     │ gt-fuzz │
└─────────┘   └─────────┘     └─────────┘
  (parallel)    (parallel)      (parallel)
```

## Quick Start

### 1. Setup GKE Cluster

```bash
python -m cli setup
```

### 2. Sync Secrets from .env

```bash
# Sync all secrets from .env to Kubernetes
# (includes Docker Hub credentials if DOCKER_USERNAME/DOCKER_PASSWORD are set)
python -m cli secrets sync

# Or manually:
kubectl create secret generic anthropic-api-key -n argo \
  --from-literal=key=$ANTHROPIC_API_KEY
```

Required `.env` variables:

```bash
# API Keys
ANTHROPIC_API_KEY=sk-ant-...
OPENAI_API_KEY=sk-...           # Optional

# Docker Hub (to avoid rate limiting when pulling images)
DOCKER_USERNAME=your-dockerhub-username
DOCKER_PASSWORD=dckr_pat_...    # Use access token from https://hub.docker.com/settings/security
```

### 3. Submit Benchmark

```bash
# Single case
python -m cli submit --cases=42

# Multiple cases
python -m cli submit --cases=42,43,44,45

# From config file
python -m cli submit --config=configs/test_1.json

# With options
python -m cli submit \
  --cases=42-50 \
  --model=claude-sonnet-4-20250514 \
  --experiment=exp-001 \
  --fuzzing-duration=300
```

### 4. Monitor

```bash
# List workflows
python -m cli status

# Watch specific workflow
python -m cli status arvo-benchmark-xxxxx -w

# View logs
python -m cli logs arvo-benchmark-xxxxx

# Argo UI
python -m cli ui
# Open https://localhost:2746
```

## CLI Commands

```bash
# Setup
python -m cli setup              # Set up GKE + Argo
python -m cli setup-status       # Check setup status

# Workflows
python -m cli submit             # Submit benchmark
python -m cli status             # List workflows
python -m cli status <name> -w   # Watch workflow
python -m cli logs <name>        # View logs
python -m cli logs <name> -f     # Follow logs
python -m cli cancel <name>      # Cancel workflow

# Experiments
python -m cli experiments list           # List experiments
python -m cli experiments results <id>   # Show results
python -m cli experiments compare a b    # Compare experiments

# Secrets
python -m cli secrets sync               # Sync .env to Kubernetes (including Docker Hub)
python -m cli secrets list               # List secrets
python -m cli secrets show <name>        # Show secret details

# Utilities
python -m cli upload-runtime     # Upload agent runtime
python -m cli ui                 # Open Argo UI
```

## Configuration

### Run Config File

```json
{
  "cases": "@datasets/autopatch/autopatch_bench.json",
  "model": "claude-sonnet-4-20250514",
  "experiment_id": "exp-001",
  "fuzzing_duration": 300,
  "build_version": "latest"
}
```

### GKE Config

Stored in `.gke-config.json`:

```json
{
  "project_id": "your-project",
  "region": "us-central1",
  "cluster_name": "arvo-cluster",
  "bucket_name": "your-bucket",
  "artifact_registry": "us-central1-docker.pkg.dev/your-project/arvo"
}
```

## Workflow Structure

Each case runs through a DAG:

```
build-vul ──→ patch ──→ fuzz-llm
                         ↑
build-fix ───────────────┘
    │
    └──→ fuzz-gt (parallel with patch!)
```

- **build-vul**: Build vulnerable image for patching
- **build-fix**: Build fixed image for fuzzing
- **patch**: Run LLM agent to generate patch
- **fuzz-llm**: Fuzz the LLM-patched binary
- **fuzz-gt**: Fuzz the ground truth binary (parallel with patch)

## Memoization

Build and patch results are cached:

- **Build**: Cached by `case-id + build-version`
- **Patch**: Cached by `case-id + model + experiment-id`

Re-submitting a workflow with the same parameters will skip completed tasks.

## Cost Optimization

- **Spot VMs**: Batch workloads run on Spot node pool (60-90% cheaper)
- **Autoscaling**: Node pool scales 0-100 based on demand
- **Memoization**: Cached tasks cost nothing

## Directory Structure

```
CybersecurityBenchmarks/
├── argo/
│   ├── templates/           # WorkflowTemplates
│   │   ├── build-template.yaml
│   │   ├── patch-template.yaml
│   │   └── fuzz-template.yaml
│   └── workflows/
│       └── arvo-benchmark.yaml
├── build/                   # Build assets (Dockerfiles, libfuzzer, CASR)
├── cli/
│   ├── main.py              # CLI entry point
│   ├── argo.py              # Argo client
│   ├── config.py            # Configuration
│   └── commands/            # CLI commands
├── portable-runtime/        # Agent code
│   ├── agent/
│   └── evaluation/
├── analysis/                # Analysis scripts
├── configs/                 # Run configurations
├── datasets/                # Benchmark data
└── scripts/
    └── patch_task.sh
```
