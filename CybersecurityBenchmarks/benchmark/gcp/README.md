# GCP Distributed Fuzzing Infrastructure

This directory contains the infrastructure for running the ARVO vulnerability patching benchmark on GCP Cloud Batch.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│  GCS Bucket: PROJECT_ID-arvo-benchmark                      │
│  ├── images/          # Built container tarballs            │
│  ├── agent-runtime/   # Portable Python+Node runtime        │
│  ├── scripts/         # Task scripts                        │
│  └── results/         # Evaluation outputs                  │
└─────────────────────────────────────────────────────────────┘
                            │
        ┌───────────────────┼───────────────────┐
        ▼                   ▼                   ▼
┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐
│  BUILD Job      │  │  EVAL Job       │  │  GT Job         │
│  (150 tasks)    │─>│  (150×N tasks)  │  │  (150 tasks)    │
│                 │  │                 │  │                 │
│  Builds images  │  │  LLM patching   │  │  Fuzz GT only   │
└─────────────────┘  └─────────────────┘  └─────────────────┘
```

## Quick Start

### Prerequisites

- Python 3.10+
- gcloud CLI installed and authenticated
- Docker (for building portable runtime)

### 1. Install the CLI

```bash
cd benchmark/gcp
pip install -e .

# Or run directly
python -m cli --help
```

### 2. Build the Portable Runtime

```bash
cd portable-runtime
./build.sh

# Test compatibility
./test_agent_runtime.sh
```

### 3. Set Up GCP Infrastructure

```bash
# Configure your project
gcloud config set project YOUR_PROJECT_ID

# Run setup
arvo-gcp setup

# Or with explicit project
arvo-gcp setup --project my-project-id
```

### 4. Add Your Anthropic API Key

```bash
echo -n 'sk-ant-api03-...' | gcloud secrets versions add anthropic-api-key --data-file=-
```

### 5. Upload the Runtime

```bash
arvo-gcp upload-runtime
```

### 6. Submit Benchmark Jobs

```bash
# Run on specific cases
arvo-gcp submit --cases 42,43,44 --model claude-sonnet-4-20250514

# Run on all cases
arvo-gcp submit --cases all --model claude-sonnet-4-20250514

# Build only (useful for initial setup)
arvo-gcp submit --cases all --build-only

# Evaluation only (requires pre-built images)
arvo-gcp submit --cases 42,43 --eval-only --model claude-sonnet-4-20250514
```

### 7. Monitor Jobs

```bash
# List all jobs
arvo-gcp monitor

# Watch mode (auto-refresh)
arvo-gcp monitor --watch

# Monitor specific job
arvo-gcp monitor --job build-20240101_120000
```

### 8. Collect Results

```bash
# Download all results
arvo-gcp collect --output ./results

# Download specific cases
arvo-gcp collect --cases 42,43 --output ./results
```

## CLI Commands

| Command | Description |
|---------|-------------|
| `arvo-gcp setup` | Set up GCP infrastructure |
| `arvo-gcp teardown` | Remove GCP resources |
| `arvo-gcp submit` | Submit benchmark jobs |
| `arvo-gcp monitor` | Monitor job progress |
| `arvo-gcp collect` | Download results from GCS |
| `arvo-gcp upload-runtime` | Upload agent runtime to GCS |

## Directory Structure

```
gcp/
├── README.md                     # This file
├── pyproject.toml                # Python package config
│
├── cli/                          # Python CLI (typer)
│   ├── __init__.py
│   ├── __main__.py
│   └── main.py                   # CLI commands
│
├── portable-runtime/             # Agent runtime bundle
│   ├── Dockerfile.builder        # Multi-stage build
│   ├── build.sh                  # Build wrapper
│   ├── agent-entrypoint.sh       # Runtime entry point
│   ├── test_agent_runtime.sh     # Compatibility tests
│   └── agent/
│       └── agent.py              # Evaluation harness
│
├── jobs/                         # Cloud Batch job specs
│   ├── build-job.json            # Build container images
│   ├── eval-job.json             # LLM evaluation
│   └── gt-job.json               # Ground truth fuzzing
│
└── scripts/                      # Per-task scripts
    ├── build_task.sh             # Container build logic
    ├── eval_task.sh              # Evaluation logic
    └── gt_task.sh                # GT fuzzing logic
```

## Portable Runtime

The portable runtime bundles Python 3.11, Node.js 18, and the Anthropic SDK in a way that works on glibc 2.17+ systems (Ubuntu 14.04+, CentOS 7+).

### How It Works

Both `python-build-standalone` and Node.js `unofficial-builds` provide binaries compiled against glibc 2.17, ensuring compatibility with older systems without needing to bundle glibc libraries.

### Supported Platforms

| Platform | glibc | Status |
|----------|-------|--------|
| CentOS 7 | 2.17 | ✅ Supported |
| Ubuntu 14.04 | 2.19 | ✅ Supported |
| Ubuntu 16.04 | 2.23 | ✅ Supported |
| Ubuntu 18.04 | 2.27 | ✅ Supported |
| Ubuntu 20.04 | 2.31 | ✅ Supported |
| Ubuntu 22.04 | 2.35 | ✅ Supported |

### Updating Agent Code

Agent code changes don't require rebuilding the runtime:

```bash
# Edit agent code
vim portable-runtime/agent/agent.py

# Rebuild tarball (fast - just repackages)
cd portable-runtime
tar -czf output/agent-runtime.tar.gz -C output/agent-runtime .

# Upload to GCS
arvo-gcp upload-runtime
```

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `ANTHROPIC_API_KEY` | Yes | Anthropic API key (from Secret Manager) |
| `AGENT_RUNTIME_DEBUG` | No | Set to `1` for debug output |
| `AGENT_RUNTIME_DIR` | No | Override runtime directory |

## Cost Estimate

| Phase | Tasks | Time/task | VM-hours | Cost (spot) |
|-------|-------|-----------|----------|-------------|
| Build | 150 | ~30 min | 75 | ~$4.50 |
| Eval | 600 | ~45 min | 450 | ~$27 |
| **Total** | | | **525** | **~$32** |

Based on e2-standard-4 spot pricing ($0.059/hr).

## Development

### Local Testing

Test a single case locally:

```bash
docker run -it --rm \
    -v $(pwd)/portable-runtime/output/agent-runtime:/agent-runtime \
    -e ANTHROPIC_API_KEY=$ANTHROPIC_API_KEY \
    n132/arvo:42-vul \
    /agent-runtime/bin/agent-entrypoint.sh python3 /agent-runtime/agent/agent.py \
        --case-id 42 --model claude-sonnet-4-20250514 --dry-run
```

### Rebuilding the Runtime

Only needed when changing Python/Node versions or adding packages:

```bash
cd portable-runtime
./build.sh --no-cache
./test_agent_runtime.sh
```
