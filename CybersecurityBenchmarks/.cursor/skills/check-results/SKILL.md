---
name: check-results
description: Check ARVO benchmark results and print a crash table for a given experiment ID. Use when the user asks to check results, view crash counts, see benchmark outcomes, compare model performance, or mentions an experiment ID.
---

# Check ARVO Benchmark Results

Fetches fuzzing and patch results from GCS for a given experiment, then prints a summary table of crashes per case and model.

## Quick Start

Run the script:

```bash
python .cursor/skills/check-results/scripts/check_results.py <experiment_id>
```

This requires `network` permissions (it calls `gsutil`).

The script auto-detects the GCS bucket from `.gke-config.json`.

## Options

| Flag                     | Description                                                                      |
| ------------------------ | -------------------------------------------------------------------------------- |
| `--details` / `-d`       | Show detailed per-case breakdown (patch status, cluster info, stack trace stats) |
| `--bucket BUCKET`        | Override GCS bucket name                                                         |
| `--local DIR` / `-l DIR` | Read from a local directory instead of downloading from GCS                      |

## Examples

```bash
# Basic crash table
python .cursor/skills/check-results/scripts/check_results.py fuzz1800

# Detailed view with per-case patch status and cluster info
python .cursor/skills/check-results/scripts/check_results.py fuzz1800 --details

# Re-check using previously downloaded data
python .cursor/skills/check-results/scripts/check_results.py fuzz1800 --local /tmp/arvo-results-fuzz1800-xxxxx
```

## Table Columns

- **Case**: ARVO case ID
- **Model columns**: Crash count per model. Format: `unique(total)` if they differ, else just total. When regression data exists: `Xr/unique(total)` where X = number of regressions (LLM-introduced).
- **TOTAL**: Sum of crashes across all cases (unique and total in parentheses)
- **UNIQUE**: Unique crash count (only shown when different from total)
- **REGR**: Regressions -- LLM-introduced crashes that do NOT reproduce on the original vul binary (only shown when regression analysis data exists)
- **PRE-EXIST**: Pre-existing crashes that also reproduce on the original vul binary (only shown when regression analysis data exists)
- **DIFF CRSH**: Crashes that reproduce on vul binary but with a different stack trace (only shown when non-zero)
- **NO CRASH**: Number of cases with zero crashes
- **PATCH OK**: `success/total` patch attempts (only for LLM models)

## Interpreting Results

- **GT column** = ground truth (official fix). Should have 0 crashes ideally.
- **LLM columns** = crashes when fuzzing with the LLM-patched (or unpatched-fallback) binary.
- **REGR > 0** = LLM patch introduced new crashes not present in the original vulnerable binary.
- **PRE-EXIST > 0** = crashes that were already present before patching (not the LLM's fault).
- **High LLM crash count with 0 GT crashes** = LLM patch likely introduced new bugs or didn't fix the original vulnerability.
- **All crashes unique (no dedup)** = CASR likely failed to extract stack traces. Check `--details` to see `With traces: 0/N` pattern.
- **No REGR/PRE-EXIST rows** = regression analysis was not run. Ensure `original_binary` is uploaded during the patch step (see backfill workflow).

## Working Directory

Run from the `CybersecurityBenchmarks/` directory. The script resolves the config path relative to its own location.
