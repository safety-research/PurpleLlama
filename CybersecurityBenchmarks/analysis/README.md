# Autopatching Failure Analysis

This directory contains tools for analyzing LLM patch failures in the autopatching benchmark.

## Overview

The analysis script (`analyze_patch_failures.py`) automates the process of:
1. Reading judge responses to identify failed cases
2. Comparing ground truth patches with LLM-generated patches
3. Using Claude API to analyze and classify failures
4. Generating detailed reports for each case

## Failure Categories

The analysis classifies failures into the following categories:

| Category | Description |
|----------|-------------|
| `wrong_file` | LLM patched the wrong file |
| `wrong_function` | LLM patched the wrong function (right file) |
| `wrong_fix_type` | Wrong approach to fixing (e.g., masking vs bounds check) |
| `incomplete_fix` | Partially correct but doesn't fully address the issue |
| `symptom_masking` | Hides the symptom instead of fixing root cause |
| `introduces_new_bug` | Fix introduces a new vulnerability |
| `memory_leak` | Fix causes memory leaks |
| `false_positive_dd` | Differential debugging false positive - patch is actually good |
| `pre_existing_bug` | Bug existed before the patch |
| `better_than_ground_truth` | LLM patch is actually better than ground truth |
| `unknown` | Cannot determine the failure reason |

## Usage

### Setup

```bash
# Install dependencies
pip install -r requirements.txt

# Set your API key
export ANTHROPIC_API_KEY="your-api-key"
```

### Running Analysis

```bash
# Analyze all failures
python analyze_patch_failures.py

# Analyze specific model
python analyze_patch_failures.py --models claude-opus-4-5-20251101

# Analyze specific cases
python analyze_patch_failures.py --cases 6975 14620 33340

# Analyze all cases (including successes)
python analyze_patch_failures.py --analyze-all

# Use a different Claude model for analysis
python analyze_patch_failures.py --model claude-opus-4-20250514
```

### Command Line Options

```
--api-key           Anthropic API key (or set ANTHROPIC_API_KEY env var)
--judge-responses   Path to judge_responses.json
--output-dir        Output directory for analysis reports
--files-dir         Directory containing case files (patches, logs)
--arvo-meta-dir     Directory containing ground truth patches
--model             Claude model to use for analysis (default: claude-sonnet-4-20250514)
--models            Filter to specific models (space-separated)
--cases             Filter to specific case IDs (space-separated)
--analyze-all       Analyze all cases, not just failures
--dry-run           List cases that would be analyzed without calling API
```

### Dry Run Mode

Test the script without making API calls:

```bash
# See what would be analyzed
python analyze_patch_failures.py --dry-run

# Dry run for specific model
python analyze_patch_failures.py --dry-run --models claude-opus-4-5-20251101
```

Output shows which cases have patches available:
```
Case 33340: GT=✓ LLM=✓ Reason=fuzzing_failed
Case 66689: GT=✓ LLM=✓ Reason=functionality_not_preserved
```
- GT=✓ means ground truth patch found
- LLM=✓ means LLM patch found
- Reason shows why the case is flagged for analysis

## Output Structure

```
output_dir/
├── analysis_summary.json    # JSON summary of all analyses
├── ANALYSIS_SUMMARY.md      # Markdown summary report
└── case_<id>/
    ├── <model>_analysis.json   # Detailed JSON analysis
    └── <model>_analysis.md     # Markdown analysis report
```

## Example Output

### Summary Statistics
```
Total cases analyzed: 50

By category:
  wrong_function: 15
  symptom_masking: 12
  wrong_file: 8
  false_positive_dd: 7
  incomplete_fix: 5
  better_than_ground_truth: 3
```

### Per-Case Report

Each case gets a detailed analysis including:
- Root cause of the vulnerability
- Ground truth fix approach
- LLM fix approach
- Comparison (correct file, function, approach)
- Classification and detailed explanation
