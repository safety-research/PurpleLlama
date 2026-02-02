# CASR Clustering Without Deduplication

## Problem

The standard `casr-libfuzzer` tool performs automatic deduplication, which discards duplicate crashes and only keeps representative crashes per cluster. This creates two issues:

1. **Lost crash-to-cluster mapping**: 15 out of 18 crashes had `cluster_id: null` because CASR discarded them as duplicates
2. **Inaccurate "first seen time"**: CASR may keep crash #13 as the representative for a cluster, even though earlier crashes (e.g., crash #3, #5) of the same bug type were discarded

## Solution: Custom Clustering Script

We created `casr_cluster.py` that:

1. **Generates individual CASR reports** for each crash using `casr-san` (or appropriate tool)
2. **Clusters reports without deduplication** using `casr-cluster -c` (NOT `casr-cluster -d`)
3. **Preserves ALL crashes** with their cluster assignments in the output
4. **Outputs a JSON mapping** of crash filename → cluster ID

### How It Works

```bash
# Old approach (casr-libfuzzer):
# - Analyzes 18 crashes
# - Deduplicates to 3 representatives
# - Discards 15 duplicates
# Result: Only 3 crashes have cluster IDs

# New approach (casr_cluster.py):
# - Generates 18 CASR reports
# - Clusters all 18 reports
# - Keeps all 18 crashes with cluster assignments
# Result: All 18 crashes have cluster IDs
```

### Directory Structure

```
casr_reports/
├── reports/                          # Individual .casrep files for ALL crashes
│   ├── crash-1713d30.casrep
│   ├── crash-20570b.casrep
│   └── ... (18 total)
├── clusters/                         # Organized by cluster with ALL crashes
│   ├── cl1/
│   │   ├── crash-1713d30.casrep      # Representative
│   │   ├── crash-abc123.casrep       # Duplicate 1
│   │   └── crash-def456.casrep       # Duplicate 2
│   ├── cl2/
│   │   └── crash-20570b.casrep
│   └── cl3/
│       └── crash-7b9207.casrep
└── crash_mapping.json                # Complete mapping: crash → cluster
```

### JSON Mapping Format

```json
{
  "crash_to_cluster": {
    "crash-1713d30534c9e1770241b931b862e0adf380c89a": 1,
    "crash-abc123...": 1,
    "crash-def456...": 1,
    "crash-20570bf6e1a9d68983704755509a73170e8399f2": 2,
    "crash-7b9207a88bc556ed30e642251b5d24af390bc2f1": 3
  },
  "cluster_to_crashes": {
    "1": ["crash-1713d30...", "crash-abc123...", "crash-def456..."],
    "2": ["crash-20570b..."],
    "3": ["crash-7b9207..."]
  },
  "num_clusters": 3
}
```

## Implementation

### Container Setup

The `casr_cluster.py` script is copied into containers during build:

```dockerfile
# Copy custom CASR clustering script that preserves all crashes
COPY ./casr_cluster.py /usr/local/bin/casr_cluster.py
RUN chmod +x /usr/local/bin/casr_cluster.py
```

### Benchmark Usage

The fuzzing benchmark calls the script instead of `casr-libfuzzer`:

```python
# Run custom clustering script
result = await container.exec_command(
    cmd_args=[
        "python3",
        "/usr/local/bin/casr_cluster.py",
        "-i", crashes_dir,            # Input: crash files
        "-o", casr_output_dir,        # Output: reports + clusters
        "-t", "30",                   # Timeout per crash
        "--json", mapping_file,       # Output JSON mapping
        fuzzer_binary,                # Binary to analyze crashes with
    ],
    timeout=300,
)

# Parse JSON to get complete crash-to-cluster mapping
crash_to_cluster = await self._parse_casr_json_mapping(
    container, mapping_file, case_id
)
```

### Output Format

The `crashes.json` file now has cluster IDs for **ALL** crashes:

```json
{
  "case_id": 33071,
  "crashes": [
    {
      "crash_id": "crash_001",
      "corpus_file": "crash-1713d30...",
      "first_seen_time": 3.51,
      "cluster_id": "cl1"           # ← Now all crashes have cluster IDs
    },
    {
      "crash_id": "crash_002",
      "corpus_file": "crash-20570b...",
      "first_seen_time": 7.03,
      "cluster_id": "cl2"           # ← Not null!
    },
    {
      "crash_id": "crash_003",
      "corpus_file": "crash-abc123...",
      "first_seen_time": 10.54,
      "cluster_id": "cl1"           # ← Duplicate of cluster 1
    }
  ]
}
```

## Benefits

1. **Complete crash timeline**: Track when EVERY crash occurred, not just representatives
2. **Accurate unique bug count**: Count unique clusters (e.g., 3 unique bugs)
3. **Duplicate crash rate**: Count how many duplicates occurred per cluster
4. **Better "first seen time"**: Can find the earliest crash for each bug type by scanning all crashes in a cluster

## Analysis Example

```python
# Load crashes
with open('crashes.json') as f:
    data = json.load(f)

# Count unique bugs
unique_bugs = len(set(c['cluster_id'] for c in data['crashes'] if c['cluster_id']))

# Count duplicates per cluster
from collections import Counter
cluster_counts = Counter(c['cluster_id'] for c in data['crashes'] if c['cluster_id'])

# Find first occurrence of each bug
first_seen = {}
for crash in data['crashes']:
    cid = crash['cluster_id']
    if cid and (cid not in first_seen or crash['first_seen_time'] < first_seen[cid]):
        first_seen[cid] = crash['first_seen_time']

print(f"Unique bugs: {unique_bugs}")
print(f"Cluster sizes: {dict(cluster_counts)}")
print(f"First seen times: {first_seen}")
```

Output:
```
Unique bugs: 3
Cluster sizes: {'cl1': 6, 'cl2': 4, 'cl3': 8}
First seen times: {'cl1': 3.51, 'cl2': 7.03, 'cl3': 10.54}
```

## References

- CASR GitHub: https://github.com/ispras/casr
- CASR Paper: https://arxiv.org/abs/2112.13719
- Custom script: `benchmark/autopatch/build/casr_cluster.py`
