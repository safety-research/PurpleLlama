#!/usr/bin/env python3
"""
Estimate GCP/GKE cost for running find_closest_vul_job.py on all eligible ARVO cases.

Accounts for:
  - GKE Standard billing (pay per node VM, not per pod)
  - Node overhead (system daemons, kubelet ~10-15% of resources)
  - Docker image pull time (images from docker.io/n132/arvo:*)
  - Init container + main container resource envelopes
  - Spot vs on-demand pricing
  - Parallelism constraints and wall-clock time
  - Artifact Registry storage for built -closest-vul images
  - Build workflow compute (build-closest-vul.yaml)
"""

import sqlite3
import sys
from dataclasses import dataclass
from math import ceil
from pathlib import Path

DB_PATH = Path(__file__).parent.parent.parent / "arvo.db"

# ---------------------------------------------------------------------------
# GKE E2 on-demand pricing (us-central1) — per hour
# https://cloud.google.com/compute/vm-instance-pricing
# ---------------------------------------------------------------------------
E2_VCPU_PER_HR = 0.031611
E2_GB_PER_HR = 0.004237

# Spot discount (typically 60-91% off on-demand; use 70% as midpoint)
SPOT_DISCOUNT = 0.70

# ---------------------------------------------------------------------------
# Workflow resource spec (from find-closest-vul.yaml)
# ---------------------------------------------------------------------------
# Init container 2 (search-closest-vul) — the dominant container
INIT2_CPU_REQ = 1.7  # vCPU
INIT2_MEM_REQ = 6.0  # GB
INIT2_CPU_LIM = 3.5
INIT2_MEM_LIM = 12.0

# Main container (GCS upload)
MAIN_CPU_REQ = 0.5
MAIN_MEM_REQ = 0.5  # 512Mi ≈ 0.5 GB
MAIN_CPU_LIM = 1.0
MAIN_MEM_LIM = 1.0

# Effective pod requests = max(init containers, sum(regular containers))
# Init containers run sequentially before the main container, so:
POD_CPU_REQ = max(INIT2_CPU_REQ, MAIN_CPU_REQ)  # 1.7
POD_MEM_REQ = max(INIT2_MEM_REQ, MAIN_MEM_REQ)  # 6.0 GB

PARALLELISM = 50

# ---------------------------------------------------------------------------
# Node sizing
# ---------------------------------------------------------------------------
# System overhead: kubelet, kube-proxy, logging agents, etc.
# GKE reserves ~0.5-1 vCPU and ~0.5-1.5 GB per node depending on size
NODE_CPU_OVERHEAD = 0.6  # vCPU reserved for system
NODE_MEM_OVERHEAD = 1.2  # GB reserved for system

# Also need room for DaemonSets (typically ~0.2 CPU, ~0.3 GB)
DAEMONSET_CPU = 0.2
DAEMONSET_MEM = 0.3


@dataclass
class NodeType:
    name: str
    vcpu: int
    mem_gb: int
    on_demand_per_hr: float  # E2 on-demand hourly rate

    @property
    def spot_per_hr(self) -> float:
        return self.on_demand_per_hr * (1 - SPOT_DISCOUNT)

    @property
    def allocatable_cpu(self) -> float:
        return self.vcpu - NODE_CPU_OVERHEAD - DAEMONSET_CPU

    @property
    def allocatable_mem(self) -> float:
        return self.mem_gb - NODE_MEM_OVERHEAD - DAEMONSET_MEM

    @property
    def pods_per_node(self) -> int:
        by_cpu = int(self.allocatable_cpu / POD_CPU_REQ)
        by_mem = int(self.allocatable_mem / POD_MEM_REQ)
        return max(1, min(by_cpu, by_mem))


# Common E2 machine types (us-central1 on-demand pricing)
NODE_TYPES = [
    NodeType("e2-standard-4", 4, 16, 0.134),
    NodeType("e2-standard-8", 8, 32, 0.268),
    NodeType("e2-standard-16", 16, 64, 0.536),
]


def get_case_and_project_counts() -> tuple[int, int]:
    """Query arvo.db for distinct eligible cases and unique projects."""
    if not DB_PATH.exists():
        print(f"WARNING: {DB_PATH} not found, using defaults", file=sys.stderr)
        return 4640, 311

    conn = sqlite3.connect(DB_PATH)
    row = conn.execute(
        """
        SELECT COUNT(*) as total_cases,
               COUNT(DISTINCT project) as unique_projects
        FROM (
            SELECT *, ROW_NUMBER() OVER (PARTITION BY fix_commit ORDER BY localId) as rn
            FROM arvo
            WHERE reproduced = 1 AND patch_located = 1
        ) WHERE rn = 1
        """
    ).fetchone()
    conn.close()
    return row[0], row[1]


@dataclass
class Scenario:
    name: str
    avg_compile_min: float  # average time spent compiling per case
    avg_image_pull_min: float  # average time pulling 2 Docker images
    avg_setup_teardown_min: float  # git ops, GCS upload, scheduling overhead
    description: str

    @property
    def avg_duration_min(self) -> float:
        return (
            self.avg_compile_min + self.avg_image_pull_min + self.avg_setup_teardown_min
        )


SCENARIOS = [
    Scenario(
        "Optimistic",
        avg_compile_min=5,
        avg_image_pull_min=5,
        avg_setup_teardown_min=3,
        description="Most cases exit early (K adjacent to A), images cached/small",
    ),
    Scenario(
        "Moderate",
        avg_compile_min=15,
        avg_image_pull_min=8,
        avg_setup_teardown_min=4,
        description="Mix of quick exits and 1-3 compile attempts",
    ),
    Scenario(
        "Conservative",
        avg_compile_min=30,
        avg_image_pull_min=10,
        avg_setup_teardown_min=5,
        description="Multiple compile attempts, large images",
    ),
    Scenario(
        "Worst case",
        avg_compile_min=60,
        avg_image_pull_min=12,
        avg_setup_teardown_min=5,
        description="Many cases need multiple 30-min compiles",
    ),
]


# -----------------------------------------------------------------------
# Artifact Registry storage pricing (us-central1)
# https://cloud.google.com/artifact-registry/pricing
# -----------------------------------------------------------------------
AR_STORAGE_PER_GB_MONTH = 0.10  # $/GB/month

# ---------------------------------------------------------------------------
# Build workflow resource spec (from build-closest-vul.yaml)
# ---------------------------------------------------------------------------
BUILD_CPU_REQ = 3.0  # vCPU (buildkit container)
BUILD_MEM_REQ = 8.0  # GB
BUILD_CPU_LIM = 7.0
BUILD_MEM_LIM = 16.0
BUILD_PARALLELISM = 50


def estimate():
    num_cases, num_projects = get_case_and_project_counts()
    print("=" * 76)
    print("  GKE Cost Estimate: find-closest-vul + build-closest-vul")
    print("=" * 76)
    print()
    print(
        f"  Cases (reproduced=1, patch_located=1, deduped by fix_commit): {num_cases:,}"
    )
    print(f"  Unique projects: {num_projects:,}")
    print(f"  Avg cases/project: {num_cases / num_projects:.1f}")
    print(f"  Images per case: 2 (docker.io/n132/arvo:{{id}}-vul, {{id}}-fix)")
    print(f"  Total image pulls: {num_cases * 2:,}")
    print(f"  Workflow parallelism: {PARALLELISM}")
    print(f"  Region: us-central1")
    print()
    print(f"  Find-closest-vul pod requests: {POD_CPU_REQ} vCPU, {POD_MEM_REQ} GB RAM")
    print(
        f"  Build-closest-vul pod requests: {BUILD_CPU_REQ} vCPU, {BUILD_MEM_REQ} GB RAM"
    )
    print()

    # -----------------------------------------------------------------------
    # Docker Hub rate-limit warning
    # -----------------------------------------------------------------------
    print("-" * 76)
    print("  ⚠  Docker Hub Rate Limits")
    print("-" * 76)
    free_pulls_per_6h = 200
    total_pulls = num_cases * 2
    hours_at_free_tier = (total_pulls / free_pulls_per_6h) * 6
    print(f"  Free tier: {free_pulls_per_6h} pulls / 6 hrs")
    print(
        f"  At free tier, {total_pulls:,} pulls would take: {hours_at_free_tier:.0f} hours"
    )
    print(f"  → Need Docker Hub Pro ($7/mo) or a GCR pull-through cache")
    print()

    # -----------------------------------------------------------------------
    # Per node type
    # -----------------------------------------------------------------------
    for node in NODE_TYPES:
        print("=" * 76)
        print(f"  Node type: {node.name}  ({node.vcpu} vCPU, {node.mem_gb} GB)")
        print(
            f"  Allocatable per node: {node.allocatable_cpu:.1f} vCPU, "
            f"{node.allocatable_mem:.1f} GB"
        )
        print(f"  Pods per node: {node.pods_per_node}")
        print(
            f"  On-demand: ${node.on_demand_per_hr:.3f}/hr   "
            f"Spot (~{SPOT_DISCOUNT:.0%} off): ${node.spot_per_hr:.3f}/hr"
        )
        print("=" * 76)

        nodes_needed = ceil(PARALLELISM / node.pods_per_node)
        actual_pod_slots = nodes_needed * node.pods_per_node
        utilization = PARALLELISM / actual_pod_slots

        print(f"  Nodes for {PARALLELISM} parallel pods: {nodes_needed}")
        print(
            f"  Actual pod capacity: {actual_pod_slots} "
            f"(utilization: {utilization:.0%})"
        )
        print()

        cluster_on_demand_per_hr = nodes_needed * node.on_demand_per_hr
        cluster_spot_per_hr = nodes_needed * node.spot_per_hr

        print(
            f"  {'Scenario':<16} {'Avg/case':>10} {'Pod-hrs':>10} "
            f"{'Wall hrs':>10} {'On-demand':>12} {'Spot':>12}"
        )
        print(f"  {'-' * 16} {'-' * 10} {'-' * 10} {'-' * 10} {'-' * 12} {'-' * 12}")

        for sc in SCENARIOS:
            avg_min = sc.avg_duration_min
            total_pod_hrs = num_cases * (avg_min / 60)

            # Wall clock: batches of PARALLELISM pods
            # Not all pods finish at the same time → ~20% overhead for stragglers
            batches = ceil(num_cases / PARALLELISM)
            wall_hrs_ideal = batches * (avg_min / 60)
            straggler_factor = 1.20
            wall_hrs = wall_hrs_ideal * straggler_factor

            # Nodes billed for full wall-clock duration (can't scale to zero mid-run)
            # In practice, GKE autoscaler may scale down between batches,
            # but conservatively assume nodes stay up for full duration
            on_demand_cost = wall_hrs * cluster_on_demand_per_hr
            spot_cost = wall_hrs * cluster_spot_per_hr

            print(
                f"  {sc.name:<16} {avg_min:>7.0f} min "
                f"{total_pod_hrs:>9,.0f}h "
                f"{wall_hrs:>9.1f}h "
                f"  ${on_demand_cost:>9,.0f} "
                f"  ${spot_cost:>9,.0f}"
            )

        print()
        print(f"  Scenario details:")
        for sc in SCENARIOS:
            print(f"    {sc.name}: {sc.description}")
        print()

    # -----------------------------------------------------------------------
    # Autopilot comparison (billed per pod resource, not per node)
    # -----------------------------------------------------------------------
    print("=" * 76)
    print("  GKE Autopilot (billed per pod, not per node)")
    print("=" * 76)
    # Autopilot pricing (us-central1)
    AP_VCPU_HR = 0.0445
    AP_GB_HR = 0.0049525
    pod_hr_cost = POD_CPU_REQ * AP_VCPU_HR + POD_MEM_REQ * AP_GB_HR
    pod_hr_spot = pod_hr_cost * (1 - 0.60)  # Autopilot spot discount ~60%

    print(f"  Per pod-hour (on-demand): ${pod_hr_cost:.4f}")
    print(f"  Per pod-hour (spot):      ${pod_hr_spot:.4f}")
    print()
    print(
        f"  {'Scenario':<16} {'Avg/case':>10} {'Pod-hrs':>10} "
        f"{'On-demand':>12} {'Spot':>12}"
    )
    print(f"  {'-' * 16} {'-' * 10} {'-' * 10} {'-' * 12} {'-' * 12}")

    for sc in SCENARIOS:
        avg_min = sc.avg_duration_min
        total_pod_hrs = num_cases * (avg_min / 60)
        on_demand = total_pod_hrs * pod_hr_cost
        spot = total_pod_hrs * pod_hr_spot

        print(
            f"  {sc.name:<16} {avg_min:>7.0f} min "
            f"{total_pod_hrs:>9,.0f}h "
            f"  ${on_demand:>9,.0f} "
            f"  ${spot:>9,.0f}"
        )

    print()

    # -----------------------------------------------------------------------
    # Artifact Registry Storage (ONGOING monthly cost)
    # -----------------------------------------------------------------------
    print("=" * 76)
    print("  Artifact Registry Storage (build-closest-vul images)")
    print("=" * 76)
    print()
    print(f"  Each case produces 1 image: {{registry}}/arvo-{{id}}-closest-vul")
    print(f"  Base: docker.io/n132/arvo:{{id}}-fix + git checkout to target commit")
    print(f"  Images pushed to: us-central1-docker.pkg.dev (Artifact Registry)")
    print(f"  AR pricing: ${AR_STORAGE_PER_GB_MONTH}/GB/month")
    print()
    print(f"  AR uses content-addressable storage → layers shared across images")
    print(f"  of the SAME project (same base OS, build tools, deps).")
    print(f"  But each case has a UNIQUE upstream -fix image, so cross-case")
    print(f"  layer sharing depends on how Docker Hub images were built.")
    print()

    # Image size estimates.  ARVO images contain:
    #   - Ubuntu base:        ~80 MB compressed
    #   - Build tools:        ~300-800 MB compressed  (clang, gcc, cmake, etc.)
    #   - Project source+deps: ~100 MB - 2 GB compressed
    #   - Compiled binaries:   ~50-500 MB compressed
    # Total per image: ~0.5-3.5 GB compressed, ~1.5 GB median
    #
    # Layer dedup within same project:  high (same Dockerfile, same deps)
    # Layer dedup across projects:      moderate (shared Ubuntu + build tools base)

    @dataclass
    class StorageScenario:
        name: str
        avg_image_gb: float  # compressed size per image
        cross_project_dedup: float  # fraction of shared base layers across projects
        same_project_dedup: float  # fraction saved when same project has N cases
        description: str

    storage_scenarios = [
        StorageScenario(
            "Low (good dedup)",
            avg_image_gb=1.0,
            cross_project_dedup=0.30,  # 30% of layers shared across all projects
            same_project_dedup=0.85,  # 85% overlap between cases of same project
            description="Small images, good layer sharing",
        ),
        StorageScenario(
            "Medium",
            avg_image_gb=1.5,
            cross_project_dedup=0.20,
            same_project_dedup=0.75,
            description="Typical ARVO images, moderate dedup",
        ),
        StorageScenario(
            "High (poor dedup)",
            avg_image_gb=2.5,
            cross_project_dedup=0.10,
            same_project_dedup=0.60,
            description="Large images, limited layer sharing",
        ),
    ]

    print(
        f"  {'Scenario':<22} {'Eff. storage':>14} {'Monthly':>10} {'3 months':>10} {'12 months':>11}"
    )
    print(f"  {'-' * 22} {'-' * 14} {'-' * 10} {'-' * 10} {'-' * 11}")

    for ss in storage_scenarios:
        # Model: each project contributes a base set of unique layers,
        # plus each additional case adds a small delta.
        # Shared base across ALL projects reduces total further.
        avg_cases_per_proj = num_cases / num_projects

        # First case per project: full image
        # Additional cases: only (1 - same_project_dedup) fraction is new
        per_project_gb = ss.avg_image_gb + (
            avg_cases_per_proj - 1
        ) * ss.avg_image_gb * (1 - ss.same_project_dedup)
        raw_total_gb = num_projects * per_project_gb

        # Cross-project dedup (shared base layers like Ubuntu, build tools)
        effective_gb = raw_total_gb * (1 - ss.cross_project_dedup)

        monthly = effective_gb * AR_STORAGE_PER_GB_MONTH

        print(
            f"  {ss.name:<22} {effective_gb:>10,.0f} GB "
            f"  ${monthly:>7,.0f} "
            f"  ${monthly * 3:>7,.0f} "
            f"  ${monthly * 12:>8,.0f}"
        )

    print()
    for ss in storage_scenarios:
        print(f"    {ss.name}: {ss.description}")
    print()

    # -----------------------------------------------------------------------
    # Build workflow compute cost (build-closest-vul.yaml)
    # -----------------------------------------------------------------------
    print("=" * 76)
    print("  Build Compute (build-closest-vul.yaml — one-time)")
    print("=" * 76)
    print()
    print(f"  Each case: buildkit builds FROM upstream-fix + git checkout")
    print(f"  Pod requests: {BUILD_CPU_REQ} vCPU, {BUILD_MEM_REQ} GB")
    print(f"  Pod limits:   {BUILD_CPU_LIM} vCPU, {BUILD_MEM_LIM} GB")
    print(f"  Runs on spot nodes (cloud.google.com/gke-spot=true)")
    print(f"  Retry: up to 3 retries per case (spot preemption)")
    print()

    # Build duration: pull base image + git fetch + checkout + push
    # These are NOT compiling — just git checkout + push layers
    # Estimated 5-15 min per case depending on image size
    build_scenarios = [
        ("Fast builds", 8),  # min per case
        ("Medium builds", 15),
        ("Slow builds", 25),
    ]

    # Build node: needs 3 CPU, 8 GB → e2-standard-4 fits 1 pod, e2-standard-8 fits 2
    build_node = NodeType("e2-standard-8", 8, 32, 0.268)
    build_pods_per_node = max(
        1,
        min(
            int(build_node.allocatable_cpu / BUILD_CPU_REQ),
            int(build_node.allocatable_mem / BUILD_MEM_REQ),
        ),
    )
    build_nodes = ceil(BUILD_PARALLELISM / build_pods_per_node)

    print(
        f"  Build node: {build_node.name} ({build_pods_per_node} pods/node, "
        f"{build_nodes} nodes for {BUILD_PARALLELISM} parallel)"
    )
    print()

    print(f"  {'Scenario':<16} {'Avg/case':>10} {'Wall hrs':>10} {'Spot cost':>12}")
    print(f"  {'-' * 16} {'-' * 10} {'-' * 10} {'-' * 12}")

    for name, avg_min in build_scenarios:
        batches = ceil(num_cases / BUILD_PARALLELISM)
        wall_hrs = batches * (avg_min / 60) * 1.20  # straggler overhead
        spot_cost = wall_hrs * build_nodes * build_node.spot_per_hr
        print(f"  {name:<16} {avg_min:>7} min {wall_hrs:>9.1f}h   ${spot_cost:>9,.0f}")

    print()

    # -----------------------------------------------------------------------
    # Summary
    # -----------------------------------------------------------------------
    print("=" * 76)
    print("  TOTAL COST SUMMARY (moderate estimates)")
    print("=" * 76)
    print()

    moderate = SCENARIOS[1]
    avg_min = moderate.avg_duration_min
    total_pod_hrs = num_cases * (avg_min / 60)
    batches = ceil(num_cases / PARALLELISM)
    wall_hrs = batches * (avg_min / 60) * 1.20

    best_node = NODE_TYPES[1]  # e2-standard-8
    nodes = ceil(PARALLELISM / best_node.pods_per_node)

    find_on_demand = wall_hrs * nodes * best_node.on_demand_per_hr
    find_spot = wall_hrs * nodes * best_node.spot_per_hr

    # Build cost (medium scenario, spot)
    build_avg_min = 15
    build_batches = ceil(num_cases / BUILD_PARALLELISM)
    build_wall_hrs = build_batches * (build_avg_min / 60) * 1.20
    build_spot = build_wall_hrs * build_nodes * build_node.spot_per_hr

    # Storage (medium scenario)
    avg_cases_per_proj = num_cases / num_projects
    med_ss = storage_scenarios[1]
    per_proj = med_ss.avg_image_gb + (avg_cases_per_proj - 1) * med_ss.avg_image_gb * (
        1 - med_ss.same_project_dedup
    )
    storage_gb = num_projects * per_proj * (1 - med_ss.cross_project_dedup)
    storage_monthly = storage_gb * AR_STORAGE_PER_GB_MONTH

    print(f"  1. Find-closest-vul compute (one-time):")
    print(
        f"     {num_cases:,} cases × ~{avg_min:.0f} min avg → {total_pod_hrs:,.0f} pod-hrs"
    )
    print(f"       On-demand ({best_node.name}):  ${find_on_demand:>8,.0f}")
    print(f"       Spot:                        ${find_spot:>8,.0f}")
    print()
    print(f"  2. Build-closest-vul compute (one-time, spot):")
    print(
        f"     {num_cases:,} cases × ~{build_avg_min} min avg → {build_wall_hrs:.0f} wall-hrs"
    )
    print(f"       Spot ({build_node.name}):      ${build_spot:>8,.0f}")
    print()
    print(f"  3. Artifact Registry storage (ONGOING):")
    print(f"     {num_cases:,} images → ~{storage_gb:,.0f} GB effective")
    print(f"       Per month:                   ${storage_monthly:>8,.0f}")
    print(f"       Per year:                    ${storage_monthly * 12:>8,.0f}")
    print()

    total_one_time_spot = find_spot + build_spot
    total_one_time_ondemand = find_on_demand + build_spot  # builds always spot
    print(f"  ┌─────────────────────────────────────────────────────┐")
    print(f"  │  ONE-TIME (compute):                                │")
    print(
        f"  │    All spot:      ${total_one_time_spot:>8,.0f}                        │"
    )
    print(
        f"  │    Find on-demand + build spot: ${total_one_time_ondemand:>8,.0f}              │"
    )
    print(f"  │                                                     │")
    print(f"  │  ONGOING (storage):                                 │")
    print(
        f"  │    ${storage_monthly:>8,.0f}/month  (${storage_monthly * 12:>8,.0f}/year)             │"
    )
    print(f"  │                                                     │")
    print(f"  │  FIRST-YEAR TOTAL (all spot):                       │")
    print(
        f"  │    ${total_one_time_spot + storage_monthly * 12:>8,.0f}                                    │"
    )
    print(f"  └─────────────────────────────────────────────────────┘")
    print()
    print(f"  + Docker Hub Pro if needed: $7/mo")
    print(f"  + GCS storage/ops: < $1")
    print()


if __name__ == "__main__":
    estimate()
