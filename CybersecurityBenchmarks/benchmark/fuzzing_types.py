# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

"""
Data structures for the FuzzingOnlyBenchmark.

These types support:
- Crash timeline tracking with timestamps and execution counts
- Original crash (PoC) reference tracking
- CASR-based crash deduplication
- Configuration for fuzzing budget (time vs executions)
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional


class FuzzingTarget(str, Enum):
    """Which binary is being fuzzed."""

    GROUND_TRUTH = "ground_truth"
    LLM_PATCH = "llm_patch"


class FuzzerType(str, Enum):
    """Type of fuzzer the binary was built for."""

    LIBFUZZER = "libfuzzer"  # Standard libFuzzer (runs binary directly)
    AFL_PLUS_PLUS = "afl++"  # AFL++ (requires afl-fuzz driver)
    UNKNOWN = "unknown"  # Unable to detect


class CaseStatus(str, Enum):
    """Status of a fuzzing case."""

    PENDING = "pending"
    GENERATING_PATCH = "generating_patch"  # LLM is generating a patch
    LOADING_RESPONSE = "loading_response"
    BUILDING_CONTAINER = "building_container"
    ANALYZING_ORIGINAL = "analyzing_original"  # Analyzing original PoC crash with CASR
    FUZZING_GT = "fuzzing_gt"  # Fuzzing ground truth patch
    FUZZING_LLM = "fuzzing_llm"  # Fuzzing LLM patch
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


class BudgetType(str, Enum):
    """Type of fuzzing budget."""

    TIME = "time"  # Fixed time budget (default)
    EXECUTIONS = "executions"  # Fixed execution count


@dataclass
class CrashInfo:
    """Detailed info about a single crash."""

    crash_id: str  # Unique identifier (e.g., "crash_001")
    corpus_file: str  # Filename in corpus (e.g., "crash-abc123")
    first_seen_time: float  # Seconds since fuzzing started
    first_seen_executions: int  # Execution count when first seen
    target: FuzzingTarget  # GT or LLM
    crash_type: str  # CASR-determined type (e.g., "heap-buffer-overflow")
    stack_trace: List[str] = field(default_factory=list)  # Function names in stack
    casr_report: Dict[str, Any] = field(default_factory=dict)  # Full CASR JSON report
    cluster_id: Optional[str] = None  # CASR cluster ID after deduplication
    matches_original: bool = False  # True if same crash type as original PoC

    def to_dict(self) -> Dict[str, Any]:
        """Convert to JSON-serializable dictionary."""
        d = asdict(self)
        d["target"] = self.target.value
        return d

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "CrashInfo":
        """Create from dictionary."""
        data = data.copy()
        if isinstance(data.get("target"), str):
            data["target"] = FuzzingTarget(data["target"])
        return cls(**data)


@dataclass
class OriginalCrash:
    """The original PoC crash from vulnerable container (reference)."""

    crash_id: str = "original_poc"
    corpus_file: str = "/tmp/poc"
    crash_type: str = ""
    stack_trace: List[str] = field(default_factory=list)
    casr_report: Dict[str, Any] = field(default_factory=dict)
    cluster_id: Optional[str] = None
    severity: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Convert to JSON-serializable dictionary."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "OriginalCrash":
        """Create from dictionary."""
        return cls(**data)


@dataclass
class CrashTimeline:
    """Timeline of crashes found during fuzzing."""

    target: FuzzingTarget  # GT or LLM
    case_id: int
    model: str
    crashes: List[CrashInfo] = field(default_factory=list)
    duration_seconds: float = 0.0
    total_executions: int = 0

    # Key metrics
    time_to_original_crash: Optional[float] = None  # Time to reproduce original crash type
    reproduced_original: bool = False  # Did we find same crash as PoC?

    def add_crash(self, crash: CrashInfo) -> None:
        """Add a crash, checking if it matches original crash type."""
        self.crashes.append(crash)
        # Sort by timestamp
        self.crashes.sort(key=lambda c: c.first_seen_time)

    def get_crashes_at_time(self, seconds: float) -> int:
        """Get total number of crashes found by a given time."""
        return sum(1 for c in self.crashes if c.first_seen_time <= seconds)

    def get_unique_crashes_at_time(self, seconds: float) -> int:
        """Get number of unique crashes (by cluster_id) found by a given time."""
        clusters = set()
        for c in self.crashes:
            if c.first_seen_time <= seconds:
                clusters.add(c.cluster_id or c.crash_id)
        return len(clusters)

    def unique_crashes(self) -> int:
        """Count unique crashes after CASR deduplication."""
        clusters = set()
        for c in self.crashes:
            clusters.add(c.cluster_id or c.crash_id)
        return len(clusters)

    def to_plot_data(self, resolution: float = 5.0) -> Dict[str, List]:
        """
        Generate data for plotting crashes vs time.

        Returns:
            {"time": [0, 5, 10, ...], "crash_count": [0, 1, 2, ...], "unique_crash_count": [0, 1, 1, ...]}
        """
        max_time = self.duration_seconds or (
            max(c.first_seen_time for c in self.crashes) if self.crashes else 0
        )
        times = []
        counts = []
        unique_counts = []
        t = 0.0
        while t <= max_time:
            times.append(t)
            counts.append(self.get_crashes_at_time(t))
            unique_counts.append(self.get_unique_crashes_at_time(t))
            t += resolution
        return {"time": times, "crash_count": counts, "unique_crash_count": unique_counts}

    def to_exec_plot_data(self, resolution: int = 10000) -> Dict[str, List]:
        """
        Generate data for plotting crashes vs executions.

        Returns:
            {"executions": [0, 10000, 20000, ...], "crash_count": [...], "unique_crash_count": [...]}
        """
        max_execs = self.total_executions or (
            max(c.first_seen_executions for c in self.crashes) if self.crashes else 0
        )
        executions = []
        counts = []
        unique_counts = []
        e = 0
        while e <= max_execs:
            executions.append(e)
            count = sum(1 for c in self.crashes if c.first_seen_executions <= e)
            counts.append(count)
            clusters = set()
            for c in self.crashes:
                if c.first_seen_executions <= e:
                    clusters.add(c.cluster_id or c.crash_id)
            unique_counts.append(len(clusters))
            e += resolution
        return {
            "executions": executions,
            "crash_count": counts,
            "unique_crash_count": unique_counts,
        }

    def to_dict(self) -> Dict[str, Any]:
        """Convert to JSON-serializable dictionary."""
        return {
            "target": self.target.value,
            "case_id": self.case_id,
            "model": self.model,
            "crash_ids": [c.crash_id for c in self.crashes],
            "timestamps": [c.first_seen_time for c in self.crashes],
            "executions": [c.first_seen_executions for c in self.crashes],
            "duration_seconds": self.duration_seconds,
            "total_executions": self.total_executions,
            "time_to_original_crash": self.time_to_original_crash,
            "reproduced_original": self.reproduced_original,
            "total_crashes": len(self.crashes),
            "unique_crashes": self.unique_crashes(),
        }

    def to_minimal_dict(self) -> Dict[str, Any]:
        """Convert to minimal JSON format for crashes.json.

        Simplified format optimized for plotting unique crashes over time:
        - crashes: array of minimal crash info (id, time, cluster)
        - summary: total and unique crash counts
        """
        return {
            "target": self.target.value,
            "case_id": self.case_id,
            "model": self.model,
            "duration_seconds": self.duration_seconds,
            "total_executions": self.total_executions,
            "crashes": [
                {
                    "crash_id": c.crash_id,
                    "first_seen_time": c.first_seen_time,
                    "first_seen_executions": c.first_seen_executions,
                    "cluster_id": c.cluster_id,
                }
                for c in self.crashes
            ],
            "summary": {
                "total_crashes": len(self.crashes),
                "unique_crashes": self.unique_crashes(),
                "time_to_original_crash": self.time_to_original_crash,
                "reproduced_original": self.reproduced_original,
            },
        }


@dataclass
class CaseState:
    """State of a single case being processed."""

    case_id: int
    model: str
    status: CaseStatus = CaseStatus.PENDING
    original_crash: Optional[OriginalCrash] = None  # Reference crash from vul container
    gt_timeline: Optional[CrashTimeline] = None
    llm_timeline: Optional[CrashTimeline] = None
    crash_details: Dict[str, CrashInfo] = field(default_factory=dict)  # crash_id -> full info
    streaming_output: str = ""  # For TUI - activity/status info
    container_logs: str = ""  # For TUI - tail command for log file
    current_activity: str = ""  # Current activity description
    current_executions: int = 0  # Live execution count
    error: Optional[str] = None  # Error message if failed

    # Cached LLM response info
    patch_path: Optional[str] = None
    binary_path: Optional[str] = None
    patched_function: Optional[str] = None

    # Log file paths for monitoring
    fuzzer_log_path: Optional[str] = None  # Path to fuzzer output log
    llm_log_path: Optional[str] = None  # Path to LLM generation log

    # PTY-related fields for v2 TUI
    pty_command: Optional[List[str]] = None  # Current command running in PTY
    container_id: Optional[str] = None  # Container ID for this case
    pty_output_buffer: str = ""  # Captured PTY output for logging

    # Fuzzer type detection
    fuzzer_type: Optional["FuzzerType"] = None  # Detected fuzzer type (libFuzzer or AFL++)

    def get_key(self) -> str:
        """Get unique key for this case."""
        return f"{self.case_id}_{self.model}"


@dataclass
class FuzzingConfig:
    """Configuration for the fuzzing-only benchmark."""

    # Budget type
    budget_type: BudgetType = BudgetType.TIME

    # Time-based budget
    fuzzing_duration_minutes: int = 60

    # Execution-based budget
    max_executions: int = 1_000_000

    # Continuous mode settings
    # fork_jobs: Number of parallel fuzzing workers per case (libFuzzer only)
    # - libFuzzer uses -fork=N to spawn N parallel workers
    # - AFL++ currently runs single-threaded (parallel mode not yet implemented)
    # - Total processes = num_containers × fork_jobs
    # - Default is 1 to avoid overloading system when running many cases in parallel
    fork_jobs: int = 1
    ignore_crashes: bool = True

    # CASR settings
    use_casr: bool = True  # Enable CASR deduplication

    # Polling settings
    poll_interval_seconds: float = 2.0  # Poll container logs every 2 seconds

    # Fuzzing targets
    fuzz_ground_truth: bool = True
    fuzz_llm_patch: bool = True

    # LLM response handling
    source_responses_dir: Optional[str] = None  # Copy responses from here
    use_cached_only: bool = False  # Skip LLM generation, only use cached

    # TUI settings
    enable_tui: bool = True
    use_tui_v2: bool = False  # Use v2 TUI with PTY-based terminal widget

    @classmethod
    def from_additional_args(cls, args_str: Optional[str]) -> "FuzzingConfig":
        """Parse configuration from --additional-args string."""
        config = cls()
        if not args_str:
            return config

        import shlex

        args = shlex.split(args_str)
        i = 0
        while i < len(args):
            arg = args[i]
            if arg == "--fuzzing-duration" and i + 1 < len(args):
                config.fuzzing_duration_minutes = int(args[i + 1])
                i += 2
            elif arg == "--max-executions" and i + 1 < len(args):
                config.max_executions = int(args[i + 1])
                i += 2
            elif arg == "--budget-type" and i + 1 < len(args):
                config.budget_type = BudgetType(args[i + 1])
                i += 2
            elif arg == "--fork-jobs" and i + 1 < len(args):
                config.fork_jobs = int(args[i + 1])
                i += 2
            elif arg == "--poll-interval" and i + 1 < len(args):
                config.poll_interval_seconds = float(args[i + 1])
                i += 2
            elif arg == "--source-responses" and i + 1 < len(args):
                config.source_responses_dir = args[i + 1]
                i += 2
            elif arg == "--fuzz-gt":
                config.fuzz_ground_truth = True
                i += 1
            elif arg == "--no-fuzz-gt":
                config.fuzz_ground_truth = False
                i += 1
            elif arg == "--fuzz-llm":
                config.fuzz_llm_patch = True
                i += 1
            elif arg == "--no-fuzz-llm":
                config.fuzz_llm_patch = False
                i += 1
            elif arg == "--use-casr":
                config.use_casr = True
                i += 1
            elif arg == "--no-use-casr":
                config.use_casr = False
                i += 1
            elif arg == "--use-cached-only":
                config.use_cached_only = True
                i += 1
            elif arg == "--enable-tui":
                config.enable_tui = True
                i += 1
            elif arg == "--no-enable-tui":
                config.enable_tui = False
                i += 1
            elif arg == "--use-tui-v2":
                config.use_tui_v2 = True
                i += 1
            elif arg == "--no-use-tui-v2":
                config.use_tui_v2 = False
                i += 1
            else:
                i += 1

        return config

    # NOTE: Fuzzer args are built directly in fuzzing_only_benchmark.py's
    # _configure_libfuzzer() and _configure_afl_plus_plus() methods,
    # which have access to run_id and target for crash directory paths.

    def get_afl_environment_vars(self) -> dict:
        """Get environment variables for AFL++ fuzzing.
        
        Note: ASAN_OPTIONS is handled specially - we append to existing value
        rather than replacing it, to preserve container-specific settings.
        """
        env = {}
        
        # Continue fuzzing after finding crashes (don't exit early)
        if self.ignore_crashes:
            env["AFL_AUTORESUME"] = "1"
        
        # Performance optimizations
        env["AFL_SKIP_CPUFREQ"] = "1"
        env["AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES"] = "1"
        env["AFL_NO_UI"] = "1"  # Disable AFL's TUI since we have our own
        
        return env
    
    def get_afl_asan_options_fix(self) -> str:
        """Get shell command to fix ASAN_OPTIONS for AFL++.
        
        AFL++ requires abort_on_error=1 in ASAN_OPTIONS. We unconditionally
        prepend it to ensure it's always present (duplicates are harmless).
        """
        return '''
# Ensure ASAN_OPTIONS has abort_on_error=1 (required by AFL++)
# Unconditionally prepend to handle all cases - duplicates are harmless
export ASAN_OPTIONS="abort_on_error=1:${ASAN_OPTIONS:-symbolize=0:detect_leaks=0}"
'''


@dataclass
class FuzzingResults:
    """Complete fuzzing results for a single case."""

    arvo_challenge_number: int
    model: str
    budget_type: str
    original_crash: Optional[Dict[str, Any]] = None
    gt_time_to_original_crash: Optional[float] = None
    llm_time_to_original_crash: Optional[float] = None
    gt_crash_timeline: Optional[Dict[str, Any]] = None
    llm_crash_timeline: Optional[Dict[str, Any]] = None
    gt_total_crashes: int = 0
    gt_unique_crashes: int = 0
    gt_total_executions: int = 0
    llm_total_crashes: int = 0
    llm_unique_crashes: int = 0
    llm_total_executions: int = 0
    gt_reproduced_original: bool = False
    llm_reproduced_original: bool = False

    def to_dict(self) -> Dict[str, Any]:
        """Convert to JSON-serializable dictionary."""
        return asdict(self)

    def save(self, path: Path) -> None:
        """Save to JSON file."""
        with open(path, "w") as f:
            json.dump(self.to_dict(), f, indent=2)

    @classmethod
    def from_case_state(cls, state: CaseState, config: FuzzingConfig) -> "FuzzingResults":
        """Create FuzzingResults from CaseState."""
        result = cls(
            arvo_challenge_number=state.case_id,
            model=state.model,
            budget_type=config.budget_type.value,
        )

        if state.original_crash:
            result.original_crash = state.original_crash.to_dict()

        if state.gt_timeline:
            result.gt_crash_timeline = state.gt_timeline.to_dict()
            result.gt_total_crashes = len(state.gt_timeline.crashes)
            result.gt_unique_crashes = state.gt_timeline.unique_crashes()
            result.gt_total_executions = state.gt_timeline.total_executions
            result.gt_time_to_original_crash = state.gt_timeline.time_to_original_crash
            result.gt_reproduced_original = state.gt_timeline.reproduced_original

        if state.llm_timeline:
            result.llm_crash_timeline = state.llm_timeline.to_dict()
            result.llm_total_crashes = len(state.llm_timeline.crashes)
            result.llm_unique_crashes = state.llm_timeline.unique_crashes()
            result.llm_total_executions = state.llm_timeline.total_executions
            result.llm_time_to_original_crash = state.llm_timeline.time_to_original_crash
            result.llm_reproduced_original = state.llm_timeline.reproduced_original

        return result


@dataclass
class CrashDetails:
    """Full crash details for a case, stored in crash_details.json."""

    original_crash: Optional[Dict[str, Any]] = None
    crashes: Dict[str, Dict[str, Any]] = field(default_factory=dict)  # crash_id -> info
    clusters: Dict[str, Dict[str, Any]] = field(default_factory=dict)  # cluster_id -> info

    def to_dict(self) -> Dict[str, Any]:
        """Convert to JSON-serializable dictionary."""
        return asdict(self)

    def save(self, path: Path) -> None:
        """Save to JSON file."""
        with open(path, "w") as f:
            json.dump(self.to_dict(), f, indent=2)

    @classmethod
    def from_case_state(cls, state: CaseState) -> "CrashDetails":
        """Create CrashDetails from CaseState."""
        details = cls()

        if state.original_crash:
            details.original_crash = state.original_crash.to_dict()

        for crash_id, crash_info in state.crash_details.items():
            details.crashes[crash_id] = crash_info.to_dict()

        # Build clusters from crash data
        cluster_map: Dict[str, List[str]] = {}
        for crash_id, crash_info in state.crash_details.items():
            cluster_id = crash_info.cluster_id or crash_id
            if cluster_id not in cluster_map:
                cluster_map[cluster_id] = []
            cluster_map[cluster_id].append(crash_id)

        for cluster_id, crash_ids in cluster_map.items():
            # Get representative crash
            rep_crash = state.crash_details.get(crash_ids[0])
            if rep_crash:
                details.clusters[cluster_id] = {
                    "crash_type": rep_crash.crash_type,
                    "representative_stack": rep_crash.stack_trace,
                    "crash_ids": crash_ids,
                }

        return details
