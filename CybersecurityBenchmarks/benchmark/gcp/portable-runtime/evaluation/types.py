# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

"""
Data types for the evaluation (fuzzing) module.

Mirrors the types from fuzzing_types.py for:
- Crash timeline tracking with timestamps
- CASR-based crash deduplication
- Fuzzer configuration
"""

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

    LIBFUZZER = "libfuzzer"
    AFL_PLUS_PLUS = "afl++"
    UNKNOWN = "unknown"


@dataclass
class CrashInfo:
    """Detailed info about a single crash."""

    crash_id: str
    corpus_file: str
    first_seen_time: float  # Seconds since fuzzing started
    target: FuzzingTarget
    crash_type: str  # CASR-determined type (e.g., "heap-buffer-overflow")
    stack_trace: List[str] = field(default_factory=list)
    casr_report: Dict[str, Any] = field(default_factory=dict)
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
class CrashTimeline:
    """Timeline of crashes found during fuzzing."""

    target: FuzzingTarget
    case_id: int
    model: str
    crashes: List[CrashInfo] = field(default_factory=list)
    duration_seconds: float = 0.0

    # Key metrics
    time_to_original_crash: Optional[float] = None
    reproduced_original: bool = False

    def add_crash(self, crash: CrashInfo) -> None:
        """Add a crash to the timeline."""
        self.crashes.append(crash)
        self.crashes.sort(key=lambda c: c.first_seen_time)

    def get_crashes_at_time(self, seconds: float) -> int:
        """Get total number of crashes found by a given time."""
        return sum(1 for c in self.crashes if c.first_seen_time <= seconds)

    def unique_crashes(self) -> int:
        """Count unique crashes after CASR deduplication."""
        clusters = set()
        for c in self.crashes:
            clusters.add(c.cluster_id or c.crash_id)
        return len(clusters)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to JSON-serializable dictionary."""
        return {
            "target": self.target.value,
            "case_id": self.case_id,
            "model": self.model,
            "crashes": [c.to_dict() for c in self.crashes],
            "duration_seconds": self.duration_seconds,
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
            "crashes": [
                {
                    "crash_id": c.crash_id,
                    "first_seen_time": c.first_seen_time,
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

    @classmethod
    def from_minimal_dict(cls, data: Dict[str, Any]) -> "CrashTimeline":
        """Create CrashTimeline from minimal JSON format (crashes.json)."""
        timeline = cls(
            target=FuzzingTarget(data["target"]),
            case_id=data["case_id"],
            model=data.get("model", "ground_truth"),
            duration_seconds=data.get("duration_seconds", 0.0),
        )

        # Restore summary fields if present
        summary = data.get("summary", {})
        timeline.time_to_original_crash = summary.get("time_to_original_crash")
        timeline.reproduced_original = summary.get("reproduced_original", False)

        # Restore crashes from minimal format
        for crash_data in data.get("crashes", []):
            crash = CrashInfo(
                crash_id=crash_data["crash_id"],
                corpus_file=crash_data.get("corpus_file", crash_data["crash_id"]),
                first_seen_time=crash_data["first_seen_time"],
                target=timeline.target,
                crash_type=crash_data.get("crash_type", "unknown"),
                cluster_id=crash_data.get("cluster_id"),
            )
            timeline.crashes.append(crash)

        return timeline

    def to_plot_data(self, resolution: float = 5.0) -> Dict[str, List]:
        """Generate data for plotting crashes vs time."""
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
            unique_counts.append(
                len(
                    set(
                        c.cluster_id or c.crash_id
                        for c in self.crashes
                        if c.first_seen_time <= t
                    )
                )
            )
            t += resolution
        return {
            "time": times,
            "crash_count": counts,
            "unique_crash_count": unique_counts,
        }


@dataclass
class FuzzingConfig:
    """Configuration for fuzzing."""

    # Duration
    duration_seconds: int = 300  # 5 minutes default

    # Continuous mode settings
    fork_jobs: int = 1  # Number of parallel fuzzing workers
    ignore_crashes: bool = True  # Continue after finding crashes

    # CASR settings
    use_casr: bool = True

    # Polling
    poll_interval_seconds: float = 2.0

    def get_libfuzzer_args(self, crash_dir: str) -> List[str]:
        """Get libFuzzer command line arguments."""
        args = [
            f"-fork={self.fork_jobs}",
            f"-max_total_time={self.duration_seconds}",
            f"-artifact_prefix={crash_dir}/",
            "-print_final_stats=1",
        ]
        if self.ignore_crashes:
            args.append("-ignore_crashes=1")
        return args

    def get_afl_args(self, input_dir: str, output_dir: str) -> List[str]:
        """Get AFL++ command line arguments."""
        return [
            "-i",
            input_dir,
            "-o",
            output_dir,
            "-V",
            str(self.duration_seconds),  # Time limit
        ]

    def get_afl_environment(self) -> Dict[str, str]:
        """Get AFL++ environment variables."""
        env = {
            "AFL_SKIP_CPUFREQ": "1",
            "AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES": "1",
            "AFL_NO_UI": "1",
        }
        if self.ignore_crashes:
            env["AFL_AUTORESUME"] = "1"
        return env


@dataclass
class FuzzingResult:
    """Result of a fuzzing run."""

    case_id: int
    model: str
    target: FuzzingTarget
    fuzzer_type: FuzzerType

    # Timing
    start_time: str = ""
    end_time: str = ""
    duration_seconds: float = 0.0

    # Crash timeline
    timeline: Optional[CrashTimeline] = None

    # Summary metrics
    total_crashes: int = 0
    unique_crashes: int = 0
    reproduced_original: bool = False
    time_to_original_crash: Optional[float] = None

    # Error
    error: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Convert to JSON-serializable dictionary."""
        return {
            "case_id": self.case_id,
            "model": self.model,
            "target": self.target.value,
            "fuzzer_type": self.fuzzer_type.value,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "duration_seconds": self.duration_seconds,
            "timeline": self.timeline.to_dict() if self.timeline else None,
            "total_crashes": self.total_crashes,
            "unique_crashes": self.unique_crashes,
            "reproduced_original": self.reproduced_original,
            "time_to_original_crash": self.time_to_original_crash,
            "error": self.error,
        }

    def save(self, path: Path) -> None:
        """Save to JSON file."""
        import json

        with open(path, "w") as f:
            json.dump(self.to_dict(), f, indent=2)
