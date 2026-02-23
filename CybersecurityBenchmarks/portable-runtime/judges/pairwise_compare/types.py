"""
Data types for blinded pairwise patch comparison analysis.

Defines the structured report format that the analysis agent produces,
including per-patch analysis, pairwise comparison, and test results.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class ApproachType(str, Enum):
    """How a patch addresses the vulnerability."""

    ROOT_CAUSE_FIX = "root_cause_fix"
    SYMPTOM_MASKING = "symptom_masking"
    INCOMPLETE_FIX = "incomplete_fix"
    OVERLY_BROAD = "overly_broad"
    NO_OP = "no_op"
    UNKNOWN = "unknown"


class Correctness(str, Enum):
    """Whether a patch correctly fixes the vulnerability."""

    CORRECT = "correct"
    PARTIAL = "partial"
    INCORRECT = "incorrect"
    UNKNOWN = "unknown"


class Similarity(str, Enum):
    """How similar two patches are in their core approach."""

    IDENTICAL = "identical"
    SIMILAR_APPROACH = "similar_approach"
    DIFFERENT_APPROACH = "different_approach"
    FUNDAMENTALLY_DIFFERENT = "fundamentally_different"


class AnalysisStatus(str, Enum):
    """Status of the analysis run."""

    INIT = "init"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    TIMEOUT = "timeout"


@dataclass
class PatchAnalysis:
    """Analysis of a single patch (Patch A or Patch B)."""

    core_idea: str = ""
    approach_type: str = ApproachType.UNKNOWN.value
    correctness: str = Correctness.UNKNOWN.value
    analysis: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "core_idea": self.core_idea,
            "approach_type": self.approach_type,
            "correctness": self.correctness,
            "analysis": self.analysis,
        }


@dataclass
class Comparison:
    """Pairwise comparison between Patch A and Patch B."""

    similarity: str = Similarity.FUNDAMENTALLY_DIFFERENT.value
    key_differences: List[str] = field(default_factory=list)
    which_is_better: str = "equivalent"  # "a", "b", or "equivalent"
    simpler_patch: str = "equivalent"  # "a", "b", or "equivalent"
    simplicity_reasoning: str = ""
    reasoning: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "similarity": self.similarity,
            "key_differences": self.key_differences,
            "which_is_better": self.which_is_better,
            "simpler_patch": self.simpler_patch,
            "simplicity_reasoning": self.simplicity_reasoning,
            "reasoning": self.reasoning,
        }


@dataclass
class TestResult:
    """Result of a differentiating test constructed by the analysis agent."""

    description: str = ""
    input_description: str = ""
    patch_a_behavior: str = ""
    patch_b_behavior: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "description": self.description,
            "input": self.input_description,
            "patch_a_behavior": self.patch_a_behavior,
            "patch_b_behavior": self.patch_b_behavior,
        }


@dataclass
class VulnerabilityInfo:
    """Information about the vulnerability being analyzed."""

    crash_type: str = ""
    root_cause_description: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": self.crash_type,
            "root_cause_description": self.root_cause_description,
        }


@dataclass
class AnalysisReport:
    """Complete analysis report for a blinded pairwise patch comparison."""

    # Identification
    case_id: int = 0
    source_experiment: str = ""
    patcher_1: str = ""
    patcher_2: str = ""

    # Vulnerability
    vulnerability: VulnerabilityInfo = field(default_factory=VulnerabilityInfo)

    # Per-patch analysis (blinded as A/B)
    patch_a: PatchAnalysis = field(default_factory=PatchAnalysis)
    patch_b: PatchAnalysis = field(default_factory=PatchAnalysis)

    # Comparison
    comparison: Comparison = field(default_factory=Comparison)

    # Differentiating tests (stretch goal, may be empty)
    test_results: List[TestResult] = field(default_factory=list)
    differentiating_inputs: List[str] = field(default_factory=list)

    # Full markdown report
    full_report: str = ""

    # Status
    status: str = AnalysisStatus.INIT.value
    error: str = ""
    duration_seconds: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "case_id": self.case_id,
            "source_experiment": self.source_experiment,
            "patcher_1": self.patcher_1,
            "patcher_2": self.patcher_2,
            "vulnerability": self.vulnerability.to_dict(),
            "patch_a": self.patch_a.to_dict(),
            "patch_b": self.patch_b.to_dict(),
            "comparison": self.comparison.to_dict(),
            "test_results": [t.to_dict() for t in self.test_results],
            "differentiating_inputs": self.differentiating_inputs,
            "full_report": self.full_report,
            "status": self.status,
            "error": self.error,
            "duration_seconds": self.duration_seconds,
        }

    @staticmethod
    def from_dict(data: Dict[str, Any]) -> "AnalysisReport":
        """Parse a report dict (e.g. from the agent's JSON output)."""
        report = AnalysisReport()
        report.case_id = data.get("case_id", 0)
        report.source_experiment = data.get("source_experiment", "")
        report.patcher_1 = data.get("patcher_1", "")
        report.patcher_2 = data.get("patcher_2", "")

        vul = data.get("vulnerability", {})
        report.vulnerability = VulnerabilityInfo(
            crash_type=vul.get("type", ""),
            root_cause_description=vul.get("root_cause_description", ""),
        )

        for key, cls in [("patch_a", PatchAnalysis), ("patch_b", PatchAnalysis)]:
            d = data.get(key, {})
            setattr(
                report,
                key,
                cls(
                    core_idea=d.get("core_idea", ""),
                    approach_type=d.get("approach_type", ApproachType.UNKNOWN.value),
                    correctness=d.get("correctness", Correctness.UNKNOWN.value),
                    analysis=d.get("analysis", ""),
                ),
            )

        comp = data.get("comparison", {})
        report.comparison = Comparison(
            similarity=comp.get("similarity", Similarity.FUNDAMENTALLY_DIFFERENT.value),
            key_differences=comp.get("key_differences", []),
            which_is_better=comp.get("which_is_better", "equivalent"),
            simpler_patch=comp.get("simpler_patch", "equivalent"),
            simplicity_reasoning=comp.get("simplicity_reasoning", ""),
            reasoning=comp.get("reasoning", ""),
        )

        for t in data.get("test_results", []):
            report.test_results.append(
                TestResult(
                    description=t.get("description", ""),
                    input_description=t.get("input", ""),
                    patch_a_behavior=t.get("patch_a_behavior", ""),
                    patch_b_behavior=t.get("patch_b_behavior", ""),
                )
            )

        report.differentiating_inputs = data.get("differentiating_inputs", [])
        report.full_report = data.get("full_report", "")
        return report
