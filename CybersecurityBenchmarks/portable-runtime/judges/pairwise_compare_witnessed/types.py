"""
Data types for the witnessed analysis module.

Reuses VulnerabilityInfo and PatchAnalysis from judges/pairwise_compare/types.py for the
analyst's per-patch assessment. Adds Claim and WitnessReport for the
witnessed comparison workflow.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List

from judges.pairwise_compare.types import (
    ApproachType,
    Correctness,
    PatchAnalysis,
    VulnerabilityInfo,
)


class ClaimCategory(str, Enum):
    """Categories of testable claims about patch differences."""

    NEW_CRASH = "new_crash"
    INCOMPLETE_FIX = "incomplete_fix"
    BEHAVIORAL_DIVERGENCE = "behavioral_divergence"
    LATENT_PORTABILITY_BUG = "latent_portability_bug"
    BUILD_ROBUSTNESS = "build_robustness"
    UNNECESSARY_CODE = "unnecessary_code"
    PERFORMANCE_REGRESSION = "performance_regression"


class ClaimStatus(str, Enum):
    """Outcome of a witness attempt for a claim."""

    PENDING = "pending"
    CONFIRMED = "confirmed"
    REFUTED = "refuted"
    UNVERIFIABLE = "unverifiable"
    ERROR = "error"
    TIMEOUT = "timeout"


class WitnessStatus(str, Enum):
    """Status of the overall witnessed analysis run."""

    INIT = "init"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    TIMEOUT = "timeout"


@dataclass
class Claim:
    """A testable claim about one or both patches."""

    id: str = ""
    category: str = ClaimCategory.BEHAVIORAL_DIVERGENCE.value
    patch: str = "comparison"  # "a", "b", or "comparison"
    claim: str = ""
    testable: bool = True
    test_strategy: str = ""
    status: str = ClaimStatus.PENDING.value
    witness_script: str = ""
    witness_output: str = ""
    witness_exit_code: int = -1

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "category": self.category,
            "patch": self.patch,
            "claim": self.claim,
            "testable": self.testable,
            "test_strategy": self.test_strategy,
            "status": self.status,
            "witness_script": self.witness_script,
            "witness_output": self.witness_output,
            "witness_exit_code": self.witness_exit_code,
        }

    @staticmethod
    def from_dict(data: Dict[str, Any]) -> "Claim":
        return Claim(
            id=data.get("id", ""),
            category=data.get("category", ClaimCategory.BEHAVIORAL_DIVERGENCE.value),
            patch=data.get("patch", "comparison"),
            claim=data.get("claim", ""),
            testable=data.get("testable", True),
            test_strategy=data.get("test_strategy", ""),
            status=data.get("status", ClaimStatus.PENDING.value),
            witness_script=data.get("witness_script", ""),
            witness_output=data.get("witness_output", ""),
            witness_exit_code=data.get("witness_exit_code", -1),
        )


@dataclass
class WitnessReport:
    """Complete report for a witnessed pairwise patch comparison."""

    # Identification
    case_id: int = 0
    source_experiment: str = ""
    patcher_1: str = ""
    patcher_2: str = ""

    # Analyst output (reused from judges/pairwise_compare/)
    vulnerability: VulnerabilityInfo = field(default_factory=VulnerabilityInfo)
    patch_a: PatchAnalysis = field(default_factory=PatchAnalysis)
    patch_b: PatchAnalysis = field(default_factory=PatchAnalysis)

    # Claims and witness results
    claims: List[Claim] = field(default_factory=list)

    # Final conclusion (written by analyst after seeing all witness results)
    conclusion: str = ""
    full_report: str = ""

    # Status
    status: str = WitnessStatus.INIT.value
    error: str = ""
    duration_seconds: float = 0.0

    @property
    def confirmed_count(self) -> int:
        return sum(1 for c in self.claims if c.status == ClaimStatus.CONFIRMED.value)

    @property
    def refuted_count(self) -> int:
        return sum(1 for c in self.claims if c.status == ClaimStatus.REFUTED.value)

    @property
    def unverifiable_count(self) -> int:
        return sum(
            1
            for c in self.claims
            if c.status == ClaimStatus.UNVERIFIABLE.value
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "case_id": self.case_id,
            "source_experiment": self.source_experiment,
            "patcher_1": self.patcher_1,
            "patcher_2": self.patcher_2,
            "vulnerability": self.vulnerability.to_dict(),
            "patch_a": self.patch_a.to_dict(),
            "patch_b": self.patch_b.to_dict(),
            "claims": [c.to_dict() for c in self.claims],
            "confirmed_count": self.confirmed_count,
            "refuted_count": self.refuted_count,
            "unverifiable_count": self.unverifiable_count,
            "conclusion": self.conclusion,
            "full_report": self.full_report,
            "status": self.status,
            "error": self.error,
            "duration_seconds": self.duration_seconds,
        }

    @staticmethod
    def from_dict(data: Dict[str, Any]) -> "WitnessReport":
        """Parse a report dict from the analyst's JSON output."""
        report = WitnessReport()
        report.case_id = data.get("case_id", 0)
        report.source_experiment = data.get("source_experiment", "")
        report.patcher_1 = data.get("patcher_1", "")
        report.patcher_2 = data.get("patcher_2", "")

        vul = data.get("vulnerability", {})
        report.vulnerability = VulnerabilityInfo(
            crash_type=vul.get("type", ""),
            root_cause_description=vul.get("root_cause_description", ""),
        )

        for key in ("patch_a", "patch_b"):
            d = data.get(key, {})
            setattr(
                report,
                key,
                PatchAnalysis(
                    core_idea=d.get("core_idea", ""),
                    approach_type=d.get(
                        "approach_type", ApproachType.UNKNOWN.value
                    ),
                    correctness=d.get("correctness", Correctness.UNKNOWN.value),
                    analysis=d.get("analysis", ""),
                ),
            )

        for c in data.get("claims", []):
            report.claims.append(Claim.from_dict(c))

        report.conclusion = data.get("conclusion", "")
        report.full_report = data.get("full_report", "")
        return report
