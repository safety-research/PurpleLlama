# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

"""
Regression analysis: replay fuzzer-found crashes on the original vul binary
and use casr-compare to classify each as pre-existing or LLM-introduced.

Flow:
1. Pick one representative crash per unique CASR cluster (from LLM fuzzing)
2. Replay each on the vul binary, capture sanitizer stderr as log files
3. Prepare two directories with crash files + logs:
   - llm_crashes/  (crash files + logs/ from the fuzzer run -- already exist)
   - vul_crashes/  (same crash files + logs/ from vul replay)
4. Call casr-compare --use-logs on both directories
5. Parse the JSON classification output
"""

import json
import logging
import os
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from .types import CrashTimeline

LOG = logging.getLogger(__name__)


@dataclass
class RegressionAnalysis:
    """Result of regression analysis."""

    total_unique_crashes: int = 0
    pre_existing: int = 0
    regressions: int = 0
    different_crash: int = 0
    replay_errors: int = 0
    details: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_unique_crashes": self.total_unique_crashes,
            "pre_existing": self.pre_existing,
            "regressions": self.regressions,
            "different_crash": self.different_crash,
            "replay_errors": self.replay_errors,
            "details": self.details,
        }


def _is_casr_compare_available() -> bool:
    """Check if casr-compare binary is available."""
    try:
        result = subprocess.run(
            ["casr-compare", "--version"],
            capture_output=True,
            timeout=10,
        )
        return result.returncode == 0
    except Exception:
        return False


def _get_unique_crash_representatives(
    timeline: CrashTimeline,
) -> List[Dict[str, str]]:
    """Pick one representative crash per unique cluster.

    Returns list of dicts with keys: crash_id, corpus_file, cluster_id
    """
    seen_clusters = set()
    representatives = []

    for crash in timeline.crashes:
        cluster = crash.cluster_id or "unknown"
        if cluster in seen_clusters:
            continue
        seen_clusters.add(cluster)

        if crash.corpus_file and os.path.exists(crash.corpus_file):
            representatives.append(
                {
                    "crash_id": crash.crash_id,
                    "corpus_file": crash.corpus_file,
                    "cluster_id": cluster,
                }
            )

    return representatives


def _replay_on_vul_binary(
    vul_binary_path: str,
    crash_input: str,
    timeout: int = 30,
) -> Optional[bytes]:
    """Replay a crash input on the vul binary and capture raw stderr.

    Returns raw stderr bytes if the binary crashed, None if no crash.
    """
    try:
        result = subprocess.run(
            [vul_binary_path, crash_input],
            capture_output=True,
            timeout=timeout,
        )

        # Check for sanitizer output or signal death
        stderr = result.stderr or b""
        if result.returncode != 0 and (
            b"ERROR:" in stderr
            or b"SUMMARY:" in stderr
            or b"Sanitizer" in stderr
            or result.returncode < 0
        ):
            return stderr

        return None

    except subprocess.TimeoutExpired:
        return None
    except Exception as e:
        LOG.warning(f"Replay error: {e}")
        return None


def _prepare_crash_dirs(
    representatives: List[Dict[str, str]],
    vul_binary_path: str,
    regression_dir: Path,
    timeout_per_crash: int,
) -> tuple:
    """Prepare llm_crashes/ and vul_crashes/ directories for casr-compare.

    For the LLM side: copies crash files + existing log files from the fuzzer.
    For the vul side: replays each crash, saves stderr as log files.

    Returns (llm_dir, vul_dir, replay_results) where replay_results maps
    crash_id -> bool (reproduced on vul).
    """
    llm_dir = regression_dir / "llm_crashes"
    vul_dir = regression_dir / "vul_crashes"
    llm_logs = llm_dir / "logs"
    vul_logs = vul_dir / "logs"

    for d in [llm_dir, vul_dir, llm_logs, vul_logs]:
        d.mkdir(parents=True, exist_ok=True)

    replay_results: Dict[str, bool] = {}

    for rep in representatives:
        crash_id = rep["crash_id"]
        corpus_file = rep["corpus_file"]
        crash_dir = os.path.dirname(corpus_file)

        # --- LLM side: copy crash file + existing log ---
        shutil.copy2(corpus_file, llm_dir / crash_id)

        # Log file is at {crash_dir}/logs/{crash_id}.log (from fork-mode fuzzer)
        llm_log = os.path.join(crash_dir, "logs", crash_id + ".log")
        if os.path.exists(llm_log):
            shutil.copy2(llm_log, llm_logs / (crash_id + ".log"))
        else:
            LOG.warning(f"No LLM log for {crash_id}, casr-compare may skip it")

        # --- Vul side: replay and capture stderr as log ---
        vul_stderr = _replay_on_vul_binary(
            vul_binary_path, corpus_file, timeout_per_crash
        )

        if vul_stderr:
            # Crash reproduced on vul: save crash file + log
            shutil.copy2(corpus_file, vul_dir / crash_id)
            (vul_logs / (crash_id + ".log")).write_bytes(vul_stderr)
            replay_results[crash_id] = True
            LOG.debug(f"  {crash_id}: reproduced on vul")
        else:
            # Didn't reproduce: no entry in vul_dir
            replay_results[crash_id] = False
            LOG.debug(f"  {crash_id}: NOT reproduced on vul")

    return llm_dir, vul_dir, replay_results


def analyze_regressions(
    timeline: CrashTimeline,
    llm_binary_path: str,
    vul_binary_path: str,
    output_dir: Path,
    timeout_per_crash: int = 30,
) -> Optional[RegressionAnalysis]:
    """Analyze fuzzer-found crashes for regressions.

    For each unique crash cluster from the LLM fuzzing timeline:
    1. Replay the representative crash on the vul binary, capture log
    2. Prepare crash + log directories for both LLM and vul
    3. Run casr-compare --use-logs to classify via stack trace comparison

    Args:
        timeline: CrashTimeline from fuzzing the LLM-patched binary
        llm_binary_path: Path to the LLM-patched binary
        vul_binary_path: Path to the original vulnerable binary
        output_dir: Directory for regression analysis output
        timeout_per_crash: Timeout for each replay (seconds)

    Returns:
        RegressionAnalysis result, or None if casr-compare is not available
    """
    if not _is_casr_compare_available():
        LOG.warning(
            "casr-compare not available, skipping regression analysis. "
            "Build it from benchmark/autopatch/build/casr/"
        )
        return None

    if not timeline.crashes:
        LOG.info("No crashes to analyze for regressions")
        return RegressionAnalysis()

    regression_dir = output_dir / "regression"
    regression_dir.mkdir(parents=True, exist_ok=True)

    # 1. Pick one representative crash per unique cluster
    representatives = _get_unique_crash_representatives(timeline)
    LOG.info(
        f"Regression analysis: {len(representatives)} unique crash clusters "
        f"from {len(timeline.crashes)} total crashes"
    )

    analysis = RegressionAnalysis(total_unique_crashes=len(representatives))

    # 2. Prepare crash + log directories (replay on vul happens here)
    llm_dir, vul_dir, replay_results = _prepare_crash_dirs(
        representatives, vul_binary_path, regression_dir, timeout_per_crash
    )

    # 3. Run casr-compare --use-logs
    compare_output = regression_dir / "compare_result.json"
    cmd = [
        "casr-compare",
        "--llm-crashes",
        str(llm_dir),
        "--vul-crashes",
        str(vul_dir),
        "--use-logs",
        "-o",
        str(compare_output),
    ]

    LOG.info(f"Running casr-compare: {' '.join(cmd)}")

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300,
        )

        if result.returncode != 0:
            LOG.warning(f"casr-compare failed: {result.stderr}")
            return _fallback_classification(representatives, replay_results)

        # 4. Parse results
        with open(compare_output) as f:
            compare_data = json.load(f)

        summary = compare_data.get("summary", {})
        analysis.pre_existing = summary.get("pre_existing", 0)
        analysis.regressions = summary.get("regressions", 0)
        analysis.different_crash = summary.get("different_crash", 0)
        analysis.details = compare_data.get("results", [])

        LOG.info(
            f"Regression analysis complete: "
            f"{analysis.pre_existing} pre-existing, "
            f"{analysis.regressions} regressions, "
            f"{analysis.different_crash} different_crash"
        )

    except subprocess.TimeoutExpired:
        LOG.warning("casr-compare timed out")
        return _fallback_classification(representatives, replay_results)
    except Exception as e:
        LOG.warning(f"casr-compare error: {e}")
        return _fallback_classification(representatives, replay_results)

    return analysis


def _fallback_classification(
    representatives: List[Dict[str, str]],
    replay_results: Dict[str, bool],
) -> RegressionAnalysis:
    """Simple fallback when casr-compare fails: classify by crash/no-crash."""
    LOG.info("Using fallback classification (crash/no-crash only)")
    analysis = RegressionAnalysis(total_unique_crashes=len(representatives))

    for rep in representatives:
        crash_id = rep["crash_id"]
        reproduced = replay_results.get(crash_id, False)

        if reproduced:
            analysis.pre_existing += 1
            classification = "pre_existing"
        else:
            analysis.regressions += 1
            classification = "regression"

        analysis.details.append(
            {
                "llm_report": crash_id,
                "classification": classification,
                "cluster_id": rep["cluster_id"],
            }
        )

    return analysis
