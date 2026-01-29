# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

"""
FuzzingOnlyBenchmark - A benchmark variant focused on fuzzing with crash timeline tracking.

Key differences from AutoPatchingBenchmark:
1. Skips QA arvo run (10 min fuzzing during container build)
2. Skips differential debugging
3. Runs configurable X minutes of fuzzing on BOTH GT and LLM patches
4. Records crash timelines for "crashes vs time" plotting
5. Supports CASR-based crash deduplication
6. Provides real-time TUI for visualization
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import shutil
import time
from multiprocessing import Lock
from multiprocessing.synchronize import Lock as LockType
from pathlib import Path
from typing import Any, Dict, List, Optional

from .arvo_utils import ArvoContainer
from .benchmark import Benchmark, BenchmarkConfig
from .fuzzing_types import (
    BudgetType,
    CaseState,
    CaseStatus,
    CrashDetails,
    CrashInfo,
    CrashTimeline,
    FuzzingConfig,
    FuzzingResults,
    FuzzingTarget,
    OriginalCrash,
)
from .llm import LLM

LOG: logging.Logger = logging.getLogger(__name__)


class FuzzingOnlyBenchmark(Benchmark):
    """
    Fuzzing-only benchmark that skips QA arvo run and differential debugging.

    Features:
    - Configurable fuzzing duration via command line
    - Fuzzing of both ground truth AND LLM patches
    - Crash timeline tracking for plotting
    - LLM response caching support
    - Optional TUI for real-time visualization
    """

    BENCHMARK_NAME: str = "fuzzing-only"

    # Lock for thread-safe file access
    RESPONSE_FILE_LOCK: LockType = Lock()
    RESULTS_FILE_LOCK: LockType = Lock()

    # Response JSON keys (compatible with AutoPatchingBenchmark)
    RESPONSES_MODEL_KEY: str = "model"
    RESPONSES_ARVO_CHALLENGE_NUMBER_KEY: str = "arvo_challenge_number"
    RESPONSES_GENERATED_PATCH_KEY: str = "generated_patch"
    RESPONSES_REBUILT_BINARY_KEY: str = "rebuilt_binary"
    RESPONSES_PATCHED_FUNCTION_KEY: str = "patched_function"
    RESPONSES_PATCH_SUCCESS_KEY: str = "patch_success"
    RESPONSES_CONTAINERS_PASS_QA_CHECKS_KEY: str = "containers_pass_qa_checks"

    def __init__(self, config: BenchmarkConfig) -> None:
        super().__init__(config)

        # Parse fuzzing-specific configuration
        self.fuzzing_config = FuzzingConfig.from_additional_args(config.additional_args)

        # Set up output directory
        self.output_dir = config.output_dir or config.response_path.parent
        self.files_dir = self.output_dir / "files"
        self.files_dir.mkdir(parents=True, exist_ok=True)

        # Set up ArvoContainer
        ArvoContainer.set_container_repository(config.container_repository)
        ArvoContainer.set_output_dir(self.output_dir)

        # State tracking for all cases
        self.case_states: Dict[str, CaseState] = {}

        # Determine test cases
        self.test_cases: List[int] = self._determine_test_cases(config)

        # Build container images (uses fuzzing template)
        LOG.info(f"Building container images for {len(self.test_cases)} test cases...")
        self.images_available: List[int] = self._build_container_images(
            self.test_cases, config.max_concurrency
        )
        LOG.info(f"Built {len(self.images_available)} container images")

    @classmethod
    def return_kind(cls) -> List[str]:
        return [cls.BENCHMARK_NAME]

    def _determine_test_cases(self, config: BenchmarkConfig) -> List[int]:
        """Determine which test cases to run based on config."""
        if config.response_path.exists():
            # Use existing responses
            return self._get_test_cases_from_responses(config.response_path)
        elif config.prompt_path:
            # Use prompt path for test case list
            return self._get_test_cases_from_prompt(
                config.num_test_cases, Path(config.prompt_path)
            )
        return []

    def _get_test_cases_from_responses(self, response_path: Path) -> List[int]:
        """Extract ARVO IDs from existing response file."""
        responses = json.loads(response_path.read_text())
        arvo_ids = list(
            set(
                r[self.RESPONSES_ARVO_CHALLENGE_NUMBER_KEY]
                for r in responses
                if self.RESPONSES_ARVO_CHALLENGE_NUMBER_KEY in r
            )
        )
        return sorted(arvo_ids)

    def _get_test_cases_from_prompt(
        self, num_test_cases: int, prompt_path: Path
    ) -> List[int]:
        """Load test case IDs from prompt file."""
        numbers = json.loads(prompt_path.read_text())
        return numbers[:num_test_cases] if num_test_cases > 0 else numbers

    def _build_container_images(
        self, test_cases: List[int], max_concurrency: int
    ) -> List[int]:
        """Build container images using the fuzzing dockerfile template."""
        # For now, use the standard build method
        # TODO: Add support for dockerfile_fuzzing_template selection
        return ArvoContainer.build_container_images(
            test_cases, max_concurrency, logging.INFO
        )

    # =========================================================================
    # Response Caching
    # =========================================================================

    def _get_case_dir(self, case_id: int, model: str) -> Path:
        """Get output directory for a specific case and model."""
        case_dir = self.files_dir / f"case_{case_id}" / model
        case_dir.mkdir(parents=True, exist_ok=True)
        return case_dir

    def _read_responses(self) -> List[Dict[str, Any]]:
        """Read existing responses from file."""
        if self.response_path.exists():
            return json.loads(self.response_path.read_text())
        return []

    def _is_response_cached(self, case_id: int, model: str) -> bool:
        """Check if LLM response exists for this case."""
        responses = self._read_responses()
        return any(
            r.get(self.RESPONSES_ARVO_CHALLENGE_NUMBER_KEY) == case_id
            and r.get(self.RESPONSES_MODEL_KEY) == model
            for r in responses
        )

    def _load_cached_response(
        self, case_id: int, model: str
    ) -> Optional[Dict[str, Any]]:
        """Load cached LLM response for a case."""
        responses = self._read_responses()
        for r in responses:
            if (
                r.get(self.RESPONSES_ARVO_CHALLENGE_NUMBER_KEY) == case_id
                and r.get(self.RESPONSES_MODEL_KEY) == model
            ):
                return r
        return None

    def _copy_responses_from_source(self, source_dir: Path) -> None:
        """Copy pre-existing LLM responses from source directory."""
        source_response = source_dir / "responses.json"
        if source_response.exists():
            LOG.info(f"Copying responses from {source_dir}")
            shutil.copy(source_response, self.response_path)

            # Copy associated files directories
            source_files = source_dir / "files"
            if source_files.exists():
                if self.files_dir.exists():
                    shutil.rmtree(self.files_dir)
                shutil.copytree(source_files, self.files_dir)
                LOG.info(f"Copied {sum(1 for _ in source_files.iterdir())} case directories")

    # =========================================================================
    # Fuzzing with Timeline Tracking
    # =========================================================================

    async def _analyze_original_crash(
        self, container: ArvoContainer, case_id: int
    ) -> Optional[OriginalCrash]:
        """Analyze the original PoC crash to establish reference."""
        LOG.info(f"Case {case_id}: Analyzing original PoC crash...")

        try:
            # Run the PoC to get crash output
            result = await container.exec_command(
                cmd_args=["arvo"], combine_outputs=True, timeout=60
            )

            crash_output = result.stdout.decode() if result.stdout else ""

            # Parse crash type from ASAN output
            crash_type = self._parse_crash_type(crash_output)

            # Extract stack trace
            stack_trace = self._parse_stack_trace(crash_output)

            return OriginalCrash(
                crash_id="original_poc",
                corpus_file="/tmp/poc",
                crash_type=crash_type,
                stack_trace=stack_trace,
                casr_report={},  # Will be populated if CASR is available
                severity="unknown",
            )
        except Exception as e:
            LOG.warning(f"Case {case_id}: Failed to analyze original crash: {e}")
            return None

    def _parse_crash_type(self, output: str) -> str:
        """Parse crash type from ASAN/fuzzer output."""
        # Common ASAN patterns
        patterns = [
            r"ERROR: AddressSanitizer: ([\w-]+)",
            r"ERROR: LeakSanitizer: ([\w-]+)",
            r"ERROR: MemorySanitizer: ([\w-]+)",
            r"ERROR: UndefinedBehaviorSanitizer: ([\w-]+)",
            r"SUMMARY: \w+: ([\w-]+)",
        ]
        for pattern in patterns:
            match = re.search(pattern, output)
            if match:
                return match.group(1)
        return "unknown"

    def _parse_stack_trace(self, output: str) -> List[str]:
        """Parse stack trace from ASAN output."""
        stack = []
        # Match lines like "#0 0x... in function_name file.c:123"
        pattern = r"#\d+\s+0x[\da-f]+\s+in\s+(\w+)"
        for match in re.finditer(pattern, output):
            stack.append(match.group(1))
        return stack[:10]  # Limit to 10 frames

    async def _set_fuzzer_continuous_mode(self, container: ArvoContainer) -> None:
        """Configure fuzzer for continuous mode (don't stop on first crash)."""
        fuzzer_args = self.fuzzing_config.get_fuzzer_args()
        LOG.debug(f"Setting FUZZER_ARGS to: {fuzzer_args}")

        # Update FUZZER_ARGS in /bin/arvo
        await container.string_replace_in_container_file(
            "/bin/arvo",
            'export FUZZER_ARGS="-rss_limit_mb=2560 -timeout=25"',
            f'export FUZZER_ARGS="{fuzzer_args}"',
        )

        # Also handle cases where max_total_time is already set
        await container.string_replace_in_container_file(
            "/bin/arvo",
            'export FUZZER_ARGS="-rss_limit_mb=2560 -timeout=25 -max_total_time=600"',
            f'export FUZZER_ARGS="{fuzzer_args}"',
        )

    async def _get_crash_files(self, container: ArvoContainer) -> List[str]:
        """Get list of crash files from corpus directory."""
        result = await container.exec_command(
            cmd_args=["ls", "-1", "/tmp/corpus/"], timeout=10
        )
        if result.returncode != 0:
            return []

        crashes = []
        stdout = result.stdout.decode() if result.stdout else ""
        for line in stdout.strip().split("\n"):
            if line.startswith("crash-") or line.startswith("oom-") or line.startswith("timeout-"):
                crashes.append(line)
        return crashes

    async def _get_execution_count(self, container: ArvoContainer) -> int:
        """Parse current execution count from fuzzer output."""
        # This is a simplified version - in practice, we'd parse the fuzzer's live output
        # For now, return 0 as a placeholder
        return 0

    async def _fuzz_with_timeline(
        self,
        container: ArvoContainer,
        target: FuzzingTarget,
        case_id: int,
        model: str,
        binary_path: Optional[str] = None,
        original_crash: Optional[OriginalCrash] = None,
        state: Optional[CaseState] = None,
    ) -> CrashTimeline:
        """
        Run fuzzing and track crashes over time.

        Args:
            container: The ArvoContainer to use
            target: Whether fuzzing GT or LLM patch
            case_id: ARVO challenge number
            model: Model name
            binary_path: Path to binary (for LLM patch)
            original_crash: Reference crash for comparison
            state: CaseState for UI updates

        Returns:
            CrashTimeline with all crash events
        """
        timeline = CrashTimeline(
            target=target,
            case_id=case_id,
            model=model,
        )

        # Configure continuous mode
        await self._set_fuzzer_continuous_mode(container)

        # Copy rebuilt binary if fuzzing LLM patch
        if target == FuzzingTarget.LLM_PATCH and binary_path:
            await container.copy_to_container(binary_path, "/tmp/rebuilt_binary")
            fuzz_cmd = ["arvo", "fuzz_fix"]
        else:
            fuzz_cmd = ["arvo", "run"]

        LOG.info(f"Case {case_id}: Starting {target.value} fuzzing...")

        # Start fuzzing
        start_time = time.time()
        duration_seconds = self.fuzzing_config.fuzzing_duration_minutes * 60

        # Run fuzzing with timeout
        try:
            fuzz_result = await asyncio.wait_for(
                container.exec_command(cmd_args=fuzz_cmd, combine_outputs=True),
                timeout=duration_seconds + 60,  # Extra buffer
            )
        except asyncio.TimeoutError:
            LOG.warning(f"Case {case_id}: Fuzzing timed out")
            fuzz_result = None

        end_time = time.time()
        timeline.duration_seconds = end_time - start_time

        # Collect crash files
        crash_files = await self._get_crash_files(container)
        LOG.info(f"Case {case_id}: Found {len(crash_files)} crash files")

        # Create CrashInfo for each crash
        crash_counter = 0
        for crash_file in crash_files:
            crash_counter += 1
            crash_id = f"crash_{crash_counter:03d}"

            # Extract hash from filename (crash-<sha1>)
            parts = crash_file.split("-")
            crash_hash = parts[1] if len(parts) > 1 else crash_file

            # Determine crash type (simplified - would use CASR in full implementation)
            crash_type = parts[0] if parts else "unknown"

            # For now, use discovery order as a proxy for timestamp
            # In a full implementation, we'd poll during fuzzing
            estimated_time = (crash_counter / max(len(crash_files), 1)) * timeline.duration_seconds

            crash_info = CrashInfo(
                crash_id=crash_id,
                corpus_file=crash_file,
                first_seen_time=estimated_time,
                first_seen_executions=0,  # Would be tracked during fuzzing
                target=target,
                crash_type=crash_type,
                stack_trace=[],
                casr_report={},
                matches_original=(
                    original_crash is not None
                    and crash_type == original_crash.crash_type
                ),
            )

            timeline.add_crash(crash_info)

            # Check if this matches original crash
            if crash_info.matches_original and timeline.time_to_original_crash is None:
                timeline.time_to_original_crash = estimated_time
                timeline.reproduced_original = True
                LOG.info(
                    f"Case {case_id}: Original crash type reproduced at {estimated_time:.1f}s"
                )

            # Update state for TUI
            if state:
                state.crash_details[crash_id] = crash_info

        return timeline

    # =========================================================================
    # Main Workflow
    # =========================================================================

    async def _process_single_case(
        self,
        case_id: int,
        model: str,
        state: CaseState,
    ) -> Optional[FuzzingResults]:
        """Process a single case: load response, fuzz GT and LLM patch."""
        LOG.info(f"Processing case {case_id} with model {model}")

        try:
            # Load cached response
            state.status = CaseStatus.LOADING_RESPONSE
            state.current_activity = "Loading cached LLM response..."

            cached = self._load_cached_response(case_id, model)
            if not cached:
                LOG.warning(f"Case {case_id}: No cached response found")
                state.status = CaseStatus.SKIPPED
                state.error = "No cached response found"
                return None

            # Check for rebuilt binary
            binary_path = cached.get(self.RESPONSES_REBUILT_BINARY_KEY)
            if not binary_path or not Path(binary_path).exists():
                # Try alternative path
                alt_path = self._get_case_dir(case_id, model) / "binary.bin"
                if alt_path.exists():
                    binary_path = str(alt_path)
                else:
                    LOG.warning(f"Case {case_id}: No rebuilt binary found")
                    state.status = CaseStatus.SKIPPED
                    state.error = "No rebuilt binary found"
                    return None

            state.binary_path = binary_path
            state.patched_function = cached.get(self.RESPONSES_PATCHED_FUNCTION_KEY)

            # Start container
            state.status = CaseStatus.BUILDING_CONTAINER
            state.current_activity = "Starting container..."

            case_dir = self._get_case_dir(case_id, model)
            container = ArvoContainer(
                case_id,
                container_type=ArvoContainer.CONTAINER_TYPE_FIX,
                model_under_test=model,
                log_level=logging.INFO,
                log_filepath=case_dir / "fuzzing_log.txt",
                artifacts_dir=case_dir,
            )
            await container.start_container()

            # Analyze original crash
            state.status = CaseStatus.ANALYZING_ORIGINAL
            state.current_activity = "Analyzing original PoC crash..."
            original_crash = await self._analyze_original_crash(container, case_id)
            state.original_crash = original_crash

            # Fuzz ground truth (if enabled)
            if self.fuzzing_config.fuzz_ground_truth:
                state.status = CaseStatus.FUZZING_GT
                state.current_activity = "Fuzzing ground truth patch..."

                state.gt_timeline = await self._fuzz_with_timeline(
                    container,
                    FuzzingTarget.GROUND_TRUTH,
                    case_id,
                    model,
                    original_crash=original_crash,
                    state=state,
                )

            # Fuzz LLM patch (if enabled)
            if self.fuzzing_config.fuzz_llm_patch:
                state.status = CaseStatus.FUZZING_LLM
                state.current_activity = "Fuzzing LLM patch..."

                state.llm_timeline = await self._fuzz_with_timeline(
                    container,
                    FuzzingTarget.LLM_PATCH,
                    case_id,
                    model,
                    binary_path=binary_path,
                    original_crash=original_crash,
                    state=state,
                )

            # Clean up container
            await container.stop_container()

            # Save results
            state.status = CaseStatus.COMPLETED
            state.current_activity = "Done"

            results = FuzzingResults.from_case_state(state, self.fuzzing_config)
            self._save_case_results(case_id, model, state, results)

            return results

        except Exception as e:
            LOG.error(f"Case {case_id}: Error during processing: {e}")
            state.status = CaseStatus.FAILED
            state.error = str(e)
            return None

    def _save_case_results(
        self,
        case_id: int,
        model: str,
        state: CaseState,
        results: FuzzingResults,
    ) -> None:
        """Save results for a single case."""
        case_dir = self._get_case_dir(case_id, model)

        # Save fuzzing results summary
        results.save(case_dir / "fuzzing_results.json")

        # Save detailed crash info
        crash_details = CrashDetails.from_case_state(state)
        crash_details.save(case_dir / "crash_details.json")

        LOG.info(f"Case {case_id}: Results saved to {case_dir}")

    def _save_all_results(self, all_results: List[FuzzingResults]) -> None:
        """Save aggregated results to fuzzing_results.json."""
        output_path = self.output_dir / "fuzzing_results.json"
        results_data = [r.to_dict() for r in all_results if r]

        with self.RESULTS_FILE_LOCK:
            output_path.write_text(json.dumps(results_data, indent=2))

        LOG.info(f"Saved {len(results_data)} results to {output_path}")

    # =========================================================================
    # Benchmark Interface Methods
    # =========================================================================

    def query_llm_to_generate_responses(
        self,
        prompt_path: Path,
        run_llm_in_parallel: int = 1,
    ) -> None:
        """
        For fuzzing-only benchmark, this loads cached responses rather than
        querying the LLM. Use --source-responses to copy from another run.
        """
        if self.fuzzing_config.source_responses_dir:
            source = Path(self.fuzzing_config.source_responses_dir)
            self._copy_responses_from_source(source)
        else:
            LOG.info(
                "Using existing responses at response_path (no LLM queries). "
                "Use --source-responses to copy from another location."
            )

    async def run(
        self,
        num_test_cases: int = 0,
        run_llm_in_parallel: int = 16,
        should_cleanup_after_eval: bool = False,
    ) -> None:
        """Run fuzzing evaluation on all cases."""
        responses = self._read_responses()

        # Build case list
        cases_to_process = []
        for response in responses:
            case_id = response.get(self.RESPONSES_ARVO_CHALLENGE_NUMBER_KEY)
            model = response.get(self.RESPONSES_MODEL_KEY)
            if case_id and model and case_id in self.images_available:
                key = f"{case_id}_{model}"
                state = CaseState(case_id=case_id, model=model)
                self.case_states[key] = state
                cases_to_process.append((case_id, model, state))

        if num_test_cases > 0:
            cases_to_process = cases_to_process[:num_test_cases]

        LOG.info(f"Processing {len(cases_to_process)} cases...")

        # Check if TUI is enabled
        if self.fuzzing_config.enable_tui:
            from .fuzzing_tui import is_textual_available

            if is_textual_available():
                # Run with TUI
                await self._run_with_tui(cases_to_process, run_llm_in_parallel)
            else:
                LOG.warning("Textual not available, running without TUI")
                await self._run_without_tui(cases_to_process, run_llm_in_parallel)
        else:
            await self._run_without_tui(cases_to_process, run_llm_in_parallel)

        if should_cleanup_after_eval:
            await ArvoContainer.cleanup_all_containers()

    async def _run_without_tui(
        self,
        cases_to_process: List[tuple],
        max_concurrent: int,
    ) -> None:
        """Run fuzzing without TUI."""
        semaphore = asyncio.Semaphore(max_concurrent)

        async def process_with_semaphore(case_id, model, state):
            async with semaphore:
                return await self._process_single_case(case_id, model, state)

        tasks = [
            process_with_semaphore(case_id, model, state)
            for case_id, model, state in cases_to_process
        ]

        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Filter out exceptions and None results
        valid_results = [r for r in results if isinstance(r, FuzzingResults)]
        self._save_all_results(valid_results)

        # Print summary
        completed = sum(
            1 for s in self.case_states.values() if s.status == CaseStatus.COMPLETED
        )
        failed = sum(
            1 for s in self.case_states.values() if s.status == CaseStatus.FAILED
        )
        skipped = sum(
            1 for s in self.case_states.values() if s.status == CaseStatus.SKIPPED
        )
        LOG.info(
            f"Completed: {completed}, Failed: {failed}, Skipped: {skipped}"
        )

    async def _run_with_tui(
        self,
        cases_to_process: List[tuple],
        max_concurrent: int,
    ) -> None:
        """Run fuzzing with TUI visualization."""
        from .fuzzing_tui import FuzzingTUI

        # Create TUI app
        tui = FuzzingTUI(
            case_states=self.case_states,
            config=self.fuzzing_config,
            on_deduplicate=self._handle_deduplicate,
        )

        # Run processing in background
        async def run_processing():
            await self._run_without_tui(cases_to_process, max_concurrent)

        # Start processing task
        processing_task = asyncio.create_task(run_processing())

        # Run TUI (blocking)
        tui.run()

        # Wait for processing to complete
        await processing_task

    def _handle_deduplicate(self, case_key: str) -> None:
        """Handle CASR deduplication request from TUI."""
        # TODO: Implement CASR deduplication
        LOG.info(f"CASR deduplication requested for {case_key}")
