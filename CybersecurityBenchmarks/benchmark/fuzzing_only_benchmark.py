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
from .autopatch.autopatch_tools import AutoPatchAgent
from .autopatch.report import ChatHistory, write_chat_history_markdown
from .autopatch.types import PatchGenerationReport
from .benchmark import Benchmark, BenchmarkConfig
from .fuzzing_types import (
    CaseState,
    CaseStatus,
    CrashDetails,
    CrashInfo,
    CrashTimeline,
    FuzzingConfig,
    FuzzingResults,
    FuzzingTarget,
    FuzzerType,
    OriginalCrash,
)
from .llm import LLM

LOG: logging.Logger = logging.getLogger(__name__)


class DebugContainerException(Exception):
    """Exception raised when a case needs debugging and container should be preserved.
    
    This exception signals that:
    1. The current case should skip the rest of its pipeline
    2. The container should NOT be cleaned up at the end
    3. The benchmark should continue running other cases
    """
    
    def __init__(self, message: str, container_id: str, case_id: int):
        super().__init__(message)
        self.container_id = container_id
        self.case_id = case_id


class FuzzingOnlyBenchmark(Benchmark):
    """
    Fuzzing-only benchmark that skips QA arvo run and differential debugging.

    Features:
    - Configurable fuzzing duration via command line
    - Fuzzing of both ground truth AND LLM patches
    - Crash timeline tracking for plotting
    - LLM response caching support
    - Optional TUI for real-time visualization

    GT (ground truth) is treated as a special "model" with model name GT_MODEL_NAME.
    It uses the pre-built -fix container instead of requiring LLM patch generation.
    """

    BENCHMARK_NAME: str = "fuzzing-only"

    # Ground truth model name - treated as a special model that uses the fix container
    GT_MODEL_NAME: str = "ground_truth"

    # Timeout for patch generation (seconds)
    PER_SAMPLE_PATCH_GENERATION_TIMEOUT: int = 60 * 20  # 20 minutes

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

        # Set up file logging (important when using TUI which captures stdout/stderr)
        self._setup_file_logging()

        # Set up ArvoContainer
        ArvoContainer.set_container_repository(config.container_repository)
        ArvoContainer.set_output_dir(self.output_dir)

        # State tracking for all cases
        self.case_states: Dict[str, CaseState] = {}

        # Determine test cases
        self.test_cases: List[int] = self._determine_test_cases(config)

        # Store config for deferred building
        self._max_concurrency = config.max_concurrency

        # Images will be built in run() so TUI can show progress
        self.images_available: List[int] = []
        self._images_built = False

        # Track containers that need to be preserved for debugging
        # Format: {container_id: {"case_id": int, "reason": str, "model": str}}
        self.debug_containers: Dict[str, Dict[str, Any]] = {}

    def _setup_file_logging(self) -> None:
        """Set up file logging for the benchmark.

        When TUI is enabled, console output is not visible, so we log to a file.
        This method also removes console handlers when TUI is enabled to prevent
        log output from corrupting the TUI display.
        """
        log_file = self.output_dir / "benchmark.log"

        # Create file handler with detailed formatting
        file_handler = logging.FileHandler(log_file, mode="a")
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(
            logging.Formatter(
                "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S",
            )
        )

        root_logger = logging.getLogger()

        # When TUI is enabled, remove all console handlers to prevent
        # log output from interfering with the TUI display
        if self.fuzzing_config.enable_tui:
            handlers_to_remove = [
                h
                for h in root_logger.handlers
                if isinstance(h, logging.StreamHandler)
                and not isinstance(h, logging.FileHandler)
            ]
            for handler in handlers_to_remove:
                root_logger.removeHandler(handler)

        # Add file handler - child loggers propagate up to root
        root_logger.addHandler(file_handler)

        LOG.info(f"=== Benchmark started, logging to {log_file} ===")

    @classmethod
    def return_kind(cls) -> List[str]:
        return [cls.BENCHMARK_NAME]

    def _determine_test_cases(self, config: BenchmarkConfig) -> List[int]:
        """Determine which test cases to run based on config.

        Priority:
        1. If prompt_path is provided, use it (user explicitly specified which cases to run)
        2. Otherwise, if response_path exists, use it (resuming a previous run)
        """
        if config.prompt_path:
            # Prompt path takes priority - user explicitly specified which cases to run
            return self._get_test_cases_from_prompt(
                config.num_test_cases, Path(config.prompt_path)
            )
        elif config.response_path.exists():
            # Fall back to existing responses (for resuming without prompt path)
            return self._get_test_cases_from_responses(config.response_path)
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
        # Use the fuzzing template which skips QA fuzzing during build
        # and allows runtime configuration of fuzzing duration
        ArvoContainer.use_fuzzing_template()
        LOG.info("Using dockerfile_fuzzing_template for container builds")

        return ArvoContainer.build_container_images(
            test_cases, max_concurrency, logging.INFO
        )

    # =========================================================================
    # Response Caching
    # =========================================================================

    def _get_case_dir(self, case_id: int, model: str) -> Path:
        """Get output directory for a specific case and model.

        Directory structure:
        /files/case_XXX/ground_truth/  - GT fuzzing results
        /files/case_XXX/model_name/    - Model-specific fuzzing results
        """
        case_dir = self.files_dir / f"case_{case_id}" / model
        case_dir.mkdir(parents=True, exist_ok=True)
        return case_dir

    def _get_target_dir(
        self, case_id: int, target: FuzzingTarget, model: str = "ground_truth"
    ) -> Path:
        """Get output directory for a specific fuzzing target.

        Args:
            case_id: Case number
            target: GROUND_TRUTH or LLM_PATCH
            model: Model name (used when target is LLM_PATCH)

        Returns:
            Path to target directory:
            - /files/case_XXX/ground_truth/ for GT
            - /files/case_XXX/model_name/ for LLM patches
        """
        if target == FuzzingTarget.GROUND_TRUTH:
            target_dir = self.files_dir / f"case_{case_id}" / "ground_truth"
        else:
            target_dir = self.files_dir / f"case_{case_id}" / model
        target_dir.mkdir(parents=True, exist_ok=True)
        return target_dir

    def _is_gt_results_cached(self, case_id: int) -> bool:
        """Check if ground truth fuzzing results already exist for this case.

        GT results are stored in /files/case_XXX/ground_truth/crashes.json
        and are shared across all models for the same case.
        """
        gt_dir = self._get_target_dir(case_id, FuzzingTarget.GROUND_TRUTH)
        crashes_file = gt_dir / "crashes.json"
        return crashes_file.exists()

    def _load_cached_gt_timeline(self, case_id: int) -> Optional[CrashTimeline]:
        """Load cached ground truth timeline from the ground_truth directory.

        Returns:
            CrashTimeline if cached results exist, None otherwise
        """
        gt_dir = self._get_target_dir(case_id, FuzzingTarget.GROUND_TRUTH)
        crashes_file = gt_dir / "crashes.json"

        if not crashes_file.exists():
            return None

        try:
            crashes_data = json.loads(crashes_file.read_text())
            timeline = CrashTimeline.from_minimal_dict(crashes_data)
            LOG.info(f"Case {case_id}: Loaded cached GT results with {len(timeline.crashes)} crashes")
            return timeline
        except Exception as e:
            LOG.warning(f"Case {case_id}: Failed to load cached GT results: {e}")
            return None

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
                LOG.info(
                    f"Copied {sum(1 for _ in source_files.iterdir())} case directories"
                )

    def _get_log_filepath(self, case_id: int, prefix: str, model: str) -> Path:
        """Get log file path for a case."""
        return self._get_case_dir(case_id, model) / f"log_{prefix}.txt"

    def _write_to_response_json(
        self,
        binary_filepath: Path,
        case_id: int,
        containers_pass_qa_checks: bool,
        exception_message: Optional[str],
        llm_under_test: LLM,
        overwrite: bool,
        patch_filepath: Path,
        patch_success: bool,
        patched_function_name: Optional[str],
    ) -> None:
        """Write response entry to the responses.json file."""
        new_response = {
            self.RESPONSES_ARVO_CHALLENGE_NUMBER_KEY: case_id,
            self.RESPONSES_MODEL_KEY: llm_under_test.model,
            self.RESPONSES_GENERATED_PATCH_KEY: str(patch_filepath)
            if patch_filepath.exists()
            else None,
            self.RESPONSES_REBUILT_BINARY_KEY: str(binary_filepath)
            if binary_filepath.exists()
            else None,
            self.RESPONSES_PATCHED_FUNCTION_KEY: patched_function_name,
            self.RESPONSES_PATCH_SUCCESS_KEY: patch_success,
            self.RESPONSES_CONTAINERS_PASS_QA_CHECKS_KEY: containers_pass_qa_checks,
        }
        if exception_message:
            new_response["exception"] = exception_message

        with self.RESPONSE_FILE_LOCK:
            responses = self._read_responses()

            if overwrite:
                # Remove existing entry for this case/model
                responses = [
                    r
                    for r in responses
                    if not (
                        r.get(self.RESPONSES_ARVO_CHALLENGE_NUMBER_KEY) == case_id
                        and r.get(self.RESPONSES_MODEL_KEY) == llm_under_test.model
                    )
                ]

            responses.append(new_response)
            self.response_path.write_text(json.dumps(responses, indent=2))

    async def _gen_patch_and_binary(
        self,
        case_id: int,
        llm_under_test: LLM,
        overwrite: bool = False,
    ) -> None:
        """Generate patch and binary using the AutoPatch agent."""
        # Create a directory for storing patch and binary files
        out_dir = self._get_case_dir(case_id, llm_under_test.model)
        patch_filepath = out_dir / "patch.patch"
        binary_filepath = out_dir / "binary.bin"
        report_filepath = out_dir / "report.json"
        chat_filepath = out_dir / "chat.md"

        if overwrite:
            for file in out_dir.glob("*"):
                if file.is_dir():
                    shutil.rmtree(file)
                else:
                    file.unlink()

        # Spin up the vul container for the autopatch agent
        vul_container = ArvoContainer(
            case_id,
            container_type=ArvoContainer.CONTAINER_TYPE_VUL,
            model_under_test=llm_under_test.model,
            log_level=logging.INFO,
            log_filepath=self._get_log_filepath(case_id, "vul", llm_under_test.model),
            artifacts_dir=out_dir,
        )
        await vul_container.start_container()

        containers_pass_qa_checks = True

        # Spin up the fix container for the autopatch agent
        fix_container = ArvoContainer(
            case_id,
            container_type=ArvoContainer.CONTAINER_TYPE_FIX,
            model_under_test=llm_under_test.model,
            log_level=logging.INFO,
            log_filepath=self._get_log_filepath(case_id, "fix", llm_under_test.model),
            artifacts_dir=out_dir,
        )
        await fix_container.start_container()

        # QA checks of vul and fix containers (use original flags, not debug flags)
        containers_pass_qa_checks = (
            await vul_container.qa_checks(use_debug_flags=False)
        ) and (await fix_container.qa_checks(use_debug_flags=False))

        patch_success = False
        patched_function_name = None
        exception_message = None

        if containers_pass_qa_checks:
            report = PatchGenerationReport()
            try:
                agent = AutoPatchAgent(
                    vul_container,
                    llm_under_test,
                    patch_filepath,
                    binary_filepath,
                    use_debug_flags=False,  # Use original flags for continuous fuzzing
                )
                LOG.info(f"Starting patch generation agent for case #{case_id}")
                report = await asyncio.wait_for(
                    agent.generate_and_persist_patch_and_binary(),
                    timeout=self.PER_SAMPLE_PATCH_GENERATION_TIMEOUT,
                )
                patch_success = report.max_patch_generation_status.is_success()
                patched_function_name = report.patched_function_name

            except asyncio.TimeoutError:
                exception_message = f"Patch generation timed out after {self.PER_SAMPLE_PATCH_GENERATION_TIMEOUT} seconds"
                LOG.error(exception_message)
                report.exception += "\n" + exception_message
            except Exception as e:
                LOG.error(f"Error during patch generation: {e}")
                exception_message = str(e)
                report.exception += "\n" + exception_message

            # Write reports
            with open(report_filepath, "wt") as f:
                f.write(report.to_json())
            write_chat_history_markdown(
                [ChatHistory.from_report(report)], chat_filepath.as_posix()
            )

        # Write response entry
        self._write_to_response_json(
            binary_filepath=binary_filepath,
            case_id=case_id,
            containers_pass_qa_checks=containers_pass_qa_checks,
            exception_message=exception_message,
            llm_under_test=llm_under_test,
            overwrite=overwrite,
            patch_filepath=patch_filepath,
            patch_success=patch_success,
            patched_function_name=patched_function_name,
        )

        LOG.info(f"Case {case_id}: Patch generation complete. Success: {patch_success}")

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

    def _load_fuzzer_type_from_metadata(self, case_id: int) -> Optional[FuzzerType]:
        """Load fuzzer type from dataset metadata file.

        The metadata files are at datasets/autopatch/arvo_meta/{case_id}-meta.json
        and contain a "fuzzer" field with value "afl" or "libfuzzer".

        Args:
            case_id: The ARVO case ID

        Returns:
            FuzzerType if metadata exists and has fuzzer info, None otherwise
        """
        # Try to find the metadata file
        meta_paths = [
            Path(__file__).parent.parent
            / "datasets"
            / "autopatch"
            / "arvo_meta"
            / f"{case_id}-meta.json",
            Path("datasets/autopatch/arvo_meta") / f"{case_id}-meta.json",
        ]

        for meta_path in meta_paths:
            if meta_path.exists():
                try:
                    meta_data = json.loads(meta_path.read_text())
                    fuzzer = (
                        meta_data.get("arvo_metadata", {}).get("fuzzer", "").lower()
                    )
                    if fuzzer == "afl":
                        LOG.info(
                            f"Case {case_id}: Loaded fuzzer type from metadata: AFL++"
                        )
                        return FuzzerType.AFL_PLUS_PLUS
                    elif fuzzer == "libfuzzer":
                        LOG.info(
                            f"Case {case_id}: Loaded fuzzer type from metadata: libFuzzer"
                        )
                        return FuzzerType.LIBFUZZER
                except Exception as e:
                    LOG.debug(f"Error loading metadata for case {case_id}: {e}")

        return None

    async def _detect_fuzzer_type(
        self,
        container: ArvoContainer,
        case_id: int = 0,
        binary_path: str = "",
    ) -> FuzzerType:
        """Detect whether the binary is built for libFuzzer or AFL++.

        Detection priority:
        1. Load from dataset metadata (most reliable)
        2. Run the binary and check output for AFL++ signature
        3. Default to libFuzzer

        Args:
            container: The container to test in
            case_id: The ARVO case ID (used to load metadata)
            binary_path: Path to the fuzzer binary (can contain wildcards)

        Returns:
            FuzzerType.AFL_PLUS_PLUS if AFL++ detected, FuzzerType.LIBFUZZER otherwise
        """
        # First, try to load from metadata (most reliable)
        if case_id > 0:
            metadata_type = self._load_fuzzer_type_from_metadata(case_id)
            if metadata_type is not None:
                return metadata_type

        # Try to run the binary to check its output
        # AFL++ binaries print "This binary is built for afl++" when run without proper setup
        try:
            # Get binary path from /bin/arvo if not provided
            if not binary_path:
                result = await container.exec_command(
                    cmd_args=[
                        "sh",
                        "-c",
                        "grep -A1 '\"run\" ]; then' /bin/arvo | tail -1 | awk '{print $1}'",
                    ],
                    timeout=10,
                )
                binary_path = result.stdout.decode().strip() if result.stdout else ""
                if binary_path and binary_path.startswith("/"):
                    LOG.info(f"Resolved binary path from arvo: {binary_path}")
                else:
                    # Fallback: find any executable in /out/
                    result = await container.exec_command(
                        cmd_args=[
                            "sh",
                            "-c",
                            "find /out/ -maxdepth 1 -type f -executable | head -1",
                        ],
                        timeout=10,
                    )
                    binary_path = (
                        result.stdout.decode().strip() if result.stdout else ""
                    )
                    if binary_path:
                        LOG.info(f"Resolved binary path via find: {binary_path}")
                    else:
                        LOG.warning("No binary found in container")
                        return FuzzerType.UNKNOWN

            LOG.info(f"Detecting fuzzer type by running binary at {binary_path}")

            # Run the binary briefly to see its output
            # Use shell to capture both stdout and stderr properly
            result = await container.exec_command(
                cmd_args=["sh", "-c", f"timeout 2 {binary_path} 2>&1 || true"],
                timeout=15,
            )

            output = result.stdout.decode(errors="replace") if result.stdout else ""
            LOG.debug(f"Binary output for detection: {output[:500]}")

            # Check for AFL++ signature (case insensitive)
            output_lower = output.lower()
            if "built for afl" in output_lower or "afl-fuzz" in output_lower:
                LOG.info(f"Detected AFL++ binary at {binary_path}")
                return FuzzerType.AFL_PLUS_PLUS

            # Check for libFuzzer signature (runs immediately or shows usage)
            if "libfuzzer" in output_lower or "BINGO" in output or "INFO:" in output:
                LOG.info(f"Detected libFuzzer binary at {binary_path}")
                return FuzzerType.LIBFUZZER

            # Also check stderr separately as a fallback
            if result.stderr:
                stderr = result.stderr.decode(errors="replace")
                stderr_lower = stderr.lower()
                LOG.debug(f"Binary stderr for detection: {stderr[:500]}")
                if "built for afl" in stderr_lower or "afl-fuzz" in stderr_lower:
                    LOG.info(f"Detected AFL++ binary at {binary_path} (from stderr)")
                    return FuzzerType.AFL_PLUS_PLUS

            # Default to libFuzzer if no clear signature
            LOG.info(
                f"No clear fuzzer signature detected in output, defaulting to libFuzzer"
            )
            return FuzzerType.LIBFUZZER

        except Exception as e:
            LOG.warning(f"Error detecting fuzzer type: {e}, defaulting to libFuzzer")
            return FuzzerType.LIBFUZZER

    async def _set_fuzzer_continuous_mode(
        self,
        container: ArvoContainer,
        target: FuzzingTarget = FuzzingTarget.GROUND_TRUTH,
        fuzzer_type: FuzzerType = FuzzerType.LIBFUZZER,
        run_id: str = "",
    ) -> None:
        """Configure fuzzer for continuous mode with custom duration.

        This method reads the /bin/arvo script and properly configures it for fuzzing.

        For libFuzzer:
        1. Sets FUZZER_ARGS with duration, fork mode, and ignore flags
        2. Replaces /tmp/poc with /tmp/corpus/ (all occurrences)
        3. Adds $FUZZER_ARGS to the fuzzer command if not present

        For AFL++:
        1. Sets up AFL_* environment variables for continuous mode
        2. Creates /tmp/afl_output directory for AFL++ output
        3. Replaces the fuzzer command with afl-fuzz invocation

        Args:
            container: The ArvoContainer to configure
            target: The fuzzing target (GT or LLM)
            fuzzer_type: The type of fuzzer (libFuzzer or AFL++)
            run_id: Unique identifier for this fuzzing run
        """
        duration_secs = self.fuzzing_config.fuzzing_duration_minutes * 60
        LOG.info(
            f"Configuring {fuzzer_type.value} fuzzer for {target.value} to run for {duration_secs} seconds"
        )

        # Read the current arvo script
        try:
            arvo_content = (await container.get_content("/bin/arvo")).decode()
        except Exception as e:
            LOG.error(f"Failed to read /bin/arvo: {e}")
            raise RuntimeError(
                f"Cannot configure fuzzer: failed to read /bin/arvo: {e}"
            )

        if fuzzer_type == FuzzerType.AFL_PLUS_PLUS:
            # AFL++ runs as single process (parallel mode not yet implemented)
            LOG.info(
                f"Configuring AFL++ (single process - fork_jobs={self.fuzzing_config.fork_jobs} not applicable)"
            )
            new_content = await self._configure_afl_plus_plus(
                container, arvo_content, target, duration_secs
            )
        else:
            # libFuzzer uses -fork=N for parallel workers
            LOG.info(
                f"Configuring libFuzzer with {self.fuzzing_config.fork_jobs} parallel workers (-fork={self.fuzzing_config.fork_jobs})"
            )
            new_content = self._configure_libfuzzer(
                arvo_content, duration_secs, target, run_id
            )
            # Create run and target-specific crash directory for libFuzzer crash artifacts
            crash_dir = f"/tmp/crashes_{run_id}_{target.value}/"
            await container.exec_command(cmd_args=["mkdir", "-p", crash_dir])
            LOG.info(f"Created {crash_dir} directory for crash artifacts")

        # Write the modified script back
        import tempfile
        import os

        with tempfile.NamedTemporaryFile(mode="w", delete=False) as f:
            f.write(new_content)
            temp_path = f.name

        await container.copy_to_container(temp_path, "/bin/arvo")
        os.unlink(temp_path)

        # Make sure /bin/arvo is executable
        await container.exec_command(cmd_args=["chmod", "+x", "/bin/arvo"])

        # Verify and log the final configuration
        verify_content = (await container.get_content("/bin/arvo")).decode()
        LOG.info("=== Modified /bin/arvo (relevant lines) ===")
        for line in verify_content.split("\n"):
            if any(
                x in line for x in ["FUZZER_ARGS", "/out/", "fuzz", "afl-fuzz", "AFL_"]
            ):
                LOG.info(f"  {line.strip()}")

    def _configure_libfuzzer(
        self,
        arvo_content: str,
        duration_secs: int,
        target: FuzzingTarget,
        run_id: str = "",
    ) -> str:
        """Configure arvo script for libFuzzer continuous mode.

        Args:
            arvo_content: Current content of /bin/arvo
            duration_secs: Total fuzzing duration in seconds
            target: Fuzzing target (GT or LLM) - determines crash directory
            run_id: Unique identifier for this fuzzing run

        Returns:
            Modified arvo script content
        """
        # Use run and target-specific crash directory to avoid pollution between runs
        crash_dir = f"/tmp/crashes_{run_id}_{target.value}/"

        # Build FUZZER_ARGS - always include fork and ignore flags for continuous mode
        new_args = [
            "-rss_limit_mb=2560",
            "-timeout=25",
            f"-max_total_time={duration_secs}",
        ]

        # Always add ignore flags for continuous fuzzing
        if self.fuzzing_config.ignore_crashes:
            new_args.append("-ignore_crashes=1")
            new_args.append("-ignore_ooms=1")
            new_args.append("-ignore_timeouts=1")

        # Always add fork mode for crash-resistant continuous fuzzing
        # -ignore_crashes only works in fork mode, so always enable it
        if self.fuzzing_config.fork_jobs >= 1:
            new_args.append(f"-fork={self.fuzzing_config.fork_jobs}")

        # Save crash files to target-specific directory for CASR deduplication
        new_args.append(f"-artifact_prefix={crash_dir}")

        new_args.append("-print_final_stats=1")

        new_fuzzer_args = " ".join(new_args)
        new_fuzzer_args_line = f'export FUZZER_ARGS="{new_fuzzer_args}"'

        # Step 1: Replace/insert FUZZER_ARGS line
        pattern = r"^export FUZZER_ARGS=.*$"
        if re.search(pattern, arvo_content, re.MULTILINE):
            new_content = re.sub(
                pattern, new_fuzzer_args_line, arvo_content, flags=re.MULTILINE
            )
            LOG.info(f"Replaced FUZZER_ARGS with: {new_fuzzer_args}")
        else:
            if arvo_content.startswith("#!/"):
                first_newline = arvo_content.find("\n")
                new_content = (
                    arvo_content[: first_newline + 1]
                    + new_fuzzer_args_line
                    + "\n"
                    + arvo_content[first_newline + 1 :]
                )
            else:
                new_content = new_fuzzer_args_line + "\n" + arvo_content
            LOG.info(f"Inserted FUZZER_ARGS: {new_fuzzer_args}")

        # Step 2: Replace ALL /tmp/poc with /tmp/corpus/ (not just first occurrence)
        new_content = new_content.replace("/tmp/poc", "/tmp/corpus/")
        LOG.info("Replaced all /tmp/poc with /tmp/corpus/")

        # Step 3: Ensure $FUZZER_ARGS is added to the fuzzer command lines
        # Match patterns like: /out/BINARY /tmp/corpus/ (handles both *_fuzzer and fuzz_* naming)
        # And add $FUZZER_ARGS if not present
        fuzzer_pattern = r"(/out/[\w-]+\s+/tmp/corpus/)(?!\s*\$FUZZER_ARGS)"
        if re.search(fuzzer_pattern, new_content):
            new_content = re.sub(fuzzer_pattern, r"\1 $FUZZER_ARGS", new_content)
            LOG.info("Added $FUZZER_ARGS to fuzzer command(s)")

        return new_content

    async def _configure_afl_plus_plus(
        self,
        container: ArvoContainer,
        arvo_content: str,
        target: FuzzingTarget,
        duration_secs: int,
    ) -> str:
        """Configure arvo script for AFL++ continuous mode.

        AFL++ requires wrapping the binary invocation with afl-fuzz.
        We modify the existing arvo script to:
        1. Add AFL++ environment variables
        2. Create output directory
        3. Wrap binary calls with afl-fuzz for 'run' and 'fuzz_fix' commands

        Args:
            container: The ArvoContainer to configure
            arvo_content: Current content of /bin/arvo
            target: The fuzzing target (GT or LLM)
            duration_secs: Total fuzzing duration in seconds

        Returns:
            Modified arvo script content
        """
        # Create AFL++ output directory
        await container.exec_command(
            cmd_args=["mkdir", "-p", "/tmp/afl_output"],
            timeout=10,
        )

        # Get AFL++ environment variables
        afl_env = self.fuzzing_config.get_afl_environment_vars()

        # Build the environment export lines
        env_exports = []
        for key, value in afl_env.items():
            env_exports.append(f'export {key}="{value}"')
        env_exports_str = "\n".join(env_exports)

        # Get ASAN_OPTIONS fix (AFL++ requires abort_on_error=1)
        asan_fix = self.fuzzing_config.get_afl_asan_options_fix()

        # Build afl-fuzz command arguments (without the binary - that comes from original script)
        afl_args = (
            f"-V {duration_secs} -t 25000 -m none -i /tmp/corpus -o /tmp/afl_output"
        )

        # Extract the fuzzer binary path from the arvo script
        # Use the same pattern as arvo_utils.get_binary_filepath(): look for "<path> /tmp/poc"
        fuzzer_match = re.search(r"(\S+)\s+/tmp/poc", arvo_content)
        if fuzzer_match:
            fuzzer_binary = fuzzer_match.group(1)
            LOG.info(f"Extracted fuzzer binary path from arvo script: {fuzzer_binary}")
        else:
            # Fallback: try to find any binary path in /out/
            fuzzer_match = re.search(r"(/out/[\w-]+)", arvo_content)
            if fuzzer_match:
                fuzzer_binary = fuzzer_match.group(1)
                LOG.info(f"Found fuzzer binary via fallback pattern: {fuzzer_binary}")
            else:
                fuzzer_binary = ""
                LOG.warning("Could not find fuzzer binary path in arvo script")

        # Start with the original script content
        new_content = arvo_content

        # Add AFL++ environment variables after the shebang
        afl_setup = (
            "\n# AFL++ environment variables for continuous fuzzing\n"
            + env_exports_str
            + "\n"
            + asan_fix
            + "\n"
            + "mkdir -p /tmp/afl_output\n\n"
        )

        if new_content.startswith("#!/"):
            first_newline = new_content.find("\n")
            new_content = (
                new_content[: first_newline + 1]
                + afl_setup
                + new_content[first_newline + 1 :]
            )
        else:
            new_content = afl_setup + new_content

        # Replace /tmp/poc with /tmp/corpus/ for corpus-based fuzzing
        new_content = new_content.replace("/tmp/poc", "/tmp/corpus/")

        # For AFL++ binaries, we need to wrap the fuzzer invocation with afl-fuzz
        # The original script likely has lines like: /path/to/binary /tmp/corpus/
        # We need to change them to: afl-fuzz [args] -- /path/to/binary

        # Build the afl-fuzz command with sanitizer options fixes
        # AFL++ requires specific sanitizer settings:
        # - ASAN_OPTIONS: abort_on_error=1 and symbolize=0
        # - MSAN_OPTIONS: exit_code=86 and symbolize=0
        # We preserve other options but override/add the required ones
        sanitizer_fix = (
            # Fix ASAN_OPTIONS
            'ASAN_OPTS_CLEAN=$(echo "$ASAN_OPTIONS" | sed "s/abort_on_error=[01]://g" | sed "s/symbolize=[01]://g"); '
            'export ASAN_OPTIONS="abort_on_error=1:symbolize=0:$ASAN_OPTS_CLEAN"; '
            # Fix MSAN_OPTIONS
            'MSAN_OPTS_CLEAN=$(echo "$MSAN_OPTIONS" | sed "s/exit_code=[0-9]*://g" | sed "s/symbolize=[01]://g"); '
            'export MSAN_OPTIONS="exit_code=86:symbolize=0:$MSAN_OPTS_CLEAN"'
        )
        afl_cmd_prefix = f"{sanitizer_fix}; afl-fuzz"

        if fuzzer_binary:
            # Replace direct binary invocation with afl-fuzz wrapper
            # Match patterns like: /path/to/binary /tmp/corpus/ [optional args]
            # But be careful not to match lines that already have afl-fuzz

            # Pattern for GT binary invocation (not in fuzz_fix block)
            gt_pattern = re.escape(fuzzer_binary) + r"\s+/tmp/corpus/[^\n]*"

            def replace_with_afl(match):
                original = match.group(0)
                if "afl-fuzz" in original:
                    return original  # Already wrapped
                return f"{afl_cmd_prefix} {afl_args} -- {fuzzer_binary}"

            new_content = re.sub(gt_pattern, replace_with_afl, new_content)

            # Also handle /tmp/rebuilt_binary for fuzz_fix
            rebuilt_pattern = r"/tmp/rebuilt_binary\s+/tmp/corpus/[^\n]*"
            new_content = re.sub(
                rebuilt_pattern,
                f"{afl_cmd_prefix} {afl_args} -- /tmp/rebuilt_binary",
                new_content,
            )

        LOG.info(f"Modified arvo script for AFL++ with time limit {duration_secs}s")
        return new_content

    async def _get_crash_files(
        self,
        container: ArvoContainer,
        fuzzer_type: FuzzerType = FuzzerType.LIBFUZZER,
        target: FuzzingTarget = FuzzingTarget.GROUND_TRUTH,
        run_id: str = "",
    ) -> List[str]:
        """Get list of crash files from fuzzer output.

        Args:
            container: The container to search for crashes
            fuzzer_type: The type of fuzzer used
            target: Fuzzing target (determines crash directory)
            run_id: Unique identifier for this fuzzing run

        Returns:
            List of crash file names
        """
        if fuzzer_type == FuzzerType.AFL_PLUS_PLUS:
            return await self._get_afl_crash_files(container)
        else:
            return await self._get_libfuzzer_crash_files(container, target, run_id)

    async def _get_libfuzzer_crash_files(
        self, container: ArvoContainer, target: FuzzingTarget, run_id: str = ""
    ) -> List[str]:
        """Get crash files from libFuzzer output in run and target-specific directory.

        Args:
            container: The container to search for crashes
            target: Fuzzing target (GT or LLM) - determines crash directory
            run_id: Unique identifier for this fuzzing run

        Returns:
            List of crash file names (limited to first 10000 to avoid timeout with crash storms)
        """
        crash_dir = f"/tmp/crashes_{run_id}_{target.value}/"

        # Use find instead of ls for better performance with large directories
        # Limit to 10000 crashes to avoid timeouts (CASR doesn't need millions of duplicates)
        # NOTE: Must wrap command in double quotes so sh -c treats it as one argument
        find_cmd = f"find \"{crash_dir}\" -maxdepth 1 -type f \\( -name 'crash-*' -o -name 'oom-*' -o -name 'timeout-*' \\) -printf '%f\\n' | head -10000"
        result = await container.exec_command(
            cmd_args=["sh", "-c", f'"{find_cmd}"'], timeout=30
        )

        if result.returncode != 0:
            return []

        crashes = []
        stdout = result.stdout.decode() if result.stdout else ""
        for line in stdout.strip().split("\n"):
            if line:
                crashes.append(line)

        if len(crashes) >= 10000:
            LOG.warning(
                f"Crash limit reached (10000+). This suggests a crash storm - "
                f"the bug may trigger very frequently. CASR will deduplicate these."
            )

        return crashes

    async def _get_afl_crash_files(self, container: ArvoContainer) -> List[str]:
        """Get crash files from AFL++ output directory.

        AFL++ stores crashes in /tmp/afl_output/default/crashes/
        The crash files are named with id: prefix, e.g., id:000000,sig:11,src:...
        """
        # Check both the default location and possible alternative
        crash_dirs = [
            "/tmp/afl_output/default/crashes",
            "/tmp/afl_output/crashes",  # Alternative if no fuzzer name
        ]

        crashes = []
        for crash_dir in crash_dirs:
            result = await container.exec_command(
                cmd_args=["ls", "-1", crash_dir], timeout=10
            )
            if result.returncode == 0:
                stdout = result.stdout.decode() if result.stdout else ""
                for line in stdout.strip().split("\n"):
                    line = line.strip()
                    # AFL++ crash files start with "id:" and don't include README
                    if line and line.startswith("id:") and "README" not in line:
                        crashes.append(line)
                if crashes:
                    LOG.info(f"Found {len(crashes)} AFL++ crashes in {crash_dir}")
                    break

        return crashes

    async def _get_execution_count(
        self,
        container: ArvoContainer,
        fuzzer_type: FuzzerType = FuzzerType.LIBFUZZER,
    ) -> int:
        """Get current execution count from fuzzer.

        Args:
            container: The container running the fuzzer
            fuzzer_type: The type of fuzzer used

        Returns:
            Number of executions, or 0 if unable to determine
        """
        if fuzzer_type == FuzzerType.AFL_PLUS_PLUS:
            return await self._get_afl_execution_count(container)
        else:
            # For libFuzzer, we parse from the output stream
            # This is a simplified version - return 0 as placeholder
            return 0

    async def _get_afl_execution_count(self, container: ArvoContainer) -> int:
        """Get execution count from AFL++ fuzzer_stats file.

        AFL++ writes stats to /tmp/afl_output/default/fuzzer_stats
        """
        stats_paths = [
            "/tmp/afl_output/default/fuzzer_stats",
            "/tmp/afl_output/fuzzer_stats",
        ]

        for stats_path in stats_paths:
            result = await container.exec_command(
                cmd_args=["cat", stats_path], timeout=10
            )
            if result.returncode == 0:
                stdout = result.stdout.decode() if result.stdout else ""
                # Parse "execs_done" from stats file
                for line in stdout.split("\n"):
                    if line.startswith("execs_done"):
                        try:
                            # Format: "execs_done        : 123456"
                            parts = line.split(":")
                            if len(parts) >= 2:
                                return int(parts[1].strip())
                        except ValueError:
                            pass
        return 0

    async def _run_casr_in_container(
        self,
        container: ArvoContainer,
        fuzzer_type: FuzzerType,
        crash_files: List[str],
        case_id: int,
        target: FuzzingTarget,
        run_id: str = "",
    ) -> Dict[str, str]:
        """Run CASR-based crash deduplication in the container.

        CASR (Crash Analysis and Severity Reporting) analyzes crashes and groups them
        into clusters based on stack traces and crash characteristics.

        Note: OOM and timeout crashes are handled separately since they don't produce
        stack traces that CASR can analyze. They are assigned to special pseudo-clusters.

        Args:
            container: The container with the fuzzer and crashes
            fuzzer_type: Type of fuzzer used (affects crash file location)
            crash_files: List of crash filenames
            case_id: Case ID for logging
            target: Whether this is GT or LLM patch
            run_id: Unique identifier for this fuzzing run

        Returns:
            Dict mapping crash filename to cluster ID
        """
        crash_to_cluster: Dict[str, str] = {}

        if not crash_files:
            LOG.info(f"Case {case_id}: No crashes to deduplicate")
            return crash_to_cluster

        # Count crash types for logging
        oom_count = sum(1 for f in crash_files if f.startswith("oom-"))
        timeout_count = sum(1 for f in crash_files if f.startswith("timeout-"))
        regular_count = len(crash_files) - oom_count - timeout_count

        LOG.info(
            f"Case {case_id}: Processing {len(crash_files)} crashes with CASR "
            f"({regular_count} regular, {oom_count} OOM, {timeout_count} timeout)"
        )
        
        # NOTE: CASR now handles ALL crash types including OOM and timeout
        # The casr-cluster-map tool creates pseudo-clusters for OOM/timeout
        # since they don't have stacktraces to cluster by

        # Determine paths based on fuzzer type and target
        if fuzzer_type == FuzzerType.AFL_PLUS_PLUS:
            crashes_dir = "/tmp/afl_output/default/crashes"
            casr_tool = "casr-afl"
        else:
            # Use run and target-specific crash directory
            crashes_dir = f"/tmp/crashes_{run_id}_{target.value}"
            casr_tool = "casr-libfuzzer"

        # Create CASR output directory (run and target-specific)
        casr_output_dir = f"/tmp/casr_reports_{run_id}_{target.value}"
        await container.exec_command(
            cmd_args=["mkdir", "-p", casr_output_dir],
            timeout=10,
        )

        # Find the fuzzer binary
        fuzzer_binary = await self._get_fuzzer_binary_path(container, target)
        if not fuzzer_binary:
            LOG.warning(f"Case {case_id}: Could not find fuzzer binary for CASR")
            return crash_to_cluster

        LOG.info(
            f"Case {case_id}: Running CASR clustering with casr-cluster-map on {len(crash_files)} crashes"
        )

        # Use casr-cluster-map Rust tool to preserve all crashes while clustering
        # This generates individual CASR reports and clusters them WITHOUT deduplication
        # Result: ALL crashes get cluster IDs, not just representative ones
        mapping_file = f"{casr_output_dir}/crash_mapping.json"

        # Build casr-cluster-map command
        cmd_args = [
            "casr-cluster-map",  # Rust binary installed in /usr/bin via symlink
            "-i",
            crashes_dir,
            "-o",
            casr_output_dir,
            "-t",
            "120",  # 120 second timeout per crash (ASAN is slow)
            "-j",
            "4",  # Limit parallel jobs to avoid overwhelming the system
            "--mapping",
            mapping_file,  # JSON mapping output file
        ]

        # For libFuzzer, use log-based clustering (no binary re-runs needed)
        # The modified libFuzzer saves crash logs to {crashes_dir}/logs/{crash_name}.log
        # In fork mode, the parent copies worker log content when crashes are detected
        if fuzzer_type != FuzzerType.AFL_PLUS_PLUS:
            cmd_args.append("--use-logs")
            LOG.info(
                f"Case {case_id}: Using log-based CASR clustering (no binary re-runs)"
            )

        # Add binary args (still required but not used in log mode for libFuzzer)
        cmd_args.extend(
            [
                "--",  # Separator before binary and args
                fuzzer_binary,
                "@@",  # Placeholder for crash input file
            ]
        )

        try:
            result = await container.exec_command(
                cmd_args=cmd_args,
                timeout=300,  # 5 minutes timeout for clustering
            )

            stdout = result.stdout.decode(errors="replace") if result.stdout else ""
            stderr = result.stderr.decode(errors="replace") if result.stderr else ""

            # Save CASR output to log file in target directory (GT or LLM)
            target_dir = self._get_target_dir(case_id, target, container.model_under_test)
            casr_log_file = target_dir / f"casr_output_{target.value}.log"
            with open(casr_log_file, "w") as f:
                f.write(f"=== CASR Clustering (casr-cluster-map) ===\n")
                f.write(f"Command: {' '.join(cmd_args)}\n")
                f.write(f"Return code: {result.returncode}\n\n")
                f.write("=== STDOUT ===\n")
                f.write(stdout)
                f.write("\n\n=== STDERR ===\n")
                f.write(stderr)
            LOG.info(f"Case {case_id}: CASR output saved to {casr_log_file}")

            if result.returncode != 0:
                LOG.warning(
                    f"Case {case_id}: CASR clustering returned non-zero exit code {result.returncode}"
                )

                # Case 1: Only 1 unique crash type - this is OK, CASR handles it
                # (CASR now creates pseudo-clusters for OOM/timeout automatically)
                if "Not enough valid reports" in stderr or "Less than 2" in stderr:
                    LOG.info(
                        f"Case {case_id}: CASR found only 1 unique stacktrace type"
                    )
                    # Don't fail - CASR will still produce a valid mapping with pseudo-clusters

                # Case 2: CASR couldn't reproduce crashes - preserve container for debugging
                elif (
                    "No reports generated" in stderr
                    or "Program terminated (no crash)" in stderr
                ):
                    error_msg = (
                        f"Case {case_id}: CASR failed to reproduce crashes!\n"
                        f"Container: {container.container_id}\n"
                        f"CASR log: {casr_log_file}\n"
                        f"CASR stderr: {stderr}\n"
                        f"Container preserved for debugging. Run:\n"
                        f"  podman exec -it {container.container_id} bash"
                    )
                    LOG.error(error_msg)
                    raise DebugContainerException(
                        message=error_msg,
                        container_id=container.container_id,
                        case_id=case_id,
                    )

                # Case 3: Unknown error - preserve container for debugging
                else:
                    error_msg = (
                        f"Case {case_id}: CASR failed with unknown error!\n"
                        f"Container: {container.container_id}\n"
                        f"CASR log: {casr_log_file}\n"
                        f"CASR stderr: {stderr}\n"
                        f"Container preserved for debugging. Run:\n"
                        f"  podman exec -it {container.container_id} bash"
                    )
                    LOG.error(error_msg)
                    raise DebugContainerException(
                        message=error_msg,
                        container_id=container.container_id,
                        case_id=case_id,
                    )

            # Parse JSON mapping file to get COMPLETE crash-to-cluster mapping
            # CASR now handles ALL crash types including OOM and timeout (as pseudo-clusters)
            crashes_mapped = any(
                crash_file in crash_to_cluster for crash_file in crash_files
            )
            if not crashes_mapped:
                parsed_mapping = await self._parse_casr_json_mapping(
                    container, mapping_file, case_id
                )
                if parsed_mapping:
                    crash_to_cluster.update(parsed_mapping)
                elif crash_files:
                    # No fallback - CASR must work reliably
                    error_msg = (
                        f"Case {case_id}: CASR failed to produce mapping for {len(crash_files)} crashes.\n"
                        f"Check casr_output_{target.value}.log for details.\n"
                        f"Container: {container.container_id}\n"
                        f"Container preserved for debugging. Run:\n"
                        f"  podman exec -it {container.container_id} bash"
                    )
                    LOG.error(error_msg)
                    raise DebugContainerException(
                        message=error_msg,
                        container_id=container.container_id,
                        case_id=case_id,
                    )

            # Copy CASR reports from container to host for analysis
            # This includes all .casrep files (JSON reports with stack traces, severity, etc.)
            await self._copy_casr_reports_to_host(
                container, casr_output_dir, case_id, target
            )

        except DebugContainerException:
            # Propagate debug container exceptions without extra logging
            raise
        except Exception as e:
            LOG.error(f"Case {case_id}: Error running CASR: {e}")
            import traceback

            LOG.error(traceback.format_exc())
            raise  # Re-raise to fail the case properly

        return crash_to_cluster

    async def _copy_casr_reports_to_host(
        self,
        container: ArvoContainer,
        casr_output_dir: str,
        case_id: int,
        target: FuzzingTarget,
    ) -> None:
        """Copy CASR reports from container to host.

        CASR reports (.casrep files) contain detailed crash analysis:
        stack traces, registers, severity, crash address, etc.

        Directory structure:
        - /files/case_XXX/ground_truth/casr_reports/ for GT
        - /files/case_XXX/model_name/casr_reports/ for LLM patches

        Args:
            container: The container with CASR output
            casr_output_dir: Path to CASR output directory in container
            case_id: Case ID
            target: Whether this is GT or LLM patch
        """
        try:
            # Get the target directory on host (ground_truth or model_name)
            target_dir = self._get_target_dir(
                case_id, target, container.model_under_test
            )
            host_casr_dir = target_dir / "casr_reports"
            host_casr_dir.mkdir(parents=True, exist_ok=True)

            # Copy entire CASR output directory from container to host
            await container.copy_from_container(casr_output_dir, str(host_casr_dir))

            LOG.info(f"Case {case_id}: Copied CASR reports to {host_casr_dir}")

        except Exception as e:
            LOG.warning(f"Case {case_id}: Failed to copy CASR reports to host: {e}")

    async def _get_fuzzer_binary_path(
        self,
        container: ArvoContainer,
        target: FuzzingTarget,
    ) -> Optional[str]:
        """Get the fuzzer binary path from the container.

        Args:
            container: The container to search
            target: Whether this is GT or LLM patch

        Returns:
            Path to fuzzer binary, or None if not found
        """
        if target == FuzzingTarget.LLM_PATCH:
            # For LLM patch, check if /tmp/rebuilt_binary exists
            result = await container.exec_command(
                cmd_args=["test", "-f", "/tmp/rebuilt_binary"],
                timeout=5,
            )
            if result.returncode == 0:
                return "/tmp/rebuilt_binary"

        # For GT or if rebuilt_binary doesn't exist, extract from /bin/arvo
        # Read the arvo script and parse it in Python to avoid shell quoting issues
        try:
            arvo_content = (await container.get_content("/bin/arvo")).decode()
            # Look for the line after '"run" ]; then'
            import re

            match = re.search(r'"run" \]; then\s*\n\s*(\S+)', arvo_content)
            if match:
                binary = match.group(1)
                if binary.startswith("/"):
                    return binary
        except Exception as e:
            LOG.debug(f"Failed to parse /bin/arvo for fuzzer binary: {e}")

        # Fallback: list /out/ and find executable
        result = await container.exec_command(
            cmd_args=["ls", "-1", "/out/"],
            timeout=10,
        )
        if result.returncode == 0 and result.stdout:
            for line in result.stdout.decode().strip().split("\n"):
                # Check if it's likely a fuzzer binary (executable, not a dict/options file)
                if line and not line.endswith((".dict", ".options", ".zip", ".txt")):
                    # Verify it's executable
                    check_result = await container.exec_command(
                        cmd_args=["test", "-x", f"/out/{line}"],
                        timeout=5,
                    )
                    if check_result.returncode == 0:
                        return f"/out/{line}"

        return None

    async def _parse_casr_clusters(
        self,
        container: ArvoContainer,
        casr_output_dir: str,
        crash_files: List[str],
        case_id: int,
    ) -> Dict[str, str]:
        """Parse CASR output directory to map crashes to clusters.

        CASR organizes crashes into directories: cl1/, cl2/, ..., clN/
        Each directory contains the crash files belonging to that cluster.

        Args:
            container: The container with CASR output
            casr_output_dir: Path to CASR output directory
            crash_files: List of original crash filenames
            case_id: Case ID for logging

        Returns:
            Dict mapping crash filename to cluster ID
        """
        crash_to_cluster: Dict[str, str] = {}

        try:
            # List cluster directories (cl1, cl2, ...)
            # Use find instead of ls with glob to avoid shell expansion issues
            result = await container.exec_command(
                cmd_args=[
                    "find",
                    casr_output_dir,
                    "-maxdepth",
                    "1",
                    "-type",
                    "d",
                    "-name",
                    "cl*",
                ],
                timeout=10,
            )

            if not result.stdout or result.returncode != 0:
                LOG.info(f"Case {case_id}: No cluster directories found in CASR output")
                return crash_to_cluster

            raw_stdout = result.stdout.decode().strip()
            cluster_dirs = raw_stdout.split("\n")
            cluster_dirs = [d for d in cluster_dirs if d and "cl" in d]
            LOG.info(f"Case {case_id}: Found {len(cluster_dirs)} cluster directories")

            # For each cluster directory, list ALL crash files
            for cluster_dir in cluster_dirs:
                cluster_name = cluster_dir.split("/")[-1]  # Extract "cl1", "cl2", etc.

                # List all files in cluster directory
                result = await container.exec_command(
                    cmd_args=["ls", "-1", cluster_dir],
                    timeout=10,
                )

                if result.returncode == 0 and result.stdout:
                    files = result.stdout.decode().strip().split("\n")
                    crash_count = 0
                    for filename in files:
                        if not filename:
                            continue
                        # Skip .casrep files - we only want the actual crash inputs
                        if filename.endswith(".casrep"):
                            continue
                        # Map crash file to cluster
                        crash_to_cluster[filename] = cluster_name
                        crash_count += 1
                    LOG.info(
                        f"Case {case_id}: Cluster {cluster_name} contains {crash_count} crash files"
                    )

            LOG.info(
                f"Case {case_id}: Mapped {len(crash_to_cluster)} crashes to {len(cluster_dirs)} clusters"
            )

        except Exception as e:
            LOG.error(f"Case {case_id}: Error parsing CASR clusters: {e}")
            import traceback

            LOG.debug(traceback.format_exc())

        return crash_to_cluster

    async def _parse_casr_json_mapping(
        self,
        container: ArvoContainer,
        mapping_file: str,
        case_id: int,
    ) -> Dict[str, str]:
        """Parse JSON mapping file from casr-cluster-map tool.

        The casr-cluster-map Rust tool generates a JSON file with complete crash-to-cluster mapping,
        preserving ALL crashes (not just representatives like casr-libfuzzer does).

        Args:
            container: The container with CASR output
            mapping_file: Path to crash_mapping.json file in container
            case_id: Case ID for logging

        Returns:
            Dict mapping crash filename to cluster ID (e.g., "crash-abc123" -> "cl1")
        """
        crash_to_cluster: Dict[str, str] = {}

        try:
            # Read the JSON mapping file from container
            # Use longer timeout and retry since system can be under heavy load
            result = None
            for attempt in range(3):
                result = await container.exec_command(
                    cmd_args=["cat", mapping_file],
                    timeout=30,
                )
                if result.returncode == 0 and result.stdout:
                    break
                if attempt < 2:
                    LOG.debug(
                        f"Case {case_id}: Retrying cat command (attempt {attempt + 2}/3)"
                    )
                    await asyncio.sleep(2)

            if not result or result.returncode != 0 or not result.stdout:
                raise RuntimeError(
                    f"Case {case_id}: Could not read CASR mapping file {mapping_file}. "
                    f"Container: {container.container_id}"
                )

            # Parse JSON from casr-cluster-map Rust tool
            # Format: {"mappings": [{"crash": "...", "cluster_id": N}, ...], "clusters": {...}, "num_clusters": N}
            import json

            mapping_data = json.loads(result.stdout.decode())

            # Build crash-to-cluster mapping from the mappings array
            # Each mapping has: {"crash": "crash-abc123", "cluster_id": 2, "is_representative": bool}
            mappings = mapping_data.get("mappings", [])
            for mapping in mappings:
                crash_name = mapping.get("crash", "")
                cluster_int = mapping.get("cluster_id", 0)
                if crash_name and cluster_int > 0:
                    crash_to_cluster[crash_name] = f"cl{cluster_int}"

            num_clusters = mapping_data.get("num_clusters", 0)
            LOG.info(
                f"Case {case_id}: Loaded mapping for {len(crash_to_cluster)} crashes across {num_clusters} clusters"
            )

            # Log cluster distribution using the clusters dict from JSON
            clusters = mapping_data.get("clusters", {})
            for cluster_id, crash_list in sorted(
                clusters.items(), key=lambda x: int(x[0])
            ):
                LOG.info(
                    f"Case {case_id}: cl{cluster_id} has {len(crash_list)} crashes"
                )

        except Exception as e:
            LOG.error(f"Case {case_id}: Error parsing CASR JSON mapping: {e}")
            import traceback

            LOG.debug(traceback.format_exc())

        return crash_to_cluster

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

        # Generate unique run ID to isolate crashes across benchmark runs
        # Uses millisecond timestamp for uniqueness and debuggability
        run_id = str(int(time.time() * 1000))
        LOG.info(f"Case {case_id}: {target.value} fuzzing run ID: {run_id}")

        # Detect fuzzer type (libFuzzer vs AFL++)
        # First try to load from metadata, then fall back to runtime detection
        fuzzer_type = await self._detect_fuzzer_type(container, case_id=case_id)
        LOG.info(f"Case {case_id}: Detected fuzzer type: {fuzzer_type.value}")

        # Store fuzzer type in state for reference
        if state:
            state.fuzzer_type = fuzzer_type

        # Configure continuous mode with appropriate flags for the target and fuzzer type
        await self._set_fuzzer_continuous_mode(container, target, fuzzer_type, run_id)

        # Copy rebuilt binary if fuzzing LLM patch
        if target == FuzzingTarget.LLM_PATCH and binary_path:
            await container.copy_to_container(binary_path, "/tmp/rebuilt_binary")
            # Fix RPATH so the binary can find shared libraries in /out/
            # Some binaries (e.g., Skia) have RPATH=$ORIGIN which only looks in the binary's directory
            await container.exec_command(
                cmd_args=[
                    "patchelf",
                    "--set-rpath",
                    "/out:$ORIGIN",
                    "/tmp/rebuilt_binary",
                ]
            )
            fuzz_cmd = ["arvo", "fuzz_fix"]
        else:
            fuzz_cmd = ["arvo", "run"]

        LOG.info(
            f"Case {case_id}: Starting {target.value} fuzzing with command: {' '.join(fuzz_cmd)}"
        )

        # Calculate duration upfront
        duration_seconds = self.fuzzing_config.fuzzing_duration_minutes * 60

        # Update state for TUI - don't overwrite LLM generation logs completely
        fuzzer_name = (
            "AFL++" if fuzzer_type == FuzzerType.AFL_PLUS_PLUS else "libFuzzer"
        )
        if state:
            state.current_activity = f"Fuzzing {target.value} ({fuzzer_name})..."
            # Clear streaming output for fuzzing phase, keep a separator from LLM gen
            state.streaming_output = (
                f"[bold]Starting {target.value} Fuzzing[/bold]\n"
                f"Fuzzer: {fuzzer_name}\n"
                f"Duration: {duration_seconds}s ({self.fuzzing_config.fuzzing_duration_minutes}m)\n"
            )

        # Start fuzzing
        start_time = time.time()
        LOG.info(f"Case {case_id}: Fuzzing will run for {duration_seconds} seconds")

        # SIMPLIFIED APPROACH: Run fuzzer directly, stream to log file
        fuzz_cmd_str = " ".join(fuzz_cmd)
        LOG.info(f"Case {case_id}: Running fuzzer: {fuzz_cmd_str}")

        # Create log file path for this fuzzing run
        # Use target directory so GT logs go to ground_truth/, not model directory
        target_dir = self._get_target_dir(case_id, target, model)
        log_file = target_dir / f"fuzzer_output_{target.value}.log"

        # Show tail command for monitoring instead of streaming output
        tail_cmd = f"tail -f {log_file}"
        if state:
            state.streaming_output = (
                f"[bold]Fuzzing {target.value} ({fuzzer_name})[/bold]\n\n"
                f"Log file:\n  {log_file}\n\n"
                f"[cyan]Monitor in another terminal:[/cyan]\n"
                f"  [green]{tail_cmd}[/green]\n\n"
                f"Or open the file in your editor for live updates.\n"
            )
            state.container_logs = f"tail -f {log_file}"
            state.fuzzer_log_path = str(log_file)

        LOG.info(f"Case {case_id}: Fuzzer output will be written to: {log_file}")

        # Build the podman exec command
        exec_cmd = f"podman exec {container.container_id} {fuzz_cmd_str}"

        # Create subprocess with real-time output
        process = await asyncio.create_subprocess_shell(
            exec_cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )

        # Read output and write to file in real-time
        output_lines: List[str] = []
        total_executions = 0

        with open(log_file, "w") as f:
            f.write(f"=== {target.value} Fuzzing Started ===\n")
            f.write(f"Fuzzer: {fuzzer_name}\n")
            f.write(f"Command: {fuzz_cmd_str}\n")
            f.write(f"Duration: {duration_seconds}s\n")
            f.write("=" * 60 + "\n\n")
            f.flush()

            assert process.stdout is not None
            while True:
                try:
                    line = await asyncio.wait_for(
                        process.stdout.readline(), timeout=1.0
                    )
                    if not line:
                        break  # EOF

                    decoded = line.decode(errors="replace").rstrip()
                    output_lines.append(decoded)

                    # Write to file immediately
                    f.write(decoded + "\n")
                    f.flush()

                    # Parse execution count based on fuzzer type
                    if fuzzer_type == FuzzerType.AFL_PLUS_PLUS:
                        # AFL++ formats:
                        # - "execs_done : 123456" (from stats)
                        # - "total_execs : 123456"
                        # - Status lines with execution info
                        exec_match = re.search(
                            r"(?:execs_done|total_execs)\s*:\s*(\d+)", decoded
                        )
                        if exec_match:
                            total_executions = int(exec_match.group(1))
                        # Also try parsing from AFL++ status line: "[*] ... (123456 execs)"
                        elif "execs" in decoded.lower():
                            exec_match = re.search(r"(\d+)\s+execs", decoded)
                            if exec_match:
                                total_executions = max(
                                    total_executions, int(exec_match.group(1))
                                )
                    else:
                        # libFuzzer format: "#258008: cov: 1552..."
                        exec_match = re.search(r"#(\d+):", decoded)
                        if exec_match:
                            total_executions = int(exec_match.group(1))

                    # Update state periodically (every 10 lines) - show stats, not raw output
                    if len(output_lines) % 10 == 0:
                        elapsed = time.time() - start_time
                        remaining = max(0, duration_seconds - elapsed)
                        if state:
                            state.current_activity = f"Fuzzing {target.value} ({fuzzer_name}, {elapsed:.0f}s, {total_executions:,} execs)"
                            state.streaming_output = (
                                f"[bold]Fuzzing {target.value} ({fuzzer_name})[/bold]\n\n"
                                f"Progress: {elapsed:.0f}s / {duration_seconds}s ({remaining:.0f}s remaining)\n"
                                f"Executions: {total_executions:,}\n\n"
                                f"Log file:\n  {log_file}\n\n"
                                f"[cyan]Monitor in another terminal:[/cyan]\n"
                                f"  [green]tail -f {log_file}[/green]\n"
                            )
                            # container_logs just shows the tail command
                            state.container_logs = f"tail -f {log_file}"
                            state.current_executions = total_executions

                except asyncio.TimeoutError:
                    if process.returncode is not None:
                        break
                    # Update state during idle periods - show stats, not raw output
                    elapsed = time.time() - start_time
                    remaining = max(0, duration_seconds - elapsed)
                    if state:
                        state.current_activity = f"Fuzzing {target.value} ({fuzzer_name}, {elapsed:.0f}s, {total_executions:,} execs)"
                        state.streaming_output = (
                            f"[bold]Fuzzing {target.value} ({fuzzer_name})[/bold]\n\n"
                            f"Progress: {elapsed:.0f}s / {duration_seconds}s ({remaining:.0f}s remaining)\n"
                            f"Executions: {total_executions:,}\n\n"
                            f"Log file:\n  {log_file}\n\n"
                            f"[cyan]Monitor in another terminal:[/cyan]\n"
                            f"  [green]tail -f {log_file}[/green]\n"
                        )

                    # Check timeout
                    if elapsed > duration_seconds + 60:
                        LOG.warning(f"Case {case_id}: Fuzzing timeout, killing")
                        process.kill()
                        f.write("\n[TIMEOUT] Fuzzing exceeded time limit\n")
                        break

            f.write("\n=== Fuzzing Complete ===\n")
            f.write(f"Total lines: {len(output_lines)}\n")
            f.write(f"Final executions: {total_executions}\n")

        # Wait for process to finish
        try:
            await asyncio.wait_for(process.wait(), timeout=10)
        except asyncio.TimeoutError:
            process.kill()

        # Store total executions in timeline
        timeline.total_executions = total_executions

        fuzz_output = "\n".join(output_lines)
        LOG.info(
            f"Case {case_id}: Fuzzing complete. {len(output_lines)} lines, {total_executions} executions"
        )

        # Final update - show completion status
        LOG.info(f"Case {case_id}: Fuzzer returned, output length: {len(fuzz_output)}")
        if state:
            state.streaming_output = (
                f"[bold green]Fuzzing {target.value} Complete[/bold green]\n\n"
                f"Duration: {timeline.duration_seconds:.1f}s\n"
                f"Total executions: {total_executions:,}\n\n"
                f"Full log available at:\n  {log_file}\n\n"
                f"[cyan]View log:[/cyan]\n"
                f"  [green]cat {log_file}[/green]\n"
            )
            state.container_logs = f"cat {log_file}"

        end_time = time.time()
        timeline.duration_seconds = end_time - start_time
        LOG.info(
            f"Case {case_id}: {target.value} fuzzing completed in {timeline.duration_seconds:.1f}s"
        )

        # Collect crash files (location depends on fuzzer type and target)
        crash_files = await self._get_crash_files(
            container, fuzzer_type, target, run_id
        )
        crash_location = (
            "/tmp/afl_output/*/crashes/"
            if fuzzer_type == FuzzerType.AFL_PLUS_PLUS
            else f"/tmp/crashes_{run_id}_{target.value}/"
        )
        LOG.info(
            f"Case {case_id}: Found {len(crash_files)} crash files in {crash_location}"
        )

        # Run CASR deduplication inside the container (where binary + libs are available)
        # CASR needs the binary to reproduce crashes and generate stack traces
        casr_clusters: Dict[str, str] = {}  # crash_file -> cluster_id
        if crash_files and self.fuzzing_config.use_casr:
            casr_clusters = await self._run_casr_in_container(
                container, fuzzer_type, crash_files, case_id, target, run_id
            )
            LOG.info(
                f"Case {case_id}: CASR found {len(set(casr_clusters.values()))} unique clusters"
            )

        # Create CrashInfo for each crash
        crash_counter = 0
        for crash_file in crash_files:
            crash_counter += 1
            crash_id = f"crash_{crash_counter:03d}"

            # Parse crash file info based on fuzzer type
            if fuzzer_type == FuzzerType.AFL_PLUS_PLUS:
                # AFL++ format: id:000000,sig:11,src:000001,time:12345,execs:123456,...
                crash_type, estimated_time, execs = self._parse_afl_crash_filename(
                    crash_file, timeline.duration_seconds
                )
            else:
                # libFuzzer format: crash-<sha1> or oom-<sha1> or timeout-<sha1>
                parts = crash_file.split("-")
                crash_type = parts[0] if parts else "unknown"
                # Use discovery order as a proxy for timestamp
                estimated_time = (
                    crash_counter / max(len(crash_files), 1)
                ) * timeline.duration_seconds
                execs = 0

            # Get CASR cluster ID if available
            cluster_id = casr_clusters.get(crash_file)

            crash_info = CrashInfo(
                crash_id=crash_id,
                corpus_file=crash_file,
                first_seen_time=estimated_time,
                first_seen_executions=execs,
                target=target,
                crash_type=crash_type,
                stack_trace=[],
                casr_report={},
                matches_original=(
                    original_crash is not None
                    and crash_type == original_crash.crash_type
                ),
                cluster_id=cluster_id,
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

    def _parse_afl_crash_filename(self, filename: str, total_duration: float) -> tuple:
        """Parse AFL++ crash filename to extract metadata.

        AFL++ crash filenames have format:
        id:000000,sig:11,src:000001,time:12345,execs:123456,op:havoc,rep:2

        Args:
            filename: The crash filename
            total_duration: Total fuzzing duration in seconds

        Returns:
            Tuple of (crash_type, estimated_time, executions)
        """
        crash_type = "crash"  # Default
        estimated_time = 0.0
        execs = 0

        try:
            # Parse comma-separated key:value pairs
            parts = filename.split(",")
            for part in parts:
                if ":" in part:
                    key, value = part.split(":", 1)
                    if key == "sig":
                        # Signal number indicates crash type
                        sig = int(value)
                        if sig == 11:
                            crash_type = "SIGSEGV"
                        elif sig == 6:
                            crash_type = "SIGABRT"
                        elif sig == 8:
                            crash_type = "SIGFPE"
                        else:
                            crash_type = f"SIG{sig}"
                    elif key == "time":
                        # Time in milliseconds since fuzzing started
                        estimated_time = int(value) / 1000.0
                    elif key == "execs":
                        execs = int(value)
        except Exception as e:
            LOG.debug(f"Error parsing AFL++ crash filename '{filename}': {e}")

        return crash_type, estimated_time, execs

    # =========================================================================
    # Main Workflow
    # =========================================================================

    async def _process_gt_case(
        self,
        case_id: int,
        state: CaseState,
    ) -> Optional[FuzzingResults]:
        """
        Process a GT (ground truth) case.

        GT is treated as a special "model" that:
        - Uses the pre-built -fix container (no LLM generation needed)
        - Fuzzes the fix container's binary directly
        - Stores results in /files/case_XXX/ground_truth/

        Args:
            case_id: ARVO case ID
            state: CaseState for this GT case

        Returns:
            FuzzingResults if successful, None otherwise
        """
        LOG.info(f"Case {case_id}: Processing GT (ground truth)")

        try:
            # Check for cached GT results
            cached_gt = self._load_cached_gt_timeline(case_id)
            if cached_gt:
                LOG.info(
                    f"Case {case_id}: Using cached GT results ({cached_gt.unique_crashes()} unique crashes)"
                )
                state.gt_timeline = cached_gt
                state.status = CaseStatus.COMPLETED
                state.current_activity = f"GT cached: {cached_gt.unique_crashes()} unique crashes"

                results = FuzzingResults.from_case_state(state, self.fuzzing_config)
                return results

            # Start fix container for GT fuzzing
            state.status = CaseStatus.BUILDING_CONTAINER
            state.current_activity = "Starting fix container..."

            gt_dir = self._get_target_dir(case_id, FuzzingTarget.GROUND_TRUTH)
            container = ArvoContainer(
                case_id,
                container_type=ArvoContainer.CONTAINER_TYPE_FIX,
                model_under_test=self.GT_MODEL_NAME,
                log_level=logging.INFO,
                log_filepath=gt_dir / "fuzzing_log.txt",
                artifacts_dir=gt_dir,
            )
            await container.start_container()

            # Analyze original crash (for reference/comparison)
            state.status = CaseStatus.ANALYZING_ORIGINAL
            state.current_activity = "Analyzing original PoC crash..."
            original_crash = await self._analyze_original_crash(container, case_id)
            state.original_crash = original_crash

            # Fuzz ground truth
            state.status = CaseStatus.FUZZING_GT
            state.current_activity = "Fuzzing ground truth patch..."

            state.gt_timeline = await self._fuzz_with_timeline(
                container,
                FuzzingTarget.GROUND_TRUTH,
                case_id,
                self.GT_MODEL_NAME,
                original_crash=original_crash,
                state=state,
            )

            # Save GT results
            if state.gt_timeline:
                crashes_file = gt_dir / "crashes.json"
                crashes_data = state.gt_timeline.to_minimal_dict()
                crashes_file.write_text(json.dumps(crashes_data, indent=2))
                LOG.info(f"Case {case_id}: Saved GT results to {crashes_file}")

            # Clean up container
            await ArvoContainer.stop_container(container.container_id)

            # Mark complete
            state.status = CaseStatus.COMPLETED
            state.current_activity = "Done"

            results = FuzzingResults.from_case_state(state, self.fuzzing_config)
            return results

        except DebugContainerException as e:
            self.debug_containers[e.container_id] = {
                "case_id": e.case_id,
                "reason": str(e),
                "model": self.GT_MODEL_NAME,
            }
            LOG.error(
                f"Case {case_id}: GT debug container preserved!\n"
                f"Container ID: {e.container_id}\n"
                f"To debug, run: podman exec -it {e.container_id} bash"
            )
            state.status = CaseStatus.FAILED
            state.error = f"Debug container preserved: {e.container_id}"
            return None

        except Exception as e:
            LOG.error(f"Case {case_id}: Error during GT processing: {e}")
            state.status = CaseStatus.FAILED
            state.error = str(e)
            return None

    async def _process_llm_case(
        self,
        case_id: int,
        model_name: str,
        llm: LLM,
        state: CaseState,
    ) -> Optional[FuzzingResults]:
        """
        Process an LLM model case.

        LLM cases:
        - Generate patch using LLM if not cached
        - Rebuild binary with the patch
        - Fuzz the patched binary
        - Store results in /files/case_XXX/model_name/

        Args:
            case_id: ARVO case ID
            model_name: LLM model name
            llm: LLM instance for patch generation
            state: CaseState for this LLM case

        Returns:
            FuzzingResults if successful, None otherwise
        """
        try:
            # Check if response is already cached
            if not self._is_response_cached(case_id, model_name):
                # Generate LLM response
                state.status = CaseStatus.GENERATING_PATCH
                state.current_activity = "Generating patch with LLM..."
                LOG.info(f"Case {case_id}: Generating LLM response...")

                await self._gen_patch_and_binary_with_state(case_id, llm, state)

                LOG.info(f"Case {case_id}: LLM response generation complete")
            else:
                LOG.info(f"Case {case_id}: Using cached response")

            # Now proceed with fuzzing
            return await self._process_single_case(case_id, model_name, state)

        except Exception as e:
            LOG.error(f"Case {case_id}: Error during LLM processing: {e}")
            state.status = CaseStatus.FAILED
            state.error = str(e)
            return None

    async def _gen_patch_and_binary_with_state(
        self,
        case_id: int,
        llm_under_test: LLM,
        state: CaseState,
    ) -> None:
        """Generate patch and binary, updating state for TUI feedback with streaming logs."""
        out_dir = self._get_case_dir(case_id, llm_under_test.model)
        patch_filepath = out_dir / "patch.patch"
        binary_filepath = out_dir / "binary.bin"
        report_filepath = out_dir / "report.json"
        chat_filepath = out_dir / "chat.md"
        llm_log_filepath = out_dir / "llm_generation.log"

        # Store log path in state for TUI access
        state.llm_log_path = str(llm_log_filepath)

        def update_streaming_output(message: str, append: bool = True) -> None:
            """Update the streaming output in the TUI."""
            timestamp = time.strftime("%H:%M:%S")
            log_line = f"[{timestamp}] {message}"
            if append:
                state.streaming_output += f"\n{log_line}"
            else:
                state.streaming_output = log_line
            # Also write to log file
            with open(llm_log_filepath, "a") as f:
                f.write(f"{log_line}\n")

        # Clean up existing files
        for file in out_dir.glob("*"):
            if file.is_dir():
                shutil.rmtree(file)
            else:
                file.unlink()

        # Initialize log file
        with open(llm_log_filepath, "w") as f:
            f.write("=== LLM Patch Generation Log ===\n")
            f.write(f"Case: {case_id}\n")
            f.write(f"Model: {llm_under_test.model}\n")
            f.write(f"Started: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("=" * 40 + "\n\n")

        state.streaming_output = (
            f"[bold]LLM Patch Generation - Case {case_id}[/bold]\n"
            f"Model: {llm_under_test.model}\n"
            f"Output directory: {out_dir}\n\n"
        )

        state.current_activity = "Starting vul container..."
        update_streaming_output("Starting vulnerable container...")

        vul_container = ArvoContainer(
            case_id,
            container_type=ArvoContainer.CONTAINER_TYPE_VUL,
            model_under_test=llm_under_test.model,
            log_level=logging.INFO,
            log_filepath=self._get_log_filepath(case_id, "vul", llm_under_test.model),
            artifacts_dir=out_dir,
        )
        await vul_container.start_container()
        update_streaming_output(
            f"Vul container started: {vul_container.container_id[:12]}"
        )

        containers_pass_qa_checks = True

        state.current_activity = "Starting fix container..."
        update_streaming_output("Starting fix container...")

        fix_container = ArvoContainer(
            case_id,
            container_type=ArvoContainer.CONTAINER_TYPE_FIX,
            model_under_test=llm_under_test.model,
            log_level=logging.INFO,
            log_filepath=self._get_log_filepath(case_id, "fix", llm_under_test.model),
            artifacts_dir=out_dir,
        )
        await fix_container.start_container()
        update_streaming_output(
            f"Fix container started: {fix_container.container_id[:12]}"
        )

        state.current_activity = "Running QA checks..."
        update_streaming_output("Running QA checks on containers...")

        # Use original flags (not debug flags like -O0/-g2) for continuous fuzzing
        vul_qa = await vul_container.qa_checks(use_debug_flags=False)
        fix_qa = await fix_container.qa_checks(use_debug_flags=False)
        containers_pass_qa_checks = vul_qa and fix_qa

        update_streaming_output(f"QA checks: vul={vul_qa}, fix={fix_qa}")

        patch_success = False
        patched_function_name = None
        exception_message = None

        if containers_pass_qa_checks:
            report = PatchGenerationReport()
            try:
                # Create a callback that streams LLM messages to the TUI
                def llm_message_callback(role: str, content: str):
                    """Callback to stream LLM messages to TUI output."""
                    timestamp = time.strftime("%H:%M:%S")
                    if role == "system":
                        update_streaming_output(f"[dim][{timestamp}] SYSTEM:[/dim]")
                        update_streaming_output(f"[dim]{content}[/dim]")
                    elif role == "human":
                        update_streaming_output(f"\n[cyan][{timestamp}] USER:[/cyan]")
                        update_streaming_output(f"[white]{content}[/white]")
                    elif role == "assistant":
                        update_streaming_output(
                            f"\n[green][{timestamp}] ASSISTANT:[/green]"
                        )
                        update_streaming_output(f"[yellow]{content}[/yellow]")
                    elif role == "error":
                        update_streaming_output(
                            f"\n[red][{timestamp}] ERROR: {content}[/red]"
                        )
                    update_streaming_output("")

                agent = AutoPatchAgent(
                    vul_container,
                    llm_under_test,
                    patch_filepath,
                    binary_filepath,
                    message_callback=llm_message_callback,
                    use_debug_flags=False,  # Use original flags for continuous fuzzing
                )
                state.current_activity = "LLM generating patch..."
                update_streaming_output("Starting LLM patch generation agent...")
                update_streaming_output(f"Patch file: {patch_filepath}")
                update_streaming_output(f"Binary file: {binary_filepath}")
                update_streaming_output("")
                update_streaming_output("[cyan]Calling LLM API...[/cyan]")

                LOG.info(f"Starting patch generation agent for case #{case_id}")

                # Run patch generation with periodic status updates
                start_time = time.time()

                async def generation_with_updates():
                    return await agent.generate_and_persist_patch_and_binary()

                # Create the generation task
                gen_task = asyncio.create_task(generation_with_updates())

                # Monitor and update status while waiting
                while not gen_task.done():
                    try:
                        await asyncio.wait_for(asyncio.shield(gen_task), timeout=10.0)
                        break
                    except asyncio.TimeoutError:
                        # Still running, update status
                        elapsed = time.time() - start_time
                        state.current_activity = f"LLM generating... ({elapsed:.0f}s)"

                report = gen_task.result()
                elapsed = time.time() - start_time
                patch_success = report.max_patch_generation_status.is_success()
                patched_function_name = report.patched_function_name

                update_streaming_output("")
                update_streaming_output(
                    f"[bold]Generation completed in {elapsed:.1f}s[/bold]"
                )
                update_streaming_output(
                    f"Patch status: {report.max_patch_generation_status}"
                )
                if patched_function_name:
                    update_streaming_output(
                        f"Patched function: {patched_function_name}"
                    )
                if patch_success:
                    update_streaming_output(
                        "[green]SUCCESS: Patch generated and binary rebuilt[/green]"
                    )
                else:
                    update_streaming_output(
                        "[red]FAILED: Patch generation unsuccessful[/red]"
                    )

                state.current_activity = (
                    f"Patch generated: {'success' if patch_success else 'failed'}"
                )

            except asyncio.TimeoutError:
                exception_message = f"Patch generation timed out after {self.PER_SAMPLE_PATCH_GENERATION_TIMEOUT} seconds"
                LOG.error(exception_message)
                report.exception += "\n" + exception_message
                state.current_activity = "Patch generation timed out"
                update_streaming_output(f"[red]TIMEOUT: {exception_message}[/red]")
            except Exception as e:
                LOG.error(f"Error during patch generation: {e}")
                exception_message = str(e)
                report.exception += "\n" + exception_message
                state.current_activity = f"Error: {str(e)[:50]}"
                update_streaming_output(f"[red]ERROR: {exception_message}[/red]")

            # Write reports
            with open(report_filepath, "wt") as f:
                f.write(report.to_json())
            write_chat_history_markdown(
                [ChatHistory.from_report(report)], chat_filepath.as_posix()
            )
            update_streaming_output(f"\nReport saved: {report_filepath}")
            update_streaming_output(f"Chat history: {chat_filepath}")
        else:
            state.current_activity = "Container QA checks failed"
            update_streaming_output(
                "[red]Container QA checks failed - skipping patch generation[/red]"
            )

        # Write response entry
        self._write_to_response_json(
            binary_filepath=binary_filepath,
            case_id=case_id,
            containers_pass_qa_checks=containers_pass_qa_checks,
            exception_message=exception_message,
            llm_under_test=llm_under_test,
            overwrite=False,
            patch_filepath=patch_filepath,
            patch_success=patch_success,
            patched_function_name=patched_function_name,
        )

        update_streaming_output("")
        update_streaming_output(f"=== LLM Generation Complete for Case {case_id} ===")

        LOG.info(f"Case {case_id}: Patch generation complete. Success: {patch_success}")

    async def _rebuild_binary_from_patch(
        self,
        case_id: int,
        model: str,
        patch_path: Path,
        binary_path: Path,
        state: CaseState,
    ) -> bool:
        """Rebuild binary from an existing patch file.

        This is used when the binary is missing but the patch exists,
        allowing us to rebuild without re-running LLM generation.

        Returns True if successful, False otherwise.
        """
        LOG.info(f"Case {case_id}: Rebuilding binary from existing patch {patch_path}")
        state.current_activity = "Rebuilding binary from cached patch..."

        out_dir = self._get_case_dir(case_id, model)

        # Start a VUL container for rebuilding
        vul_container = ArvoContainer(
            case_id,
            container_type=ArvoContainer.CONTAINER_TYPE_VUL,
            model_under_test=model,
            log_level=logging.INFO,
            log_filepath=out_dir / "rebuild_log.txt",
            artifacts_dir=out_dir,
        )

        try:
            await vul_container.start_container()

            # Copy and apply the patch
            state.current_activity = "Applying patch..."
            await vul_container.copy_to_container(str(patch_path), "/tmp/patch")

            apply_result = await vul_container.exec_command(
                cmd_args=["git", "apply", "/tmp/patch"]
            )

            if apply_result.returncode != 0:
                LOG.error(
                    f"Case {case_id}: Failed to apply patch. Return code: {apply_result.returncode}"
                )
                LOG.error(f"Stdout: {apply_result.stdout.decode()}")
                LOG.error(f"Stderr: {apply_result.stderr.decode()}")
                return False

            LOG.info(f"Case {case_id}: Patch applied successfully")

            # Recompile (use original flags, not debug flags like -O0/-g2)
            state.current_activity = "Recompiling with patch..."
            recompile_result = await vul_container.recompile(use_debug_flags=False)

            if recompile_result.returncode != 0:
                LOG.error(
                    f"Case {case_id}: Recompilation failed: {recompile_result.stderr.decode()}"
                )
                return False

            LOG.info(f"Case {case_id}: Recompilation successful")

            # Get the rebuilt binary path from the container
            fuzzer_path = await vul_container.get_binary_filepath()
            if not fuzzer_path:
                LOG.error(f"Case {case_id}: Could not find rebuilt binary in container")
                return False

            # Copy the rebuilt binary out
            state.current_activity = "Extracting rebuilt binary..."
            await vul_container.copy_from_container(fuzzer_path, str(binary_path))

            if binary_path.exists():
                LOG.info(
                    f"Case {case_id}: Successfully rebuilt binary at {binary_path}"
                )
                return True
            else:
                LOG.error(f"Case {case_id}: Binary not found after extraction")
                return False

        except Exception as e:
            LOG.error(f"Case {case_id}: Error rebuilding binary: {e}")
            return False
        finally:
            await ArvoContainer.stop_container(vul_container.container_id)
            await vul_container.remove_container()

    async def _process_single_case(
        self,
        case_id: int,
        model: str,
        state: CaseState,
    ) -> Optional[FuzzingResults]:
        """Process a single LLM case: load response and fuzz LLM patch.

        Note: GT is now handled separately by _process_gt_case as its own "model".
        This method only handles LLM patch fuzzing.
        """
        LOG.info(f"Processing LLM case {case_id} with model {model}")

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
                    # Binary not found - check if we can rebuild from existing patch
                    patch_path = self._get_case_dir(case_id, model) / "patch.patch"
                    if patch_path.exists():
                        LOG.info(
                            f"Case {case_id}: Binary missing but patch exists - rebuilding"
                        )
                        state.current_activity = (
                            "Rebuilding binary from cached patch..."
                        )

                        rebuild_success = await self._rebuild_binary_from_patch(
                            case_id, model, patch_path, alt_path, state
                        )

                        if rebuild_success:
                            binary_path = str(alt_path)
                            LOG.info(f"Case {case_id}: Successfully rebuilt binary")
                        else:
                            LOG.warning(
                                f"Case {case_id}: Failed to rebuild binary from patch"
                            )
                            state.status = CaseStatus.SKIPPED
                            state.error = "Failed to rebuild binary from patch"
                            return None
                    else:
                        LOG.warning(f"Case {case_id}: No rebuilt binary or patch found")
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

            # Analyze original crash (for reference/comparison)
            state.status = CaseStatus.ANALYZING_ORIGINAL
            state.current_activity = "Analyzing original PoC crash..."
            original_crash = await self._analyze_original_crash(container, case_id)
            state.original_crash = original_crash

            # Fuzz LLM patch
            # Reset corpus to start fresh - ensures fair comparison with GT
            LOG.info(f"Case {case_id}: Resetting corpus for LLM fuzzing...")
            state.current_activity = "Resetting corpus..."

            # Log corpus state before reset
            result = await container.exec_command(
                cmd_args=["sh", "-c", "'ls /tmp/corpus/ | wc -l'"]
            )
            LOG.info(
                f"Case {case_id}: Corpus files BEFORE reset: {result.stdout.decode().strip()}"
            )

            # Clean corpus directory - use find to delete all files
            result = await container.exec_command(
                cmd_args=["sh", "-c", "'find /tmp/corpus/ -type f -delete'"]
            )
            LOG.info(f"Case {case_id}: find/delete exit code: {result.returncode}")

            # Clean up libFuzzer temp directories from fork mode
            result = await container.exec_command(
                cmd_args=["sh", "-c", "'rm -rf /tmp/libFuzzer*'"]
            )
            LOG.info(
                f"Case {case_id}: libFuzzer cleanup exit code: {result.returncode}"
            )

            # Copy only the PoC as starting seed
            result = await container.exec_command(
                cmd_args=["cp", "/tmp/poc", "/tmp/corpus/poc"]
            )
            LOG.info(f"Case {case_id}: cp exit code: {result.returncode}")

            # Verify corpus state after reset
            result = await container.exec_command(
                cmd_args=["sh", "-c", "'ls /tmp/corpus/ | wc -l'"]
            )
            LOG.info(
                f"Case {case_id}: Corpus files AFTER reset: {result.stdout.decode().strip()}"
            )

            LOG.info(f"Case {case_id}: Corpus reset complete, starting LLM fuzzing")

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
            await ArvoContainer.stop_container(container.container_id)

            # Save results
            state.status = CaseStatus.COMPLETED
            state.current_activity = "Done"

            results = FuzzingResults.from_case_state(state, self.fuzzing_config)
            self._save_case_results(case_id, model, state, results)

            return results

        except DebugContainerException as e:
            # Track container for debugging - do NOT clean it up
            self.debug_containers[e.container_id] = {
                "case_id": e.case_id,
                "reason": str(e),
                "model": model,
            }
            LOG.error(
                f"Case {case_id}: Debug container preserved!\n"
                f"Container ID: {e.container_id}\n"
                f"To debug, run: podman exec -it {e.container_id} bash\n"
                f"Skipping rest of pipeline for this case. Benchmark will continue."
            )
            state.status = CaseStatus.FAILED
            state.error = f"Debug container preserved: {e.container_id}"
            return None

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
        """Save results for a single case.

        Saves crashes.json in minimal format to appropriate directories:
        - /files/case_XXX/ground_truth/crashes.json for GT (saved during processing, not here)
        - /files/case_XXX/model_name/crashes.json for LLM patches

        Detailed crash analysis is in casr_reports/ subdirectory.

        Note: GT results are saved immediately after GT fuzzing in _process_single_case
        to allow other models to reuse them. We don't save them again here.
        """
        # Save LLM timeline if available
        if state.llm_timeline:
            llm_dir = self._get_target_dir(case_id, FuzzingTarget.LLM_PATCH, model)
            crashes_file = llm_dir / "crashes.json"
            crashes_data = state.llm_timeline.to_minimal_dict()
            crashes_file.write_text(json.dumps(crashes_data, indent=2))
            LOG.info(f"Case {case_id}: Saved LLM crashes to {crashes_file}")

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
        LLM response generation is now handled in run() with the TUI.
        This method is kept for interface compatibility but is a no-op.
        """
        # Count cases that need generation
        cases_needing_generation = sum(
            1
            for llm in self.llms_under_test
            for case_id in self.images_available
            if not self._is_response_cached(case_id, llm.model)
        )
        total_cases = len(self.llms_under_test) * len(self.images_available)
        cached_cases = total_cases - cases_needing_generation

        LOG.info(
            f"LLM responses: {cached_cases} cached, {cases_needing_generation} to generate. "
            "Generation will happen during evaluation with TUI."
        )

    async def run(
        self,
        num_test_cases: int = 0,
        run_llm_in_parallel: int = 16,
        should_cleanup_after_eval: bool = False,
    ) -> None:
        """Run LLM generation (if needed) and fuzzing evaluation on all cases."""
        # Initialize case states for ALL test cases first (before building)
        # This allows TUI to show building progress
        self._test_cases_to_use = (
            self.test_cases[:num_test_cases] if num_test_cases > 0 else self.test_cases
        )

        # Create GT case states (one per case_id) if GT fuzzing is enabled
        # GT is treated as a special "model" that uses the pre-built fix container
        if self.fuzzing_config.fuzz_ground_truth:
            for case_id in self._test_cases_to_use:
                key = f"{case_id}_{self.GT_MODEL_NAME}"
                state = CaseState(case_id=case_id, model=self.GT_MODEL_NAME)
                state.status = CaseStatus.PENDING
                state.current_activity = "Waiting for container build..."
                self.case_states[key] = state

        # Create LLM model case states if LLM fuzzing is enabled
        if self.fuzzing_config.fuzz_llm_patch:
            for llm in self.llms_under_test:
                for case_id in self._test_cases_to_use:
                    key = f"{case_id}_{llm.model}"
                    state = CaseState(case_id=case_id, model=llm.model)
                    state.status = CaseStatus.PENDING
                    state.current_activity = "Waiting for container build..."
                    self.case_states[key] = state

        LOG.info(
            f"Initialized {len(self.case_states)} case states for {len(self._test_cases_to_use)} test cases"
        )

        # Check if TUI is enabled
        if self.fuzzing_config.enable_tui:
            from .fuzzing_tui import is_textual_available

            if is_textual_available():
                await self._run_with_tui(run_llm_in_parallel)
            else:
                LOG.warning("Textual not available, running without TUI")
                await self._build_and_run_without_tui(run_llm_in_parallel)
        else:
            await self._build_and_run_without_tui(run_llm_in_parallel)

        # Log debug containers summary at the end of the benchmark
        if self.debug_containers:
            LOG.warning(
                f"\n{'='*60}\n"
                f"DEBUG CONTAINERS PRESERVED: {len(self.debug_containers)}\n"
                f"{'='*60}\n"
                f"The following containers have been preserved for debugging.\n"
                f"They will NOT be automatically cleaned up.\n"
            )
            for container_id, info in self.debug_containers.items():
                LOG.warning(
                    f"\n  Case {info['case_id']} ({info['model']}):\n"
                    f"    Container: {container_id}\n"
                    f"    Command:   podman exec -it {container_id} bash\n"
                    f"    Reason:    {info['reason'][:100]}..."
                )
            LOG.warning(
                f"\n{'='*60}\n"
                f"To manually clean up these containers later, run:\n"
                f"  podman stop {' '.join(self.debug_containers.keys())}\n"
                f"  podman rm {' '.join(self.debug_containers.keys())}\n"
                f"{'='*60}\n"
            )

        if should_cleanup_after_eval:
            if self.debug_containers:
                LOG.warning(
                    "Skipping automatic container cleanup because debug containers exist.\n"
                    "Clean them up manually after debugging."
                )
            else:
                await ArvoContainer.cleanup_all_containers()

    def _build_containers_and_get_cases(self) -> List[tuple]:
        """Build containers and return list of cases to process.

        Returns list of tuples: (case_id, model_name, llm_or_none, state)
        - For GT cases: llm_or_none is None
        - For LLM cases: llm_or_none is the LLM instance

        Note: Caller should set CaseStatus.BUILDING_CONTAINER before calling this.
        """
        if not self._images_built:
            LOG.info(
                f"Building container images for {len(self._test_cases_to_use)} test cases..."
            )
            self.images_available = self._build_container_images(
                self._test_cases_to_use, self._max_concurrency
            )
            self._images_built = True
            LOG.info(f"Built {len(self.images_available)} container images")

            # Update case states for build results
            available_set = set(self.images_available)

            # Update GT case states
            if self.fuzzing_config.fuzz_ground_truth:
                for case_id in self._test_cases_to_use:
                    key = f"{case_id}_{self.GT_MODEL_NAME}"
                    state = self.case_states.get(key)
                    if state:
                        if case_id not in available_set:
                            state.status = CaseStatus.FAILED
                            state.current_activity = f"Container build failed (see build_logs/{case_id}-*.log)"
                        else:
                            state.status = CaseStatus.PENDING
                            # Check if GT results already exist
                            if self._is_gt_results_cached(case_id):
                                state.current_activity = "GT cached, ready to process"
                            else:
                                state.current_activity = "Build complete, ready to fuzz"

            # Update LLM case states
            if self.fuzzing_config.fuzz_llm_patch:
                for llm in self.llms_under_test:
                    for case_id in self._test_cases_to_use:
                        key = f"{case_id}_{llm.model}"
                        state = self.case_states.get(key)
                        if state:
                            if case_id not in available_set:
                                state.status = CaseStatus.FAILED
                                state.current_activity = f"Container build failed (see build_logs/{case_id}-*.log)"
                            else:
                                state.status = CaseStatus.PENDING
                                # Check if response already exists
                                if self._is_response_cached(case_id, llm.model):
                                    state.current_activity = (
                                        "Response cached, ready to process"
                                    )
                                else:
                                    state.current_activity = (
                                        "Build complete, waiting for patch generation"
                                    )

        # Build case list from successfully built images
        cases_to_process = []

        # Add GT cases first (they don't need LLM generation)
        if self.fuzzing_config.fuzz_ground_truth:
            for case_id in self.images_available:
                if case_id not in self._test_cases_to_use:
                    continue
                key = f"{case_id}_{self.GT_MODEL_NAME}"
                state = self.case_states.get(key)
                if state and state.status != CaseStatus.FAILED:
                    # GT cases have None for LLM
                    cases_to_process.append((case_id, self.GT_MODEL_NAME, None, state))

        # Add LLM cases
        if self.fuzzing_config.fuzz_llm_patch:
            for llm in self.llms_under_test:
                for case_id in self.images_available:
                    if case_id not in self._test_cases_to_use:
                        continue
                    key = f"{case_id}_{llm.model}"
                    state = self.case_states.get(key)
                    if state and state.status != CaseStatus.FAILED:
                        cases_to_process.append((case_id, llm.model, llm, state))

        LOG.info(f"Processing {len(cases_to_process)} cases...")
        return cases_to_process

    async def _build_and_run_without_tui(self, max_concurrent: int) -> None:
        """Build containers then run without TUI."""
        cases_to_process = self._build_containers_and_get_cases()
        await self._run_without_tui(cases_to_process, max_concurrent)

    async def _run_without_tui(
        self,
        cases_to_process: List[tuple],
        max_concurrent: int,
    ) -> None:
        """Run LLM generation and fuzzing without TUI.

        Args:
            cases_to_process: List of (case_id, model_name, llm_or_none, state) tuples
                - For GT cases: llm_or_none is None
                - For LLM cases: llm_or_none is the LLM instance
            max_concurrent: Maximum number of concurrent tasks
        """
        semaphore = asyncio.Semaphore(max_concurrent)

        async def process_with_semaphore(case_id, model_name, llm_or_none, state):
            async with semaphore:
                if model_name == self.GT_MODEL_NAME:
                    # GT case - no LLM generation needed
                    return await self._process_gt_case(case_id, state)
                else:
                    # LLM case - generate patch then fuzz
                    return await self._process_llm_case(
                        case_id, model_name, llm_or_none, state
                    )

        tasks = [
            process_with_semaphore(case_id, model_name, llm_or_none, state)
            for case_id, model_name, llm_or_none, state in cases_to_process
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
        LOG.info(f"Completed: {completed}, Failed: {failed}, Skipped: {skipped}")

    async def _run_with_tui(
        self,
        max_concurrent: int,
    ) -> None:
        """Run fuzzing with TUI visualization.

        TUI launches immediately, then container building and processing
        happens in the background so user can see progress.
        """
        from .fuzzing_tui import FuzzingTUI

        # Create TUI app - launches immediately with all case states visible
        tui = FuzzingTUI(
            case_states=self.case_states,
            config=self.fuzzing_config,
            output_dir=self.output_dir,
        )

        # Run building + processing in background
        async def run_build_and_processing():
            # Small delay to let TUI initialize and render first tick
            await asyncio.sleep(0.5)

            # Update states to show building is starting
            for key, state in self.case_states.items():
                state.status = CaseStatus.BUILDING_CONTAINER
                case_id = state.case_id
                state.current_activity = (
                    f"Building container... (logs: build_logs/{case_id}-*.log)"
                )

            # Another small delay to let TUI show "building" status
            await asyncio.sleep(0.5)

            # Build containers in executor (blocking call)
            cases_to_process = await asyncio.get_event_loop().run_in_executor(
                None, self._build_containers_and_get_cases
            )
            # Process all cases
            await self._run_without_tui(cases_to_process, max_concurrent)

        # Start processing task
        processing_task = asyncio.create_task(run_build_and_processing())

        # Run TUI (async-compatible version for use within existing event loop)
        await tui.run_async()

        # Wait for processing to complete
        await processing_task
