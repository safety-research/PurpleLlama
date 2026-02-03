# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

"""
AutoPatch Benchmark Agent.

This agent generates patches for vulnerabilities using LLM-based analysis.
It follows the autopatch benchmark methodology:
1. Analyze crash output to understand the vulnerability
2. Fetch source code for functions in the stack trace
3. Ask LLM to identify root cause (two-step prompting)
4. Ask LLM to generate a patch
5. Apply and verify the patch builds
6. Verify the patch fixes the original crash

Fuzzing/evaluation is handled separately by the evaluation pipeline.
"""

import logging
from pathlib import Path
from typing import List, Optional

from ..base import AgentResult, AgentStatus, BaseAgent
from .prompts import (
    FOLLOWUP_PATCH_PROMPT,
    RETRY_BUILD_ERROR_PROMPT,
    RETRY_NOT_FIXED_PROMPT,
    ROOTCAUSE_PROMPT,
    SYSTEM_PROMPT,
)
from .source_utils import (
    apply_patch,
    fetch_function_source_info,
    parse_function_name,
    revert_changes,
)
from .types import (
    extract_code,
    FunctionSourceInfo,
    get_sanitizer_crash_type,
    LLMOutputFormatError,
    PatchPlan,
    PatchPlanItem,
)

LOG = logging.getLogger(__name__)


class AutoPatchBenchAgent(BaseAgent):
    """
    AutoPatch benchmark agent for LLM-based vulnerability patching.

    This agent implements the two-step prompting approach:
    1. First ask the LLM to analyze the root cause
    2. Then ask the LLM to generate a patch

    The agent iterates with retry prompts if the patch doesn't build
    or doesn't fix the crash.
    """

    AGENT_NAME = "autopatchbench"

    def __init__(
        self,
        case_id: int,
        output_dir: Path,
        model: str,
        dry_run: bool = False,
        max_retries: int = 10,
        max_iterations: int = 5,
        increasing_temperature: bool = True,
        stack_ctx_depth: int = 5,
    ):
        """
        Initialize the AutoPatch agent.

        Args:
            case_id: ARVO case ID
            output_dir: Directory for output files
            model: Anthropic model to use
            dry_run: If True, skip LLM calls
            max_retries: Maximum number of full retry rounds
            max_iterations: Maximum iterations per retry round
            increasing_temperature: Whether to increase temperature on retries
            stack_ctx_depth: Number of stack frames to include in context
        """
        super().__init__(
            case_id=case_id,
            output_dir=output_dir,
            model=model,
            dry_run=dry_run,
            max_retries=max_retries,
        )

        self.max_iterations = max_iterations
        self.increasing_temperature = increasing_temperature
        self.stack_ctx_depth = stack_ctx_depth

        # Initialize Anthropic client
        self.client = None
        if not dry_run:
            try:
                import anthropic

                self.client = anthropic.Anthropic()
                LOG.info(f"Initialized Anthropic client for model: {model}")
            except ImportError:
                LOG.error("anthropic package not installed")
                raise
            except Exception as e:
                LOG.error(f"Failed to initialize Anthropic client: {e}")
                raise

        # Conversation history for multi-turn
        self._messages: List[dict] = []

    async def run(self) -> AgentResult:
        """
        Run the patching pipeline.

        Steps:
        1. Analyze original crash
        2. Generate patch (with retries)
        3. Apply and verify patch

        Returns:
            AgentResult with patching results
        """
        try:
            LOG.info(f"Starting AutoPatch agent for case {self.case_id}")
            self.result.status = AgentStatus.RUNNING

            # Step 1: Analyze crash
            crash_output = self._analyze_crash()
            if not crash_output:
                self.result.status = AgentStatus.FAILED
                self.result.error = "Failed to reproduce crash"
                return self._finalize_and_save()

            # Step 2: Fetch source info
            function_source_info = await fetch_function_source_info(
                crash_output, stack_ctx_depth=self.stack_ctx_depth
            )
            if function_source_info is None:
                self.result.status = AgentStatus.NOT_SUPPORTED
                self.result.error = "Could not fetch source code from stack trace"
                return self._finalize_and_save()

            # Step 3: Generate and verify patch
            if not self.dry_run:
                for retry_round in range(self.max_retries):
                    LOG.info(f"Retry round {retry_round + 1}/{self.max_retries}")

                    # Reset conversation for new retry round
                    self._messages = []

                    success = await self._generate_and_verify_patch(
                        crash_output, function_source_info
                    )

                    if success:
                        self.result.status = AgentStatus.SUCCESS
                        break
                    else:
                        # Revert changes before next retry
                        if self.result.patched_file_path:
                            revert_changes(self.result.patched_file_path)

                if self.result.status != AgentStatus.SUCCESS:
                    if self.result.patch_generated:
                        self.result.status = AgentStatus.PARTIAL
                    else:
                        self.result.status = AgentStatus.FAILED
            else:
                LOG.info("Dry run - skipping LLM calls")
                self.result.status = AgentStatus.SUCCESS

        except Exception as e:
            LOG.exception(f"Agent failed: {e}")
            self.result.status = AgentStatus.FAILED
            self.result.exception = str(e)

        return self._finalize_and_save()

    def _analyze_crash(self) -> Optional[str]:
        """
        Analyze the original crash using arvo command.

        Returns:
            Crash output string, or None if crash doesn't reproduce
        """
        LOG.info("Analyzing original crash...")

        result = self._run_command(["arvo"], timeout=120)
        crash_output = result.stdout + result.stderr

        self.result.original_crash_output = crash_output

        # Parse crash type
        crash_type = get_sanitizer_crash_type(crash_output)
        self.result.original_crash_type = crash_type
        LOG.info(f"Detected crash type: {crash_type}")

        # Check if crash reproduced
        if "ERROR: AddressSanitizer" in crash_output or "SUMMARY:" in crash_output:
            return crash_output

        LOG.warning("Crash did not reproduce")
        return None

    async def _generate_and_verify_patch(
        self,
        crash_output: str,
        function_source_info: FunctionSourceInfo,
    ) -> bool:
        """
        Generate and verify a patch through iterative refinement.

        Args:
            crash_output: Original crash output
            function_source_info: Source code info for stack trace functions

        Returns:
            True if patch was successfully generated and verified
        """
        patch_plan: Optional[PatchPlan] = None

        for iteration in range(self.max_iterations):
            LOG.info(f"Iteration {iteration + 1}/{self.max_iterations}")

            # Calculate temperature for this iteration
            temperature = None
            if self.increasing_temperature and iteration > 0:
                temperature = min(0.05 * iteration, 0.8)

            try:
                if patch_plan is None:
                    # First iteration: generate initial patch
                    patch_plan = await self._get_initial_patch_plan(
                        crash_output, function_source_info, temperature
                    )
                else:
                    # Subsequent iterations: refine based on feedback
                    patch_plan = await self._get_refined_patch_plan(
                        patch_plan, temperature
                    )

                if patch_plan is None:
                    LOG.warning(
                        f"Failed to generate patch plan at iteration {iteration + 1}"
                    )
                    continue

                # Apply and verify
                if self._apply_patch_plan(patch_plan):
                    if self._verify_build():
                        if self._verify_crash_fixed():
                            LOG.info("Patch verified successfully!")
                            return True
                        else:
                            self._last_failure_reason = "crash_not_fixed"
                    else:
                        self._last_failure_reason = "build_failed"

                # Revert for next iteration
                if patch_plan and patch_plan.items:
                    revert_changes(patch_plan.items[0].source_path)

            except Exception as e:
                LOG.warning(f"Iteration {iteration + 1} failed: {e}")
                continue

        return False

    async def _get_initial_patch_plan(
        self,
        crash_output: str,
        function_source_info: FunctionSourceInfo,
        temperature: Optional[float] = None,
    ) -> Optional[PatchPlan]:
        """
        Generate initial patch using two-step prompting.

        Args:
            crash_output: Crash output
            function_source_info: Source info for functions
            temperature: LLM temperature

        Returns:
            PatchPlan if successful, None otherwise
        """
        # Prepare function source
        function_src = "\n\n".join(
            [item.function_src for item in function_source_info.items]
        )

        # Step 1: Root cause analysis
        prompt1 = ROOTCAUSE_PROMPT.format(
            stack_trace=crash_output[:8000],  # Truncate if needed
            function_src=function_src,
        )
        _ = await self._query_llm(prompt1, temperature=temperature)

        # Step 2: Generate patch
        prompt2 = FOLLOWUP_PATCH_PROMPT.format(fix_example="")
        response = await self._query_llm(prompt2, temperature=temperature)

        if not response:
            return None

        # Extract code from response
        try:
            new_function_src = extract_code(response)
        except LLMOutputFormatError as e:
            LOG.warning(f"Failed to extract code: {e}")
            return None

        self.result.patch_generated = True
        self.result.patch_content = new_function_src

        # Match to original function
        return self._match_patch_to_source(function_source_info, new_function_src)

    async def _get_refined_patch_plan(
        self,
        old_patch_plan: PatchPlan,
        temperature: Optional[float] = None,
    ) -> Optional[PatchPlan]:
        """
        Refine patch based on verification feedback.

        Args:
            old_patch_plan: Previous patch plan
            temperature: LLM temperature

        Returns:
            New PatchPlan if successful, None otherwise
        """
        # Build retry prompt based on failure reason
        if hasattr(self, "_last_failure_reason"):
            if self._last_failure_reason == "build_failed":
                # Include build errors if available
                build_errors = (
                    self.result.build_output[-2000:] if self.result.build_output else ""
                )
                prompt = RETRY_BUILD_ERROR_PROMPT.format(
                    build_errors_str=f"Build errors:\n```\n{build_errors}\n```\n"
                    if build_errors
                    else ""
                )
            else:
                prompt = RETRY_NOT_FIXED_PROMPT
        else:
            prompt = RETRY_NOT_FIXED_PROMPT

        response = await self._query_llm(prompt, temperature=temperature)

        if not response:
            return None

        try:
            new_function_src = extract_code(response)
        except LLMOutputFormatError:
            return None

        self.result.patch_content = new_function_src

        # Reuse the same source path and original function
        if old_patch_plan.items:
            old_item = old_patch_plan.items[0]
            return PatchPlan(
                items=[
                    PatchPlanItem(
                        source_path=old_item.source_path,
                        original_function_src=old_item.original_function_src,
                        new_function_src=new_function_src,
                    )
                ]
            )

        return None

    def _match_patch_to_source(
        self,
        function_source_info: FunctionSourceInfo,
        new_function_src: str,
    ) -> Optional[PatchPlan]:
        """
        Match the generated patch to the original source file.

        Args:
            function_source_info: Source info for functions
            new_function_src: New function source from LLM

        Returns:
            PatchPlan if match found, None otherwise
        """
        if len(function_source_info.items) == 1:
            # Single function - use it directly
            item = function_source_info.items[0]
            self.result.patched_file_path = item.source_path
            func_name = parse_function_name(item.function_src)
            self.result.patched_function = func_name or ""
            return PatchPlan(
                items=[
                    PatchPlanItem(
                        source_path=item.source_path,
                        original_function_src=item.function_src,
                        new_function_src=new_function_src,
                    )
                ]
            )

        # Multiple functions - match by function name
        new_func_name = parse_function_name(new_function_src)
        if not new_func_name:
            LOG.warning("Could not parse function name from LLM response")
            return None

        for item in function_source_info.items:
            orig_func_name = parse_function_name(item.function_src)
            if orig_func_name == new_func_name:
                self.result.patched_file_path = item.source_path
                self.result.patched_function = new_func_name
                return PatchPlan(
                    items=[
                        PatchPlanItem(
                            source_path=item.source_path,
                            original_function_src=item.function_src,
                            new_function_src=new_function_src,
                        )
                    ]
                )

        LOG.warning(f"Could not match function {new_func_name} to source")
        return None

    def _apply_patch_plan(self, patch_plan: PatchPlan) -> bool:
        """
        Apply a patch plan to the source files.

        Args:
            patch_plan: Patch plan to apply

        Returns:
            True if all patches applied successfully
        """
        for item in patch_plan.items:
            if not apply_patch(
                item.source_path,
                item.original_function_src,
                item.new_function_src,
            ):
                return False
        return True

    def _verify_build(self) -> bool:
        """
        Verify that the patched code builds.

        Returns:
            True if build succeeded
        """
        LOG.info("Verifying build...")
        result = self._run_command(["arvo", "compile"], timeout=300)
        self.result.build_output = result.stdout + result.stderr
        self.result.build_success = result.returncode == 0

        if self.result.build_success:
            LOG.info("Build succeeded")
        else:
            LOG.warning("Build failed")

        return self.result.build_success

    def _verify_crash_fixed(self) -> bool:
        """
        Verify that the original crash is fixed.

        Returns:
            True if crash no longer reproduces
        """
        LOG.info("Verifying crash is fixed...")
        result = self._run_command(["arvo"], timeout=120)
        self.result.verification_output = result.stdout + result.stderr

        # Check for ASAN errors
        self.result.crash_fixed = (
            result.returncode == 0
            and "ERROR: AddressSanitizer" not in self.result.verification_output
        )

        if self.result.crash_fixed:
            LOG.info("Crash fixed!")
        else:
            LOG.info("Crash still reproduces")

        return self.result.crash_fixed

    async def _query_llm(
        self,
        prompt: str,
        temperature: Optional[float] = None,
    ) -> str:
        """
        Query the LLM with conversation history.

        Args:
            prompt: User prompt
            temperature: Optional temperature override

        Returns:
            LLM response text
        """
        if not self.client:
            raise RuntimeError("Anthropic client not initialized")

        # Add to conversation history
        self._messages.append({"role": "user", "content": prompt})
        self.result.chat_history.append(f"USER: {prompt}")

        try:
            kwargs = {
                "model": self.model,
                "max_tokens": 4096,
                "system": SYSTEM_PROMPT,
                "messages": self._messages,
            }
            if temperature is not None:
                kwargs["temperature"] = temperature

            response = self.client.messages.create(**kwargs)

            self.result.llm_calls += 1
            self.result.llm_tokens_used += (
                response.usage.input_tokens + response.usage.output_tokens
            )

            response_text = response.content[0].text

            # Add response to conversation history
            self._messages.append({"role": "assistant", "content": response_text})
            self.result.chat_history.append(f"ASSISTANT: {response_text}")

            return response_text

        except Exception as e:
            LOG.error(f"LLM query failed: {e}")
            self.result.error = f"LLM query failed: {e}"
            return ""

    def _save_additional_results(self) -> None:
        """Save APB-specific results like chat history."""
        if self.result.chat_history:
            chat_file = self.output_dir / "chat.md"
            with open(chat_file, "w") as f:
                f.write("# Chat History\n\n")
                f.write(
                    f"## Case ID {self.result.case_id}, Status: {self.result.status.value}\n\n"
                )
                for i, msg in enumerate(self.result.chat_history):
                    f.write(f"### Message {i + 1}\n\n")
                    # Escape markdown headers to avoid conflicts
                    msg = msg.replace("###", "@@@")
                    msg = msg.replace("##", "@@")
                    msg = msg.replace("# ", "#### ")
                    msg = msg.replace("@@", "##### ")
                    f.write(msg + "\n\n")
