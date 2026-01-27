#!/usr/bin/env python3
"""
Automated analysis of LLM patch failures for the autopatching benchmark.

Features:
- Interactive TUI with arrow key navigation
- Concurrent analysis with streaming output
- Per-case logging
- Extended thinking support

Usage:
    # Interactive TUI
    python analyze_patch_failures.py tui --models claude-opus-4-5-20251101

    # Batch mode (no TUI)
    python analyze_patch_failures.py analyze --cases 35172

    # Dry run
    python analyze_patch_failures.py dry-run
"""

import json
import os
import logging
from pathlib import Path
from dataclasses import dataclass, asdict
from typing import Optional, Dict, Any, List
from enum import Enum
from datetime import datetime
import time
import threading

import typer
from rich.console import Console
from rich.table import Table
from rich import box
from dotenv import load_dotenv
import anthropic

# Load environment variables from .env file
load_dotenv(Path(__file__).parent.parent / ".env")

# Initialize Typer app
app = typer.Typer(
    name="analyze-patches",
    help="Analyze autopatching failures using Claude API",
    rich_markup_mode="rich",
)

# Rich console for output
console = Console()


class FailureCategory(str, Enum):
    """Categories of patch failures."""

    WRONG_FILE = "wrong_file"
    WRONG_FUNCTION = "wrong_function"
    PATCH_GEN_FAILED = "patch_gen_failed"
    WRONG_FIX_TYPE = "wrong_fix_type"
    INCOMPLETE_FIX = "incomplete_fix"
    SYMPTOM_MASKING = "symptom_masking"
    INTRODUCES_NEW_BUG = "introduces_new_bug"
    MEMORY_LEAK = "memory_leak"
    FALSE_POSITIVE_DD = "false_positive_dd"
    PRE_EXISTING_BUG = "pre_existing_bug"
    BETTER_THAN_GT = "better_than_ground_truth"
    NO_PATCH_GENERATED = "no_patch_generated"
    UNKNOWN = "unknown"


class AnalysisStatus(str, Enum):
    """Status of a case analysis."""

    PENDING = "pending"
    RUNNING = "running"
    STREAMING = "streaming"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


@dataclass
class CaseAnalysis:
    """Analysis result for a single case."""

    case_id: str
    model: str
    passed_qa_checks: bool
    full_fuzzing_passed: bool
    functionality_preserved: Optional[bool]
    error_running_debugging: Optional[str]
    failure_category: str
    summary: str
    detailed_analysis: str
    ground_truth_patch_location: str
    llm_patch_location: str
    root_cause_identified: bool
    correct_file: bool
    correct_function: bool
    ground_truth_patch_path: str
    llm_patch_path: str


@dataclass
class CaseState:
    """State of a case being analyzed."""

    case_id: str
    model: str
    status: AnalysisStatus = AnalysisStatus.PENDING
    current_activity: str = ""
    streaming_text: str = ""
    thinking_text: str = ""
    result: Optional[CaseAnalysis] = None
    error: Optional[str] = None
    start_time: Optional[float] = None
    end_time: Optional[float] = None
    log_file: Optional[Path] = None


ANALYSIS_PROMPT = """You are an expert security researcher analyzing LLM-generated patches for software vulnerabilities.

## Task
Analyze why an LLM's patch failed (or succeeded) compared to the ground truth patch. Classify the failure into categories.

## Context
- The autopatching benchmark tests LLM's ability to generate correct security patches
- A case can fail due to: full fuzzing finding crashes, or differential debugging showing functionality differences
- Some "failures" may be false positives where the LLM patch is actually correct or even better

## Input Data

### Case Information
- Case ID: {case_id}
- Model: {model}
- Passed QA Checks: {passed_qa_checks}
- Full Fuzzing Passed: {full_fuzzing_passed}
- Functionality Preserved: {functionality_preserved}
- Error Running Debugging: {error_running_debugging}

### Ground Truth Patch
File: {ground_truth_filename}
```
{ground_truth_patch}
```

### LLM's Patch
```
{llm_patch}
```

### Additional Context (if available)
{additional_context}

## Analysis Required

Please analyze:
1. **Root Cause**: What is the actual vulnerability being fixed?
2. **Ground Truth Approach**: How does the ground truth patch fix it?
3. **LLM Approach**: How does the LLM patch attempt to fix it?
4. **Comparison**: 
   - Is the LLM patch in the correct file?
   - Is the LLM patch in the correct function?
   - Does the LLM patch address the root cause?
5. **Classification**: Categorize the failure (or success)

## Output Format (JSON)
```json
{{
    "failure_category": "<one of: wrong_file, wrong_function, wrong_fix_type, incomplete_fix, symptom_masking, introduces_new_bug, memory_leak, false_positive_dd, pre_existing_bug, better_than_ground_truth, unknown>",
    "summary": "<one-line summary of the issue>",
    "detailed_analysis": "<detailed analysis in markdown format>",
    "root_cause_identified": <true/false - did LLM identify the root cause>,
    "correct_file": <true/false>,
    "correct_function": <true/false>,
    "ground_truth_patch_location": "<file:function>",
    "llm_patch_location": "<file:function>"
}}
```

Respond ONLY with the JSON object, no additional text.
"""

PATCH_GEN_FAILED_PROMPT = """You are an expert security researcher analyzing why an LLM failed to generate a working patch for a software vulnerability.

## Task
Analyze why the LLM's patch generation failed. The LLM attempted to fix the vulnerability but couldn't produce a working binary after multiple retries.

## Context
- The autopatching benchmark tests LLM's ability to generate correct security patches
- This case failed during patch generation - no valid binary was produced
- We have the LLM's conversation history showing what it tried

## Input Data

### Case Information
- Case ID: {case_id}
- Model: {model}
- Patch Generation Status: {patch_status}
- Max Status Reached: {max_status}
- Retry Rounds: {retry_rounds}
- Build Iterations: {build_iters}
- Fix Crash Iterations: {fix_crash_iters}
- Function LLM Tried to Patch: {llm_patched_function}
- File LLM Tried to Patch: {llm_patched_file}

### Ground Truth Patch
File: {ground_truth_filename}
```
{ground_truth_patch}
```

### LLM's Conversation History (showing its analysis and attempts)
```
{chat_history}
```

### Additional Context
{additional_context}

## Analysis Required

Please analyze:
1. **Actual Vulnerability**: What is the real vulnerability based on the ground truth patch?
2. **LLM's Diagnosis**: What did the LLM think was the root cause?
3. **Why It Failed**: 
   - Did the LLM identify the correct file?
   - Did the LLM identify the correct function?
   - Did the LLM understand the actual root cause?
   - Why couldn't the LLM produce a working fix?
4. **Classification**: Categorize the failure

## Output Format (JSON)
```json
{{
    "failure_category": "<one of: wrong_file, wrong_function, wrong_fix_type, incomplete_fix, symptom_masking, patch_gen_failed, unknown>",
    "summary": "<one-line summary of why patch generation failed>",
    "detailed_analysis": "<detailed analysis in markdown format>",
    "root_cause_identified": <true/false - did LLM correctly identify the root cause>,
    "correct_file": <true/false - did LLM try to patch the correct file>,
    "correct_function": <true/false - did LLM try to patch the correct function>,
    "ground_truth_patch_location": "<file:function>",
    "llm_patch_location": "<file:function that LLM tried to patch>"
}}
```

Respond ONLY with the JSON object, no additional text.
"""


class PatchAnalyzer:
    """Core analysis logic for patches."""

    def __init__(
        self,
        api_key: str,
        judge_responses_path: Path,
        output_dir: Path,
        files_dir: Path,
        arvo_meta_dir: Path,
        model: str = "claude-opus-4-20250514",
        use_thinking: bool = True,
    ):
        self.client = anthropic.Anthropic(api_key=api_key)
        self.judge_responses_path = judge_responses_path
        self.output_dir = output_dir
        self.files_dir = files_dir
        self.arvo_meta_dir = arvo_meta_dir
        self.model = model
        self.use_thinking = use_thinking

        # Create output directories
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.logs_dir = self.output_dir / "logs"
        self.logs_dir.mkdir(exist_ok=True)

    def load_judge_responses(self) -> Dict[str, Dict[str, Any]]:
        """Load the judge responses JSON."""
        with open(self.judge_responses_path) as f:
            return json.load(f)

    def setup_case_logger(self, case_id: str, model: str) -> tuple:
        """Set up a logger for a specific case."""
        log_dir = self.logs_dir / f"case_{case_id}"
        log_dir.mkdir(exist_ok=True)

        log_file = log_dir / f"{model}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"

        logger = logging.getLogger(f"case_{case_id}_{model}")
        logger.setLevel(logging.DEBUG)
        logger.handlers.clear()

        fh = logging.FileHandler(log_file)
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
        logger.addHandler(fh)

        return logger, log_file

    def _find_case_dir(self, case_id: str, model: str) -> Optional[Path]:
        """Find the case directory for a given case and model."""
        case_dirs = [
            self.files_dir / f"case_{case_id}" / model,
            self.files_dir.parent
            / "output_full_dd"
            / "files"
            / f"case_{case_id}"
            / model,
        ]
        for d in case_dirs:
            if d.exists():
                return d
        return None

    def get_ground_truth_patch(self, case_id: str) -> tuple:
        """Load ground truth patch from arvo_meta directory."""
        patch_path = self.arvo_meta_dir / f"{case_id}-patch.json"
        if not patch_path.exists():
            return "", f"Ground truth patch not found: {patch_path}"

        with open(patch_path) as f:
            data = json.load(f)

        if not data:
            return "", "Empty patch data"

        patches = []
        for item in data:
            filename = item.get("filename", "unknown")
            patch = item.get("patch", "")
            summary = item.get("summary", "")
            patches.append(f"File: {filename}\nSummary: {summary}\nPatch:\n{patch}")

        return "\n\n".join(patches), data[0].get(
            "filename", "unknown"
        ) if data else "unknown"

    def get_llm_patch(self, case_id: str, model: str) -> str:
        """Load LLM's patch from the case directory."""
        possible_paths = [
            self.files_dir / f"case_{case_id}" / model / "patch.patch",
            self.files_dir.parent
            / "output_full_dd"
            / "files"
            / f"case_{case_id}"
            / model
            / "patch.patch",
        ]

        for patch_path in possible_paths:
            if patch_path.exists():
                with open(patch_path) as f:
                    return f.read()

        return f"LLM patch not found. Searched: {[str(p) for p in possible_paths]}"

    def get_patch_gen_context(self, case_id: str, model: str) -> Dict[str, Any]:
        """Load patch generation context from report.json and chat.md."""
        case_dir = self._find_case_dir(case_id, model)
        if not case_dir:
            return {}

        context = {}

        # Load report.json
        report_path = case_dir / "report.json"
        if report_path.exists():
            try:
                with open(report_path) as f:
                    report = json.load(f)
                context["patch_status"] = report.get(
                    "patch_generation_status", "unknown"
                )
                context["max_status"] = report.get(
                    "max_patch_generation_status", "unknown"
                )
                context["retry_rounds"] = report.get("retry_round", 0)
                context["build_iters"] = report.get("build_iters", 0)
                context["fix_crash_iters"] = report.get("fix_crash_iters", 0)
                context["llm_patched_function"] = report.get(
                    "patched_function_name", "unknown"
                )
                context["llm_patched_file"] = report.get("patched_file_path", "unknown")
                context["exception"] = report.get("exception", "")
            except Exception:
                pass

        # Load chat.md
        chat_path = case_dir / "chat.md"
        if chat_path.exists():
            try:
                with open(chat_path) as f:
                    chat_content = f.read()
                if len(chat_content) > 8000:
                    chat_content = chat_content[:8000] + "\n\n... [truncated] ..."
                context["chat_history"] = chat_content
            except Exception:
                context["chat_history"] = "Could not load chat history"

        return context

    def get_additional_context(self, case_id: str, model: str) -> str:
        """Load additional context like log files, deltas, etc."""
        context_parts = []
        case_dir = self._find_case_dir(case_id, model)

        if not case_dir:
            return "No additional context available."

        # Load deltas
        deltas_path = case_dir / "list_of_deltas.json"
        if deltas_path.exists():
            try:
                with open(deltas_path) as f:
                    deltas = json.load(f)
                if deltas:
                    delta_summary = deltas[:10] if len(deltas) > 10 else deltas
                    context_parts.append(
                        f"### Differential Debugging Deltas (showing {len(delta_summary)} of {len(deltas)}):\n```json\n{json.dumps(delta_summary, indent=2)}\n```"
                    )
            except Exception:
                pass

        # Load log summary
        log_fix_path = case_dir / "log_fix.txt"
        if log_fix_path.exists():
            try:
                with open(log_fix_path) as f:
                    lines = f.readlines()
                relevant_lines = [
                    line
                    for line in lines
                    if any(
                        kw in line.lower()
                        for kw in [
                            "fuzzing",
                            "crash",
                            "functionality",
                            "differential",
                            "debugging",
                            "passed",
                            "failed",
                        ]
                    )
                ]
                if relevant_lines:
                    context_parts.append(
                        f"### Log Summary (relevant lines):\n```\n{''.join(relevant_lines[-20:])}\n```"
                    )
            except Exception:
                pass

        return (
            "\n\n".join(context_parts)
            if context_parts
            else "No additional context available."
        )

    def should_analyze_case(self, case_data: Dict[str, Any]) -> bool:
        """Determine if a case should be analyzed."""
        if case_data.get("patched_function_name_exists") is False:
            return True
        if case_data.get("passed_qa_checks") is False:
            return True
        if not case_data.get("full_fuzzing_passed", True):
            return True
        if case_data.get("functionality_preserved") is False:
            return True
        if case_data.get("error_running_debugging"):
            return True
        return False

    def is_already_analyzed(self, case_id: str, model: str) -> bool:
        """Check if a case has already been analyzed."""
        result_path = self.output_dir / f"case_{case_id}" / f"{model}_analysis.json"
        return result_path.exists()

    def load_existing_analysis(
        self, case_id: str, model: str
    ) -> Optional[CaseAnalysis]:
        """Load an existing analysis result."""
        result_path = self.output_dir / f"case_{case_id}" / f"{model}_analysis.json"
        if not result_path.exists():
            return None
        try:
            with open(result_path) as f:
                data = json.load(f)
            return CaseAnalysis(**data)
        except Exception:
            return None

    def analyze_case(
        self,
        case_id: str,
        model_name: str,
        case_data: Dict[str, Any],
        state: Optional[CaseState] = None,
        on_thinking: Optional[callable] = None,
        on_text: Optional[callable] = None,
    ) -> Optional[CaseAnalysis]:
        """Analyze a single case."""
        logger, log_file = self.setup_case_logger(case_id, model_name)
        if state:
            state.log_file = log_file
            state.status = AnalysisStatus.RUNNING
            state.current_activity = "Loading patches..."

        logger.info(f"Starting analysis for case {case_id}")

        # Get ground truth
        ground_truth_patch, gt_filename = self.get_ground_truth_patch(case_id)
        if not ground_truth_patch or "not found" in ground_truth_patch.lower():
            logger.warning("No ground truth patch found")
            if state:
                state.status = AnalysisStatus.SKIPPED
                state.error = "No ground truth patch"
            return None

        is_patch_gen_failed = case_data.get("patched_function_name_exists") is False

        if is_patch_gen_failed:
            if state:
                state.current_activity = "Loading chat history..."
            logger.info("Patch generation failed - analyzing chat history")
            pg_context = self.get_patch_gen_context(case_id, model_name)
            if not pg_context.get("chat_history"):
                logger.warning("No chat history available")
                if state:
                    state.status = AnalysisStatus.SKIPPED
                    state.error = "No chat history"
                return None

            additional_context = self.get_additional_context(case_id, model_name)
            if pg_context.get("exception"):
                additional_context += (
                    f"\n\n### Exception:\n```\n{pg_context['exception']}\n```"
                )

            prompt = PATCH_GEN_FAILED_PROMPT.format(
                case_id=case_id,
                model=model_name,
                patch_status=pg_context.get("patch_status", "unknown"),
                max_status=pg_context.get("max_status", "unknown"),
                retry_rounds=pg_context.get("retry_rounds", 0),
                build_iters=pg_context.get("build_iters", 0),
                fix_crash_iters=pg_context.get("fix_crash_iters", 0),
                llm_patched_function=pg_context.get("llm_patched_function", "unknown"),
                llm_patched_file=pg_context.get("llm_patched_file", "unknown"),
                ground_truth_filename=gt_filename,
                ground_truth_patch=ground_truth_patch,
                chat_history=pg_context.get("chat_history", "No chat history"),
                additional_context=additional_context,
            )
            llm_patch_path = (
                f"{pg_context.get('llm_patched_file', 'unknown')} (no binary)"
            )
        else:
            if state:
                state.current_activity = "Loading LLM patch..."
            llm_patch = self.get_llm_patch(case_id, model_name)
            if not llm_patch or "not found" in llm_patch.lower():
                logger.warning("No LLM patch found")
                if state:
                    state.status = AnalysisStatus.SKIPPED
                    state.error = "No LLM patch"
                return None

            additional_context = self.get_additional_context(case_id, model_name)

            prompt = ANALYSIS_PROMPT.format(
                case_id=case_id,
                model=model_name,
                passed_qa_checks=case_data.get("passed_qa_checks", "unknown"),
                full_fuzzing_passed=case_data.get("full_fuzzing_passed", "unknown"),
                functionality_preserved=case_data.get(
                    "functionality_preserved", "unknown"
                ),
                error_running_debugging=case_data.get(
                    "error_running_debugging", "none"
                ),
                ground_truth_filename=gt_filename,
                ground_truth_patch=ground_truth_patch,
                llm_patch=llm_patch,
                additional_context=additional_context,
            )
            llm_patch_path = str(
                self.files_dir / f"case_{case_id}" / model_name / "patch.patch"
            )

        # Call API
        if state:
            state.current_activity = "Calling API..."
            state.status = AnalysisStatus.STREAMING
        logger.info("Calling Claude API")

        try:
            api_params = {
                "model": self.model,
                "max_tokens": 16000,
                "messages": [{"role": "user", "content": prompt}],
            }

            if self.use_thinking:
                api_params["thinking"] = {
                    "type": "enabled",
                    "budget_tokens": 8000,
                }

            response_text = ""
            thinking_chars = 0
            response_chars = 0
            with self.client.messages.stream(**api_params) as stream:
                for event in stream:
                    if hasattr(event, "type"):
                        if event.type == "content_block_delta":
                            if hasattr(event.delta, "thinking"):
                                thinking_chars += len(event.delta.thinking)
                                if state:
                                    state.current_activity = (
                                        f"Thinking... ({thinking_chars} chars)"
                                    )
                                # Use callback if provided, otherwise update state directly
                                if on_thinking:
                                    on_thinking(event.delta.thinking)
                                elif state:
                                    state.thinking_text += event.delta.thinking
                                logger.debug(f"Thinking: {event.delta.thinking}")
                            elif hasattr(event.delta, "text"):
                                response_chars += len(event.delta.text)
                                if state:
                                    state.current_activity = (
                                        f"Responding... ({response_chars} chars)"
                                    )
                                # Use callback if provided, otherwise update state directly
                                if on_text:
                                    on_text(event.delta.text)
                                elif state:
                                    state.streaming_text += event.delta.text
                                logger.debug(f"Text: {event.delta.text}")

                message = stream.get_final_message()
                for block in message.content:
                    if hasattr(block, "text"):
                        response_text = block.text
                        break

            logger.info("API call completed")
            logger.debug(f"Response: {response_text[:500]}...")

            # Parse response
            if state:
                state.current_activity = "Parsing response..."
            if "```json" in response_text:
                response_text = response_text.split("```json")[1].split("```")[0]
            elif "```" in response_text:
                response_text = response_text.split("```")[1].split("```")[0]

            # Try to parse JSON, with fallback for malformed responses
            try:
                result = json.loads(response_text.strip())
            except json.JSONDecodeError as e:
                logger.warning(f"JSON parse error, attempting recovery: {e}")
                # Try to extract key fields using regex as fallback
                import re

                result = {}

                # Extract failure_category
                cat_match = re.search(
                    r'"failure_category"\s*:\s*"([^"]+)"', response_text
                )
                result["failure_category"] = (
                    cat_match.group(1) if cat_match else "unknown"
                )

                # Extract summary
                sum_match = re.search(
                    r'"summary"\s*:\s*"([^"]*(?:\\.[^"]*)*)"', response_text
                )
                result["summary"] = (
                    sum_match.group(1) if sum_match else "Parse error - see logs"
                )

                # Extract booleans
                for field in [
                    "root_cause_identified",
                    "correct_file",
                    "correct_function",
                ]:
                    match = re.search(
                        rf'"{field}"\s*:\s*(true|false)', response_text, re.IGNORECASE
                    )
                    result[field] = match.group(1).lower() == "true" if match else False

                # Extract locations
                for field in ["ground_truth_patch_location", "llm_patch_location"]:
                    match = re.search(rf'"{field}"\s*:\s*"([^"]*)"', response_text)
                    result[field] = match.group(1) if match else "unknown"

                # Set detailed_analysis to indicate recovery
                result["detailed_analysis"] = (
                    f"[JSON parse error - partial recovery]\n\nOriginal response excerpt:\n{response_text[:1000]}..."
                )

                logger.info(f"Recovered analysis: {result.get('failure_category')}")

            logger.info(f"Analysis complete: {result.get('failure_category')}")

            analysis = CaseAnalysis(
                case_id=case_id,
                model=model_name,
                passed_qa_checks=case_data.get("passed_qa_checks", False),
                full_fuzzing_passed=case_data.get("full_fuzzing_passed", False),
                functionality_preserved=case_data.get("functionality_preserved"),
                error_running_debugging=case_data.get("error_running_debugging"),
                failure_category=result.get("failure_category", "unknown"),
                summary=result.get("summary", ""),
                detailed_analysis=result.get("detailed_analysis", ""),
                ground_truth_patch_location=result.get(
                    "ground_truth_patch_location", ""
                ),
                llm_patch_location=result.get("llm_patch_location", ""),
                root_cause_identified=result.get("root_cause_identified", False),
                correct_file=result.get("correct_file", False),
                correct_function=result.get("correct_function", False),
                ground_truth_patch_path=str(
                    self.arvo_meta_dir / f"{case_id}-patch.json"
                ),
                llm_patch_path=llm_patch_path,
            )

            if state:
                state.result = analysis
                state.status = AnalysisStatus.COMPLETED

            return analysis

        except json.JSONDecodeError as e:
            logger.error(f"JSON parse error: {e}")
            if state:
                state.status = AnalysisStatus.FAILED
                state.error = f"JSON parse error: {e}"
            return None
        except Exception as e:
            logger.error(f"API error: {e}")
            if state:
                state.status = AnalysisStatus.FAILED
                state.error = str(e)
            return None

    def save_case_report(self, analysis: CaseAnalysis):
        """Save individual case report."""
        case_output_dir = self.output_dir / f"case_{analysis.case_id}"
        case_output_dir.mkdir(parents=True, exist_ok=True)

        # JSON report
        report_path = case_output_dir / f"{analysis.model}_analysis.json"
        with open(report_path, "w") as f:
            json.dump(asdict(analysis), f, indent=2)

        # Markdown report
        md_path = case_output_dir / f"{analysis.model}_analysis.md"
        with open(md_path, "w") as f:
            f.write(f"# Analysis: Case {analysis.case_id} - {analysis.model}\n\n")
            f.write(f"## Summary\n{analysis.summary}\n\n")
            f.write(f"## Failure Category\n`{analysis.failure_category}`\n\n")
            f.write("## Status\n")
            f.write(f"- Passed QA Checks: {analysis.passed_qa_checks}\n")
            f.write(f"- Full Fuzzing Passed: {analysis.full_fuzzing_passed}\n")
            f.write(f"- Functionality Preserved: {analysis.functionality_preserved}\n")
            f.write(
                f"- Error Running Debugging: {analysis.error_running_debugging}\n\n"
            )
            f.write("## Patch Locations\n")
            f.write(f"- Ground Truth: `{analysis.ground_truth_patch_location}`\n")
            f.write(f"- LLM Patch: `{analysis.llm_patch_location}`\n\n")
            f.write("## Analysis\n")
            f.write(f"- Root Cause Identified: {analysis.root_cause_identified}\n")
            f.write(f"- Correct File: {analysis.correct_file}\n")
            f.write(f"- Correct Function: {analysis.correct_function}\n\n")
            f.write(f"## Detailed Analysis\n{analysis.detailed_analysis}\n")

        return report_path, md_path


# ============================================================================
# Textual TUI App
# ============================================================================

try:
    from textual.app import App, ComposeResult
    from textual.widgets import (
        Header,
        Footer,
        DataTable,
        Static,
        RichLog,
        TabbedContent,
        TabPane,
    )
    from textual.containers import Container, Vertical
    from textual.binding import Binding
    from textual.reactive import reactive
    from textual import work

    TEXTUAL_AVAILABLE = True

    class AnalysisTUI(App):
        """Interactive TUI for monitoring analysis progress."""

        CSS = """
        Screen {
            layout: grid;
            grid-size: 2 2;
            grid-columns: 1fr 2fr;
            grid-rows: auto 1fr;
        }
        
        #header-container {
            column-span: 2;
            height: 3;
        }
        
        #cases-table {
            height: 100%;
            border: solid green;
        }
        
        #details-container {
            height: 100%;
        }
        
        RichLog {
            height: 1fr;
            scrollbar-gutter: stable;
            overflow-y: auto;
        }
        
        #log-output {
            border: solid cyan;
        }
        
        #thinking-output {
            border: solid yellow;
        }
        
        #response-output {
            border: solid blue;
        }
        
        DataTable > .datatable--cursor {
            background: $accent;
        }
        """

        BINDINGS = [
            Binding("q", "quit", "Quit"),
            Binding("t", "toggle_tab", "Toggle Tab"),
            Binding("up", "cursor_up", "Up", show=False),
            Binding("down", "cursor_down", "Down", show=False),
        ]

        selected_case_key: reactive[str | None] = reactive(None)

        def __init__(
            self,
            analyzer: PatchAnalyzer,
            cases: Dict[str, CaseState],
            judge_responses: Dict[str, Dict[str, Any]],
            max_concurrent: int = 3,
            view_only: bool = False,
            **kwargs,
        ):
            super().__init__(**kwargs)
            self.analyzer = analyzer
            self.cases = cases
            self.judge_responses = judge_responses
            self.max_concurrent = max_concurrent
            self.view_only = view_only
            self.lock = threading.Lock()
            self._update_timer = None
            self._col_keys = {}  # Store column keys for updates

        def compose(self) -> ComposeResult:
            yield Header()
            with Container(id="header-container"):
                yield Static(
                    f"[bold]Autopatch Analyzer[/] | {len(self.cases)} cases | [dim]↑↓[/] navigate | [dim]t[/] toggle tab | [dim]q[/] quit",
                    id="title",
                )

            yield DataTable(id="cases-table")

            with Vertical(id="details-container"):
                with TabbedContent():
                    with TabPane("Thinking", id="tab-thinking"):
                        yield RichLog(
                            id="thinking-output", wrap=True, highlight=True, markup=True
                        )
                    with TabPane("Response", id="tab-response"):
                        yield RichLog(
                            id="response-output", wrap=True, highlight=True, markup=True
                        )
                    with TabPane("Log", id="tab-log"):
                        yield RichLog(id="log-output", wrap=True, highlight=True)

            yield Footer()

        def on_mount(self) -> None:
            """Set up the data table and auto-start analysis."""
            table = self.query_one(DataTable)
            # Store column keys for later updates
            col_keys = table.add_columns("Case ID", "Model", "Status", "Activity")
            self._col_keys = {
                "case_id": col_keys[0],
                "model": col_keys[1],
                "status": col_keys[2],
                "activity": col_keys[3],
            }
            table.cursor_type = "row"

            for key, state in self.cases.items():
                table.add_row(
                    state.case_id,
                    state.model[:20],
                    state.status.value,
                    state.current_activity[:30] if state.current_activity else "",
                    key=key,
                )

            # Select first case
            if self.cases:
                first_key = list(self.cases.keys())[0]
                self.selected_case_key = first_key

            # Start periodic UI updates
            self._update_timer = self.set_interval(0.5, self.periodic_update)

            # Auto-start analysis
            self.run_analysis()

        def periodic_update(self) -> None:
            """Periodically update UI."""
            self.update_table()
            self.update_details()

        def on_data_table_row_highlighted(
            self, event: DataTable.RowHighlighted
        ) -> None:
            """Handle row highlight (cursor movement)."""
            if event.row_key:
                self.selected_case_key = event.row_key.value
                self.update_details()

        def update_table(self) -> None:
            """Update the table with current state."""
            table = self.query_one(DataTable)
            status_col = self._col_keys.get("status")
            activity_col = self._col_keys.get("activity")

            if not status_col or not activity_col:
                return

            for key, state in self.cases.items():
                try:
                    status_display = state.status.value
                    if state.status == AnalysisStatus.STREAMING:
                        status_display = "🔄 streaming"
                    elif state.status == AnalysisStatus.COMPLETED:
                        status_display = "✓ done"
                    elif state.status == AnalysisStatus.FAILED:
                        status_display = "✗ failed"
                    elif state.status == AnalysisStatus.RUNNING:
                        status_display = "⏳ running"

                    # Use stored column keys
                    table.update_cell(key, status_col, status_display)
                    activity = (
                        state.current_activity[:30] if state.current_activity else ""
                    )
                    table.update_cell(key, activity_col, activity)
                except Exception:
                    # Ignore update errors (row may not exist yet)
                    pass

        def update_details(self) -> None:
            """Update the details panel for selected case."""
            if not self.selected_case_key:
                return

            state = self.cases.get(self.selected_case_key)
            if not state:
                return

            thinking_log = self.query_one("#thinking-output", RichLog)
            response_log = self.query_one("#response-output", RichLog)
            log_output = self.query_one("#log-output", RichLog)

            # Update thinking - show last portion with word wrap
            if state.thinking_text:
                thinking_log.clear()
                # Write text which will auto-wrap
                thinking_log.write(state.thinking_text[-4000:])

            # Update response - show last portion
            if state.streaming_text:
                response_log.clear()
                response_log.write(state.streaming_text[-4000:])

            # Update log output - show log file content or status info
            log_output.clear()
            log_lines = []
            log_lines.append(f"Case: {state.case_id}")
            log_lines.append(f"Model: {state.model}")
            log_lines.append(f"Status: {state.status.value}")
            if state.error:
                log_lines.append(f"Error: {state.error}")
            if state.log_file and state.log_file.exists():
                log_lines.append(f"Log file: {state.log_file}")
                try:
                    with open(state.log_file) as f:
                        content = f.read()
                    # Show last 2000 chars of log
                    log_lines.append("--- Log Content ---")
                    log_lines.append(
                        content[-2000:] if len(content) > 2000 else content
                    )
                except Exception as e:
                    log_lines.append(f"Error reading log: {e}")
            if state.result:
                log_lines.append("--- Result ---")
                log_lines.append(f"Category: {state.result.failure_category}")
                log_lines.append(f"Summary: {state.result.summary}")
            log_output.write("\n".join(log_lines))

        @work(thread=True)
        def run_analysis(self) -> None:
            """Run analysis in background threads."""
            import concurrent.futures

            def analyze_one(key: str, state: CaseState):
                # Skip already completed cases
                if state.status == AnalysisStatus.COMPLETED:
                    return state.result

                case_id = state.case_id
                model_name = state.model

                # Find case data
                case_data = self.judge_responses.get(model_name, {}).get(case_id, {})

                def on_thinking(text):
                    with self.lock:
                        state.thinking_text += text

                def on_text(text):
                    with self.lock:
                        state.streaming_text += text

                state.start_time = time.time()
                try:
                    analysis = self.analyzer.analyze_case(
                        case_id,
                        model_name,
                        case_data,
                        state,
                        on_thinking=on_thinking,
                        on_text=on_text,
                    )
                    state.end_time = time.time()

                    if analysis:
                        self.analyzer.save_case_report(analysis)
                        state.current_activity = f"Done: {analysis.failure_category}"
                    return analysis
                except Exception as e:
                    state.status = AnalysisStatus.FAILED
                    state.error = str(e)
                    state.current_activity = f"Error: {str(e)[:20]}"
                    return None

            # Only submit tasks for pending cases
            pending_cases = {
                key: state
                for key, state in self.cases.items()
                if state.status != AnalysisStatus.COMPLETED
            }

            if not pending_cases:
                self.call_from_thread(self.notify, "All cases already analyzed!")
                return

            with concurrent.futures.ThreadPoolExecutor(
                max_workers=self.max_concurrent
            ) as executor:
                futures = {
                    executor.submit(analyze_one, key, state): key
                    for key, state in pending_cases.items()
                }
                for future in concurrent.futures.as_completed(futures):
                    key = futures[future]
                    try:
                        future.result()
                    except Exception as e:
                        self.cases[key].status = AnalysisStatus.FAILED
                        self.cases[key].error = str(e)

            self.call_from_thread(self.notify, "Analysis complete!")

        def action_toggle_tab(self) -> None:
            """Toggle between tabs."""
            tabbed = self.query_one(TabbedContent)
            if tabbed.active == "tab-thinking":
                tabbed.active = "tab-response"
            elif tabbed.active == "tab-response":
                tabbed.active = "tab-log"
            else:
                tabbed.active = "tab-thinking"

except ImportError:
    TEXTUAL_AVAILABLE = False


# ============================================================================
# CLI Commands
# ============================================================================


@app.command()
def analyze(
    models: Optional[List[str]] = typer.Option(
        None, "--models", "-m", help="Filter to specific models"
    ),
    cases: Optional[List[str]] = typer.Option(
        None, "--cases", "-c", help="Filter to specific case IDs"
    ),
    analyze_all: bool = typer.Option(
        False, "--all", "-a", help="Analyze all cases, not just failures"
    ),
    resume: bool = typer.Option(
        True,
        "--resume/--no-resume",
        "-r",
        help="Skip already analyzed cases (default: True)",
    ),
    model: str = typer.Option(
        "claude-opus-4-20250514", "--model", help="Claude model for analysis"
    ),
    no_thinking: bool = typer.Option(
        False, "--no-thinking", help="Disable extended thinking"
    ),
    max_concurrent: int = typer.Option(
        3, "--concurrent", "-j", help="Max concurrent analyses"
    ),
    sequential: bool = typer.Option(
        False, "--sequential", "-s", help="Run sequentially (for debugging)"
    ),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose output"),
    judge_responses: Path = typer.Option(
        Path("/data/autopatch/output_full_dd_v4/judge_responses.json"),
        "--judge-responses",
        help="Path to judge_responses.json",
    ),
    output_dir: Path = typer.Option(
        Path("/data/autopatch/output_full_dd_v4/analysis"),
        "--output-dir",
        "-o",
        help="Output directory",
    ),
    files_dir: Path = typer.Option(
        Path("/data/autopatch/output_full_dd/files"),
        "--files-dir",
        help="Directory containing case files",
    ),
    arvo_meta_dir: Path = typer.Option(
        Path(
            "/home/camyang/PurpleLlama/CybersecurityBenchmarks/datasets/autopatch/arvo_meta"
        ),
        "--arvo-meta-dir",
        help="Directory containing ground truth patches",
    ),
):
    """
    Analyze autopatching failures (batch mode with progress output).

    Examples:
        analyze -c 35172                    # Analyze single case
        analyze -m claude-opus-4-5-20251101 # Analyze all failures for Opus
        analyze --all                       # Analyze everything
    """
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        console.print("[red]Error: ANTHROPIC_API_KEY not set[/]")
        raise typer.Exit(1)

    analyzer = PatchAnalyzer(
        api_key=api_key,
        judge_responses_path=judge_responses,
        output_dir=output_dir,
        files_dir=files_dir,
        arvo_meta_dir=arvo_meta_dir,
        model=model,
        use_thinking=not no_thinking,
    )

    console.print("[bold]Loading judge responses...[/]")
    judge_data = analyzer.load_judge_responses()

    if models:
        judge_data = {m: v for m, v in judge_data.items() if m in models}

    # Build case list
    cases_to_analyze = []
    skipped_count = 0
    for model_name, model_cases in judge_data.items():
        filtered_cases = model_cases
        if cases:
            filtered_cases = {c: v for c, v in model_cases.items() if c in cases}

        for case_id, case_data in filtered_cases.items():
            if not analyze_all and not analyzer.should_analyze_case(case_data):
                continue
            # Skip already analyzed cases if resume is enabled
            if resume and analyzer.is_already_analyzed(case_id, model_name):
                skipped_count += 1
                continue
            cases_to_analyze.append((case_id, model_name, case_data))

    if skipped_count > 0:
        console.print(
            f"[dim]Skipping {skipped_count} already analyzed cases (use --no-resume to re-analyze)[/]"
        )

    if not cases_to_analyze:
        console.print("[yellow]No cases to analyze - all done![/]")
        return

    console.print(f"[bold]Found {len(cases_to_analyze)} cases to analyze[/]")

    results = {"completed": 0, "failed": 0, "skipped": 0, "by_category": {}}

    if sequential:
        # Sequential mode for debugging
        for idx, (case_id, model_name, case_data) in enumerate(cases_to_analyze, 1):
            console.print(
                f"\n[cyan][{idx}/{len(cases_to_analyze)}][/] Analyzing case {case_id}..."
            )

            def on_text(text):
                if verbose:
                    console.print(text, end="")

            def on_thinking(text):
                if verbose:
                    console.print(f"[dim]{text}[/]", end="")

            try:
                analysis = analyzer.analyze_case(
                    case_id,
                    model_name,
                    case_data,
                    on_text=on_text if verbose else None,
                    on_thinking=on_thinking if verbose else None,
                )
                if analysis:
                    analyzer.save_case_report(analysis)
                    results["completed"] += 1
                    cat = analysis.failure_category
                    results["by_category"][cat] = results["by_category"].get(cat, 0) + 1
                    console.print(
                        f"[green]✓[/] {case_id}: {analysis.failure_category} - {analysis.summary[:60]}"
                    )
                else:
                    results["skipped"] += 1
                    console.print(f"[yellow]○[/] {case_id}: skipped")
            except Exception as e:
                results["failed"] += 1
                console.print(f"[red]✗[/] {case_id}: {str(e)}")
                if verbose:
                    import traceback

                    console.print(traceback.format_exc())
    else:
        # Parallel mode with progress bar
        from rich.progress import (
            Progress,
            SpinnerColumn,
            TextColumn,
            BarColumn,
            TimeElapsedColumn,
        )

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
            console=console,
        ) as progress:
            task = progress.add_task("Analyzing...", total=len(cases_to_analyze))

            import concurrent.futures

            with concurrent.futures.ThreadPoolExecutor(
                max_workers=max_concurrent
            ) as executor:
                futures = {}
                for case_id, model_name, case_data in cases_to_analyze:
                    future = executor.submit(
                        analyzer.analyze_case, case_id, model_name, case_data
                    )
                    futures[future] = (case_id, model_name)

                for future in concurrent.futures.as_completed(futures):
                    case_id, model_name = futures[future]
                    try:
                        analysis = future.result()
                        if analysis:
                            analyzer.save_case_report(analysis)
                            results["completed"] += 1
                            cat = analysis.failure_category
                            results["by_category"][cat] = (
                                results["by_category"].get(cat, 0) + 1
                            )
                            progress.update(
                                task,
                                description=f"[green]✓[/] {case_id}: {analysis.failure_category}",
                            )
                        else:
                            results["skipped"] += 1
                            progress.update(
                                task, description=f"[yellow]○[/] {case_id}: skipped"
                            )
                    except Exception as e:
                        results["failed"] += 1
                        progress.update(
                            task, description=f"[red]✗[/] {case_id}: {str(e)[:30]}"
                        )

                    progress.advance(task)

    # Print summary
    console.print("\n[bold]Analysis Summary[/]")
    table = Table(title="Results by Category", box=box.ROUNDED)
    table.add_column("Category", style="cyan")
    table.add_column("Count", justify="right")

    for cat, count in sorted(results["by_category"].items(), key=lambda x: -x[1]):
        table.add_row(cat, str(count))

    console.print(table)
    console.print(
        f"\nCompleted: {results['completed']} | Failed: {results['failed']} | Skipped: {results['skipped']}"
    )
    console.print(f"Results saved to: {output_dir}")

    # Save summary
    summary_path = output_dir / "analysis_summary.json"
    with open(summary_path, "w") as f:
        json.dump(results, f, indent=2)


@app.command()
def tui(
    models: Optional[List[str]] = typer.Option(
        None, "--models", "-m", help="Filter to specific models"
    ),
    cases: Optional[List[str]] = typer.Option(
        None, "--cases", "-c", help="Filter to specific case IDs"
    ),
    analyze_all: bool = typer.Option(False, "--all", "-a", help="Include all cases"),
    resume: bool = typer.Option(
        True,
        "--resume/--no-resume",
        "-r",
        help="Skip already analyzed cases (default: True)",
    ),
    model: str = typer.Option(
        "claude-opus-4-20250514", "--model", help="Claude model for analysis"
    ),
    no_thinking: bool = typer.Option(
        False, "--no-thinking", help="Disable extended thinking"
    ),
    max_concurrent: int = typer.Option(
        3, "--concurrent", "-j", help="Max concurrent analyses"
    ),
    judge_responses: Path = typer.Option(
        Path("/data/autopatch/output_full_dd_v4/judge_responses.json"),
        "--judge-responses",
        help="Path to judge_responses.json",
    ),
    output_dir: Path = typer.Option(
        Path("/data/autopatch/output_full_dd_v4/analysis"),
        "--output-dir",
        "-o",
        help="Output directory",
    ),
    files_dir: Path = typer.Option(
        Path("/data/autopatch/output_full_dd/files"),
        "--files-dir",
        help="Directory containing case files",
    ),
    arvo_meta_dir: Path = typer.Option(
        Path(
            "/home/camyang/PurpleLlama/CybersecurityBenchmarks/datasets/autopatch/arvo_meta"
        ),
        "--arvo-meta-dir",
        help="Directory containing ground truth patches",
    ),
):
    """
    Launch interactive TUI for monitoring analysis.

    Analysis starts automatically. Use ↑↓ to navigate cases, 't' to toggle tabs.
    """
    if not TEXTUAL_AVAILABLE:
        console.print("[red]Error: textual not installed. Run: pip install textual[/]")
        raise typer.Exit(1)

    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        console.print("[red]Error: ANTHROPIC_API_KEY not set[/]")
        raise typer.Exit(1)

    analyzer = PatchAnalyzer(
        api_key=api_key,
        judge_responses_path=judge_responses,
        output_dir=output_dir,
        files_dir=files_dir,
        arvo_meta_dir=arvo_meta_dir,
        model=model,
        use_thinking=not no_thinking,
    )

    # Load judge responses
    judge_data = analyzer.load_judge_responses()
    if models:
        judge_data = {m: v for m, v in judge_data.items() if m in models}

    # Build case states
    case_states: Dict[str, CaseState] = {}
    already_done_count = 0
    pending_count = 0
    for model_name, model_cases in judge_data.items():
        filtered_cases = model_cases
        if cases:
            filtered_cases = {c: v for c, v in model_cases.items() if c in cases}

        for case_id, case_data in filtered_cases.items():
            if not analyze_all and not analyzer.should_analyze_case(case_data):
                continue
            key = f"{case_id}_{model_name}"
            state = CaseState(case_id=case_id, model=model_name)

            # Check if already analyzed - load results if resume enabled
            if resume and analyzer.is_already_analyzed(case_id, model_name):
                existing = analyzer.load_existing_analysis(case_id, model_name)
                if existing:
                    state.status = AnalysisStatus.COMPLETED
                    state.result = existing
                    state.current_activity = f"Done: {existing.failure_category}"
                    already_done_count += 1
            else:
                pending_count += 1

            case_states[key] = state

    if already_done_count > 0:
        console.print(f"[dim]Loaded {already_done_count} already analyzed cases[/]")
    console.print(f"[bold]{pending_count} cases pending analysis[/]")

    if not case_states:
        console.print("[yellow]No cases match the criteria[/]")
        return

    if pending_count == 0:
        console.print(
            "[green]All cases already analyzed! Use --no-resume to re-analyze.[/]"
        )

    # Run the TUI
    app_instance = AnalysisTUI(
        analyzer, case_states, judge_data, max_concurrent=max_concurrent
    )
    app_instance.run()


@app.command()
def dry_run(
    models: Optional[List[str]] = typer.Option(
        None, "--models", "-m", help="Filter to specific models"
    ),
    cases: Optional[List[str]] = typer.Option(
        None, "--cases", "-c", help="Filter to specific case IDs"
    ),
    analyze_all: bool = typer.Option(False, "--all", "-a", help="Include all cases"),
    judge_responses: Path = typer.Option(
        Path("/data/autopatch/output_full_dd_v4/judge_responses.json"),
        "--judge-responses",
        help="Path to judge_responses.json",
    ),
    files_dir: Path = typer.Option(
        Path("/data/autopatch/output_full_dd/files"),
        "--files-dir",
        help="Directory containing case files",
    ),
    arvo_meta_dir: Path = typer.Option(
        Path(
            "/home/camyang/PurpleLlama/CybersecurityBenchmarks/datasets/autopatch/arvo_meta"
        ),
        "--arvo-meta-dir",
        help="Directory containing ground truth patches",
    ),
):
    """
    List cases that would be analyzed without calling the API.
    """
    with open(judge_responses) as f:
        judge_data = json.load(f)

    if models:
        judge_data = {m: v for m, v in judge_data.items() if m in models}

    table = Table(title="Cases to Analyze", box=box.ROUNDED)
    table.add_column("Case ID", style="cyan")
    table.add_column("Model")
    table.add_column("GT", width=3)
    table.add_column("LLM", width=4)
    table.add_column("Reason")

    count = 0
    for model_name, model_cases in judge_data.items():
        cases_to_check = model_cases
        if cases:
            cases_to_check = {c: v for c, v in model_cases.items() if c in cases}

        for case_id, case_data in cases_to_check.items():
            # Check if should analyze
            should_analyze = (
                case_data.get("patched_function_name_exists") is False
                or case_data.get("passed_qa_checks") is False
                or not case_data.get("full_fuzzing_passed", True)
                or case_data.get("functionality_preserved") is False
                or case_data.get("error_running_debugging")
            )

            if not analyze_all and not should_analyze:
                continue

            # Check file existence
            gt_path = arvo_meta_dir / f"{case_id}-patch.json"
            gt_found = "✓" if gt_path.exists() else "✗"

            llm_paths = [
                files_dir / f"case_{case_id}" / model_name / "patch.patch",
                files_dir.parent
                / "output_full_dd"
                / "files"
                / f"case_{case_id}"
                / model_name
                / "patch.patch",
            ]
            llm_found = "✓" if any(p.exists() for p in llm_paths) else "✗"

            reasons = []
            if case_data.get("patched_function_name_exists") is False:
                reasons.append("no_binary")
            if not case_data.get("full_fuzzing_passed", True):
                reasons.append("fuzzing_failed")
            if case_data.get("functionality_preserved") is False:
                reasons.append("func_not_preserved")
            if case_data.get("error_running_debugging"):
                reasons.append("dd_error")

            table.add_row(
                case_id,
                model_name,
                gt_found,
                llm_found,
                ", ".join(reasons) or "unknown",
            )
            count += 1

    console.print(table)
    console.print(f"\n[bold]Total cases: {count}[/]")


@app.command()
def view_logs(
    case_id: str = typer.Argument(..., help="Case ID to view logs for"),
    output_dir: Path = typer.Option(
        Path("/data/autopatch/output_full_dd_v4/analysis"),
        "--output-dir",
        "-o",
    ),
    follow: bool = typer.Option(False, "-f", "--follow", help="Follow the log file"),
):
    """View logs for a specific case."""
    log_dir = output_dir / "logs" / f"case_{case_id}"
    if not log_dir.exists():
        console.print(f"[yellow]No logs found for case {case_id}[/]")
        return

    log_files = list(log_dir.glob("*.log"))
    if not log_files:
        console.print(f"[yellow]No log files in {log_dir}[/]")
        return

    # Show most recent log
    latest = sorted(log_files, key=lambda f: f.stat().st_mtime)[-1]
    console.print(f"[bold cyan]--- {latest.name} ---[/]")

    if follow:
        import subprocess

        subprocess.run(["tail", "-f", str(latest)])
    else:
        with open(latest) as f:
            console.print(f.read())


@app.command()
def summary(
    output_dir: Path = typer.Option(
        Path("/data/autopatch/output_full_dd_v4/analysis"),
        "--output-dir",
        "-o",
    ),
):
    """Show summary of all analyzed cases."""
    summary_path = output_dir / "analysis_summary.json"
    if not summary_path.exists():
        console.print("[yellow]No summary found. Run analyze first.[/]")
        return

    with open(summary_path) as f:
        data = json.load(f)

    table = Table(title="Analysis Summary", box=box.ROUNDED)
    table.add_column("Category", style="cyan")
    table.add_column("Count", justify="right")

    for cat, count in sorted(data.get("by_category", {}).items(), key=lambda x: -x[1]):
        table.add_row(cat, str(count))

    console.print(table)
    console.print(
        f"\nTotal: {data.get('completed', 0) + data.get('failed', 0) + data.get('skipped', 0)}"
    )
    console.print(
        f"Completed: {data.get('completed', 0)} | Failed: {data.get('failed', 0)} | Skipped: {data.get('skipped', 0)}"
    )


@app.command()
def plot(
    output_dir: Path = typer.Option(
        Path("/data/autopatch/output_full_dd_v4/analysis"),
        "--output-dir",
        "-o",
    ),
    judge_responses: Path = typer.Option(
        Path("/data/autopatch/output_full_dd_v4/judge_responses.json"),
        "--judge-responses",
        help="Path to judge_responses.json (for correctly fixed cases)",
    ),
    models: Optional[List[str]] = typer.Option(
        None, "--models", "-m", help="Filter to specific models"
    ),
    output_file: Optional[Path] = typer.Option(
        None, "--output", "-f", help="Save plot to file (PNG, PDF, SVG)"
    ),
    show: bool = typer.Option(True, "--show/--no-show", help="Display the plot"),
    stacked: bool = typer.Option(
        False, "--stacked", "-s", help="Use stacked bar chart"
    ),
):
    """
    Plot histogram of failure categories (including correctly fixed cases).

    Examples:
        plot                           # Show plot for all models
        plot -f failures.png           # Save to file
        plot -m claude-opus-4-5-20251101  # Single model
        plot --stacked                 # Stacked bar chart comparing models
    """
    try:
        import matplotlib.pyplot as plt
        import pandas as pd
    except ImportError:
        console.print(
            "[red]Error: matplotlib and pandas required. Run: pip install matplotlib pandas[/]"
        )
        raise typer.Exit(1)

    # Load judge_responses to categorize ALL cases
    judge_case_status = {}  # (case_id, model) -> category
    if judge_responses.exists():
        with open(judge_responses) as f:
            judge_data = json.load(f)
        for model_name, model_cases in judge_data.items():
            if models and model_name not in models:
                continue
            for case_id, case_data in model_cases.items():
                key = (case_id, model_name)
                # Check if passed all criteria (correctly fixed)
                if (
                    case_data.get("patched_function_name_exists", True)
                    and case_data.get("passed_qa_checks", False)
                    and case_data.get("full_fuzzing_passed", False)
                    and case_data.get("functionality_preserved", False)
                ):
                    judge_case_status[key] = "correctly_fixed"
                elif not case_data.get("passed_qa_checks", True):
                    # Container health check failed - not LLM's fault
                    judge_case_status[key] = "qa_check_failed"
                elif case_data.get("error_running_debugging"):
                    # DD infrastructure error
                    judge_case_status[key] = "dd_infra_error"
                else:
                    # Failed case that should have been analyzed
                    judge_case_status[key] = "needs_analysis"

    # Collect all analysis results
    results = []
    analyzed_cases = set()  # Track which cases we've seen

    for case_dir in output_dir.glob("case_*"):
        if not case_dir.is_dir():
            continue
        case_id = case_dir.name.replace("case_", "")

        for analysis_file in case_dir.glob("*_analysis.json"):
            model_name = analysis_file.stem.replace("_analysis", "")
            if models and model_name not in models:
                continue

            analyzed_cases.add((case_id, model_name))

            try:
                with open(analysis_file) as f:
                    data = json.load(f)
                results.append(
                    {
                        "case_id": case_id,
                        "model": model_name,
                        "failure_category": data.get("failure_category", "unknown"),
                        "correct_file": data.get("correct_file", False),
                        "correct_function": data.get("correct_function", False),
                        "root_cause_identified": data.get(
                            "root_cause_identified", False
                        ),
                    }
                )
            except Exception as e:
                console.print(
                    f"[yellow]Warning: Could not load {analysis_file}: {e}[/]"
                )

    # Add cases that weren't analyzed but have a known status from judge_responses
    for (case_id, model_name), status in judge_case_status.items():
        if (case_id, model_name) not in analyzed_cases:
            if status == "correctly_fixed":
                results.append(
                    {
                        "case_id": case_id,
                        "model": model_name,
                        "failure_category": "correctly_fixed",
                        "correct_file": True,
                        "correct_function": True,
                        "root_cause_identified": True,
                    }
                )
            elif status == "qa_check_failed":
                results.append(
                    {
                        "case_id": case_id,
                        "model": model_name,
                        "failure_category": "qa_check_failed",
                        "correct_file": None,
                        "correct_function": None,
                        "root_cause_identified": None,
                    }
                )
            elif status == "dd_infra_error":
                results.append(
                    {
                        "case_id": case_id,
                        "model": model_name,
                        "failure_category": "dd_infra_error",
                        "correct_file": None,
                        "correct_function": None,
                        "root_cause_identified": None,
                    }
                )
            elif status == "needs_analysis":
                # Cases that failed but weren't analyzed yet
                results.append(
                    {
                        "case_id": case_id,
                        "model": model_name,
                        "failure_category": "pending_analysis",
                        "correct_file": None,
                        "correct_function": None,
                        "root_cause_identified": None,
                    }
                )

    if not results:
        console.print("[yellow]No analysis results found[/]")
        return

    df = pd.DataFrame(results)
    console.print(f"[bold]Loaded {len(df)} analysis results[/]")

    # Define category order and colors
    category_order = [
        # Success categories
        "correctly_fixed",
        "better_than_ground_truth",
        "false_positive_dd",
        # Infrastructure issues (not LLM's fault)
        "qa_check_failed",
        "dd_infra_error",
        "pre_existing_bug",
        # LLM failure categories
        "wrong_file",
        "wrong_function",
        "wrong_fix_type",
        "incomplete_fix",
        "symptom_masking",
        "patch_gen_failed",
        "introduces_new_bug",
        # Other
        "pending_analysis",
        "unknown",
    ]

    colors = {
        # Success (greens)
        "correctly_fixed": "#1abc9c",  # Teal
        "better_than_ground_truth": "#2ecc71",  # Light green
        "false_positive_dd": "#27ae60",  # Green
        # Infrastructure issues (blues/grays)
        "qa_check_failed": "#3498db",  # Blue
        "dd_infra_error": "#5dade2",  # Light blue
        "pre_existing_bug": "#7f8c8d",  # Dark gray
        # LLM failures (warm colors)
        "wrong_file": "#e74c3c",  # Red
        "wrong_function": "#e67e22",  # Orange
        "wrong_fix_type": "#f39c12",  # Yellow-orange
        "incomplete_fix": "#f1c40f",  # Yellow
        "symptom_masking": "#9b59b6",  # Purple
        "patch_gen_failed": "#95a5a6",  # Gray
        "introduces_new_bug": "#c0392b",  # Dark red
        # Other
        "pending_analysis": "#d5dbdb",  # Very light gray - needs to be analyzed
        "unknown": "#bdc3c7",  # Light gray
    }

    # Set up the plot style
    plt.style.use("seaborn-v0_8-whitegrid")

    unique_models = df["model"].unique()

    if stacked or len(unique_models) > 1:
        # Grouped/stacked bar chart for multiple models
        fig, ax = plt.subplots(figsize=(14, 8))

        # Pivot the data
        pivot = df.groupby(["model", "failure_category"]).size().unstack(fill_value=0)

        # Reorder columns
        existing_cats = [c for c in category_order if c in pivot.columns]
        pivot = pivot[existing_cats]

        if stacked:
            pivot.T.plot(kind="bar", stacked=True, ax=ax, width=0.8)
            ax.set_xlabel("Failure Category", fontsize=12)
            ax.set_ylabel("Count", fontsize=12)
            ax.set_title(
                "Failure Categories by Model (Stacked)", fontsize=14, fontweight="bold"
            )
            plt.xticks(rotation=45, ha="right")
        else:
            pivot.plot(kind="bar", ax=ax, width=0.8)
            ax.set_xlabel("Model", fontsize=12)
            ax.set_ylabel("Count", fontsize=12)
            ax.set_title("Failure Categories by Model", fontsize=14, fontweight="bold")
            plt.xticks(rotation=15, ha="right")

        ax.legend(title="Category", bbox_to_anchor=(1.02, 1), loc="upper left")

    else:
        # Single model - simple bar chart
        fig, ax = plt.subplots(figsize=(12, 6))

        counts = df["failure_category"].value_counts()
        # Reorder by category_order
        ordered_counts = pd.Series(
            {
                cat: counts.get(cat, 0)
                for cat in category_order
                if cat in counts.index or counts.get(cat, 0) > 0
            }
        )
        ordered_counts = ordered_counts[ordered_counts > 0]

        bar_colors = [colors.get(cat, "#bdc3c7") for cat in ordered_counts.index]
        bars = ax.bar(
            range(len(ordered_counts)), ordered_counts.values, color=bar_colors
        )

        ax.set_xticks(range(len(ordered_counts)))
        ax.set_xticklabels(ordered_counts.index, rotation=45, ha="right")
        ax.set_xlabel("Failure Category", fontsize=12)
        ax.set_ylabel("Count", fontsize=12)
        ax.set_title(
            f"Failure Categories - {unique_models[0]}", fontsize=14, fontweight="bold"
        )

        # Add count labels on bars
        for bar, count in zip(bars, ordered_counts.values):
            ax.text(
                bar.get_x() + bar.get_width() / 2,
                bar.get_height() + 0.5,
                str(count),
                ha="center",
                va="bottom",
                fontsize=10,
            )

    plt.tight_layout()

    # Save or show
    if output_file:
        plt.savefig(output_file, dpi=150, bbox_inches="tight")
        console.print(f"[green]Plot saved to {output_file}[/]")

    if show:
        plt.show()

    # Print summary table
    console.print("\n[bold]Summary Table:[/]")
    summary_table = Table(box=box.ROUNDED)
    summary_table.add_column("Category", style="cyan")

    for model in sorted(unique_models):
        summary_table.add_column(model[:20], justify="right")
    summary_table.add_column("Total", justify="right", style="bold")

    for cat in category_order:
        cat_data = df[df["failure_category"] == cat]
        if len(cat_data) == 0:
            continue
        row = [cat]
        for model in sorted(unique_models):
            count = len(cat_data[cat_data["model"] == model])
            row.append(str(count) if count > 0 else "-")
        row.append(str(len(cat_data)))
        summary_table.add_row(*row)

    # Add totals row
    total_row = ["[bold]TOTAL[/]"]
    for model in sorted(unique_models):
        total_row.append(f"[bold]{len(df[df['model'] == model])}[/]")
    total_row.append(f"[bold]{len(df)}[/]")
    summary_table.add_row(*total_row)

    console.print(summary_table)


if __name__ == "__main__":
    app()
