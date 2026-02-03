# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

"""
Base agent interface for ARVO patching.

Agents are responsible for PATCHING ONLY:
1. Analyzing crashes
2. Generating patches
3. Applying patches
4. Build verification

Evaluation (fuzzing, crash detection) is handled separately by the evaluation pipeline.
"""

import logging
import subprocess
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

LOG = logging.getLogger(__name__)


class AgentStatus(Enum):
    """Status of agent execution."""

    INIT = "init"
    RUNNING = "running"
    SUCCESS = "success"  # Patch generated, built, and fixes original crash
    PARTIAL = "partial"  # Patch generated but doesn't fix crash or doesn't build
    FAILED = "failed"  # Could not generate a valid patch
    NOT_SUPPORTED = "not_supported"  # Agent cannot handle this crash type


@dataclass
class AgentResult:
    """Results from agent patching run."""

    # Identification
    case_id: int
    agent_name: str
    model: Optional[str] = None

    # Timing
    start_time: str = ""
    end_time: str = ""
    duration_seconds: float = 0.0

    # Status
    status: AgentStatus = AgentStatus.INIT

    # Crash analysis
    original_crash_type: str = ""
    original_crash_output: str = ""

    # Patch generation
    patch_generated: bool = False
    patch_content: str = ""
    patched_function: str = ""
    patched_file_path: str = ""
    llm_calls: int = 0
    llm_tokens_used: int = 0

    # Build verification
    build_success: bool = False
    build_output: str = ""

    # Crash fix verification (against original crash input)
    crash_fixed: bool = False
    verification_output: str = ""

    # Binary path (for fuzzing the patched binary)
    fuzzer_binary_path: str = ""

    # Errors
    error: str = ""
    exception: str = ""

    # Chat history (for debugging)
    chat_history: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "case_id": self.case_id,
            "agent_name": self.agent_name,
            "model": self.model,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "duration_seconds": self.duration_seconds,
            "status": self.status.value,
            "original_crash_type": self.original_crash_type,
            "patch_generated": self.patch_generated,
            "patched_function": self.patched_function,
            "patched_file_path": self.patched_file_path,
            "llm_calls": self.llm_calls,
            "llm_tokens_used": self.llm_tokens_used,
            "build_success": self.build_success,
            "crash_fixed": self.crash_fixed,
            "fuzzer_binary_path": self.fuzzer_binary_path,
            "error": self.error,
        }

    def is_success(self) -> bool:
        """Check if patching was successful (patch fixes the original crash)."""
        return self.status == AgentStatus.SUCCESS


class BaseAgent(ABC):
    """
    Base class for all ARVO patching agents.

    Agents are responsible for PATCHING:
    1. Analyzing crashes
    2. Generating patches
    3. Applying patches
    4. Verifying the patch builds
    5. Verifying the patch fixes the original crash

    Evaluation (fuzzing) is handled separately.
    """

    # Agent identifier - must be unique
    AGENT_NAME: str = "base"

    def __init__(
        self,
        case_id: int,
        output_dir: Path,
        model: Optional[str] = None,
        dry_run: bool = False,
        max_retries: int = 10,
    ):
        """
        Initialize the agent.

        Args:
            case_id: ARVO case ID
            output_dir: Directory for output files
            model: LLM model to use (if applicable)
            dry_run: If True, skip LLM calls
            max_retries: Maximum number of patch generation retries
        """
        self.case_id = case_id
        self.output_dir = output_dir
        self.model = model
        self.dry_run = dry_run
        self.max_retries = max_retries

        self.result = AgentResult(
            case_id=case_id,
            agent_name=self.AGENT_NAME,
            model=model,
            start_time=datetime.utcnow().isoformat() + "Z",
        )

    @abstractmethod
    async def run(self) -> AgentResult:
        """
        Run the agent patching pipeline.

        Returns:
            AgentResult containing the patching results.
        """
        pass

    def _run_command(
        self,
        cmd: List[str],
        timeout: int = 60,
        capture: bool = True,
        cwd: Optional[Path] = None,
    ) -> subprocess.CompletedProcess:
        """
        Run a command and return the result.

        Args:
            cmd: Command to run as list of strings
            timeout: Timeout in seconds
            capture: Whether to capture output
            cwd: Working directory

        Returns:
            CompletedProcess result
        """
        LOG.debug(f"Running: {' '.join(cmd)}")
        try:
            result = subprocess.run(
                cmd,
                capture_output=capture,
                text=True,
                timeout=timeout,
                cwd=cwd,
            )
            return result
        except subprocess.TimeoutExpired:
            LOG.warning(f"Command timed out after {timeout}s: {' '.join(cmd)}")
            raise

    def _finalize_result(self) -> None:
        """Finalize the result with timing information."""
        self.result.end_time = datetime.utcnow().isoformat() + "Z"
        start = datetime.fromisoformat(self.result.start_time.rstrip("Z"))
        end = datetime.fromisoformat(self.result.end_time.rstrip("Z"))
        self.result.duration_seconds = (end - start).total_seconds()

    def _save_results(self) -> None:
        """Save results to output directory."""
        import json

        self.output_dir.mkdir(parents=True, exist_ok=True)

        # Save rebuilt binary if crash was fixed (do this BEFORE saving result.json
        # so the fuzzer_binary_path is included in the result)
        if self.result.crash_fixed:
            self._save_rebuilt_binary()

        # Save result JSON
        result_file = self.output_dir / "result.json"
        result_file.write_text(json.dumps(self.result.to_dict(), indent=2))
        LOG.info(f"Results saved to {result_file}")

        # Save patch if generated
        if self.result.patch_content:
            patch_file = self.output_dir / "patch.txt"
            patch_file.write_text(self.result.patch_content)

        # Save crash output
        if self.result.original_crash_output:
            crash_file = self.output_dir / "crash_output.txt"
            crash_file.write_text(self.result.original_crash_output)

        # Allow subclasses to save additional agent-specific data
        self._save_additional_results()

    def _finalize_and_save(self) -> "AgentResult":
        """Finalize result and save to disk. Returns the result."""
        self._finalize_result()
        self._save_results()
        return self.result

    def _save_additional_results(self) -> None:
        """
        Hook for subclasses to save agent-specific results.

        Override this method in subclasses to save additional data
        (e.g., chat history, debug logs, intermediate outputs).

        The output directory is already created when this is called.
        """
        pass

    def _find_fuzzer_binary(
        self, arvo_script: str = "/bin/arvo", out_dir: str = "/out"
    ) -> Optional[str]:
        """
        Find the fuzzer binary path from the ARVO container.

        The /bin/arvo script specifies which fuzzer to use for each case.
        This function parses that script to extract the correct binary path.

        Args:
            arvo_script: Path to the /bin/arvo script
            out_dir: Fallback directory to search for executables

        Returns:
            Path to the fuzzer binary, or None if not found
        """
        import os
        import re

        # Priority 1: Parse /bin/arvo to get the exact binary path
        # The script has lines like: /out/png_transforms_fuzzer /tmp/poc
        arvo_path = Path(arvo_script)
        if arvo_path.exists():
            try:
                content = arvo_path.read_text()

                # Look for pattern: <binary_path> /tmp/poc (or /tmp/corpus)
                # This is how ARVO specifies which fuzzer to use
                match = re.search(r"(/out/[\w\-\.]+)\s+/tmp/(poc|corpus)", content)
                if match:
                    binary_path = match.group(1)
                    if os.path.exists(binary_path) and os.access(binary_path, os.X_OK):
                        LOG.info(f"Found fuzzer binary from /bin/arvo: {binary_path}")
                        return binary_path
                    else:
                        LOG.warning(
                            f"Binary from /bin/arvo not found or not executable: {binary_path}"
                        )

                # Alternative pattern: look after 'run' command
                match = re.search(r'"run"[^/]*/([^\s]+)\s', content)
                if match:
                    binary_path = (
                        "/" + match.group(1)
                        if not match.group(1).startswith("/")
                        else match.group(1)
                    )
                    if os.path.exists(binary_path) and os.access(binary_path, os.X_OK):
                        LOG.info(
                            f"Found fuzzer binary from /bin/arvo (run command): {binary_path}"
                        )
                        return binary_path

            except Exception as e:
                LOG.warning(f"Failed to parse {arvo_script}: {e}")

        # Priority 2: Fallback to finding executable in /out/
        out_path = Path(out_dir)
        if out_path.exists():
            executables = [
                f
                for f in out_path.iterdir()
                if f.is_file()
                and os.access(f, os.X_OK)
                and not f.name.endswith((".dict", ".options", ".zip", ".txt"))
            ]
            if executables:
                # Prefer files with "fuzzer" in name
                fuzzer_bins = [f for f in executables if "fuzzer" in f.name.lower()]
                selected = fuzzer_bins[0] if fuzzer_bins else executables[0]
                LOG.warning(f"Using fallback fuzzer binary: {selected}")
                return str(selected)

        LOG.error("Could not find fuzzer binary")
        return None

    def _save_rebuilt_binary(self) -> bool:
        """
        Copy the rebuilt fuzzer binary to output directory if crash was fixed.

        Returns:
            True if binary was saved successfully, False otherwise
        """
        import shutil

        if not self.result.crash_fixed:
            LOG.debug("Crash not fixed, skipping binary save")
            return False

        # Find the binary path
        binary_path = self._find_fuzzer_binary()
        if not binary_path:
            LOG.warning("Could not find fuzzer binary to save")
            return False

        self.result.fuzzer_binary_path = binary_path

        # Copy to output directory
        dest_path = self.output_dir / "rebuilt_binary"
        try:
            shutil.copy2(binary_path, dest_path)
            LOG.info(f"Saved rebuilt binary to {dest_path}")
            return True
        except Exception as e:
            LOG.error(f"Failed to copy binary: {e}")
            return False
