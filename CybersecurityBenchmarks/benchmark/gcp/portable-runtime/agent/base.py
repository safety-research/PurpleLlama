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
import os
import shutil
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
    agent_id: Optional[str] = None  # Pipeline-level identifier (from AgentSpec.id)

    # Timing
    start_time: str = ""
    end_time: str = ""
    duration_seconds: float = 0.0

    # Time budget tracking (for agents with time-based limits)
    # active_runtime_seconds = duration_seconds - excluded_retry_seconds
    active_runtime_seconds: float = 0.0  # Time budget was measured against
    excluded_retry_seconds: float = 0.0  # Time excluded (API retries due to 529 errors)
    api_retry_count: int = 0  # Number of API retries detected

    # Escalation: if the agent runs >= this many seconds on the first Argo
    # attempt without fixing the crash, main.py exits with code 2 to trigger
    # a retry on a larger pod (more CPU).  Configurable via AGENT_CONFIG JSON.
    escalation_timeout: int = 1800  # default 30 minutes

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

    # Indicates if rebuilt_binary contains a successful patch
    # True = patched binary that fixes the crash
    # False = original vulnerable binary (baseline for fuzzing)
    patch_successful: bool = False

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "case_id": self.case_id,
            "agent_name": self.agent_name,
            "agent_id": self.agent_id,
            "model": self.model,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "duration_seconds": self.duration_seconds,
            "active_runtime_seconds": self.active_runtime_seconds,
            "excluded_retry_seconds": self.excluded_retry_seconds,
            "api_retry_count": self.api_retry_count,
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
            "patch_successful": self.patch_successful,
            "escalation_timeout": self.escalation_timeout,
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

        # Overlay state (initialized by _setup_overlays)
        self._use_overlay = False
        self._overlay_mounted: list[str] = []

    # -------------------------------------------------------------------------
    # OverlayFS-based source/build snapshot and revert
    # -------------------------------------------------------------------------
    # These methods provide instant filesystem revert for retry attempts.
    # With SYS_ADMIN capability, overlayfs is used (instant, zero-copy).
    # Without it, falls back to cp -a snapshots (slow but correct).

    _overlay_paths = ["/src", "/out", "/work"]
    _overlay_base = "/tmp/overlay"
    _overlay_tmpfs = "/mnt/overlay_tmpfs"
    _snapshot_suffix = ".bak"

    def _setup_overlays(self) -> None:
        """Mount overlayfs on writable paths. Call once before patching.

        Upper/work dirs are placed on a tmpfs because the container root
        is itself an overlay filesystem (Docker/containerd), and the Linux
        kernel requires upper/work to be on a non-overlay fs.

        Falls back to cp -a if overlayfs is not available (no SYS_ADMIN
        or AppArmor blocking mount).
        """
        # Create a tmpfs for upper/work dirs (required: overlay can't nest
        # upper/work on the container's own overlay root filesystem)
        try:
            os.makedirs(self._overlay_tmpfs, exist_ok=True)
            subprocess.run(
                ["mount", "-t", "tmpfs", "tmpfs", self._overlay_tmpfs],
                check=True,
                capture_output=True,
                timeout=10,
            )
        except (subprocess.CalledProcessError, PermissionError, OSError) as e:
            LOG.warning(
                f"Cannot mount tmpfs for overlay upper/work ({e}), "
                f"falling back to cp -a snapshots"
            )
            self._use_overlay = False
            self._setup_snapshots()
            return

        for path in self._overlay_paths:
            if not os.path.exists(path):
                continue
            try:
                self._mount_overlay(path)
                self._use_overlay = True
            except (subprocess.CalledProcessError, PermissionError, OSError) as e:
                if not self._overlay_mounted:
                    # First path failed -- overlay not available, use cp fallback
                    LOG.warning(
                        f"OverlayFS not available ({e}), falling back to cp -a snapshots"
                    )
                    self._use_overlay = False
                    self._setup_snapshots()
                    return
                else:
                    LOG.warning(f"Failed to mount overlay on {path}: {e}")

        if self._overlay_mounted:
            LOG.info(f"OverlayFS mounted on {self._overlay_mounted} for retry support")

    def _mount_overlay(self, path: str) -> None:
        """Mount a single overlayfs on a path.

        Upper/work dirs are on the tmpfs at _overlay_tmpfs so the kernel
        doesn't reject the mount due to nested overlay filesystems.
        """
        upper = f"{self._overlay_tmpfs}{path}/upper"
        work = f"{self._overlay_tmpfs}{path}/work"
        os.makedirs(upper, exist_ok=True)
        os.makedirs(work, exist_ok=True)
        subprocess.run(
            [
                "mount",
                "-t",
                "overlay",
                "overlay",
                "-o",
                f"lowerdir={path},upperdir={upper},workdir={work}",
                path,
            ],
            check=True,
            capture_output=True,
            timeout=30,
        )
        self._overlay_mounted.append(path)

    def _reset_overlays(self) -> None:
        """Revert all paths to their pre-patching state.

        With overlay: unmount, clear upper layer, remount (instant).
        Without overlay: restore from cp -a backup.
        """
        if self._use_overlay:
            for path in self._overlay_mounted:
                try:
                    subprocess.run(
                        ["umount", path],
                        check=True,
                        capture_output=True,
                        timeout=30,
                    )
                    upper = f"{self._overlay_tmpfs}{path}/upper"
                    work = f"{self._overlay_tmpfs}{path}/work"
                    shutil.rmtree(upper)
                    shutil.rmtree(work)
                    os.makedirs(upper)
                    os.makedirs(work)
                    subprocess.run(
                        [
                            "mount",
                            "-t",
                            "overlay",
                            "overlay",
                            "-o",
                            f"lowerdir={path},upperdir={upper},workdir={work}",
                            path,
                        ],
                        check=True,
                        capture_output=True,
                        timeout=30,
                    )
                except Exception as e:
                    LOG.warning(f"Failed to reset overlay on {path}: {e}")
            LOG.info("Reset overlays (instant revert)")
        else:
            self._restore_snapshots()

    def _teardown_overlays(self) -> None:
        """Unmount all overlays. Call at end of run."""
        if not self._use_overlay:
            return
        for path in self._overlay_mounted:
            try:
                subprocess.run(
                    ["umount", path],
                    check=True,
                    capture_output=True,
                    timeout=30,
                )
            except Exception:
                pass  # Best effort
        self._overlay_mounted.clear()

    # -- cp -a fallback --

    def _setup_snapshots(self) -> None:
        """Fallback: take cp -a snapshots of writable paths."""
        for path in self._overlay_paths:
            backup = path + self._snapshot_suffix
            if os.path.exists(backup) or not os.path.exists(path):
                continue
            try:
                subprocess.run(
                    ["cp", "-a", path, backup],
                    check=True,
                    capture_output=True,
                    timeout=120,
                )
            except Exception as e:
                LOG.warning(f"Failed to snapshot {path}: {e}")
        LOG.info("Snapshotted source/build dirs (cp -a fallback)")

    def _restore_snapshots(self) -> None:
        """Fallback: restore from cp -a snapshots."""
        for path in self._overlay_paths:
            backup = path + self._snapshot_suffix
            if not os.path.exists(backup):
                continue
            try:
                subprocess.run(
                    ["rm", "-rf", path],
                    check=True,
                    capture_output=True,
                    timeout=60,
                )
                subprocess.run(
                    ["mv", backup, path],
                    check=True,
                    capture_output=True,
                    timeout=60,
                )
            except Exception as e:
                LOG.warning(f"Failed to restore {path}: {e}")
        # Re-snapshot for next retry
        self._setup_snapshots()
        LOG.info("Restored source/build dirs from snapshots")

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

        # Compute active runtime (excluding API retry time)
        # Agents that track retries set excluded_retry_seconds before calling this
        self.result.active_runtime_seconds = (
            self.result.duration_seconds - self.result.excluded_retry_seconds
        )

    def _save_results(self) -> None:
        """Save results to output directory."""
        import json

        self.output_dir.mkdir(parents=True, exist_ok=True)

        # Always save a binary for fuzzing (do this BEFORE saving result.json
        # so the fuzzer_binary_path and patch_successful are included in the result)
        # - If crash_fixed: save the patched binary (patch_successful=True)
        # - Otherwise: save the original binary as baseline (patch_successful=False)
        self._save_binary_for_fuzzing()

        # Generate unified diff of all source changes (patch.patch)
        # Do this BEFORE saving result.json so patch_generated/patch_content are included
        self._generate_patch_diff()

        # Save result JSON
        result_file = self.output_dir / "result.json"
        result_file.write_text(json.dumps(self.result.to_dict(), indent=2))
        LOG.info(f"Results saved to {result_file}")

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

    def _generate_patch_diff(self) -> None:
        """Generate a unified diff of all source changes (patch.patch).

        Finds the git repo root (typically /src/{project}/) and runs
        ``git diff`` there.  Works for all agents -- autopatchbench,
        claudecode, and any future agents.  The output is a standard
        unified diff that can be applied with ``git apply patch.patch``.

        Safe to call multiple times: skips if a patch was already captured
        (e.g. before overlay teardown).
        """
        # Skip if we already captured the patch (e.g. before overlay teardown)
        if self.result.patch_content:
            LOG.debug("Patch diff already captured, skipping")
            return

        from shared.paths import find_git_root

        git_root = find_git_root()
        LOG.debug(f"Generating patch diff from git root: {git_root}")

        try:
            result = subprocess.run(
                ["git", "diff"],
                capture_output=True,
                text=True,
                timeout=30,
                cwd=git_root,
            )
            if result.stdout.strip():
                patch_file = self.output_dir / "patch.patch"
                patch_file.write_text(result.stdout)
                self.result.patch_content = result.stdout
                self.result.patch_generated = True
                LOG.info(
                    f"Saved unified diff ({len(result.stdout)} bytes) to {patch_file}"
                )
            else:
                LOG.info("No source changes detected (git diff empty)")
        except Exception as e:
            LOG.warning(f"Failed to generate patch diff: {e}")

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

    def _save_binary_for_fuzzing(self) -> bool:
        """
        Always copy a fuzzer binary to output directory for downstream fuzzing.

        - If crash_fixed: copies the patched binary (patch_successful=True)
        - Otherwise: copies the original vulnerable binary as baseline (patch_successful=False)

        This ensures the fuzz-llm step always has a binary to fuzz, enabling
        baseline fuzzing data collection even when patching fails.

        Safe to call multiple times: skips if the binary was already saved
        (e.g. before overlay teardown).

        Returns:
            True if binary was saved successfully, False otherwise
        """
        import shutil

        # Skip if we already saved the binary (e.g. before overlay teardown)
        dest_path = self.output_dir / "rebuilt_binary"
        if dest_path.exists():
            LOG.debug("Binary already saved, skipping")
            return True

        # Find the binary path
        binary_path = self._find_fuzzer_binary()
        if not binary_path:
            LOG.warning("Could not find fuzzer binary to save")
            self.result.patch_successful = False
            return False

        self.result.fuzzer_binary_path = binary_path

        # Set patch_successful based on whether the patch actually fixed the crash
        self.result.patch_successful = self.result.crash_fixed

        # Copy to output directory
        dest_path = self.output_dir / "rebuilt_binary"
        try:
            shutil.copy2(binary_path, dest_path)
            if self.result.patch_successful:
                LOG.info(f"Saved patched binary to {dest_path}")
            else:
                LOG.info(f"Saved original binary (baseline) to {dest_path}")
            return True
        except Exception as e:
            LOG.error(f"Failed to copy binary: {e}")
            return False
