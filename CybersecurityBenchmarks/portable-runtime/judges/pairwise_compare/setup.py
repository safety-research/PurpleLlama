"""
Workspace setup for blinded pairwise patch comparison.

Creates git worktrees for each patch, randomizes the blinding assignment
(which patcher maps to Patch A vs Patch B), places pre-built binaries,
and produces the crash output for the analysis agent.

Workspace layout after setup:
    /src/                          Original vulnerable source (git repo)
    /workspace/patch-a/            Git worktree with Patch A applied
    /workspace/patch-b/            Git worktree with Patch B applied
    /binaries/original             Original vulnerable binary
    /binaries/patch-a              Binary for Patch A
    /binaries/patch-b              Binary for Patch B
    /tmp/poc                       PoC crash input (pre-existing in container)
    /tmp/artifacts/                Fetched artifacts from init containers
"""

import json
import logging
import os
import random
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from shared.paths import get_project_root

LOG = logging.getLogger(__name__)

# Directories
WORKSPACE_DIR = "/workspace"
BINARIES_DIR = "/binaries"
ARTIFACTS_DIR = "/tmp/artifacts"
OUTPUT_DIR_DEFAULT = "/output"

# Patcher artifact subdirectories (populated by init containers / manual fetch)
PATCHER_1_ARTIFACTS = f"{ARTIFACTS_DIR}/patcher-1"
PATCHER_2_ARTIFACTS = f"{ARTIFACTS_DIR}/patcher-2"
GT_BINARY_PATH = f"{ARTIFACTS_DIR}/gt-binary"  # From -fix image init container


@dataclass
class BlindingKey:
    """Records which patcher was assigned to which blinded label."""

    patch_a_patcher: str  # The patcher ID assigned to "Patch A"
    patch_b_patcher: str  # The patcher ID assigned to "Patch B"
    patcher_1: str  # Original patcher-1 ID
    patcher_2: str  # Original patcher-2 ID

    def to_dict(self):
        return {
            "patch_a_patcher": self.patch_a_patcher,
            "patch_b_patcher": self.patch_b_patcher,
            "patcher_1": self.patcher_1,
            "patcher_2": self.patcher_2,
        }


@dataclass
class WorkspaceInfo:
    """Information about the set up workspace, passed to the analysis agent."""

    source_path: str  # Original source (e.g. /src or /src/{project})
    patch_a_path: str  # Worktree for Patch A
    patch_b_path: str  # Worktree for Patch B
    original_binary: str  # Path to original binary
    patch_a_binary: str  # Path to Patch A binary
    patch_b_binary: str  # Path to Patch B binary
    patch_a_diff: str  # Unified diff for Patch A
    patch_b_diff: str  # Unified diff for Patch B
    crash_output: str  # Original crash output from PoC
    blinding_key: BlindingKey  # Sealed blinding assignment


def _resolve_patcher_patch(patcher_id: str, artifacts_dir: str) -> Optional[str]:
    """Load the patch diff for a patcher from its artifacts directory.

    For regular agents: reads patch.patch (unified diff).
    For 'gt': reads the patch JSON and converts to unified diff format.

    Returns the unified diff string, or None if not found.
    """
    # Regular agent: patch.patch file
    patch_file = Path(artifacts_dir) / "patch.patch"
    if patch_file.exists():
        content = patch_file.read_text()
        if content.strip():
            return content

    # GT: patch JSON file (array of {filename, patch, summary})
    patch_json = Path(artifacts_dir) / "patch.json"
    if patch_json.exists():
        try:
            patches = json.loads(patch_json.read_text())
            diffs = []
            for p in patches:
                filename = p.get("filename", "unknown")
                patch_text = p.get("patch", "")
                if patch_text:
                    # patch_text starts with hunk range (e.g. "-260,8 +260,19 @@ ...")
                    # and contains the diff body with context/+/- lines.
                    hunk = f"@@ {patch_text}"
                    if not hunk.endswith("\n"):
                        hunk += "\n"
                    diffs.append(f"--- a/{filename}\n+++ b/{filename}\n{hunk}")
            return "\n".join(diffs) if diffs else None
        except (json.JSONDecodeError, KeyError) as e:
            LOG.warning(f"Failed to parse GT patch JSON: {e}")

    LOG.warning(f"No patch found for patcher '{patcher_id}' in {artifacts_dir}")
    return None


def _resolve_patcher_binary(patcher_id: str, artifacts_dir: str) -> Optional[str]:
    """Find the binary for a patcher from its artifacts directory.

    For regular agents: rebuilt_binary in artifacts dir.
    For 'gt': binary extracted from -fix image by init container.

    Returns path to the binary, or None if not found.
    """
    # Regular agent: rebuilt_binary
    binary = Path(artifacts_dir) / "rebuilt_binary"
    if binary.exists():
        return str(binary)

    # GT: from -fix image init container
    gt_binary = Path(GT_BINARY_PATH)
    if patcher_id == "gt" and gt_binary.exists():
        return str(gt_binary)

    LOG.warning(f"No binary found for patcher '{patcher_id}' in {artifacts_dir}")
    return None


def _get_crash_output() -> str:
    """Get the original crash output by running the PoC against the vulnerable binary."""
    # First check if crash_output.txt was fetched from GCS
    crash_file = Path(ARTIFACTS_DIR) / "crash_output.txt"
    if crash_file.exists():
        content = crash_file.read_text()
        if content.strip():
            LOG.info("Loaded crash output from fetched artifact")
            return content

    # Otherwise, run the PoC to generate it
    LOG.info("Generating crash output by running PoC...")
    try:
        result = subprocess.run(
            ["arvo"],
            capture_output=True,
            text=True,
            timeout=120,
        )
        output = result.stdout + result.stderr
        if "SUMMARY:" in output or "ERROR:" in output:
            LOG.info("Crash reproduced successfully")
            return output
        LOG.warning("PoC did not produce expected crash output")
        return output
    except subprocess.TimeoutExpired:
        LOG.warning("PoC timed out")
        return "PoC execution timed out after 120 seconds"
    except Exception as e:
        LOG.error(f"Failed to run PoC: {e}")
        return f"Failed to run PoC: {e}"


def _create_worktree(src_dir: str, worktree_path: str, branch_name: str) -> None:
    """Create a git worktree from the source repo."""
    # Create the branch
    subprocess.run(
        ["git", "branch", branch_name, "HEAD"],
        capture_output=True,
        text=True,
        cwd=src_dir,
        timeout=30,
    )
    # Create the worktree
    result = subprocess.run(
        ["git", "worktree", "add", worktree_path, branch_name],
        capture_output=True,
        text=True,
        cwd=src_dir,
        timeout=60,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"Failed to create worktree at {worktree_path}: {result.stderr}"
        )
    LOG.info(f"Created worktree: {worktree_path} (branch: {branch_name})")


def _apply_patch_to_worktree(worktree_path: str, patch_diff: str) -> None:
    """Apply a unified diff patch to a worktree.

    Tries `git apply` first, falls back to `patch -p1` (no fuzz allowed).
    Raises RuntimeError if neither method can apply the patch cleanly.

    GT patches from ARVO metadata sometimes have incorrect hunk line counts,
    which makes `git apply` reject them. `patch -p1 -F0` handles these
    since it only checks content matches, not header arithmetic.
    """
    patch_file = Path(worktree_path) / ".tmp_patch.diff"
    patch_file.write_text(patch_diff)

    try:
        result = subprocess.run(
            ["git", "apply", str(patch_file)],
            capture_output=True,
            text=True,
            cwd=worktree_path,
            timeout=30,
        )
        if result.returncode == 0:
            LOG.info(f"Applied patch to {worktree_path} via git apply")
            return

        git_err = result.stderr.strip()
        LOG.info(f"git apply failed ({git_err}), trying patch -p1")

        # -F0 disables fuzz: lines must match at exact offsets (no guessing)
        result = subprocess.run(
            ["patch", "-p1", "-F0", "-i", str(patch_file)],
            capture_output=True,
            text=True,
            cwd=worktree_path,
            timeout=30,
        )
        if result.returncode == 0:
            LOG.info(f"Applied patch to {worktree_path} via patch -p1 -F0")
            return

        raise RuntimeError(
            f"Patch cannot be applied to {worktree_path}.\n"
            f"  git apply: {git_err}\n"
            f"  patch -p1 -F0: {result.stderr.strip()}"
        )
    finally:
        patch_file.unlink(missing_ok=True)


def _find_original_binary() -> Optional[str]:
    """Find the original vulnerable binary in the container."""
    # Check /out/ for the fuzzer binary (same logic as BaseAgent._find_fuzzer_binary)
    import re

    arvo_script = Path("/bin/arvo")
    if arvo_script.exists():
        content = arvo_script.read_text()
        match = re.search(r"(/out/[\w\-\.]+)\s+/tmp/(poc|corpus)", content)
        if match:
            binary_path = match.group(1)
            if os.path.exists(binary_path) and os.access(binary_path, os.X_OK):
                return binary_path

    # Fallback: scan /out/
    out_dir = Path("/out")
    if out_dir.exists():
        executables = [
            f
            for f in out_dir.iterdir()
            if f.is_file()
            and os.access(f, os.X_OK)
            and not f.name.endswith((".dict", ".options", ".zip", ".txt", ".a", ".o"))
        ]
        if executables:
            fuzzer_bins = [f for f in executables if "fuzz" in f.name.lower()]
            selected = fuzzer_bins[0] if fuzzer_bins else executables[0]
            return str(selected)

    return None


def setup_workspace(
    patcher_1_id: str,
    patcher_2_id: str,
    output_dir: str = OUTPUT_DIR_DEFAULT,
) -> WorkspaceInfo:
    """Set up the analysis workspace with worktrees, blinding, and binaries.

    Args:
        patcher_1_id: ID of the first patcher (e.g. agent ID or "gt")
        patcher_2_id: ID of the second patcher
        output_dir: Directory for output files (blinding key saved here)

    Returns:
        WorkspaceInfo with paths and diffs for the analysis agent.

    Raises:
        RuntimeError: If workspace setup fails critically.
    """
    source_path = get_project_root()
    LOG.info(f"Setting up analysis workspace for {patcher_1_id} vs {patcher_2_id}")
    LOG.info(f"Project source: {source_path}")

    # Ensure directories exist
    os.makedirs(WORKSPACE_DIR, exist_ok=True)
    os.makedirs(BINARIES_DIR, exist_ok=True)
    os.makedirs(output_dir, exist_ok=True)

    # 1. Get crash output
    crash_output = _get_crash_output()

    # 2. Load patches for both patchers
    patch_1_diff = _resolve_patcher_patch(patcher_1_id, PATCHER_1_ARTIFACTS)
    patch_2_diff = _resolve_patcher_patch(patcher_2_id, PATCHER_2_ARTIFACTS)

    if not patch_1_diff:
        raise RuntimeError(f"No patch found for patcher '{patcher_1_id}'")
    if not patch_2_diff:
        raise RuntimeError(f"No patch found for patcher '{patcher_2_id}'")

    # 3. Load binaries for both patchers
    binary_1 = _resolve_patcher_binary(patcher_1_id, PATCHER_1_ARTIFACTS)
    binary_2 = _resolve_patcher_binary(patcher_2_id, PATCHER_2_ARTIFACTS)

    # 4. Randomize blinding: coin flip assigns patchers to A/B
    if random.random() < 0.5:
        a_patcher, b_patcher = patcher_1_id, patcher_2_id
        a_diff, b_diff = patch_1_diff, patch_2_diff
        a_binary_src, b_binary_src = binary_1, binary_2
    else:
        a_patcher, b_patcher = patcher_2_id, patcher_1_id
        a_diff, b_diff = patch_2_diff, patch_1_diff
        a_binary_src, b_binary_src = binary_2, binary_1

    blinding_key = BlindingKey(
        patch_a_patcher=a_patcher,
        patch_b_patcher=b_patcher,
        patcher_1=patcher_1_id,
        patcher_2=patcher_2_id,
    )

    # Save blinding key (sealed -- the analysis agent should not read this)
    key_file = Path(output_dir) / "blinding_key.json"
    key_file.write_text(json.dumps(blinding_key.to_dict(), indent=2))
    LOG.info(f"Blinding key saved to {key_file}")
    LOG.info(f"Assignment: Patch A = {a_patcher}, Patch B = {b_patcher}")

    # 5. Create git worktrees
    git_root = source_path  # project root IS the git root
    LOG.info(f"Git root: {git_root}")
    patch_a_path = f"{WORKSPACE_DIR}/patch-a"
    patch_b_path = f"{WORKSPACE_DIR}/patch-b"

    _create_worktree(git_root, patch_a_path, "analysis-patch-a")
    _create_worktree(git_root, patch_b_path, "analysis-patch-b")

    # 6. Apply patches to worktrees (raises RuntimeError on failure)
    _apply_patch_to_worktree(patch_a_path, a_diff)
    _apply_patch_to_worktree(patch_b_path, b_diff)

    # 7. Place binaries
    original_binary = _find_original_binary()
    original_binary_dest = f"{BINARIES_DIR}/original"
    patch_a_binary_dest = f"{BINARIES_DIR}/patch-a"
    patch_b_binary_dest = f"{BINARIES_DIR}/patch-b"

    if original_binary:
        shutil.copy2(original_binary, original_binary_dest)
        os.chmod(original_binary_dest, 0o755)
        LOG.info(f"Placed original binary: {original_binary_dest}")
    else:
        LOG.warning("Original binary not found")

    if a_binary_src:
        shutil.copy2(a_binary_src, patch_a_binary_dest)
        os.chmod(patch_a_binary_dest, 0o755)
        LOG.info(f"Placed Patch A binary: {patch_a_binary_dest}")
    else:
        LOG.warning("Patch A binary not available")

    if b_binary_src:
        shutil.copy2(b_binary_src, patch_b_binary_dest)
        os.chmod(patch_b_binary_dest, 0o755)
        LOG.info(f"Placed Patch B binary: {patch_b_binary_dest}")
    else:
        LOG.warning("Patch B binary not available")

    return WorkspaceInfo(
        source_path=source_path,
        patch_a_path=patch_a_path,
        patch_b_path=patch_b_path,
        original_binary=original_binary_dest,
        patch_a_binary=patch_a_binary_dest,
        patch_b_binary=patch_b_binary_dest,
        patch_a_diff=a_diff,
        patch_b_diff=b_diff,
        crash_output=crash_output,
        blinding_key=blinding_key,
    )
