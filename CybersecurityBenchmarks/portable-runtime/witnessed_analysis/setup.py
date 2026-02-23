"""
Workspace setup for witnessed pairwise patch comparison.

Creates git worktrees for each patch, randomizes the blinding assignment
(which patcher maps to Patch A vs Patch B), places pre-built binaries,
produces crash output, and creates the witnesses directory.

Reuses helper functions from analysis/setup.py.

Workspace layout after setup:
    /src/                          Original vulnerable source (git repo)
    /workspace/patch-a/            Git worktree with Patch A applied
    /workspace/patch-b/            Git worktree with Patch B applied
    /binaries/original             Original vulnerable binary
    /binaries/patch-a              Binary for Patch A
    /binaries/patch-b              Binary for Patch B
    /tmp/poc                       PoC crash input (pre-existing in container)
    /tmp/artifacts/                Fetched artifacts from init containers
    /output/witnesses/             Witness scripts produced by sub-agents
"""

import json
import logging
import os
import shutil
from pathlib import Path

from analysis.setup import (
    ARTIFACTS_DIR,
    BINARIES_DIR,
    PATCHER_1_ARTIFACTS,
    PATCHER_2_ARTIFACTS,
    BlindingKey,
    WorkspaceInfo,
    _apply_patch_to_worktree,
    _create_worktree,
    _find_original_binary,
    _get_crash_output,
    _resolve_patcher_binary,
    _resolve_patcher_patch,
)

from shared.paths import get_project_root

LOG = logging.getLogger(__name__)

WORKSPACE_DIR = "/workspace"
OUTPUT_DIR_DEFAULT = "/output"
WITNESSES_DIR = "/output/witnesses"


def setup_workspace(
    patcher_1_id: str,
    patcher_2_id: str,
    output_dir: str = OUTPUT_DIR_DEFAULT,
) -> WorkspaceInfo:
    """Set up the witnessed analysis workspace with worktrees, blinding, and binaries.

    Identical to analysis/setup.setup_workspace but also creates the
    witnesses output directory.

    Args:
        patcher_1_id: ID of the first patcher (e.g. agent ID or "gt")
        patcher_2_id: ID of the second patcher
        output_dir: Directory for output files (blinding key saved here)

    Returns:
        WorkspaceInfo with paths and diffs for the analyst agent.

    Raises:
        RuntimeError: If workspace setup fails critically.
    """
    source_path = get_project_root()
    LOG.info(
        f"Setting up witnessed analysis workspace for "
        f"{patcher_1_id} vs {patcher_2_id}"
    )
    LOG.info(f"Project source: {source_path}")

    os.makedirs(WORKSPACE_DIR, exist_ok=True)
    os.makedirs(BINARIES_DIR, exist_ok=True)
    os.makedirs(output_dir, exist_ok=True)
    os.makedirs(WITNESSES_DIR, exist_ok=True)

    crash_output = _get_crash_output()

    patch_1_diff = _resolve_patcher_patch(patcher_1_id, PATCHER_1_ARTIFACTS)
    patch_2_diff = _resolve_patcher_patch(patcher_2_id, PATCHER_2_ARTIFACTS)

    if not patch_1_diff:
        raise RuntimeError(f"No patch found for patcher '{patcher_1_id}'")
    if not patch_2_diff:
        raise RuntimeError(f"No patch found for patcher '{patcher_2_id}'")

    binary_1 = _resolve_patcher_binary(patcher_1_id, PATCHER_1_ARTIFACTS)
    binary_2 = _resolve_patcher_binary(patcher_2_id, PATCHER_2_ARTIFACTS)

    # Randomize blinding: coin flip assigns patchers to A/B
    import random

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

    key_file = Path(output_dir) / "blinding_key.json"
    key_file.write_text(json.dumps(blinding_key.to_dict(), indent=2))
    LOG.info(f"Blinding key saved to {key_file}")
    LOG.info(f"Assignment: Patch A = {a_patcher}, Patch B = {b_patcher}")

    git_root = source_path
    LOG.info(f"Git root: {git_root}")
    patch_a_path = f"{WORKSPACE_DIR}/patch-a"
    patch_b_path = f"{WORKSPACE_DIR}/patch-b"

    _create_worktree(git_root, patch_a_path, "witnessed-patch-a")
    _create_worktree(git_root, patch_b_path, "witnessed-patch-b")

    if not _apply_patch_to_worktree(patch_a_path, a_diff):
        LOG.error("Failed to apply Patch A -- analysis may be limited")
    if not _apply_patch_to_worktree(patch_b_path, b_diff):
        LOG.error("Failed to apply Patch B -- analysis may be limited")

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
