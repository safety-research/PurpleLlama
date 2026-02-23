"""
Project source / git root resolution for ARVO containers.

ARVO containers have source code at /src/{project}/ where the PROJECT
env var identifies the project.  /src/ itself is NOT a git repository.
The project directory IS the git root.
"""

import logging
import os
import subprocess

LOG = logging.getLogger(__name__)


def get_project_root() -> str:
    """Get the project root directory (source tree and git root).

    Resolution order:
        1. PROJECT_ROOT env var (explicit override)
        2. /src/{PROJECT} if PROJECT env var is set and contains .git/
        3. git rev-parse --show-toplevel from /src
        4. Scan /src/ subdirectories for .git/
        5. /src as last resort

    Returns:
        Absolute path to the project root.
    """
    src_dir = os.environ.get("SRC", "/src")

    # 1. Explicit override
    project_root = os.environ.get("PROJECT_ROOT")
    if project_root and os.path.isdir(project_root):
        return project_root

    # 2. /src/{PROJECT}
    project = os.environ.get("PROJECT")
    if project:
        candidate = os.path.join(src_dir, project)
        if os.path.isdir(candidate):
            return candidate

    # 3. git rev-parse
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            capture_output=True,
            text=True,
            cwd=src_dir,
            timeout=10,
        )
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip()
    except Exception:
        pass

    # 4. Scan /src/ for any subdirectory with .git/
    if os.path.isdir(src_dir):
        for entry in os.listdir(src_dir):
            candidate = os.path.join(src_dir, entry)
            if os.path.isdir(os.path.join(candidate, ".git")):
                LOG.debug(f"Found project root by scanning: {candidate}")
                return candidate

    # 5. Last resort
    LOG.warning(f"Could not find project root, falling back to {src_dir}")
    return src_dir


# Aliases for callers that use more specific names
get_project_source_path = get_project_root
find_git_root = get_project_root
