"""
Hash computation utilities for build assets, runtime, and dependencies.
"""

import hashlib
import json
import subprocess
from pathlib import Path
from typing import Optional

from .config import get_script_dir
from .output import echo_warning


def run_gsutil(args: list[str], check: bool = True) -> subprocess.CompletedProcess:
    """Run gsutil command.

    Args:
        args: Arguments to pass to gsutil
        check: If True, raise on non-zero exit

    Returns:
        CompletedProcess with stdout/stderr
    """
    result = subprocess.run(
        ["gsutil"] + args,
        capture_output=True,
        text=True,
    )
    if check and result.returncode != 0:
        raise RuntimeError(f"gsutil failed: {result.stderr}")
    return result


# Path to autopatch build directory (relative to benchmark/gcp/)
AUTOPATCH_BUILD_DIR = Path(__file__).parent.parent.parent / "autopatch" / "build"


# =============================================================================
# Generic Hash Functions
# =============================================================================


def _call_hash_script(hash_type: str, target_path: Path) -> str:
    """Call the shared compute_hashes.sh script.

    Args:
        hash_type: One of 'casr', 'dd', 'runtime', 'file'
        target_path: Path to the file or directory to hash

    Returns:
        Hash string, or empty string on error
    """
    hash_script = get_script_dir() / "scripts" / "compute_hashes.sh"
    if not hash_script.exists():
        echo_warning(f"Hash script not found: {hash_script}")
        return ""

    result = subprocess.run(
        ["bash", str(hash_script), hash_type, str(target_path)],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        echo_warning(f"Hash computation failed: {result.stderr}")
        return ""
    return result.stdout.strip()


def compute_file_hash(filepath: Path) -> str:
    """Compute SHA256 hash of a file."""
    sha256 = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha256.update(chunk)
    return sha256.hexdigest()


def compute_directory_hash(dirpath: Path) -> str:
    """Compute combined SHA256 hash of all files in a directory."""
    sha256 = hashlib.sha256()
    # Sort files for deterministic ordering
    for filepath in sorted(dirpath.rglob("*")):
        if filepath.is_file():
            # Include relative path in hash for structure-awareness
            rel_path = filepath.relative_to(dirpath)
            sha256.update(str(rel_path).encode())
            sha256.update(compute_file_hash(filepath).encode())
    return sha256.hexdigest()


# =============================================================================
# Build Version Functions
# =============================================================================


def compute_build_version(build_dir: Path) -> tuple[str, dict]:
    """Compute build version hash from all build assets.

    Returns:
        Tuple of (version_hash, asset_hashes_dict)
        version_hash is first 8 chars of combined hash
    """
    asset_hashes = {}

    # Hash Dockerfile templates
    templates = [
        "dockerfile_vul_template",
        "dockerfile_fix_template",
        "dockerfile_fuzzing_template",
    ]
    for template_name in templates:
        template_file = build_dir / template_name
        if template_file.exists():
            asset_hashes[template_name] = compute_file_hash(template_file)

    # Hash libfuzzer-modern directory
    libfuzzer_dir = build_dir / "libfuzzer-modern"
    if libfuzzer_dir.exists():
        asset_hashes["libfuzzer-modern"] = compute_directory_hash(libfuzzer_dir)

    # Hash CASR binaries tarball
    casr_tarball = build_dir / "casr-binaries.tar.gz"
    if casr_tarball.exists():
        asset_hashes["casr-binaries.tar.gz"] = compute_file_hash(casr_tarball)

    # Hash glibc deb
    glibc_deb = build_dir / "libc6_2.35-0ubuntu3_amd64.deb"
    if glibc_deb.exists():
        asset_hashes["libc6_2.35-0ubuntu3_amd64.deb"] = compute_file_hash(glibc_deb)

    # Hash differential-debugging-deps debs
    for deb_file in sorted(build_dir.glob("differential-debugging-deps-*.deb")):
        asset_hashes[deb_file.name] = compute_file_hash(deb_file)

    # Hash casr_cluster.py
    casr_cluster_py = build_dir / "casr_cluster.py"
    if casr_cluster_py.exists():
        asset_hashes["casr_cluster.py"] = compute_file_hash(casr_cluster_py)

    # Compute combined hash from all asset hashes
    combined = hashlib.sha256()
    for key in sorted(asset_hashes.keys()):
        combined.update(key.encode())
        combined.update(asset_hashes[key].encode())

    # Use first 8 chars as version (like git short hash)
    version_hash = combined.hexdigest()[:8]

    return version_hash, asset_hashes


def compute_image_build_version(build_dir: Path) -> tuple[str, dict]:
    """Compute image build version from all inputs that affect Docker images.

    Unlike compute_build_version() which hashes built artifacts (tarballs, debs),
    this hashes SOURCE inputs so that changing CASR/DD source immediately
    invalidates the build version even before artifacts are rebuilt.

    Returns:
        Tuple of (version_hash, input_hashes_dict)
        version_hash is first 8 chars of combined hash
    """
    input_hashes: dict[str, str] = {}

    # Hash Dockerfile templates
    for template_name in [
        "dockerfile_vul_template",
        "dockerfile_fix_template",
        "dockerfile_fuzzing_template",
    ]:
        template_file = build_dir / template_name
        if template_file.exists():
            input_hashes[template_name] = compute_file_hash(template_file)

    # Hash libfuzzer-modern directory
    libfuzzer_dir = build_dir / "libfuzzer-modern"
    if libfuzzer_dir.exists():
        input_hashes["libfuzzer-modern"] = compute_directory_hash(libfuzzer_dir)

    # Hash CASR and DD SOURCE (not built artifacts)
    # This ensures changing source invalidates images before deps are rebuilt
    casr_hash, dd_hash = compute_deps_source_hash(build_dir)
    if casr_hash:
        input_hashes["casr-source"] = casr_hash
    if dd_hash:
        input_hashes["dd-source"] = dd_hash

    # Hash casr_cluster.py
    casr_cluster_py = build_dir / "casr_cluster.py"
    if casr_cluster_py.exists():
        input_hashes["casr_cluster.py"] = compute_file_hash(casr_cluster_py)

    # Hash glibc deb (rarely changes, but include for correctness)
    glibc_deb = build_dir / "libc6_2.35-0ubuntu3_amd64.deb"
    if glibc_deb.exists():
        input_hashes["libc6_2.35-0ubuntu3_amd64.deb"] = compute_file_hash(glibc_deb)

    # Compute combined hash
    combined = hashlib.sha256()
    for key in sorted(input_hashes.keys()):
        combined.update(key.encode())
        combined.update(input_hashes[key].encode())

    version_hash = combined.hexdigest()[:8]
    return version_hash, input_hashes


def get_build_version_from_gcs(bucket: str) -> Optional[str]:
    """Get current build version from GCS manifest."""
    result = run_gsutil(
        ["cat", f"gs://{bucket}/build-assets/manifest.json"],
        check=False,
    )
    if result.returncode == 0:
        try:
            manifest = json.loads(result.stdout)
            return manifest.get("version")
        except json.JSONDecodeError:
            pass
    return None


# =============================================================================
# Runtime Hash Functions
# =============================================================================


def compute_runtime_source_hash() -> str:
    """Compute hash of agent/ and evaluation/ source files.

    Uses the shared compute_hashes.sh script as the single source of truth.

    Returns:
        SHA256 hash of all Python source files in agent/ and evaluation/
    """
    runtime_dir = get_script_dir() / "portable-runtime"
    return _call_hash_script("runtime", runtime_dir)


def get_runtime_built_hash() -> Optional[str]:
    """Get the source hash from the last built runtime.

    Returns:
        Hash string if found, None otherwise
    """
    manifest_path = get_script_dir() / "portable-runtime" / "output" / "source-hash.txt"
    if manifest_path.exists():
        return manifest_path.read_text().strip()
    return None


def save_runtime_built_hash(source_hash: str) -> None:
    """Save the source hash after building runtime."""
    manifest_path = get_script_dir() / "portable-runtime" / "output" / "source-hash.txt"
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(source_hash)


def check_runtime_needs_rebuild() -> tuple[bool, str]:
    """Check if the runtime needs to be rebuilt.

    Returns:
        Tuple of (needs_rebuild, reason)
    """
    runtime_dir = get_script_dir() / "portable-runtime"
    runtime_tar = runtime_dir / "output" / "agent-runtime.tar.gz"

    # Check if tarball exists
    if not runtime_tar.exists():
        return True, "runtime tarball not found"

    # Compare source hashes
    current_hash = compute_runtime_source_hash()
    built_hash = get_runtime_built_hash()

    if built_hash is None:
        return True, "no build hash found"

    if current_hash != built_hash:
        return True, f"source changed ({built_hash[:8]}... -> {current_hash[:8]}...)"

    return False, "up to date"


# =============================================================================
# Dependencies Hash Functions
# =============================================================================


def compute_deps_source_hash(build_dir: Path) -> tuple[str, str]:
    """Compute hashes of deps source files.

    Uses the shared compute_hashes.sh script as the single source of truth.

    Returns:
        Tuple of (casr_hash, dd_hash)
    """
    casr_hash = ""
    dd_hash = ""

    # Hash CASR source
    casr_dir = build_dir / "casr"
    if casr_dir.exists():
        casr_hash = _call_hash_script("casr", casr_dir)

    # Hash DD build script
    dd_script = build_dir / "build_deb_packages.sh"
    if dd_script.exists():
        dd_hash = _call_hash_script("dd", dd_script)

    return casr_hash, dd_hash


def get_deps_manifest_from_gcs(bucket: str) -> dict:
    """Get deps manifest from GCS."""
    result = run_gsutil(
        ["cat", f"gs://{bucket}/build-assets/deps-manifest.json"],
        check=False,
    )
    if result.returncode == 0:
        try:
            return json.loads(result.stdout)
        except json.JSONDecodeError:
            pass
    return {}


def check_deps_artifacts_exist(bucket: str) -> bool:
    """Check if all deps artifacts exist in GCS."""
    artifacts = [
        "casr-binaries.tar.gz",
        "differential-debugging-deps-16.04.deb",
        "differential-debugging-deps-20.04.deb",
    ]
    for artifact in artifacts:
        result = run_gsutil(
            ["ls", f"gs://{bucket}/build-assets/{artifact}"],
            check=False,
        )
        if result.returncode != 0:
            return False
    return True


def check_deps_need_rebuild(bucket: str, build_dir: Path) -> tuple[bool, str, bool]:
    """Check if deps need to be rebuilt.

    Returns:
        Tuple of (needs_rebuild, reason, needs_dd_rebuild)
        needs_dd_rebuild is True if DD (differential-debugging-deps) needs rebuild,
        which requires 32 cores due to LLDB compilation.
    """
    # Check if artifacts exist
    if not check_deps_artifacts_exist(bucket):
        return (
            True,
            "deps artifacts missing in GCS",
            True,
        )  # Assume DD needed if missing

    # Compare hashes
    local_casr_hash, local_dd_hash = compute_deps_source_hash(build_dir)
    manifest = get_deps_manifest_from_gcs(bucket)

    gcs_casr_hash = manifest.get("casr_hash", "")[:16]
    gcs_dd_hash = manifest.get("dd_hash", "")[:16]

    casr_changed = local_casr_hash != gcs_casr_hash
    dd_changed = local_dd_hash != gcs_dd_hash

    if casr_changed and dd_changed:
        return (
            True,
            f"CASR and DD changed",
            True,  # DD needs rebuild
        )
    if dd_changed:
        return (
            True,
            f"DD script changed ({gcs_dd_hash[:8]}... -> {local_dd_hash[:8]}...)",
            True,  # DD needs rebuild
        )
    if casr_changed:
        return (
            True,
            f"CASR source changed ({gcs_casr_hash[:8]}... -> {local_casr_hash[:8]}...)",
            False,  # Only CASR, no DD rebuild needed
        )

    return False, "deps up to date", False
