"""
Upload commands: upload-runtime, upload-build-assets, upload-deps-sources.
"""

import json
import subprocess
from datetime import datetime
from typing import Annotated

import typer

from ..gcp_utils import get_script_dir, load_config, run_gsutil
from ..hashing import (
    AUTOPATCH_BUILD_DIR,
    check_runtime_needs_rebuild,
    compute_build_version,
    compute_runtime_source_hash,
    get_build_version_from_gcs,
    save_runtime_built_hash,
)
from ..output import echo_error, echo_info, echo_success, echo_warning


# =============================================================================
# Runtime Upload Functions
# =============================================================================


def rebuild_runtime(quiet: bool = False) -> bool:
    """Rebuild the agent runtime.

    Returns:
        True if build succeeded, False otherwise
    """
    runtime_dir = get_script_dir() / "portable-runtime"
    build_script = runtime_dir / "build.sh"

    if not build_script.exists():
        if not quiet:
            echo_error(f"Build script not found: {build_script}")
        return False

    if not quiet:
        echo_info("Rebuilding agent runtime...")

    result = subprocess.run(
        ["bash", str(build_script)],
        cwd=str(runtime_dir),
        capture_output=True,
        text=True,
    )

    if result.returncode != 0:
        if not quiet:
            echo_error("Runtime build failed")
            if result.stderr:
                typer.echo(result.stderr[-500:])  # Show last 500 chars of error
        return False

    # Save the source hash
    source_hash = compute_runtime_source_hash()
    save_runtime_built_hash(source_hash)

    if not quiet:
        echo_success("Runtime rebuilt successfully")

    return True


def upload_runtime_impl(bucket: str, quiet: bool = False, auto_rebuild: bool = True) -> bool:
    """Upload portable runtime to GCS.

    Args:
        bucket: GCS bucket name
        quiet: If True, reduce output verbosity
        auto_rebuild: If True, automatically rebuild if source changed

    Returns:
        True if upload succeeded, False otherwise
    """
    runtime_tar = (
        get_script_dir() / "portable-runtime" / "output" / "agent-runtime.tar.gz"
    )

    # Check if rebuild is needed
    if auto_rebuild:
        needs_rebuild, reason = check_runtime_needs_rebuild()
        if needs_rebuild:
            if not quiet:
                echo_info(f"Runtime needs rebuild: {reason}")
            if not rebuild_runtime(quiet=quiet):
                return False

    if not runtime_tar.exists():
        if not quiet:
            echo_error(f"Runtime tarball not found: {runtime_tar}")
            echo_info("Build it first: cd portable-runtime && ./build.sh")
        return False

    if not quiet:
        echo_info(f"Uploading {runtime_tar.name} to gs://{bucket}/agent-runtime/")

    result = run_gsutil(
        ["cp", str(runtime_tar), f"gs://{bucket}/agent-runtime/"], check=False
    )
    if result.returncode != 0:
        if not quiet:
            echo_error("Failed to upload runtime")
        return False

    if not quiet:
        echo_success("Runtime uploaded!")
    return True


def upload_runtime() -> None:
    """Upload portable runtime to GCS (with auto-rebuild if source changed)."""
    config = load_config()
    if not config:
        echo_error("GCP not configured. Run 'setup' first.")
        raise typer.Exit(1)

    bucket = config["bucket_name"]
    if not upload_runtime_impl(bucket, quiet=False, auto_rebuild=True):
        echo_error("Failed to upload runtime")
        raise typer.Exit(1)

    echo_success("Runtime uploaded!")


# =============================================================================
# Build Assets Upload Functions
# =============================================================================


def upload_build_assets_impl(bucket: str, quiet: bool = False) -> tuple[bool, str]:
    """Upload build assets to GCS if they have changed.

    Args:
        bucket: GCS bucket name
        quiet: If True, reduce output verbosity

    Returns:
        Tuple of (success, version_hash)
    """
    build_dir = AUTOPATCH_BUILD_DIR

    if not build_dir.exists():
        if not quiet:
            echo_error(f"Build directory not found: {build_dir}")
        return False, ""

    # Compute local build version
    version_hash, asset_hashes = compute_build_version(build_dir)

    # Check if GCS version matches
    gcs_version = get_build_version_from_gcs(bucket)
    if gcs_version == version_hash:
        if not quiet:
            echo_info(f"Build assets unchanged (version: {version_hash})")
        return True, version_hash

    if not quiet:
        echo_info(f"Build assets changed: {gcs_version or 'none'} -> {version_hash}")
        echo_info("Uploading build assets...")

    # Upload all assets (simplified - just the essential ones)
    templates = [
        "dockerfile_vul_template",
        "dockerfile_fix_template",
        "dockerfile_fuzzing_template",
    ]
    for template_name in templates:
        template_file = build_dir / template_name
        if template_file.exists():
            run_gsutil(
                ["cp", str(template_file), f"gs://{bucket}/build-assets/"], check=False
            )

    # Upload libfuzzer-modern directory
    libfuzzer_dir = build_dir / "libfuzzer-modern"
    if libfuzzer_dir.exists():
        run_gsutil(
            ["-m", "cp", "-r", str(libfuzzer_dir), f"gs://{bucket}/build-assets/"],
            check=False,
        )

    # Upload casr-binaries.tar.gz
    casr_tarball = build_dir / "casr-binaries.tar.gz"
    if casr_tarball.exists():
        run_gsutil(
            ["cp", str(casr_tarball), f"gs://{bucket}/build-assets/"], check=False
        )

    # Upload glibc 2.35
    glibc_deb = build_dir / "libc6_2.35-0ubuntu3_amd64.deb"
    if glibc_deb.exists():
        run_gsutil(["cp", str(glibc_deb), f"gs://{bucket}/build-assets/"], check=False)

    # Upload differential-debugging-deps debs
    for deb_file in build_dir.glob("differential-debugging-deps-*.deb"):
        run_gsutil(["cp", str(deb_file), f"gs://{bucket}/build-assets/"], check=False)

    # Upload microsnapshots directory
    microsnapshots_dir = build_dir / "microsnapshots"
    if microsnapshots_dir.exists():
        run_gsutil(
            ["-m", "cp", "-r", str(microsnapshots_dir), f"gs://{bucket}/build-assets/"],
            check=False,
        )

    # Upload casr_cluster.py
    casr_cluster_py = build_dir / "casr_cluster.py"
    if casr_cluster_py.exists():
        run_gsutil(
            ["cp", str(casr_cluster_py), f"gs://{bucket}/build-assets/"], check=False
        )

    # Generate and upload manifest
    manifest = {
        "version": version_hash,
        "assets": asset_hashes,
        "updated_at": datetime.utcnow().isoformat() + "Z",
    }
    manifest_path = build_dir / "manifest.json"
    with open(manifest_path, "w") as f:
        json.dump(manifest, f, indent=2)

    run_gsutil(["cp", str(manifest_path), f"gs://{bucket}/build-assets/"], check=False)
    manifest_path.unlink()  # Clean up local file

    if not quiet:
        echo_success(f"Build assets uploaded (version: {version_hash})")

    return True, version_hash


def upload_build_assets(
    skip_if_unchanged: Annotated[
        bool, typer.Option("--skip-if-unchanged", help="Skip upload if hashes match")
    ] = False,
) -> None:
    """Upload build assets (Dockerfile template, libfuzzer, CASR) to GCS.

    These assets are required by the build job to create ARVO container images.
    Source: benchmark/autopatch/build/

    Computes SHA256 hashes of all assets and generates a manifest.json with a
    version hash. The version hash changes when any build asset changes, which
    triggers container rebuilds.
    """
    config = load_config()
    if not config:
        echo_error("GCP not configured. Run 'setup' first.")
        raise typer.Exit(1)

    bucket = config["bucket_name"]
    build_dir = AUTOPATCH_BUILD_DIR

    if not build_dir.exists():
        echo_error(f"Build directory not found: {build_dir}")
        raise typer.Exit(1)

    typer.echo("=" * 50)
    typer.echo("Upload Build Assets")
    typer.echo("=" * 50)
    typer.echo(f"Source:      {build_dir}")
    typer.echo(f"Destination: gs://{bucket}/build-assets/")
    typer.echo()

    # Compute build version hash
    echo_info("Computing build version hash...")
    version_hash, asset_hashes = compute_build_version(build_dir)
    typer.echo(f"Build version: {version_hash}")
    typer.echo()

    # Check if we should skip upload
    if skip_if_unchanged:
        current_version = get_build_version_from_gcs(bucket)
        if current_version == version_hash:
            echo_success(f"Build assets unchanged (version: {version_hash})")
            typer.echo("Skipping upload.")
            return

    # Upload all Dockerfile templates
    templates = [
        "dockerfile_vul_template",  # For -vul images (minimal, just libfuzzer)
        "dockerfile_fix_template",  # For GT -fix images (with 10-min QA fuzzing)
        "dockerfile_fuzzing_template",  # For eval -fix images (no 10-min QA)
    ]
    for template_name in templates:
        template_file = build_dir / template_name
        if template_file.exists():
            echo_info(f"Uploading {template_name}...")
            run_gsutil(["cp", str(template_file), f"gs://{bucket}/build-assets/"])
            echo_success(f"{template_name} uploaded")
        else:
            echo_warning(f"{template_name} not found at {template_file}")

    # Upload libfuzzer-modern directory
    libfuzzer_dir = build_dir / "libfuzzer-modern"
    if libfuzzer_dir.exists():
        echo_info("Uploading libfuzzer-modern/...")
        run_gsutil(
            ["-m", "cp", "-r", str(libfuzzer_dir), f"gs://{bucket}/build-assets/"]
        )
        echo_success("libfuzzer-modern uploaded")
    else:
        echo_warning(f"libfuzzer-modern not found at {libfuzzer_dir}")

    # Upload casr-binaries.tar.gz (required for CASR crash deduplication)
    casr_tarball = build_dir / "casr-binaries.tar.gz"
    if casr_tarball.exists():
        echo_info("Uploading casr-binaries.tar.gz...")
        run_gsutil(["cp", str(casr_tarball), f"gs://{bucket}/build-assets/"])
        echo_success("casr-binaries.tar.gz uploaded")
    else:
        casr_dir = build_dir / "casr"
        if casr_dir.exists():
            echo_warning("casr-binaries.tar.gz not found")
            echo_info("You may need to build CASR binaries first:")
            echo_info(f"  cd {casr_dir} && cargo build --release")
            echo_info("  Then create casr-binaries.tar.gz with the binaries")
        else:
            echo_warning("Neither casr-binaries.tar.gz nor casr/ source found")

    # Upload glibc 2.35 (required by CASR in containers with older glibc)
    glibc_deb = build_dir / "libc6_2.35-0ubuntu3_amd64.deb"
    if glibc_deb.exists():
        echo_info("Uploading libc6_2.35-0ubuntu3_amd64.deb...")
        run_gsutil(["cp", str(glibc_deb), f"gs://{bucket}/build-assets/"])
        echo_success("libc6_2.35-0ubuntu3_amd64.deb uploaded")
    else:
        echo_warning(f"libc6_2.35-0ubuntu3_amd64.deb not found at {glibc_deb}")

    # Upload differential-debugging-deps debs
    for deb_file in build_dir.glob("differential-debugging-deps-*.deb"):
        echo_info(f"Uploading {deb_file.name}...")
        run_gsutil(["cp", str(deb_file), f"gs://{bucket}/build-assets/"])
        echo_success(f"{deb_file.name} uploaded")

    # Upload microsnapshots directory (for differential debugging)
    microsnapshots_dir = build_dir / "microsnapshots"
    if microsnapshots_dir.exists():
        echo_info("Uploading microsnapshots/...")
        run_gsutil(
            ["-m", "cp", "-r", str(microsnapshots_dir), f"gs://{bucket}/build-assets/"]
        )
        echo_success("microsnapshots uploaded")
    else:
        echo_warning(f"microsnapshots not found at {microsnapshots_dir}")

    # Upload casr_cluster.py (custom CASR clustering script)
    casr_cluster_py = build_dir / "casr_cluster.py"
    if casr_cluster_py.exists():
        echo_info("Uploading casr_cluster.py...")
        run_gsutil(["cp", str(casr_cluster_py), f"gs://{bucket}/build-assets/"])
        echo_success("casr_cluster.py uploaded")
    else:
        echo_warning(f"casr_cluster.py not found at {casr_cluster_py}")

    # Generate and upload manifest
    typer.echo()
    echo_info("Generating manifest.json...")
    manifest = {
        "version": version_hash,
        "assets": asset_hashes,
        "updated_at": datetime.utcnow().isoformat() + "Z",
    }
    manifest_path = build_dir / "manifest.json"
    with open(manifest_path, "w") as f:
        json.dump(manifest, f, indent=2)

    run_gsutil(["cp", str(manifest_path), f"gs://{bucket}/build-assets/"])
    manifest_path.unlink()  # Clean up local file
    echo_success(f"manifest.json uploaded (version: {version_hash})")

    typer.echo()
    echo_success("Build assets uploaded!")
    typer.echo()
    typer.echo(f"Build version: {version_hash}")
    typer.echo()
    typer.echo("Verify with:")
    typer.echo(f"  gsutil ls gs://{bucket}/build-assets/")
    typer.echo(f"  gsutil cat gs://{bucket}/build-assets/manifest.json")


# =============================================================================
# Deps Sources Upload Functions
# =============================================================================


def upload_deps_sources_impl(
    bucket: str, build_dir, quiet: bool = False
) -> bool:
    """Upload deps sources to GCS.

    Returns:
        True if upload succeeded
    """
    # Upload CASR submodule
    casr_dir = build_dir / "casr"
    if not casr_dir.exists():
        if not quiet:
            echo_error(f"CASR submodule not found at {casr_dir}")
        return False

    if not quiet:
        echo_info("Uploading CASR source...")
    result = subprocess.run(
        [
            "gsutil",
            "-m",
            "rsync",
            "-r",
            "-x",
            r"\.git|target|\.build-cache",
            str(casr_dir),
            f"gs://{bucket}/deps-sources/casr/",
        ],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        if not quiet:
            echo_error("Failed to upload CASR source")
        return False

    # Upload build_deb_packages.sh
    build_script = build_dir / "build_deb_packages.sh"
    if build_script.exists():
        run_gsutil(
            ["cp", str(build_script), f"gs://{bucket}/deps-sources/"], check=False
        )

    # Upload Dockerfile.casr-builder
    dockerfile = build_dir / "Dockerfile.casr-builder"
    if dockerfile.exists():
        run_gsutil(["cp", str(dockerfile), f"gs://{bucket}/deps-sources/"], check=False)

    # Upload test script
    test_script = build_dir / "test_deb_install.sh"
    if test_script.exists():
        run_gsutil(
            ["cp", str(test_script), f"gs://{bucket}/deps-sources/"], check=False
        )

    # Upload compute_hashes.sh (single source of truth for hash computation)
    hash_script = get_script_dir() / "scripts" / "compute_hashes.sh"
    if hash_script.exists():
        run_gsutil(
            ["cp", str(hash_script), f"gs://{bucket}/deps-sources/"], check=False
        )

    if not quiet:
        echo_success("Deps sources uploaded")
    return True


def upload_deps_sources() -> None:
    """Upload CASR source and DD build scripts to GCS for deps build.

    This uploads the source files needed by the deps build job:
    - benchmark/autopatch/build/casr/ (CASR submodule)
    - benchmark/autopatch/build/build_deb_packages.sh
    - benchmark/autopatch/build/Dockerfile.casr-builder

    Run this before submitting a deps build job.
    """
    config = load_config()
    if not config:
        echo_error("GCP not configured. Run 'setup' first.")
        raise typer.Exit(1)

    bucket = config["bucket_name"]
    build_dir = AUTOPATCH_BUILD_DIR

    typer.echo("=" * 50)
    typer.echo("Upload Dependencies Sources")
    typer.echo("=" * 50)
    typer.echo(f"Source:      {build_dir}")
    typer.echo(f"Destination: gs://{bucket}/deps-sources/")
    typer.echo()

    # Upload CASR submodule
    casr_dir = build_dir / "casr"
    if casr_dir.exists():
        echo_info("Uploading CASR source (this may take a moment)...")
        # Exclude .git and target directories to reduce size
        result = subprocess.run(
            [
                "gsutil",
                "-m",
                "rsync",
                "-r",
                "-x",
                r"\.git|target|\.build-cache",
                str(casr_dir),
                f"gs://{bucket}/deps-sources/casr/",
            ],
            capture_output=True,
            text=True,
        )
        if result.returncode == 0:
            echo_success("CASR source uploaded")
        else:
            echo_error("Failed to upload CASR source")
            typer.echo(result.stderr)
    else:
        echo_error(f"CASR submodule not found at {casr_dir}")
        echo_info("Initialize with: git submodule update --init")
        raise typer.Exit(1)

    # Upload build_deb_packages.sh
    build_script = build_dir / "build_deb_packages.sh"
    if build_script.exists():
        echo_info("Uploading build_deb_packages.sh...")
        run_gsutil(["cp", str(build_script), f"gs://{bucket}/deps-sources/"])
        echo_success("build_deb_packages.sh uploaded")
    else:
        echo_warning(f"build_deb_packages.sh not found at {build_script}")

    # Upload Dockerfile.casr-builder
    dockerfile = build_dir / "Dockerfile.casr-builder"
    if dockerfile.exists():
        echo_info("Uploading Dockerfile.casr-builder...")
        run_gsutil(["cp", str(dockerfile), f"gs://{bucket}/deps-sources/"])
        echo_success("Dockerfile.casr-builder uploaded")
    else:
        echo_warning(f"Dockerfile.casr-builder not found at {dockerfile}")

    # Upload test script
    test_script = build_dir / "test_deb_install.sh"
    if test_script.exists():
        echo_info("Uploading test_deb_install.sh...")
        run_gsutil(["cp", str(test_script), f"gs://{bucket}/deps-sources/"])
        echo_success("test_deb_install.sh uploaded")

    # Upload compute_hashes.sh (single source of truth for hash computation)
    hash_script = get_script_dir() / "scripts" / "compute_hashes.sh"
    if hash_script.exists():
        echo_info("Uploading compute_hashes.sh...")
        run_gsutil(["cp", str(hash_script), f"gs://{bucket}/deps-sources/"])
        echo_success("compute_hashes.sh uploaded")
    else:
        echo_warning(f"compute_hashes.sh not found at {hash_script}")

    typer.echo()
    echo_success("Dependencies sources uploaded!")
    typer.echo()
    typer.echo("Verify with:")
    typer.echo(f"  gsutil ls gs://{bucket}/deps-sources/")
