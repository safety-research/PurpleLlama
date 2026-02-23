"""
Dependencies build command: build-deps, upload-build-assets.
"""

import json
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Annotated, Optional

import typer

from ..argo import submit_workflow
from ..config import GKEConfig, get_script_dir
from ..output import echo_error, echo_info, echo_success, echo_warning


AUTOPATCH_BUILD_DIR = get_script_dir() / "build"


def _run_gsutil(args: list[str], check: bool = True) -> subprocess.CompletedProcess:
    """Run gsutil command."""
    result = subprocess.run(
        ["gsutil"] + args,
        capture_output=True,
        text=True,
    )
    if check and result.returncode != 0:
        raise RuntimeError(f"gsutil failed: {result.stderr}")
    return result


def upload_deps_sources(
    quiet: Annotated[bool, typer.Option("--quiet", "-q", help="Reduce output")] = False,
) -> None:
    """Upload CASR source and DD build scripts to GCS.

    This uploads the source files needed by the deps build jobs:
    - build/casr/ (CASR submodule)
    - build/build_deb_packages.sh
    - scripts/compute_hashes.sh

    Run this before submitting deps build jobs.
    """
    gke_config = GKEConfig.load()
    if not gke_config.is_configured():
        echo_error("GKE not configured. Run: python -m cli setup")
        raise typer.Exit(1)

    bucket = gke_config.bucket_name
    build_dir = AUTOPATCH_BUILD_DIR

    if not quiet:
        typer.echo("=" * 50)
        typer.echo("Upload Dependencies Sources")
        typer.echo("=" * 50)
        typer.echo(f"Source:      {build_dir}")
        typer.echo(f"Destination: gs://{bucket}/deps-sources/")
        typer.echo()

    # Upload CASR submodule
    casr_dir = build_dir / "casr"
    if casr_dir.exists():
        if not quiet:
            echo_info("Uploading CASR source (this may take a moment)...")
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
            if not quiet:
                echo_success("CASR source uploaded")
        else:
            echo_error("Failed to upload CASR source")
            typer.echo(result.stderr)
            raise typer.Exit(1)
    else:
        echo_error(f"CASR submodule not found at {casr_dir}")
        echo_info("Initialize with: git submodule update --init")
        raise typer.Exit(1)

    # Upload build_deb_packages.sh
    build_script = build_dir / "build_deb_packages.sh"
    if build_script.exists():
        if not quiet:
            echo_info("Uploading build_deb_packages.sh...")
        _run_gsutil(["cp", str(build_script), f"gs://{bucket}/deps-sources/"])
        if not quiet:
            echo_success("build_deb_packages.sh uploaded")
    else:
        echo_warning(f"build_deb_packages.sh not found at {build_script}")

    # Upload Dockerfile.casr-builder
    dockerfile = build_dir / "Dockerfile.casr-builder"
    if dockerfile.exists():
        if not quiet:
            echo_info("Uploading Dockerfile.casr-builder...")
        _run_gsutil(["cp", str(dockerfile), f"gs://{bucket}/deps-sources/"])
        if not quiet:
            echo_success("Dockerfile.casr-builder uploaded")

    # Upload build-libfuzzer.sh
    libfuzzer_build_script = build_dir / "build-libfuzzer.sh"
    if libfuzzer_build_script.exists():
        if not quiet:
            echo_info("Uploading build-libfuzzer.sh...")
        _run_gsutil(["cp", str(libfuzzer_build_script), f"gs://{bucket}/deps-sources/"])
        if not quiet:
            echo_success("build-libfuzzer.sh uploaded")
    else:
        echo_warning(f"build-libfuzzer.sh not found at {libfuzzer_build_script}")

    # Upload libfuzzer-modern source (needed by build-libfuzzer GKE job)
    libfuzzer_dir = build_dir / "libfuzzer-modern"
    if libfuzzer_dir.exists():
        if not quiet:
            echo_info("Uploading libfuzzer-modern/ to deps-sources...")
        result = subprocess.run(
            [
                "gsutil",
                "-m",
                "rsync",
                "-r",
                "-x",
                r"\.git|libFuzzer\.a|libFuzzer_no_main\.a",
                str(libfuzzer_dir),
                f"gs://{bucket}/deps-sources/libfuzzer-modern/",
            ],
            capture_output=True,
            text=True,
        )
        if result.returncode == 0:
            if not quiet:
                echo_success("libfuzzer-modern source uploaded")
        else:
            echo_warning(f"Failed to upload libfuzzer-modern: {result.stderr}")
    else:
        echo_warning(f"libfuzzer-modern not found at {libfuzzer_dir}")

    # Upload compute_hashes.sh
    hash_script = get_script_dir() / "scripts" / "compute_hashes.sh"
    if hash_script.exists():
        if not quiet:
            echo_info("Uploading compute_hashes.sh...")
        _run_gsutil(["cp", str(hash_script), f"gs://{bucket}/deps-sources/"])
        if not quiet:
            echo_success("compute_hashes.sh uploaded")
    else:
        echo_warning(f"compute_hashes.sh not found at {hash_script}")

    if not quiet:
        typer.echo()
        echo_success("Dependencies sources uploaded!")
        typer.echo()
        typer.echo("Verify with:")
        typer.echo(f"  gsutil ls gs://{bucket}/deps-sources/")


def upload_build_assets(
    quiet: Annotated[bool, typer.Option("--quiet", "-q", help="Reduce output")] = False,
) -> None:
    """Upload build assets to GCS.

    Uploads Dockerfile templates, libfuzzer-modern, and other build assets
    from build/ to GCS.
    """
    gke_config = GKEConfig.load()
    if not gke_config.is_configured():
        echo_error("GKE not configured. Run: python -m cli setup")
        raise typer.Exit(1)

    bucket = gke_config.bucket_name
    build_dir = AUTOPATCH_BUILD_DIR

    if not quiet:
        typer.echo("=" * 50)
        typer.echo("Upload Build Assets")
        typer.echo("=" * 50)
        typer.echo(f"Source:      {build_dir}")
        typer.echo(f"Destination: gs://{bucket}/build-assets/")
        typer.echo()

    # Upload Dockerfile templates
    templates = [
        "dockerfile_vul_template",
        "dockerfile_fix_template",
        "dockerfile_fuzzing_template",
    ]
    for template_name in templates:
        template_file = build_dir / template_name
        if template_file.exists():
            if not quiet:
                echo_info(f"Uploading {template_name}...")
            _run_gsutil(["cp", str(template_file), f"gs://{bucket}/build-assets/"])
            if not quiet:
                echo_success(f"{template_name} uploaded")
        else:
            echo_warning(f"{template_name} not found")

    # Upload MSan scoped-disable backport script
    patch_script = build_dir / "patch-msan-scoped-disable.sh"
    if patch_script.exists():
        if not quiet:
            echo_info("Uploading patch-msan-scoped-disable.sh...")
        _run_gsutil(["cp", str(patch_script), f"gs://{bucket}/build-assets/"])
        if not quiet:
            echo_success("patch-msan-scoped-disable.sh uploaded")
    else:
        echo_warning("patch-msan-scoped-disable.sh not found")

    # Upload libfuzzer-modern directory
    libfuzzer_dir = build_dir / "libfuzzer-modern"
    if libfuzzer_dir.exists():
        if not quiet:
            echo_info("Uploading libfuzzer-modern/...")
        _run_gsutil(
            ["-m", "cp", "-r", str(libfuzzer_dir), f"gs://{bucket}/build-assets/"]
        )
        if not quiet:
            echo_success("libfuzzer-modern uploaded")
    else:
        echo_warning(f"libfuzzer-modern not found at {libfuzzer_dir}")

    # Upload casr-binaries.tar.gz
    casr_tarball = build_dir / "casr-binaries.tar.gz"
    if casr_tarball.exists():
        if not quiet:
            echo_info("Uploading casr-binaries.tar.gz...")
        _run_gsutil(["cp", str(casr_tarball), f"gs://{bucket}/build-assets/"])
        if not quiet:
            echo_success("casr-binaries.tar.gz uploaded")
    else:
        echo_warning("casr-binaries.tar.gz not found (run build-casr first)")

    # Upload glibc 2.35
    glibc_deb = build_dir / "libc6_2.35-0ubuntu3_amd64.deb"
    if glibc_deb.exists():
        if not quiet:
            echo_info("Uploading libc6_2.35-0ubuntu3_amd64.deb...")
        _run_gsutil(["cp", str(glibc_deb), f"gs://{bucket}/build-assets/"])
        if not quiet:
            echo_success("libc6_2.35-0ubuntu3_amd64.deb uploaded")

    # Upload differential-debugging-deps debs
    for deb_file in sorted(build_dir.glob("differential-debugging-deps-*.deb")):
        if not quiet:
            echo_info(f"Uploading {deb_file.name}...")
        _run_gsutil(["cp", str(deb_file), f"gs://{bucket}/build-assets/"])
        if not quiet:
            echo_success(f"{deb_file.name} uploaded")

    # Upload libfuzzer-prebuilt.tar.gz
    libfuzzer_prebuilt = build_dir / "libfuzzer-prebuilt" / "libfuzzer-prebuilt.tar.gz"
    if libfuzzer_prebuilt.exists():
        if not quiet:
            echo_info("Uploading libfuzzer-prebuilt.tar.gz...")
        _run_gsutil(["cp", str(libfuzzer_prebuilt), f"gs://{bucket}/build-assets/"])
        if not quiet:
            echo_success("libfuzzer-prebuilt.tar.gz uploaded")
    else:
        if not quiet:
            echo_warning(
                "libfuzzer-prebuilt.tar.gz not found (run build-libfuzzer first)"
            )

    # Upload microsnapshots directory
    microsnapshots_dir = build_dir / "microsnapshots"
    if microsnapshots_dir.exists():
        if not quiet:
            echo_info("Uploading microsnapshots/...")
        _run_gsutil(
            ["-m", "cp", "-r", str(microsnapshots_dir), f"gs://{bucket}/build-assets/"]
        )
        if not quiet:
            echo_success("microsnapshots uploaded")

    if not quiet:
        typer.echo()
        echo_success("Build assets uploaded!")
        typer.echo()
        typer.echo("Verify with:")
        typer.echo(f"  gsutil ls gs://{bucket}/build-assets/")


def build_casr(
    force: Annotated[
        bool, typer.Option("--force", "-f", help="Force rebuild even if unchanged")
    ] = False,
    dry_run: Annotated[
        bool, typer.Option("--dry-run", help="Show what would be done")
    ] = False,
) -> None:
    """Build CASR binaries on GKE.

    Submits an Argo workflow to build CASR from source.
    CASR is built using the Rust compiler (~15-30 minutes).

    The workflow:
    1. Downloads CASR source from GCS (upload with: upload-deps-sources)
    2. Compiles with cargo build --release
    3. Uploads casr-binaries.tar.gz to GCS
    """
    gke_config = GKEConfig.load()
    if not gke_config.is_configured():
        echo_error("GKE not configured. Run: python -m cli setup")
        raise typer.Exit(1)

    typer.echo("=" * 50)
    typer.echo("Build CASR")
    typer.echo("=" * 50)
    typer.echo(f"Bucket:        gs://{gke_config.bucket_name}")
    typer.echo(f"Force Rebuild: {force}")
    typer.echo()

    if dry_run:
        echo_warning("DRY RUN MODE")
        typer.echo("Would submit workflow to build CASR")
        return

    # Check if deps sources are uploaded
    result = _run_gsutil(
        ["ls", f"gs://{gke_config.bucket_name}/deps-sources/casr/"],
        check=False,
    )
    if result.returncode != 0:
        echo_error("CASR source not found in GCS")
        echo_info("Upload with: python -m cli upload-deps-sources")
        raise typer.Exit(1)

    # Submit workflow
    workflow_yaml = f"""
apiVersion: argoproj.io/v1alpha1
kind: Workflow
metadata:
  generateName: casr-build-
  namespace: argo
spec:
  entrypoint: main
  serviceAccountName: arvo-workflow-sa
  templates:
    - name: main
      dag:
        tasks:
          - name: build-casr
            templateRef:
              name: arvo-deps-build
              template: build-casr
            arguments:
              parameters:
                - name: bucket
                  value: "{gke_config.bucket_name}"
                - name: force-rebuild
                  value: "{str(force).lower()}"
"""

    # Write temp workflow file
    import tempfile

    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
        f.write(workflow_yaml)
        temp_path = f.name

    echo_info("Submitting CASR build workflow...")
    workflow_name = submit_workflow(temp_path, {})

    Path(temp_path).unlink()

    if workflow_name:
        typer.echo()
        echo_success(f"Workflow submitted: {workflow_name}")
        typer.echo()
        typer.echo("Monitor with:")
        typer.echo(f"  python -m cli status {workflow_name}")
        typer.echo(f"  python -m cli logs {workflow_name}")
    else:
        echo_error("Failed to submit workflow")
        raise typer.Exit(1)


def build_dd(
    force: Annotated[
        bool, typer.Option("--force", "-f", help="Force rebuild even if unchanged")
    ] = False,
    dry_run: Annotated[
        bool, typer.Option("--dry-run", help="Show what would be done")
    ] = False,
) -> None:
    """Build differential-debugging-deps packages on GKE.

    Submits an Argo workflow to build DD packages from source.
    This requires Docker-in-Docker and takes 2-4 hours.

    The workflow:
    1. Downloads build script from GCS (upload with: upload-deps-sources)
    2. Builds Python 3.7 and LLDB 13 in containers
    3. Creates .deb packages for Ubuntu 16.04 and 20.04
    4. Uploads packages to GCS
    """
    gke_config = GKEConfig.load()
    if not gke_config.is_configured():
        echo_error("GKE not configured. Run: python -m cli setup")
        raise typer.Exit(1)

    typer.echo("=" * 50)
    typer.echo("Build Differential Debugging Deps")
    typer.echo("=" * 50)
    typer.echo(f"Bucket:        gs://{gke_config.bucket_name}")
    typer.echo(f"Force Rebuild: {force}")
    typer.echo()
    echo_warning("This build takes 2-4 hours!")
    typer.echo()

    if dry_run:
        echo_warning("DRY RUN MODE")
        typer.echo("Would submit workflow to build DD packages")
        return

    # Check if deps sources are uploaded
    result = _run_gsutil(
        ["ls", f"gs://{gke_config.bucket_name}/deps-sources/build_deb_packages.sh"],
        check=False,
    )
    if result.returncode != 0:
        echo_error("DD build script not found in GCS")
        echo_info("Upload with: python -m cli upload-deps-sources")
        raise typer.Exit(1)

    # Submit workflow
    workflow_yaml = f"""
apiVersion: argoproj.io/v1alpha1
kind: Workflow
metadata:
  generateName: dd-build-
  namespace: argo
spec:
  entrypoint: build-dd
  serviceAccountName: arvo-workflow-sa
  templates:
    - name: build-dd
      templateRef:
        name: arvo-deps-build
        template: build-dd
      arguments:
        parameters:
          - name: bucket
            value: "{gke_config.bucket_name}"
          - name: force-rebuild
            value: "{str(force).lower()}"
"""

    # Write temp workflow file
    import tempfile

    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
        f.write(workflow_yaml)
        temp_path = f.name

    echo_info("Submitting DD build workflow...")
    workflow_name = submit_workflow(temp_path, {})

    Path(temp_path).unlink()

    if workflow_name:
        typer.echo()
        echo_success(f"Workflow submitted: {workflow_name}")
        typer.echo()
        typer.echo("Monitor with:")
        typer.echo(f"  python -m cli status {workflow_name}")
        typer.echo(f"  python -m cli logs {workflow_name}")
        typer.echo()
        echo_warning("This build takes 2-4 hours. Check status periodically.")
    else:
        echo_error("Failed to submit workflow")
        raise typer.Exit(1)


def build_libfuzzer(
    force: Annotated[
        bool, typer.Option("--force", "-f", help="Force rebuild even if unchanged")
    ] = False,
    dry_run: Annotated[
        bool, typer.Option("--dry-run", help="Show what would be done")
    ] = False,
) -> None:
    """Build namespace-isolated libFuzzer archives on GKE.

    Submits an Argo workflow to build libFuzzer with a private copy of
    libc++ in the __Fuzzer ABI namespace (matching LLVM's approach).
    This eliminates MSan false positives from uninstrumented libc++.

    The workflow:
    1. Downloads LLVM 10 libc++ source
    2. Builds libc++ with __Fuzzer namespace isolation
    3. Compiles our modified libfuzzer with matching flags
    4. Partial links + localizes symbols
    5. Produces libfuzzer-prebuilt.tar.gz (x86_64 + i386)
    """
    gke_config = GKEConfig.load()
    if not gke_config.is_configured():
        echo_error("GKE not configured. Run: python -m cli setup")
        raise typer.Exit(1)

    typer.echo("=" * 50)
    typer.echo("Build Namespace-Isolated libFuzzer")
    typer.echo("=" * 50)
    typer.echo(f"Bucket:        gs://{gke_config.bucket_name}")
    typer.echo(f"Force Rebuild: {force}")
    typer.echo()

    if dry_run:
        echo_warning("DRY RUN MODE")
        typer.echo("Would submit workflow to build libFuzzer")
        return

    # Check if deps sources are uploaded
    result = _run_gsutil(
        ["ls", f"gs://{gke_config.bucket_name}/deps-sources/build-libfuzzer.sh"],
        check=False,
    )
    if result.returncode != 0:
        echo_error("build-libfuzzer.sh not found in GCS")
        echo_info("Upload with: python -m cli upload-deps-sources")
        raise typer.Exit(1)

    # Submit workflow
    workflow_yaml = f"""
apiVersion: argoproj.io/v1alpha1
kind: Workflow
metadata:
  generateName: libfuzzer-build-
  namespace: argo
spec:
  entrypoint: main
  serviceAccountName: arvo-workflow-sa
  templates:
    - name: main
      dag:
        tasks:
          - name: build-libfuzzer
            templateRef:
              name: arvo-deps-build
              template: build-libfuzzer
            arguments:
              parameters:
                - name: bucket
                  value: "{gke_config.bucket_name}"
                - name: force-rebuild
                  value: "{str(force).lower()}"
"""

    import tempfile

    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
        f.write(workflow_yaml)
        temp_path = f.name

    echo_info("Submitting libFuzzer build workflow...")
    workflow_name = submit_workflow(temp_path, {})

    Path(temp_path).unlink()

    if workflow_name:
        typer.echo()
        echo_success(f"Workflow submitted: {workflow_name}")
        typer.echo()
        typer.echo("Monitor with:")
        typer.echo(f"  python -m cli status {workflow_name}")
        typer.echo(f"  python -m cli logs {workflow_name}")
    else:
        echo_error("Failed to submit workflow")
        raise typer.Exit(1)


def build_deps(
    casr_only: Annotated[
        bool, typer.Option("--casr-only", help="Only build CASR (skip DD)")
    ] = False,
    dd_only: Annotated[
        bool, typer.Option("--dd-only", help="Only build DD (skip CASR)")
    ] = False,
    force: Annotated[
        bool, typer.Option("--force", "-f", help="Force rebuild even if unchanged")
    ] = False,
    dry_run: Annotated[
        bool, typer.Option("--dry-run", help="Show what would be done")
    ] = False,
) -> None:
    """Build all dependencies (CASR and DD).

    This submits Argo workflows to build:
    - CASR: Crash Analysis and Severity Reporting binaries (~15-30 min)
    - DD: Differential debugging deps (Python 3.7 + LLDB 13) (~2-4 hours)

    Prerequisites:
    1. Upload source files: python -m cli upload-deps-sources
    2. Apply workflow template: kubectl apply -f argo/templates/deps-build-template.yaml
    """
    gke_config = GKEConfig.load()
    if not gke_config.is_configured():
        echo_error("GKE not configured. Run: python -m cli setup")
        raise typer.Exit(1)

    typer.echo("=" * 50)
    typer.echo("Build Dependencies")
    typer.echo("=" * 50)
    typer.echo(f"Bucket:        gs://{gke_config.bucket_name}")
    typer.echo(f"Force Rebuild: {force}")
    typer.echo(f"Build CASR:    {not dd_only}")
    typer.echo(f"Build DD:      {not casr_only}")
    typer.echo()

    if not casr_only and not dd_only:
        echo_warning("Building both CASR (~30 min) and DD (~2-4 hours)")
        typer.echo()

    if not dd_only:
        build_casr(force=force, dry_run=dry_run)
        typer.echo()

    if not casr_only:
        build_dd(force=force, dry_run=dry_run)
