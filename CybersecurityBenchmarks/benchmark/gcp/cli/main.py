#!/usr/bin/env python3
"""
ARVO Benchmark GCP CLI

Command-line interface for managing ARVO benchmark jobs on GCP Cloud Batch.

Usage:
    python -m cli setup --project my-project
    python -m cli submit --cases 42,43,44 --model claude-sonnet-4-20250514
    python -m cli monitor --watch
    python -m cli collect --output ./results
"""

import typer

from .commands import collect as collect_mod
from .commands import deps as deps_mod
from .commands import monitor as monitor_mod
from .commands import runs as runs_mod
from .commands import setup as setup_mod
from .commands import submit as submit_mod
from .commands import upload as upload_mod
from .commands import vm as vm_mod


app = typer.Typer(
    name="arvo-gcp",
    help="ARVO Benchmark GCP CLI - Manage benchmark jobs on Cloud Batch",
    add_completion=False,
)

# =============================================================================
# Register Commands
# =============================================================================

# Setup commands
app.command()(setup_mod.setup)
app.command(name="check-permissions")(setup_mod.check_permissions)
app.command()(setup_mod.teardown)

# Job commands
app.command()(submit_mod.submit)
app.command()(monitor_mod.monitor)
app.command()(collect_mod.collect)

# Upload commands
app.command(name="upload-runtime")(upload_mod.upload_runtime)
app.command(name="upload-build-assets")(upload_mod.upload_build_assets)
app.command(name="upload-deps-sources")(upload_mod.upload_deps_sources)

# Deps build command
app.command(name="build-deps")(deps_mod.build_deps)

# VM commands
app.command(name="create-vm-image")(vm_mod.create_vm_image)
app.command(name="debug-vm")(vm_mod.debug_vm)
app.command(name="delete-debug-vm")(vm_mod.delete_debug_vm)
app.command(name="debug")(vm_mod.debug_job)

# =============================================================================
# Runs Subcommand Group
# =============================================================================

runs_app = typer.Typer(help="Manage benchmark runs")
app.add_typer(runs_app, name="runs")

runs_app.command("list")(runs_mod.runs_list)
runs_app.command("status")(runs_mod.runs_status)
runs_app.command("jobs")(runs_mod.runs_jobs)
runs_app.command("logs")(runs_mod.runs_logs)
runs_app.command("delete")(runs_mod.runs_delete)


# =============================================================================
# Main
# =============================================================================


def main() -> None:
    """Entry point."""
    app()


if __name__ == "__main__":
    main()
