"""
Terminal output helper functions for the ARVO GCP CLI.
"""

import typer


def echo_success(msg: str) -> None:
    """Print success message."""
    typer.echo(typer.style(f"✓ {msg}", fg=typer.colors.GREEN))


def echo_info(msg: str) -> None:
    """Print info message."""
    typer.echo(typer.style(f"• {msg}", fg=typer.colors.BLUE))


def echo_warning(msg: str) -> None:
    """Print warning message."""
    typer.echo(typer.style(f"⚠ {msg}", fg=typer.colors.YELLOW))


def echo_error(msg: str) -> None:
    """Print error message."""
    typer.echo(typer.style(f"✗ {msg}", fg=typer.colors.RED), err=True)
