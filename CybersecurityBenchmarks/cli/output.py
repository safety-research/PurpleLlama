"""
Output utilities for CLI.
"""

import typer


def echo_info(message: str) -> None:
    """Print info message."""
    typer.echo(f"[*] {message}")


def echo_success(message: str) -> None:
    """Print success message."""
    typer.echo(typer.style(f"[+] {message}", fg=typer.colors.GREEN))


def echo_warning(message: str) -> None:
    """Print warning message."""
    typer.echo(typer.style(f"[!] {message}", fg=typer.colors.YELLOW))


def echo_error(message: str) -> None:
    """Print error message."""
    typer.echo(typer.style(f"[-] {message}", fg=typer.colors.RED))
