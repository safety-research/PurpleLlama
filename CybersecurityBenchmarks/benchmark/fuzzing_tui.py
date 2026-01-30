# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

"""
TUI (Terminal User Interface) for the FuzzingOnlyBenchmark.

Provides real-time visualization of:
- Case status (pending, running, completed, failed)
- Fuzzing progress (time elapsed, crashes found)
- Per-case crash timeline
- CASR deduplication on demand

Uses Textual library with DataTable, RichLog, and TabbedContent.
"""

from __future__ import annotations

import threading
from typing import TYPE_CHECKING, Callable, Dict, Optional

if TYPE_CHECKING:
    from .fuzzing_types import CaseState, FuzzingConfig

try:
    from rich.markup import escape as rich_escape
    from textual.app import App, ComposeResult
    from textual.binding import Binding
    from textual.containers import Container, Vertical
    from textual.reactive import reactive
    from textual.widgets import (
        DataTable,
        Footer,
        Header,
        RichLog,
        Static,
        TabbedContent,
        TabPane,
    )

    TEXTUAL_AVAILABLE = True
except ImportError:
    TEXTUAL_AVAILABLE = False


def is_textual_available() -> bool:
    """Check if Textual library is available."""
    return TEXTUAL_AVAILABLE


if TEXTUAL_AVAILABLE:

    class FuzzingTUI(App):
        """Interactive TUI for monitoring fuzzing progress.

        Text Selection: Hold SHIFT while clicking and dragging to select text
        in most terminals (iTerm uses OPTION key instead).
        """

        ENABLE_COMMAND_PALETTE = False

        CSS = """
        Screen {
            layout: grid;
            grid-size: 2 2;
            grid-columns: 1fr 2fr;
            grid-rows: auto 1fr;
        }

        #header-container {
            column-span: 2;
            height: 3;
        }

        #cases-table {
            height: 100%;
            border: solid green;
        }

        #details-container {
            height: 100%;
        }

        RichLog {
            height: 1fr;
            scrollbar-gutter: stable;
            overflow-y: auto;
        }

        #fuzzing-output {
            border: solid cyan;
        }

        #timeline-time {
            border: solid yellow;
        }

        #timeline-execs {
            border: solid magenta;
        }

        #crash-details {
            border: solid red;
        }

        DataTable > .datatable--cursor {
            background: $accent;
        }

        .progress-bar {
            height: 1;
            background: $surface;
        }

        .progress-bar-fill {
            background: $success;
        }
        """

        BINDINGS = [
            Binding("q", "quit", "Quit"),
            Binding("t", "toggle_tab", "Toggle Tab"),
            Binding("d", "deduplicate", "Dedupe (CASR)"),
            Binding("r", "refresh", "Refresh"),
            Binding("c", "copy_output", "Copy Output"),
            Binding("l", "copy_log_path", "Copy Log Path"),
            Binding("up", "cursor_up", "Up", show=False),
            Binding("down", "cursor_down", "Down", show=False),
        ]

        selected_case_key: reactive[str | None] = reactive(None)

        def __init__(
            self,
            case_states: Dict[str, "CaseState"],
            config: "FuzzingConfig",
            on_deduplicate: Optional[Callable[[str], None]] = None,
            **kwargs,
        ):
            super().__init__(**kwargs)
            self.case_states = case_states
            self.config = config
            self.on_deduplicate = on_deduplicate
            self.lock = threading.Lock()
            self._col_keys = {}
            self._fuzzing_duration = config.fuzzing_duration_minutes * 60

        def compose(self) -> ComposeResult:
            yield Header()
            with Container(id="header-container"):
                budget_str = (
                    f"{self.config.fuzzing_duration_minutes}m"
                    if self.config.budget_type.value == "time"
                    else f"{self.config.max_executions:,} execs"
                )
                yield Static(
                    f"[bold]Fuzzing Benchmark[/] | {len(self.case_states)} cases | "
                    f"Budget: {budget_str} | "
                    "[dim]l[/] copy log cmd | [dim]c[/] copy output | [dim]t[/] tab | "
                    "[dim]SHIFT+drag[/] select | [dim]q[/] quit",
                    id="title",
                )

            yield DataTable(id="cases-table")

            with Vertical(id="details-container"):
                with TabbedContent():
                    with TabPane("Fuzzing Output", id="tab-output"):
                        yield RichLog(
                            id="fuzzing-output", wrap=True, highlight=True, markup=True
                        )
                    with TabPane("Container Logs", id="tab-container"):
                        yield RichLog(
                            id="container-logs", wrap=True, highlight=True, markup=False
                        )
                    with TabPane("Timeline (Time)", id="tab-timeline-time"):
                        yield RichLog(
                            id="timeline-time", wrap=True, highlight=True, markup=True
                        )
                    with TabPane("Timeline (Execs)", id="tab-timeline-execs"):
                        yield RichLog(
                            id="timeline-execs", wrap=True, highlight=True, markup=True
                        )
                    with TabPane("Crash Details", id="tab-crashes"):
                        yield RichLog(id="crash-details", wrap=True, highlight=True)

            yield Footer()

        def on_mount(self) -> None:
            """Set up the data table."""
            table = self.query_one(DataTable)
            col_keys = table.add_columns(
                "Case ID",
                "Model",
                "Status",
                "Target",
                "Progress",
                "Raw",
                "Unique",
                "Orig Repro?",
            )
            self._col_keys = {
                "case_id": col_keys[0],
                "model": col_keys[1],
                "status": col_keys[2],
                "target": col_keys[3],
                "progress": col_keys[4],
                "raw": col_keys[5],
                "unique": col_keys[6],
                "orig_repro": col_keys[7],
            }
            table.cursor_type = "row"

            # Add rows for all cases
            for key, state in self.case_states.items():
                table.add_row(
                    str(state.case_id),
                    state.model[:15],
                    state.status.value,
                    "",
                    "",
                    "",
                    "",
                    "--",
                    key=key,
                )

            # Select first case
            if self.case_states:
                self.selected_case_key = list(self.case_states.keys())[0]

            # Start periodic updates
            self.set_interval(0.5, self.periodic_update)

        def periodic_update(self) -> None:
            """Update UI periodically."""
            self.update_table()
            self.update_details()

        def on_data_table_row_highlighted(
            self, event: DataTable.RowHighlighted
        ) -> None:
            """Handle row selection."""
            if event.row_key:
                self.selected_case_key = event.row_key.value
                self.update_details()

        def update_table(self) -> None:
            """Update table with current state."""
            table = self.query_one(DataTable)

            for key, state in self.case_states.items():
                try:
                    from .fuzzing_types import CaseStatus, FuzzingTarget

                    # Status with indicator
                    status_display = {
                        CaseStatus.PENDING: "pending",
                        CaseStatus.GENERATING_PATCH: "gen patch",
                        CaseStatus.LOADING_RESPONSE: "loading",
                        CaseStatus.BUILDING_CONTAINER: "building",
                        CaseStatus.ANALYZING_ORIGINAL: "analyzing",
                        CaseStatus.FUZZING_GT: "fuzz GT",
                        CaseStatus.FUZZING_LLM: "fuzz LLM",
                        CaseStatus.COMPLETED: "done",
                        CaseStatus.FAILED: "FAILED",
                        CaseStatus.SKIPPED: "skipped",
                    }.get(state.status, str(state.status))

                    # Target being fuzzed
                    target = ""
                    if state.status == CaseStatus.FUZZING_GT:
                        target = "GT"
                    elif state.status == CaseStatus.FUZZING_LLM:
                        target = "LLM"

                    # Progress
                    progress = ""
                    if state.current_executions > 0:
                        if self.config.budget_type.value == "time":
                            # Show time-based progress
                            progress = f"{state.current_executions:,} execs"
                        else:
                            pct = min(
                                100,
                                int(
                                    state.current_executions
                                    / self.config.max_executions
                                    * 100
                                ),
                            )
                            progress = f"{pct}%"

                    # Crash counts
                    gt_raw = len(state.gt_timeline.crashes) if state.gt_timeline else 0
                    llm_raw = (
                        len(state.llm_timeline.crashes) if state.llm_timeline else 0
                    )
                    raw_str = f"G:{gt_raw} L:{llm_raw}" if gt_raw or llm_raw else ""

                    gt_unique = (
                        state.gt_timeline.unique_crashes() if state.gt_timeline else 0
                    )
                    llm_unique = (
                        state.llm_timeline.unique_crashes() if state.llm_timeline else 0
                    )
                    unique_str = (
                        f"G:{gt_unique} L:{llm_unique}"
                        if gt_unique or llm_unique
                        else ""
                    )

                    # Original crash reproduction status
                    orig_repro = "--"
                    if state.status == CaseStatus.COMPLETED:
                        gt_repro = (
                            state.gt_timeline.reproduced_original
                            if state.gt_timeline
                            else False
                        )
                        llm_repro = (
                            state.llm_timeline.reproduced_original
                            if state.llm_timeline
                            else False
                        )

                        if llm_repro and state.llm_timeline:
                            t = state.llm_timeline.time_to_original_crash
                            orig_repro = f"LLM:{t:.0f}s" if t else "LLM:YES"
                        elif gt_repro and state.gt_timeline:
                            t = state.gt_timeline.time_to_original_crash
                            orig_repro = f"GT:{t:.0f}s" if t else "GT:YES"
                        else:
                            orig_repro = "NO"

                    table.update_cell(key, self._col_keys["status"], status_display)
                    table.update_cell(key, self._col_keys["target"], target)
                    table.update_cell(key, self._col_keys["progress"], progress)
                    table.update_cell(key, self._col_keys["raw"], raw_str)
                    table.update_cell(key, self._col_keys["unique"], unique_str)
                    table.update_cell(key, self._col_keys["orig_repro"], orig_repro)

                except Exception:
                    pass

        def update_details(self) -> None:
            """Update detail panels for selected case."""
            if not self.selected_case_key:
                return

            state = self.case_states.get(self.selected_case_key)
            if not state:
                return

            # Fuzzing output
            output_log = self.query_one("#fuzzing-output", RichLog)
            output_log.clear()
            output_log.write(f"[bold]Case {state.case_id}[/] - {state.model}\n")
            output_log.write(f"Status: {state.status.value}\n")
            if state.current_activity:
                output_log.write(f"Activity: {state.current_activity}\n")
            if state.error:
                output_log.write(f"[red]Error: {state.error}[/]\n")
            if state.streaming_output:
                output_log.write(f"\n{rich_escape(state.streaming_output[-2000:])}")

            # Container logs - show tail command for monitoring
            container_log = self.query_one("#container-logs", RichLog)
            container_log.clear()
            container_log.write(
                f"[bold]=== Log Monitoring for Case {state.case_id} ===[/bold]\n\n"
            )

            from .fuzzing_types import CaseStatus

            if state.status in (CaseStatus.FUZZING_GT, CaseStatus.FUZZING_LLM):
                # During fuzzing, show the tail command
                container_log.write("[cyan]Fuzzing is in progress.[/cyan]\n\n")
                if state.container_logs:
                    container_log.write(
                        "To monitor fuzzer output in another terminal:\n\n"
                    )
                    container_log.write(
                        f"  [green]{rich_escape(state.container_logs)}[/green]\n\n"
                    )
                container_log.write(
                    "Or open the log file in your code editor for live updates.\n"
                )
            elif state.status == CaseStatus.COMPLETED:
                container_log.write("[green]Fuzzing completed.[/green]\n\n")
                if state.container_logs:
                    container_log.write("To view the full fuzzer log:\n\n")
                    container_log.write(
                        f"  [green]{rich_escape(state.container_logs)}[/green]\n\n"
                    )
            elif state.status == CaseStatus.GENERATING_PATCH:
                container_log.write(
                    "[yellow]LLM patch generation in progress...[/yellow]\n\n"
                )
                if state.llm_log_path:
                    container_log.write("To monitor LLM generation:\n\n")
                    container_log.write(
                        f"  [green]tail -f {rich_escape(state.llm_log_path)}[/green]\n\n"
                    )
                else:
                    container_log.write(
                        "Check the 'Fuzzing Output' tab for LLM generation progress.\n"
                    )
            else:
                if state.container_logs:
                    container_log.write(
                        f"  [green]{rich_escape(state.container_logs)}[/green]\n\n"
                    )
                else:
                    container_log.write("[dim]No log file available yet...[/dim]\n\n")
                    container_log.write("Logs will be available once fuzzing starts.")

            # Timeline (Time) view
            time_log = self.query_one("#timeline-time", RichLog)
            time_log.clear()
            time_log.write("[bold]Crash Timeline (vs Time)[/]\n\n")
            self._render_timeline(time_log, state, use_time=True)

            # Timeline (Executions) view
            exec_log = self.query_one("#timeline-execs", RichLog)
            exec_log.clear()
            exec_log.write("[bold]Crash Timeline (vs Executions)[/]\n\n")
            self._render_timeline(exec_log, state, use_time=False)

            # Crash details
            crash_log = self.query_one("#crash-details", RichLog)
            crash_log.clear()
            crash_log.write("[bold]Crash Details[/]\n\n")

            if state.original_crash:
                crash_log.write("[cyan]Original Crash (PoC):[/]\n")
                crash_log.write(f"  Type: {state.original_crash.crash_type}\n")
                if state.original_crash.stack_trace:
                    crash_log.write(
                        f"  Stack: {' -> '.join(state.original_crash.stack_trace[:5])}\n"
                    )
                crash_log.write("\n")

            for name, timeline in [
                ("Ground Truth", state.gt_timeline),
                ("LLM Patch", state.llm_timeline),
            ]:
                if timeline and timeline.crashes:
                    crash_log.write(f"[yellow]{name} Crashes:[/]\n")
                    for i, crash in enumerate(timeline.crashes[:10]):
                        match_str = (
                            " [red]*MATCHES ORIGINAL*[/]"
                            if crash.matches_original
                            else ""
                        )
                        crash_log.write(
                            f"  {i + 1}. [{crash.first_seen_time:.1f}s] "
                            f"{crash.crash_type}{match_str}\n"
                        )
                    if len(timeline.crashes) > 10:
                        crash_log.write(
                            f"  ... and {len(timeline.crashes) - 10} more\n"
                        )
                    crash_log.write("\n")

        def _render_timeline(
            self, log: RichLog, state: "CaseState", use_time: bool
        ) -> None:
            """Render ASCII timeline chart."""
            for name, timeline in [
                ("Ground Truth", state.gt_timeline),
                ("LLM Patch", state.llm_timeline),
            ]:
                if timeline:
                    log.write(f"[cyan]{name}:[/]\n")
                    log.write(f"  Duration: {timeline.duration_seconds:.1f}s\n")
                    log.write(f"  Executions: {timeline.total_executions:,}\n")
                    log.write(
                        f"  Crashes: {len(timeline.crashes)} raw, "
                        f"{timeline.unique_crashes()} unique\n"
                    )
                    if timeline.reproduced_original:
                        log.write(
                            f"  [red]Original Reproduced: "
                            f"{timeline.time_to_original_crash:.1f}s[/]\n"
                        )

                    # Simple ASCII timeline
                    if timeline.crashes:
                        if use_time:
                            data = timeline.to_plot_data(resolution=30.0)
                            x_label = "time"
                            x_unit = "s"
                        else:
                            data = timeline.to_exec_plot_data(resolution=50000)
                            x_label = "execs"
                            x_unit = ""

                        log.write(f"\n  Crashes over {x_label}:\n  ")
                        max_count = (
                            max(data["crash_count"]) if data["crash_count"] else 0
                        )
                        for i, (x, c) in enumerate(
                            zip(
                                data.get(x_label, data.get("time", [])),
                                data["crash_count"],
                            )
                        ):
                            if i % 4 == 0 and max_count > 0:
                                bar_len = int(c / max_count * 10) if max_count else 0
                                log.write(f"{'█' * bar_len}{'░' * (10 - bar_len)} ")
                        log.write("\n")
                    log.write("\n")

        def action_toggle_tab(self) -> None:
            """Toggle between tabs."""
            tabbed = self.query_one(TabbedContent)
            tabs = [
                "tab-output",
                "tab-container",
                "tab-timeline-time",
                "tab-timeline-execs",
                "tab-crashes",
            ]
            current_idx = tabs.index(tabbed.active) if tabbed.active in tabs else 0
            next_idx = (current_idx + 1) % len(tabs)
            tabbed.active = tabs[next_idx]

        def action_deduplicate(self) -> None:
            """Trigger CASR deduplication on selected case."""
            if self.selected_case_key and self.on_deduplicate:
                self.notify(
                    f"Running CASR deduplication on {self.selected_case_key}..."
                )
                self.on_deduplicate(self.selected_case_key)

        def action_refresh(self) -> None:
            """Force refresh the display."""
            self.update_table()
            self.update_details()
            self.notify("Refreshed")

        def action_copy_output(self) -> None:
            """Copy the current fuzzing output to clipboard."""
            if not self.selected_case_key:
                self.notify("No case selected", severity="warning")
                return

            state = self.case_states.get(self.selected_case_key)
            if not state:
                self.notify("Case not found", severity="warning")
                return

            # Build the text to copy
            lines = [
                f"Case {state.case_id} - {state.model}",
                f"Status: {state.status.value}",
            ]
            if state.current_activity:
                lines.append(f"Activity: {state.current_activity}")
            if state.error:
                lines.append(f"Error: {state.error}")
            if state.streaming_output:
                lines.append("")
                # Strip markup for clean copy
                import re

                clean_output = re.sub(
                    r"\[/?[^\]]+\]", "", state.streaming_output[-4000:]
                )
                lines.append(clean_output)

            text = "\n".join(lines)
            self.copy_to_clipboard(text)
            self.notify(f"Copied {len(text)} chars to clipboard")

        def action_copy_log_path(self) -> None:
            """Copy the log file path to clipboard for easy terminal access."""
            if not self.selected_case_key:
                self.notify("No case selected", severity="warning")
                return

            state = self.case_states.get(self.selected_case_key)
            if not state:
                self.notify("Case not found", severity="warning")
                return

            # Determine which log path to copy based on current status
            from .fuzzing_types import CaseStatus

            log_path = None
            if state.status in (CaseStatus.FUZZING_GT, CaseStatus.FUZZING_LLM):
                log_path = state.fuzzer_log_path
            elif state.status == CaseStatus.GENERATING_PATCH:
                log_path = state.llm_log_path
            elif state.status == CaseStatus.COMPLETED:
                # Prefer fuzzer log if available
                log_path = state.fuzzer_log_path or state.llm_log_path
            else:
                log_path = state.llm_log_path or state.fuzzer_log_path

            if log_path:
                # Copy the tail command for convenience
                tail_cmd = f"tail -f {log_path}"
                self.copy_to_clipboard(tail_cmd)
                self.notify(f"Copied: {tail_cmd}")
            else:
                self.notify("No log file available yet", severity="warning")

else:
    # Stub class when Textual is not available
    class FuzzingTUI:  # type: ignore
        """Stub TUI class when Textual is not installed."""

        def __init__(self, *args, **kwargs):
            raise ImportError("Textual library not installed. Run: pip install textual")

        def run(self):
            pass
