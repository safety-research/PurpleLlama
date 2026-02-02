# Copyright (c) Meta Platforms, Inc. and affiliates.
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.
"""TUI (Terminal User Interface) for the FuzzingOnlyBenchmark.

Provides real-time visualization of:
- Case status (pending, building, fuzzing, completed, failed)
- Fuzzing progress (executions, crashes found)
- Log file preview with editor integration
"""

from __future__ import annotations
import os
from pathlib import Path
from typing import TYPE_CHECKING, Callable, Dict, Optional

if TYPE_CHECKING:
    from .fuzzing_types import CaseState, FuzzingConfig

try:
    from rich.markup import escape as rich_escape
    from textual.app import App, ComposeResult
    from textual.binding import Binding
    from textual.containers import Container, Vertical
    from textual.reactive import reactive
    from textual.widgets import DataTable, Footer, Header, RichLog, Static

    TEXTUAL_AVAILABLE = True
except ImportError:
    TEXTUAL_AVAILABLE = False


def is_textual_available() -> bool:
    return TEXTUAL_AVAILABLE


if TEXTUAL_AVAILABLE:

    class LogPreview(RichLog):
        DEFAULT_CSS = "LogPreview { height: 100%; border: solid $primary; }"

    class CaseInfo(Static):
        DEFAULT_CSS = "CaseInfo { height: auto; padding: 1; background: $surface; border: solid $success; }"

    class FuzzingTUI(App):
        """Interactive TUI for monitoring fuzzing progress."""

        ENABLE_COMMAND_PALETTE = False
        CSS = """
        Screen { layout: grid; grid-size: 2 2; grid-columns: 2fr 3fr; grid-rows: auto 1fr; }
        #header-container { column-span: 2; height: 4; background: $surface; padding: 0 1; }
        #cases-container { height: 100%; border: solid $success; }
        #cases-table { height: 100%; }
        #detail-container { height: 100%; layout: vertical; }
        #case-info { height: auto; max-height: 12; }
        #log-preview { height: 1fr; }
        DataTable > .datatable--cursor { background: $accent; }
        DataTable { width: 100%; }
        """
        BINDINGS = [
            Binding("q", "quit", "Quit"),
            Binding("e", "open_in_editor", "Edit Log"),
            Binding("y", "yank_path", "Copy Path"),
            Binding("t", "show_tail_cmd", "Tail Cmd"),
            Binding("r", "refresh", "Refresh"),
            Binding("j", "cursor_down", "Down", show=False),
            Binding("k", "cursor_up", "Up", show=False),
            Binding("up", "cursor_up", "Up", show=False),
            Binding("down", "cursor_down", "Down", show=False),
        ]
        selected_case_key: reactive[str | None] = reactive(None)

        def __init__(
            self,
            case_states: Dict[str, "CaseState"],
            config: "FuzzingConfig",
            pty_pool=None,
            output_dir: Optional[Path] = None,
            **kwargs,
        ):
            super().__init__(**kwargs)
            self.case_states = case_states
            self.config = config
            self.output_dir = output_dir
            self.benchmark_log = output_dir / "benchmark.log" if output_dir else None
            self.build_logs_dir = output_dir / "build_logs" if output_dir else None
            self._col_keys = {}
            self._last_log_content: Dict[str, str] = {}
            # Track case_ids that are "collapsed" (showing one row during build)
            # Maps case_id -> key of the representative row
            self._collapsed_cases: Dict[int, str] = {}

        def compose(self) -> ComposeResult:
            yield Header()
            with Container(id="header-container"):
                budget = (
                    f"{self.config.fuzzing_duration_minutes}m"
                    if self.config.budget_type.value == "time"
                    else f"{self.config.max_executions:,}"
                )
                log_info = (
                    f"[bold cyan]Log:[/] {self.benchmark_log}"
                    if self.benchmark_log
                    else ""
                )
                build_info = (
                    f"  [bold yellow]Build logs:[/] {self.build_logs_dir}/"
                    if self.build_logs_dir
                    else ""
                )
                yield Static(
                    f"{log_info}{build_info}\n[bold]Fuzzing[/] | {len(self.case_states)} cases | {budget} | [dim]e[/]edit [dim]y[/]copy [dim]t[/]tail [dim]q[/]quit"
                )
            with Container(id="cases-container"):
                yield DataTable(id="cases-table")
            with Vertical(id="detail-container"):
                yield CaseInfo(id="case-info")
                yield LogPreview(
                    id="log-preview", wrap=True, highlight=True, markup=True
                )
            yield Footer()

        def on_mount(self) -> None:
            from .fuzzing_types import CaseStatus

            table = self.query_one("#cases-table", DataTable)
            cols = table.add_columns("Case", "Model", "Status", "Execs", "Cl")
            self._col_keys = {
                "case_id": cols[0],
                "model": cols[1],
                "status": cols[2],
                "execs": cols[3],
                "clusters": cols[4],
            }
            table.cursor_type = "row"

            # During initial mount, check if we're in build phase
            # If so, show only unique case_ids (containers are shared across models)
            # Track which case_ids are collapsed (one row per case during build)
            for key, state in self.case_states.items():
                # During build phase, only show each case once (container is shared)
                if state.status in (CaseStatus.PENDING, CaseStatus.BUILDING_CONTAINER):
                    if state.case_id in self._collapsed_cases:
                        continue  # Skip duplicate case_ids during build
                    self._collapsed_cases[state.case_id] = key  # Track representative row
                    model_display = "(building)"  # Indicate shared build
                else:
                    model_display = state.model[:15]
                table.add_row(
                    str(state.case_id), model_display, self._fmt(state), "", "", key=key
                )

            if self.case_states:
                self.selected_case_key = list(self.case_states.keys())[0]
                self._update_detail()
            self.set_interval(1.5, self._tick)

        def _fmt(self, s) -> str:
            from .fuzzing_types import CaseStatus

            # For BUILDING_CONTAINER, check build progress from log files
            if s.status == CaseStatus.BUILDING_CONTAINER and self.build_logs_dir:
                vul_log = self.build_logs_dir / f"{s.case_id}-vul.log"
                fix_log = self.build_logs_dir / f"{s.case_id}-fix.log"
                if not vul_log.exists() and not fix_log.exists():
                    return "[dim]queued[/]"
                # Check if build completed (look for "Successfully tagged" in log)
                try:
                    if fix_log.exists():
                        content = fix_log.read_text(errors="replace")
                        if "Successfully tagged" in content:
                            return "[green]ready[/]"
                except:
                    pass
                return "[yellow]build[/]"
            # For PENDING after build complete, show "ready"
            if s.status == CaseStatus.PENDING and s.current_activity:
                activity_lower = s.current_activity.lower()
                if (
                    "build complete" in activity_lower
                    or "ready to process" in activity_lower
                ):
                    return "[green]ready[/]"
            m = {
                CaseStatus.PENDING: "[dim]pending[/]",
                CaseStatus.GENERATING_PATCH: "[yellow]gen[/]",
                CaseStatus.BUILDING_CONTAINER: "[yellow]build[/]",
                CaseStatus.FUZZING_GT: "[cyan]fuzz GT[/]",
                CaseStatus.FUZZING_LLM: "[cyan]fuzz LLM[/]",
                CaseStatus.COMPLETED: "[green]done[/]",
                CaseStatus.FAILED: "[red]FAIL[/]",
                CaseStatus.SKIPPED: "[dim]skip[/]",
            }
            return m.get(s.status, str(s.status))

        def _tick(self) -> None:
            self._update_table()
            self._update_detail()  # Updates Case Info + Log Preview

        def on_data_table_row_highlighted(self, event) -> None:
            if event.row_key:
                self.selected_case_key = event.row_key.value
                self._update_detail()

        def _update_table(self) -> None:
            from .fuzzing_types import CaseStatus

            table = self.query_one("#cases-table", DataTable)

            # Get set of existing row keys
            existing_keys = set(str(row_key.value) for row_key in table.rows.keys())

            # Check if any collapsed cases need to be expanded
            # A case should expand when ANY of its models moves past build phase
            cases_to_expand = set()
            for k, s in self.case_states.items():
                if s.case_id in self._collapsed_cases:
                    # Check if this model has moved past build phase
                    if s.status not in (CaseStatus.PENDING, CaseStatus.BUILDING_CONTAINER):
                        cases_to_expand.add(s.case_id)
                    # Also expand if build is complete (indicated by activity text)
                    elif s.current_activity and (
                        "ready" in s.current_activity.lower()
                        or "cached" in s.current_activity.lower()
                        or "complete" in s.current_activity.lower()
                    ):
                        cases_to_expand.add(s.case_id)

            # Expand collapsed cases - add all model rows
            for case_id in cases_to_expand:
                if case_id in self._collapsed_cases:
                    del self._collapsed_cases[case_id]
                    # Add all model rows for this case
                    for k, s in self.case_states.items():
                        if s.case_id == case_id and k not in existing_keys:
                            table.add_row(
                                str(s.case_id), s.model[:15], self._fmt(s), "", "", key=k
                            )
                            existing_keys.add(k)

            # Update all visible rows
            for k, s in self.case_states.items():
                # Skip rows that are hidden (collapsed case, not the representative)
                if s.case_id in self._collapsed_cases and self._collapsed_cases[s.case_id] != k:
                    continue

                # Add row if it doesn't exist and case is not collapsed
                if k not in existing_keys and s.case_id not in self._collapsed_cases:
                    table.add_row(
                        str(s.case_id), s.model[:15], self._fmt(s), "", "", key=k
                    )
                    existing_keys.add(k)

                # Update existing row
                if k in existing_keys:
                    try:
                        ex = f"{s.current_executions:,}" if s.current_executions else ""

                        # Get cluster count for THIS model (GT or LLM)
                        if s.model == "ground_truth":
                            timeline = s.gt_timeline
                        else:
                            timeline = s.llm_timeline

                        unique_count = timeline.unique_crashes() if timeline else 0
                        cl = str(unique_count) if unique_count else ""

                        table.update_cell(k, self._col_keys["status"], self._fmt(s))
                        table.update_cell(k, self._col_keys["execs"], ex)
                        table.update_cell(k, self._col_keys["clusters"], cl)

                        # During build phase (collapsed), show "(building)" instead of model
                        if s.case_id in self._collapsed_cases:
                            table.update_cell(k, self._col_keys["model"], "(building)")
                        else:
                            table.update_cell(k, self._col_keys["model"], s.model[:15])
                    except:
                        pass

        def _state(self):
            return (
                self.case_states.get(self.selected_case_key)
                if self.selected_case_key
                else None
            )

        def _log(self, s):
            from .fuzzing_types import CaseStatus

            if s.status in (CaseStatus.FUZZING_GT, CaseStatus.FUZZING_LLM):
                return s.fuzzer_log_path
            if s.status == CaseStatus.GENERATING_PATCH:
                return s.llm_log_path
            if s.status == CaseStatus.BUILDING_CONTAINER and self.build_logs_dir:
                # Return the -fix.log build log (more relevant for fuzzing)
                fix_log = self.build_logs_dir / f"{s.case_id}-fix.log"
                if fix_log.exists():
                    return str(fix_log)
                # Fall back to -vul.log if fix log doesn't exist yet
                vul_log = self.build_logs_dir / f"{s.case_id}-vul.log"
                if vul_log.exists():
                    return str(vul_log)
            return s.fuzzer_log_path or s.llm_log_path

        def _update_detail(self) -> None:
            s = self._state()
            if not s:
                return
            info = self.query_one("#case-info", CaseInfo)
            lp = self._log(s)
            lines = [
                f"[bold]Case {s.case_id}[/] - {s.model}",
                f"Status: {s.status.value}",
            ]
            if s.current_activity:
                lines.append(f"Activity: {s.current_activity}")
            if s.error:
                lines.append(f"[red]Error: {s.error}[/]")
            lines.append("")

            # Show build log paths during building phase
            from .fuzzing_types import CaseStatus

            if s.status == CaseStatus.BUILDING_CONTAINER and self.build_logs_dir:
                vul_log = self.build_logs_dir / f"{s.case_id}-vul.log"
                fix_log = self.build_logs_dir / f"{s.case_id}-fix.log"
                vul_exists = vul_log.exists()
                fix_exists = fix_log.exists()

                if vul_exists or fix_exists:
                    lines.append("[yellow]Build logs:[/]")
                    if vul_exists:
                        vul_size = f" ({vul_log.stat().st_size // 1024}KB)"
                        lines.append(f"  [green]{vul_log}[/]{vul_size}")
                    else:
                        lines.append(f"  [dim]{vul_log} (pending)[/]")
                    if fix_exists:
                        fix_size = f" ({fix_log.stat().st_size // 1024}KB)"
                        lines.append(f"  [green]{fix_log}[/]{fix_size}")
                    else:
                        lines.append(f"  [dim]{fix_log} (pending)[/]")
                else:
                    lines.append("[yellow]Build queued[/] - waiting for build slot...")
                lines.append("")

            if lp:
                lines.extend(
                    [
                        f"[cyan]Log:[/] [green]{lp}[/]",
                        "",
                        "[dim][e]edit [y]copy [t]tail[/dim]",
                    ]
                )
            else:
                lines.append("[dim]No log yet[/dim]")
            info.update("\n".join(lines))
            self._update_preview()

        def _update_preview(self) -> None:
            s = self._state()
            if not s:
                return
            pv = self.query_one("#log-preview", LogPreview)
            lp = self._log(s)
            content = self._tail(lp)

            from .fuzzing_types import CaseStatus

            # Always clear and redraw - simpler and more reliable
            pv.clear()

            if s.status == CaseStatus.BUILDING_CONTAINER:
                # Show build-specific message
                if content:
                    pv.write("[dim]--- Build Log (last 30) ---[/dim]\n" + content)
                else:
                    # No log yet - build queued or just starting
                    pv.write("[yellow]Build queued...[/yellow]\n\n")
                    pv.write(
                        f"Container build for case {s.case_id} is waiting to start.\n"
                    )
                    pv.write("Builds run in parallel - this case will start soon.\n\n")
                    if self.build_logs_dir:
                        pv.write("[dim]Log will appear at:[/dim]\n")
                        pv.write(f"  {self.build_logs_dir}/{s.case_id}-fix.log\n")
            elif s.streaming_output and not lp:
                pv.write(
                    "[dim]--- Activity ---[/dim]\n"
                    + rich_escape(s.streaming_output[-2000:])
                )
            elif content:
                pv.write("[dim]--- Log (last 30) ---[/dim]\n" + content)
            else:
                pv.write("[dim]Waiting...[/dim]")

            if s.status == CaseStatus.COMPLETED:
                pv.write("\n[dim]--- Summary ---[/dim]\n")
                # Show summary for THIS model (GT or LLM)
                if s.model == "ground_truth":
                    timeline = s.gt_timeline
                    label = "GT"
                    color = "cyan"
                else:
                    timeline = s.llm_timeline
                    label = "LLM"
                    color = "yellow"

                if timeline:
                    pv.write(
                        f"[{color}]{label}:[/{color}] {timeline.duration_seconds:.1f}s {timeline.total_executions:,}ex {timeline.unique_crashes()}cl ({len(timeline.crashes)}cr)\n"
                    )

        def _tail(self, lp, n=30) -> str:
            if not lp:
                return ""
            p = Path(lp)
            if not p.exists():
                return ""
            try:
                # Handle potential encoding issues with build logs
                content = p.read_text(errors="replace")
                ls = content.splitlines()
                return rich_escape("\n".join(ls[-n:]))
            except Exception as e:
                return f"[red]Error reading log: {e}[/]"

        def action_open_in_editor(self) -> None:
            s = self._state()
            if not s:
                self.notify("No case", severity="warning")
                return
            lp = self._log(s)
            if not lp or not Path(lp).exists():
                self.notify("No log", severity="warning")
                return
            ed = os.environ.get("EDITOR", "vim")
            with self.suspend():
                os.system(f'{ed} "{lp}"')

        def action_yank_path(self) -> None:
            s = self._state()
            if not s:
                self.notify("No case", severity="warning")
                return
            lp = self._log(s)
            if not lp:
                self.notify("No log", severity="warning")
                return
            self.copy_to_clipboard(lp)
            self.notify(f"Copied: {lp}")

        def action_show_tail_cmd(self) -> None:
            s = self._state()
            if not s:
                self.notify("No case", severity="warning")
                return
            lp = self._log(s)
            if not lp:
                self.notify("No log", severity="warning")
                return
            self.copy_to_clipboard(f"tail -f {lp}")
            self.notify(f"Copied: tail -f {lp}")

        def action_refresh(self) -> None:
            self._update_table()
            self._update_detail()
            self.notify("Refreshed")

        def action_cursor_up(self) -> None:
            self.query_one("#cases-table", DataTable).action_cursor_up()

        def action_cursor_down(self) -> None:
            self.query_one("#cases-table", DataTable).action_cursor_down()

        def on_unmount(self) -> None:
            print("\n" + "=" * 60 + "\nLog files:\n" + "=" * 60)
            if self.benchmark_log:
                print(f"  [Benchmark log] {self.benchmark_log}")
            for k, s in self.case_states.items():
                lp = self._log(s)
                if lp:
                    print(f"  Case {s.case_id}: {lp}")
            print("=" * 60 + "\n")

else:

    class FuzzingTUI:  # type: ignore
        """Stub TUI class when Textual is not installed."""

        def __init__(self, *args, **kwargs):
            raise ImportError("Textual library not installed. Run: pip install textual")

        def run(self):
            pass
