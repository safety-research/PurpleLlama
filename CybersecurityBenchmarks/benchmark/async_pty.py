# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

"""
AsyncPTYProcess - Async wrapper for running subprocesses in a PTY.

Provides:
- Spawning subprocess with PTY allocation
- Async read/write to the PTY
- Terminal resize support (TIOCSWINSZ)
- Clean termination and resource cleanup

Used by FuzzingTUI to run each benchmark case in its own PTY,
enabling proper terminal output with scroll/select/copy support.
"""

from __future__ import annotations

import asyncio
import fcntl
import logging
import os
import pty
import signal
import struct
import termios
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, List, Optional

LOG: logging.Logger = logging.getLogger(__name__)


class PTYProcessState(str, Enum):
    """State of a PTY process."""

    CREATED = "created"
    RUNNING = "running"
    STOPPED = "stopped"
    TERMINATED = "terminated"


@dataclass
class AsyncPTYProcess:
    """
    Async wrapper for a subprocess running in a PTY.

    Example usage:
        process = AsyncPTYProcess(command=["bash", "-c", "htop"])
        await process.start()

        # Read output asynchronously
        async for chunk in process.read_stream():
            print(chunk, end='')

        # Or read all at once
        output = await process.read_all(timeout=5.0)

        # Resize terminal
        process.resize(80, 24)

        # Clean shutdown
        await process.terminate()
    """

    command: List[str]
    cwd: Optional[str] = None
    env: Optional[dict] = None
    initial_size: tuple = (80, 24)  # (cols, rows)

    # Internal state
    master_fd: int = field(default=-1, init=False)
    slave_fd: int = field(default=-1, init=False)
    pid: int = field(default=-1, init=False)
    state: PTYProcessState = field(default=PTYProcessState.CREATED, init=False)
    _output_buffer: str = field(default="", init=False)
    _read_task: Optional[asyncio.Task] = field(default=None, init=False)
    _callbacks: List[Callable[[str], None]] = field(default_factory=list, init=False)

    async def start(self) -> None:
        """Start the subprocess in a PTY."""
        if self.state != PTYProcessState.CREATED:
            raise RuntimeError(f"Cannot start process in state {self.state}")

        LOG.info(f"Starting PTY process: {' '.join(self.command)}")

        # Create PTY pair
        self.master_fd, self.slave_fd = pty.openpty()

        # Set initial terminal size
        cols, rows = self.initial_size
        self._set_winsize(self.master_fd, rows, cols)

        # Set master to non-blocking
        flags = fcntl.fcntl(self.master_fd, fcntl.F_GETFL)
        fcntl.fcntl(self.master_fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)

        # Fork and exec
        self.pid = os.fork()
        if self.pid == 0:
            # Child process
            self._child_exec()
        else:
            # Parent process
            os.close(self.slave_fd)
            self.slave_fd = -1
            self.state = PTYProcessState.RUNNING
            LOG.info(f"PTY process started with PID {self.pid}")

    def _child_exec(self) -> None:
        """Execute command in child process (runs in forked child)."""
        try:
            # Create new session
            os.setsid()

            # Make slave the controlling terminal
            os.dup2(self.slave_fd, 0)  # stdin
            os.dup2(self.slave_fd, 1)  # stdout
            os.dup2(self.slave_fd, 2)  # stderr

            # Close master in child
            os.close(self.master_fd)

            # Close original slave fd (we've duped it)
            if self.slave_fd > 2:
                os.close(self.slave_fd)

            # Set up environment
            env = os.environ.copy()
            if self.env:
                env.update(self.env)
            env["TERM"] = "xterm-256color"

            # Change directory if specified
            if self.cwd:
                os.chdir(self.cwd)

            # Execute command
            os.execvpe(self.command[0], self.command, env)

        except Exception as e:
            # Write error and exit
            os.write(2, f"exec failed: {e}\n".encode())
            os._exit(1)

    def _set_winsize(self, fd: int, rows: int, cols: int) -> None:
        """Set terminal window size using TIOCSWINSZ."""
        winsize = struct.pack("HHHH", rows, cols, 0, 0)
        fcntl.ioctl(fd, termios.TIOCSWINSZ, winsize)

    def resize(self, cols: int, rows: int) -> None:
        """Resize the PTY terminal."""
        if self.master_fd < 0:
            return
        try:
            self._set_winsize(self.master_fd, rows, cols)
            # Send SIGWINCH to child process group
            if self.pid > 0:
                os.killpg(os.getpgid(self.pid), signal.SIGWINCH)
        except (OSError, ProcessLookupError):
            pass  # Process may have exited

    async def read(self, size: int = 4096, timeout: Optional[float] = None) -> bytes:
        """Read from PTY with optional timeout."""
        if self.state != PTYProcessState.RUNNING:
            return b""

        loop = asyncio.get_event_loop()

        async def _do_read() -> bytes:
            while True:
                try:
                    data = os.read(self.master_fd, size)
                    if data:
                        return data
                except BlockingIOError:
                    # No data available, wait a bit
                    await asyncio.sleep(0.01)
                except OSError:
                    # FD closed or error
                    return b""

        try:
            if timeout:
                return await asyncio.wait_for(_do_read(), timeout=timeout)
            else:
                return await _do_read()
        except asyncio.TimeoutError:
            return b""

    async def read_stream(self, chunk_size: int = 4096):
        """Async generator that yields output chunks."""
        while self.state == PTYProcessState.RUNNING:
            data = await self.read(chunk_size, timeout=0.1)
            if data:
                decoded = data.decode(errors="replace")
                self._output_buffer += decoded
                yield decoded

                # Notify callbacks
                for callback in self._callbacks:
                    try:
                        callback(decoded)
                    except Exception as e:
                        LOG.warning(f"Output callback error: {e}")

            # Check if process is still alive
            if not self.is_alive():
                self.state = PTYProcessState.TERMINATED
                break

    async def read_all(self, timeout: float = 30.0) -> str:
        """Read all output until process exits or timeout."""
        output = []
        try:
            async with asyncio.timeout(timeout):
                async for chunk in self.read_stream():
                    output.append(chunk)
        except asyncio.TimeoutError:
            LOG.warning(f"read_all timed out after {timeout}s")
        return "".join(output)

    async def write(self, data: bytes) -> int:
        """Write data to the PTY input."""
        if self.master_fd < 0 or self.state != PTYProcessState.RUNNING:
            return 0
        try:
            return os.write(self.master_fd, data)
        except OSError as e:
            LOG.warning(f"PTY write error: {e}")
            return 0

    async def write_str(self, text: str) -> int:
        """Write string to the PTY input."""
        return await self.write(text.encode())

    def add_output_callback(self, callback: Callable[[str], None]) -> None:
        """Add callback to be called when output is received."""
        self._callbacks.append(callback)

    def remove_output_callback(self, callback: Callable[[str], None]) -> None:
        """Remove an output callback."""
        if callback in self._callbacks:
            self._callbacks.remove(callback)

    def get_output_buffer(self) -> str:
        """Get all captured output."""
        return self._output_buffer

    def clear_output_buffer(self) -> None:
        """Clear the output buffer."""
        self._output_buffer = ""

    def is_alive(self) -> bool:
        """Check if the subprocess is still running."""
        if self.pid <= 0:
            return False
        try:
            pid, status = os.waitpid(self.pid, os.WNOHANG)
            if pid == 0:
                return True  # Still running
            else:
                return False  # Exited
        except ChildProcessError:
            return False

    def get_exit_code(self) -> Optional[int]:
        """Get exit code if process has terminated."""
        if self.pid <= 0:
            return None
        try:
            pid, status = os.waitpid(self.pid, os.WNOHANG)
            if pid == 0:
                return None  # Still running
            if os.WIFEXITED(status):
                return os.WEXITSTATUS(status)
            if os.WIFSIGNALED(status):
                return -os.WTERMSIG(status)
            return None
        except ChildProcessError:
            return None

    async def terminate(self, timeout: float = 5.0) -> None:
        """Terminate the process gracefully, then forcefully if needed."""
        if self.pid <= 0:
            return

        LOG.info(f"Terminating PTY process {self.pid}")

        try:
            # Try SIGTERM first
            os.killpg(os.getpgid(self.pid), signal.SIGTERM)

            # Wait for process to exit
            for _ in range(int(timeout * 10)):
                if not self.is_alive():
                    break
                await asyncio.sleep(0.1)
            else:
                # Force kill if still running
                LOG.warning(f"Process {self.pid} didn't terminate, sending SIGKILL")
                os.killpg(os.getpgid(self.pid), signal.SIGKILL)
                await asyncio.sleep(0.1)

        except (ProcessLookupError, OSError):
            pass  # Process already gone

        # Reap zombie
        try:
            os.waitpid(self.pid, 0)
        except ChildProcessError:
            pass

        self.state = PTYProcessState.TERMINATED
        LOG.info(f"PTY process {self.pid} terminated")

    async def kill(self) -> None:
        """Forcefully kill the process."""
        if self.pid <= 0:
            return
        try:
            os.killpg(os.getpgid(self.pid), signal.SIGKILL)
        except (ProcessLookupError, OSError):
            pass
        self.state = PTYProcessState.TERMINATED

    def close(self) -> None:
        """Close PTY file descriptors."""
        if self.master_fd >= 0:
            try:
                os.close(self.master_fd)
            except OSError:
                pass
            self.master_fd = -1

        if self.slave_fd >= 0:
            try:
                os.close(self.slave_fd)
            except OSError:
                pass
            self.slave_fd = -1

    async def __aenter__(self) -> "AsyncPTYProcess":
        """Async context manager entry."""
        await self.start()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        """Async context manager exit."""
        await self.terminate()
        self.close()


class PTYProcessPool:
    """
    Pool of PTY processes for managing multiple concurrent cases.

    Provides methods to:
    - Create and track processes by key
    - Get active process for a key
    - Clean up all processes
    """

    def __init__(self, max_concurrent: int = 16):
        self.max_concurrent = max_concurrent
        self._processes: dict[str, AsyncPTYProcess] = {}
        self._lock = asyncio.Lock()

    async def create_process(
        self,
        key: str,
        command: List[str],
        cwd: Optional[str] = None,
        env: Optional[dict] = None,
        start: bool = True,
    ) -> AsyncPTYProcess:
        """Create a new PTY process for the given key."""
        async with self._lock:
            # Clean up existing process for this key
            if key in self._processes:
                old_process = self._processes[key]
                if old_process.is_alive():
                    await old_process.terminate()
                old_process.close()

            process = AsyncPTYProcess(command=command, cwd=cwd, env=env)
            self._processes[key] = process

            if start:
                await process.start()

            return process

    def get_process(self, key: str) -> Optional[AsyncPTYProcess]:
        """Get the PTY process for a key."""
        return self._processes.get(key)

    def get_all_processes(self) -> dict[str, AsyncPTYProcess]:
        """Get all processes."""
        return self._processes.copy()

    async def terminate_process(self, key: str) -> None:
        """Terminate a specific process."""
        process = self._processes.get(key)
        if process:
            if process.is_alive():
                await process.terminate()
            process.close()

    async def terminate_all(self) -> None:
        """Terminate all processes."""
        async with self._lock:
            for key, process in self._processes.items():
                try:
                    if process.is_alive():
                        await process.terminate()
                    process.close()
                except Exception as e:
                    LOG.warning(f"Error terminating process {key}: {e}")
            self._processes.clear()

    def __len__(self) -> int:
        return len(self._processes)


async def run_command_in_pty(
    command: List[str],
    cwd: Optional[str] = None,
    timeout: float = 60.0,
    on_output: Optional[Callable[[str], None]] = None,
) -> tuple[str, int]:
    """
    Convenience function to run a command in a PTY and capture output.

    Args:
        command: Command and arguments to run
        cwd: Working directory
        timeout: Maximum time to wait
        on_output: Optional callback for streaming output

    Returns:
        Tuple of (output_text, exit_code)
    """
    process = AsyncPTYProcess(command=command, cwd=cwd)
    if on_output:
        process.add_output_callback(on_output)

    try:
        await process.start()
        output = await process.read_all(timeout=timeout)
        exit_code = process.get_exit_code() or 0
        return output, exit_code
    finally:
        if process.is_alive():
            await process.terminate()
        process.close()
