# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

# pyre-strict
import logging
import shlex
import subprocess
import time
from abc import ABC, abstractmethod
from logging import Logger, LoggerAdapter
from pathlib import Path
from subprocess import CalledProcessError
from types import TracebackType
from typing import Callable, Dict, List, Optional, Type

# pyre-fixme[21]: Could not find name `Node`, `Parser` in `tree_sitter`.
from tree_sitter import Language, Node as TreeSitterNode, Parser

from .types import FunctionSourceInfo, FunctionSourceInfoItem, PathAndLine

LOGGER: Logger = logging.getLogger(__name__)


def subprocess_run(
    cmd: List[str], check: bool = False
) -> subprocess.CompletedProcess[str]:
    """Run a subprocess command."""
    logging.info(f"Running: {' '.join(shlex.quote(x) for x in cmd)}")
    return subprocess.run(cmd, capture_output=True, check=check, text=True)


class SourceUtilsInterface(ABC):
    """
    This class defines the interface for retrieving source code information about the repo.
    It enables better testability as we can use a fake source utils implementation in the tests.
    """

    @abstractmethod
    async def retrieve_src_of_func(self, path_and_line: PathAndLine) -> Optional[str]:
        """
        Retrieves the source code of the function encompassing `path_and_line` from a stacktrace.

        Args:
            path_and_line: A path and line from a stacktrace.
            repo_hash: Repo hash to use. If None, the latest repo hash will be used.

        Returns:
            Source code of the function. None if the function is not found.
        """

    @staticmethod
    @abstractmethod
    def _get_repo_root() -> Path:
        """
        Returns the root of the repo.
        """

    @classmethod
    def get_absolute_path(cls, path_str: str) -> Path:
        path = Path(path_str)
        if not path.is_absolute():
            # If the filename is not absolute, we assume it is relative to the repo root.
            return cls._get_repo_root() / path
        return path

    @staticmethod
    @abstractmethod
    async def save_current_changes_to_file(
        output_patch: Path, patched_src_path: Optional[str] = None
    ) -> None:
        """
        Saves the current changes to a file.
        """

    @staticmethod
    @abstractmethod
    async def revert_current_changes(hard: bool = False) -> None:
        """
        Reverts the current changes.

        Args:
            hard: If True, revert all changes including untracked files. If False, revert only tracked changes.
        """

    @classmethod
    def add_dummy_line(cls, filename: str) -> None:
        """
        Adds a dummy line to the end of the file.
        """
        ext = Path(filename).suffix
        if ext in [".h", ".hpp", ".hh", ".c", ".cpp", ".cc"]:
            comment_header = "// "
        elif ext in [".py"]:
            comment_header = "# "
        else:
            raise RuntimeError(f"Unsupported file extension: {ext}")

        with open(cls.get_absolute_path(filename), "a") as f:
            f.write(f"\n{comment_header} dummy line\n")


class FakeRepoRevisionHelper:
    """
    This class helps to fake the repo revision.
    """

    def __init__(self, target_revision: Optional[str]) -> None:
        self._target_revision: Optional[str] = target_revision

    async def __aenter__(self) -> None:
        pass

    async def __aexit__(
        self,
        exc_type: Optional[Type[BaseException]],
        exc_val: Optional[BaseException],
        exc_tb: Optional[TracebackType],
    ) -> bool:
        return False


class FakeSourceUtils(SourceUtilsInterface):
    def __init__(self, fake_source_config: Optional[Dict[str, str]] = None) -> None:
        self._fake_source_config: Optional[Dict[str, str]] = fake_source_config

    @staticmethod
    def _get_repo_root() -> Path:
        return Path("")

    @staticmethod
    async def save_current_changes_to_file(
        output_patch: Path, patched_src_path: Optional[str] = None
    ) -> None:
        pass

    @staticmethod
    async def revert_current_changes(hard: bool = False) -> None:
        pass

    async def retrieve_src_of_func(self, path_and_line: PathAndLine) -> Optional[str]:
        if self._fake_source_config is None:
            return None
        if path_and_line.file_path not in self._fake_source_config:
            return None
        return self._fake_source_config[path_and_line.file_path]


def ts_traverse(
    # pyre-fixme[11]: Annotation `TreeSitterNode` is not defined as a type.
    node: TreeSitterNode,
    collected_nodes: List[TreeSitterNode],
    fn: Callable[[TreeSitterNode, List[TreeSitterNode]], bool],
) -> None:
    """
    Traverse the AST and collect nodes using the provided function. The function should return True
    if traversal should continue on the node's children and False otherwise.

    Args:
        node: The node to traverse.
        collected_nodes: Collected nodes will be stored in this list.
        fn: The function to use to collect nodes.
    """
    if fn(node, collected_nodes):
        for child in node.children:
            ts_traverse(child, collected_nodes, fn=fn)


class TreeSitterSourceUtils(SourceUtilsInterface):
    """
    Tree-sitter-based implementation of SourceUtils.
    """

    # pyre-ignore[11]: Annotation `Parser` is not defined as a type.
    _ts_parser: Optional[Parser] = None

    def __init__(self, cells: Optional[List[str]] = None) -> None:
        """
        Args:
            cells: List of folders in the root to search for source files. If
            None, only the root will be searched.
        """
        self.cells: List[str] = cells or [""]

    @staticmethod
    def _get_repo_root() -> Path:
        """
        Returns the root of the source code in the ARVO container.
        ARVO containers have source code at /src.
        """
        return Path("/src")

    @staticmethod
    async def save_current_changes_to_file(
        output_patch: Path, patched_src_path: Optional[str] = None
    ) -> None:
        """
        Saves the current changes to a file using git diff.
        """
        try:
            if patched_src_path:
                result = subprocess_run(
                    ["git", "diff", "--", patched_src_path],
                    check=False,
                )
            else:
                result = subprocess_run(["git", "diff"], check=False)
            output_patch.write_text(result.stdout)
        except Exception as e:
            LOGGER.warning(f"Failed to save changes to file: {e}")

    @staticmethod
    async def revert_current_changes(hard: bool = False) -> None:
        """
        Reverts the current changes using git.
        """
        try:
            if hard:
                subprocess_run(["git", "checkout", "--", "."], check=False)
                subprocess_run(["git", "clean", "-fd"], check=False)
            else:
                subprocess_run(["git", "checkout", "--", "."], check=False)
        except Exception as e:
            LOGGER.warning(f"Failed to revert changes: {e}")

    @classmethod
    def get_ts_parser(cls) -> Parser:
        if cls._ts_parser is not None:
            return cls._ts_parser
        try:
            # pyre-fixme[16]: Module `tree_sitter` has no attribute `Parser`.
            ts_parser: Parser = Parser()
            # The language library is a remote resource managed by BUCK
            ts_parser.set_language(
                Language(str(Path(__file__).parent / "tree-sitter-languages.so"), "cpp")
            )
            cls._ts_parser = ts_parser
            return cls._ts_parser
        except Exception:
            # pyre-ignore[21]: Could not find a module corresponding to import `tree_sitter_cpp`.
            import tree_sitter_cpp as tscpp  # @manual

            # pyre-fixme[16]: Module `tree_sitter` has no attribute `Parser`.
            # pyre-ignore[20]: Call `Language.__init__` expects argument `name`.
            cls._ts_parser = Parser(Language(tscpp.language()))
            return cls._ts_parser

    async def retrieve_src_of_func(self, path_and_line: PathAndLine) -> Optional[str]:
        """Retrieves the source code of the function encompassing
        `path_and_line` from a stacktrace.

        Args:
            path_and_line: A path and line from a stacktrace.

        Returns:
            Source code of the function. None if the function is not found.

        Raises:
            RuntimeError: If the function is not found.
        """
        repo_root = Path(self._get_repo_root())
        path = Path("")
        for cell in self.cells:
            path = repo_root / cell / path_and_line.file_path
            if await self.does_path_exist(path):
                break
        if not (await self.does_path_exist(path)):
            return None

        return await self._retrieve_src_of_func(path, path_and_line.line_number)

    @classmethod
    async def _retrieve_src_of_func(cls, path: Path, line_nbr: int) -> Optional[str]:
        file_content = await cls.get_file_content(path)
        function_nodes = cls.get_function_nodes_cpp(file_content)
        for node in function_nodes:
            start_line = node.start_point[0]
            end_line = node.end_point[0]
            if start_line <= line_nbr <= end_line:
                # pyre-fixme[16]: `int` has no attribute `decode`.
                return file_content[node.start_byte : node.end_byte].decode()
        return None

    @staticmethod
    async def get_file_content(path: Path) -> bytes:
        with open(path, "rb") as fp:
            return fp.read()

    async def does_path_exist(self, path: Path) -> bool:
        return path.exists()

    @classmethod
    def get_function_nodes_cpp(cls, file_content: bytes) -> List[TreeSitterNode]:
        """
        Returns a list of (templated and untemplated) function TreeSitterNodes in
        the given C++ source code.
        """
        root_node = cls.get_ts_parser().parse(file_content).root_node
        collected_nodes: List[TreeSitterNode] = []

        ts_traverse(
            root_node, collected_nodes, fn=TreeSitterSourceUtils.collect_functions
        )
        return collected_nodes

    @staticmethod
    def collect_functions(
        node: TreeSitterNode, collected_nodes: List[TreeSitterNode]
    ) -> bool:
        # Standard function.
        if node.type == "function_definition":
            collected_nodes.append(node)
            return False

        # Templated function.
        if node.type == "template_declaration":
            for child in node.children:
                if child.type == "function_definition":
                    collected_nodes.append(node)
                    return False

        return True


def parse_function_name(
    function_source: str,
    # pyre-ignore[24]: Generic type `LoggerAdapter` expects 1 type parameter
    logger: Optional[LoggerAdapter] = None,
) -> Optional[str]:
    """Parsers the source code of a function and returns the function name.
    Returns None upon parsing failure.
    """
    buf = function_source.encode()
    root_node = TreeSitterSourceUtils.get_ts_parser().parse(buf).root_node
    collected_nodes: List[TreeSitterNode] = []

    def collect_function_names(
        node: TreeSitterNode, collected_nodes: List[TreeSitterNode]
    ) -> bool:
        if node.type == "function_declarator":
            collected_nodes.append(node.children[0])
            return False

        return True

    ts_traverse(root_node, collected_nodes, fn=collect_function_names)

    if len(collected_nodes) == 0:
        return None

    if len(collected_nodes) > 1 and logger:
        # warn and heusistically choose the first function name
        logger.warn(
            f"Multiple function names found in {function_source}: {collected_nodes}"
        )

    node = collected_nodes[0]
    # pyre-fixme[16]: `int` has no attribute `decode`.
    return buf[node.start_byte : node.end_byte].decode()


class Stopwatch:
    """A stop watch that measures time elapsed within a context manager"""

    def __init__(self) -> None:
        self._start_time: Optional[float] = None
        self._elapsed_time: Optional[float] = None

    def __enter__(self) -> "Stopwatch":
        """Start a new timer"""
        self.start()
        return self

    def start(self) -> "Stopwatch":
        """Start a new timer"""
        if self._elapsed_time:
            raise RuntimeError("Cannot re-start a finished timer")
        self._start_time = time.monotonic()
        return self

    def stop(self) -> int:
        """Stop the timer"""
        if self._elapsed_time:
            raise RuntimeError("The timer has already stopped")
        end_time = time.monotonic()
        self._elapsed_time = (end_time - self._start_time) if self._start_time else 0
        return self.elapsed_seconds()

    def elapsed_seconds(self) -> int:
        """Return the elapsed time in seconds. Return 0 if the timer did not run."""
        return round(self._elapsed_time or 0.0)

    def __exit__(
        self, exc_type: Type[BaseException], exc_value: BaseException, tb: TracebackType
    ) -> None:
        """Stop the timer"""
        self.stop()


# =============================================================================
# Helper functions for the agent (wrapping the original TreeSitterSourceUtils)
# =============================================================================


async def fetch_function_source_info(
    crash_output: str,
    stack_ctx_depth: int = 3,
) -> Optional[FunctionSourceInfo]:
    """
    Fetch source code for functions in the crash stack trace.

    This is a convenience function that wraps TreeSitterSourceUtils.

    Args:
        crash_output: ASAN crash output
        stack_ctx_depth: Number of stack frames to include

    Returns:
        FunctionSourceInfo containing source for relevant functions
    """
    path_and_lines = PathAndLine.from_crash_output(crash_output)

    if len(path_and_lines) == 0 or len(path_and_lines[0]) == 0:
        LOGGER.warning("No stack trace found in crash output")
        return None

    # Get the first stack trace
    first_trace = path_and_lines[0]
    num_func_to_show = min(stack_ctx_depth, len(first_trace))

    source_utils = TreeSitterSourceUtils()
    items: List[FunctionSourceInfoItem] = []

    for path_and_line in first_trace[:num_func_to_show]:
        try:
            # Await the async function directly
            func_src = await source_utils.retrieve_src_of_func(path_and_line)
            if func_src is None:
                LOGGER.warning(
                    f"Could not find source for: {path_and_line.file_path}:{path_and_line.line_number}"
                )
                continue
            items.append(FunctionSourceInfoItem(path_and_line.file_path, func_src))
        except Exception as e:
            LOGGER.warning(f"Failed to retrieve source for {path_and_line}: {e}")
            continue

    if not items:
        return None

    return FunctionSourceInfo(items)


def apply_patch(
    source_path: str,
    original_function_src: str,
    new_function_src: str,
) -> bool:
    """
    Apply a patch by replacing the original function with the new one.

    Args:
        source_path: Path to the source file
        original_function_src: Original function source to replace
        new_function_src: New function source

    Returns:
        True if patch was applied successfully
    """
    try:
        with open(source_path, "r") as f:
            content = f.read()

        if original_function_src not in content:
            LOGGER.error(f"Original function not found in {source_path}")
            return False

        new_content = content.replace(original_function_src, new_function_src, 1)

        with open(source_path, "w") as f:
            f.write(new_content)

        LOGGER.info(f"Successfully patched {source_path}")
        return True

    except IOError as e:
        LOGGER.error(f"Failed to apply patch to {source_path}: {e}")
        return False


def revert_changes(source_path: str) -> bool:
    """
    Revert changes to a source file using git.

    Args:
        source_path: Path to the source file

    Returns:
        True if revert was successful
    """
    try:
        result = subprocess.run(
            ["git", "checkout", "--", source_path],
            capture_output=True,
            text=True,
            cwd=Path(source_path).parent,
        )
        return result.returncode == 0
    except Exception as e:
        LOGGER.warning(f"Failed to revert {source_path}: {e}")
        return False
