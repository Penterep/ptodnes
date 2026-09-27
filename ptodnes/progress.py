"""
Shared progress display for ptodnes.

Rich allows only one live display per console (before rich 14.1 a second one
raises LiveError, from 14.1 they nest but only in strict LIFO order). ptodnes
runs datasources and domains concurrently, so every part of the program shares
a single Progress instance here. It is started when the first task is added
and stopped when the last task finishes.

Datasources that run meanwhile (VirusTotal, ...) can show one status line
each above the bars via status(); the terminal allows only one live region,
so an in-place '\r' line would otherwise break it.

The progress bar is shown only when output is verbose (not -j/-y/-c) and
stdout is a terminal, so it never gets into the machine-readable output
consumed by the Penterep platform.
"""
from contextlib import contextmanager
from typing import Iterable, Iterator

from rich.console import Console, RenderableType
from rich.text import Text
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeRemainingColumn,
)

from ptodnes.metaclasses import Singleton


class _StatusProgress(Progress):
    """Progress that renders status lines above the bars."""

    def __init__(self, *args, **kwargs):
        # set before super().__init__(), which already renders the display
        self.status_lines: dict[str, str] = {}
        super().__init__(*args, **kwargs)

    def get_renderables(self) -> Iterable[RenderableType]:
        # the refresh thread reads this while the event loop writes it -> copy
        for source, message in list(self.status_lines.items()):
            line = Text("[✓] ", style="green")
            line.append(f"{source}: ", style="bold")
            line.append(message)
            yield line
        yield from super().get_renderables()


class ProgressTask:
    """Handle for one progress task (one bar)."""

    def __init__(self, progress: Progress | None = None, task_id=None):
        self._progress = progress
        self._task_id = task_id

    def advance(self, step: float = 1) -> None:
        if self._progress is not None:
            self._progress.advance(self._task_id, step)

    def update(self, **kwargs) -> None:
        if self._progress is not None:
            self._progress.update(self._task_id, **kwargs)


class ProgressManager(metaclass=Singleton):
    """Single shared Progress for the whole program."""

    def __init__(self):
        self._console = Console()
        self._progress: _StatusProgress | None = None
        self._active_tasks = 0

    @property
    def is_active(self) -> bool:
        """True while the live progress display is on screen."""
        return self._progress is not None

    def status(self, source: str, message: str) -> None:
        """Show (or replace) the status line of one source above the bars."""
        if self._progress is not None:
            self._progress.status_lines[source] = message
            self._progress.refresh()

    def clear_status(self, source: str) -> None:
        if self._progress is not None:
            self._progress.status_lines.pop(source, None)

    def _is_enabled(self, verbose: bool) -> bool:
        return verbose and self._console.is_terminal

    def _start(self) -> _StatusProgress:
        progress = _StatusProgress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            MofNCompleteColumn(),
            TimeRemainingColumn(),
            console=self._console,
            transient=True,
            redirect_stdout=True,  # ptprint() output is printed above the bars
        )
        progress.start()
        return progress

    @contextmanager
    def task(self, description: str, total: float | None = None, *, verbose: bool = True) -> Iterator[ProgressTask]:
        """
        Context manager that adds one bar and removes it on exit.

        with ProgressManager().task("Querying A", total=100, verbose=self._verbose) as bar:
            bar.advance()
        """
        if not self._is_enabled(verbose):
            yield ProgressTask()  # no-op handle
            return

        if self._progress is None:
            self._progress = self._start()
        self._active_tasks += 1
        task_id = self._progress.add_task(description, total=total)
        try:
            yield ProgressTask(self._progress, task_id)
        finally:
            self._progress.remove_task(task_id)
            self._active_tasks -= 1
            if self._active_tasks == 0:
                self._progress.stop()
                self._progress = None
