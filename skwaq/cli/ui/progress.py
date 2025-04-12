"""Progress and status indicators for the Skwaq CLI."""


from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
    TimeRemainingColumn,
)
from rich.status import Status

from .console import console


def create_progress_bar(
    description: str = "Processing",
    total: int = 100,
    unit: str = "items",
    transient: bool = False,
    auto_refresh: bool = True,
) -> Progress:
    """Create a rich progress bar.

    Args:
        description: Description of the progress bar
        total: Total number of steps
        unit: Unit of measurement
        transient: Whether to remove the progress bar after completion
        auto_refresh: Whether to automatically refresh the progress

    Returns:
        Progress bar instance
    """
    return Progress(
        SpinnerColumn(),
        TextColumn("[cyan]{task.description}"),
        BarColumn(bar_width=40),
        TaskProgressColumn(),
        TextColumn(f"[cyan]{{task.completed}} of {{task.total}} {unit}"),
        TimeRemainingColumn(),
        console=console,
        transient=transient,
        auto_refresh=auto_refresh,
    )


def create_status_indicator(
    message: str = "Working", spinner: str = "dots", spinner_style: str = "cyan"
) -> Status:
    """Create a rich status indicator.

    Args:
        message: Message to display
        spinner: Spinner animation to use
        spinner_style: Style for the spinner

    Returns:
        Status indicator instance
    """
    return Status(
        message, spinner=spinner, spinner_style=spinner_style, console=console
    )
