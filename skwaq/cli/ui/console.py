"""Console utilities for the Skwaq CLI."""

from typing import Optional

from rich.console import Console
from rich.panel import Panel
from rich.theme import Theme

# Define custom theme for the console
skwaq_theme = Theme(
    {
        "info": "cyan",
        "warning": "yellow",
        "danger": "bold red",
        "success": "bold green",
        "heading": "bold blue",
        "filename": "yellow",
        "command": "green",
        "option": "cyan",
        "banner": "bold magenta",
        "version": "italic cyan",
    }
)

# Create the main console instance
console = Console(theme=skwaq_theme)


def print_banner(
    include_version: bool = True, version: Optional[str] = None, file=None
) -> None:
    """Print the Skwaq banner.

    Args:
        include_version: Whether to include the version
        version: Version string to include (if None, will use default)
        file: File object to print to (default None for stdout)
    """
    banner_text = r"""
     _                          
 ___| | ___      ____ _  __ _   
/ __| |/ \ \ /\ / / _|  |/ _  |  
\__ \   <  \ V  V / (_| | (_| |  
|___/_|\_\  \_/\_/ \__,_|\__, |__  
                            |___/

⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣀⣀⣀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣴⣿⣿⡟⠋⢻⣷⣄⡀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣤⣾⣿⣷⣿⣿⣿⣿⣿⣶⣾⣿⣿⠿⠿⠿⠶⠄⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠉⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡟⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠃⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⣿⣿⣿⣿⣿⣿⡟⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⣿⣿⣿⣿⣿⠟⠻⣧⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⣼⣿⣿⣿⣿⣿⣆⣤⠿⢶⣦⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⢰⣿⣿⣿⣿⣿⣿⣿⣿⡀⠀⠀⠀⠑⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠸⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠉⠙⠛⠋⠉⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
    """

    if include_version:
        version_text = f"Version: {version or '1.0.0'}"
        banner = Panel(
            f"{banner_text}\n[version]{version_text}[/version]",
            style="banner",
            expand=False,
        )
    else:
        banner = Panel(banner_text, style="banner", expand=False)

    # If file is None, print to console's default output
    # Otherwise, use the specified file
    if file is None:
        console.print(banner)
    else:
        # For file output, we need to render the panel as a string
        result = console.render_str(banner)
        print(result, file=file)


def error(message: str) -> None:
    """Print an error message to console.

    Args:
        message: Error message to print
    """
    console.print(f"[danger]Error: {message}[/danger]")


def warning(message: str) -> None:
    """Print a warning message to console.

    Args:
        message: Warning message to print
    """
    console.print(f"[warning]Warning: {message}[/warning]")


def info(message: str) -> None:
    """Print an informational message to console.

    Args:
        message: Info message to print
    """
    console.print(f"[info]{message}[/info]")


def success(message: str) -> None:
    """Print a success message to console.

    Args:
        message: Success message to print
    """
    console.print(f"[success]{message}[/success]")


def heading(message: str) -> None:
    """Print a heading to console.

    Args:
        message: Heading text
    """
    console.print(f"[heading]{message}[/heading]")
