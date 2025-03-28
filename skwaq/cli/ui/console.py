"""Console utilities for the Skwaq CLI."""

import sys
from typing import Optional

from rich.console import Console
from rich.theme import Theme
from rich.panel import Panel
from rich.style import Style

# Define custom theme for the console
skwaq_theme = Theme({
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
})

# Create the main console instance
console = Console(theme=skwaq_theme)

def print_banner(include_version: bool = True, version: Optional[str] = None) -> None:
    """Print the Skwaq banner.
    
    Args:
        include_version: Whether to include the version
        version: Version string to include (if None, will use default)
    """
    banner_text = """
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
        banner = Panel(f"{banner_text}\n[version]{version_text}[/version]", 
                     style="banner", expand=False)
    else:
        banner = Panel(banner_text, style="banner", expand=False)
    
    console.print(banner)

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