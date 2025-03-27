"""Base functionality for command handlers."""

import argparse
import sys
from typing import Any, Callable, Dict, List, Optional, Type, TypeVar, Union

from ..ui.console import console, error

T = TypeVar('T')

class CommandHandler:
    """Base class for command handlers.
    
    This class provides the basic structure for implementing command handlers.
    Subclasses should override the handle method to implement command-specific logic.
    """
    
    def __init__(self, args: argparse.Namespace) -> None:
        """Initialize the command handler.
        
        Args:
            args: Parsed command-line arguments
        """
        self.args = args
    
    async def handle(self) -> int:
        """Handle the command.
        
        This method should be overridden by subclasses to implement
        command-specific logic.
        
        Returns:
            Exit code (0 for success, non-zero for errors)
        """
        raise NotImplementedError("Subclasses must implement handle()")

def handle_command_error(func: Callable[..., Any]) -> Callable[..., Any]:
    """Decorator for handling command errors gracefully.
    
    Args:
        func: Function to decorate
        
    Returns:
        Decorated function
    """
    async def wrapper(*args: Any, **kwargs: Any) -> int:
        try:
            return await func(*args, **kwargs)
        except Exception as e:
            error(f"Command failed: {str(e)}")
            import traceback
            console.print(f"[dim]{traceback.format_exc()}[/dim]")
            return 1
    
    return wrapper