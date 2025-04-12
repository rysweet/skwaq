"""Interactive prompt utilities for the Skwaq CLI."""

from typing import List, Optional, TypeVar

from rich.prompt import Confirm, IntPrompt, Prompt

from .console import console

T = TypeVar("T")


def prompt_for_input(
    message: str, default: Optional[str] = None, password: bool = False
) -> str:
    """Prompt the user for input.

    Args:
        message: Message to display
        default: Default value
        password: Whether to hide input (for passwords)

    Returns:
        User input
    """
    return Prompt.ask(message, console=console, default=default, password=password)


def prompt_for_confirmation(message: str, default: bool = False) -> bool:
    """Prompt the user for confirmation.

    Args:
        message: Message to display
        default: Default value

    Returns:
        True if confirmed, False otherwise
    """
    return Confirm.ask(message, console=console, default=default)


def prompt_for_integer(
    message: str,
    default: Optional[int] = None,
    min_value: Optional[int] = None,
    max_value: Optional[int] = None,
) -> int:
    """Prompt the user for an integer value.

    Args:
        message: Message to display
        default: Default value
        min_value: Minimum allowed value
        max_value: Maximum allowed value

    Returns:
        Integer value
    """
    return IntPrompt.ask(
        message,
        console=console,
        default=default,
        choices=(
            [str(i) for i in range(min_value or 0, (max_value or 100) + 1)]
            if min_value is not None and max_value is not None
            else None
        ),
    )


def prompt_for_choice(
    message: str, choices: List[str], default: Optional[str] = None
) -> str:
    """Prompt the user to select from a list of choices.

    Args:
        message: Message to display
        choices: List of choices
        default: Default choice

    Returns:
        Selected choice
    """
    return Prompt.ask(message, console=console, default=default, choices=choices)


def prompt_for_api_key(service_name: str, current_value: Optional[str] = None) -> str:
    """Prompt the user for an API key.

    Args:
        service_name: Name of the service
        current_value: Current API key value

    Returns:
        API key
    """
    if current_value:
        masked_key = (
            current_value[:4] + "*" * (len(current_value) - 8) + current_value[-4:]
        )
        message = f"Enter {service_name} API key [cyan](current: {masked_key})[/cyan]"
    else:
        message = f"Enter {service_name} API key"

    return Prompt.ask(
        message, console=console, password=True, default="" if current_value else None
    )
