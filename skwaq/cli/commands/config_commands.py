"""Command handlers for configuration commands."""

import json
from typing import Dict, List

from ...core.openai_client import test_openai_connection
from ...utils.config import get_config, reset_config, save_config, update_config
from ...utils.logging import get_logger
from ..ui.console import console, error, info, success, warning
from ..ui.formatters import format_panel
from ..ui.progress import create_status_indicator
from ..ui.prompts import prompt_for_api_key, prompt_for_confirmation, prompt_for_input
from .base import CommandHandler, handle_command_error

logger = get_logger(__name__)


class ConfigCommandHandler(CommandHandler):
    """Handler for the config command."""

    @handle_command_error
    async def handle(self) -> int:
        """Handle the config command.

        Returns:
            Exit code (0 for success, non-zero for errors)
        """
        if not hasattr(self.args, "config_command") or not self.args.config_command:
            error("No config command specified")
            return 1

        # Dispatch to appropriate subcommand handler
        if self.args.config_command == "show":
            return await self._handle_show()
        elif self.args.config_command == "set":
            return await self._handle_set()
        elif self.args.config_command == "reset":
            return await self._handle_reset()
        elif self.args.config_command == "check":
            return await self._handle_check()
        else:
            error(f"Unknown config command: {self.args.config_command}")
            return 1

    async def _handle_show(self) -> int:
        """Handle the config show command.

        Returns:
            Exit code (0 for success, non-zero for errors)
        """
        config_path = getattr(self.args, "path", None)
        output_format = self.args.format

        # Get configuration
        config = get_config()

        if config_path:
            # Show specific configuration path
            path_parts = config_path.split(".")
            current = config

            try:
                for part in path_parts:
                    current = current[part]

                result = {config_path: current}
            except (KeyError, TypeError):
                error(f"Configuration path not found: {config_path}")
                return 1
        else:
            # Show all configuration
            result = config

        # Display result
        if output_format == "json":
            console.print_json(json.dumps(result, indent=2))
        else:
            self._display_config(result)

        return 0

    def _display_config(self, config: Dict, prefix: str = "") -> None:
        """Display configuration in a readable format.

        Args:
            config: Configuration dictionary
            prefix: Prefix for nested keys
        """
        for key, value in config.items():
            full_key = f"{prefix}.{key}" if prefix else key

            if isinstance(value, dict):
                console.print(f"[cyan]{full_key}[/cyan]:")
                self._display_config(value, full_key)
            else:
                # Handle sensitive values
                if any(
                    sensitive in full_key.lower()
                    for sensitive in ["key", "token", "secret", "password"]
                ):
                    display_value = (
                        f"{str(value)[:4]}****{str(value)[-4:]}"
                        if value and len(str(value)) > 8
                        else "****"
                    )
                    console.print(
                        f"  [yellow]{full_key}[/yellow]: [dim]{display_value}[/dim] [red](SENSITIVE)[/red]"
                    )
                else:
                    console.print(f"  [yellow]{full_key}[/yellow]: {value}")

    async def _handle_set(self) -> int:
        """Handle the config set command.

        Returns:
            Exit code (0 for success, non-zero for errors)
        """
        config_path = self.args.path
        config_value = self.args.value

        # Convert value to appropriate type if possible
        try:
            # Try to convert to int
            config_value = int(config_value)
        except ValueError:
            try:
                # Try to convert to float
                config_value = float(config_value)
            except ValueError:
                # Try to convert to boolean
                if config_value.lower() == "true":
                    config_value = True
                elif config_value.lower() == "false":
                    config_value = False
                # Try to convert to JSON
                elif config_value.startswith("{") or config_value.startswith("["):
                    try:
                        config_value = json.loads(config_value)
                    except json.JSONDecodeError:
                        pass

        # Update configuration
        with create_status_indicator(
            "[bold blue]Updating configuration...", spinner="dots"
        ) as status:
            try:
                update_config(config_path, config_value)
                save_config()
                status.update("[bold green]Configuration updated!")

                success(f"Configuration updated: {config_path} = {config_value}")
                return 0
            except Exception as e:
                status.update("[bold red]Configuration update failed!")
                error(f"Failed to update configuration: {str(e)}")
                return 1

    async def _handle_reset(self) -> int:
        """Handle the config reset command.

        Returns:
            Exit code (0 for success, non-zero for errors)
        """
        force = getattr(self.args, "force", False)

        if not force:
            confirmed = prompt_for_confirmation(
                "Are you sure you want to reset configuration to defaults? This cannot be undone."
            )

            if not confirmed:
                info("Reset cancelled.")
                return 0

        with create_status_indicator(
            "[bold blue]Resetting configuration...", spinner="dots"
        ) as status:
            try:
                reset_config()
                status.update("[bold green]Configuration reset to defaults!")

                success("Configuration has been reset to defaults")
                return 0
            except Exception as e:
                status.update("[bold red]Configuration reset failed!")
                error(f"Failed to reset configuration: {str(e)}")
                return 1

    async def _handle_check(self) -> int:
        """Handle the config check command.

        Returns:
            Exit code (0 for success, non-zero for errors)
        """
        fix = getattr(self.args, "fix", False)

        issues = []

        # Check OpenAI API configuration
        config = get_config()
        openai_config = config.get("openai", {})

        if not openai_config.get("api_key"):
            issues.append("OpenAI API key not configured")

        if not openai_config.get("endpoint"):
            issues.append("OpenAI API endpoint not configured")

        # Check database configuration
        database_config = config.get("database", {})

        if not database_config.get("uri"):
            issues.append("Neo4j URI not configured")

        if not database_config.get("username"):
            issues.append("Neo4j username not configured")

        if not database_config.get("password"):
            issues.append("Neo4j password not configured")

        # Display check results
        if not issues:
            success("Configuration check passed. All required settings are present.")
        else:
            warning("Configuration check found issues:")
            for issue in issues:
                console.print(f"  - [yellow]{issue}[/yellow]")

            if fix:
                # Prompt for missing configuration values
                fixed = await self._fix_configuration(issues)
                if fixed:
                    success("Configuration issues fixed")
                    return 0
                else:
                    warning("Some configuration issues remain")
                    return 1
            else:
                info("Use 'skwaq config check --fix' to fix these issues interactively")
                return 1

        # Test connectivity
        if "OpenAI API" not in " ".join(issues):
            with create_status_indicator(
                "[bold blue]Testing OpenAI API connection...", spinner="dots"
            ) as status:
                try:
                    result = await test_openai_connection()
                    if result:
                        status.update("[bold green]OpenAI API connection successful!")
                    else:
                        status.update("[bold red]OpenAI API connection failed!")
                        warning(
                            "Could not connect to OpenAI API. Check your configuration."
                        )
                        if fix:
                            await self._fix_openai_connection()
                except Exception as e:
                    status.update("[bold red]OpenAI API connection failed!")
                    warning(f"OpenAI API connection error: {str(e)}")
                    if fix:
                        await self._fix_openai_connection()

        # Test Neo4j connection if no issues
        if not any(issue.startswith("Neo4j") for issue in issues):
            with create_status_indicator(
                "[bold blue]Testing Neo4j connection...", spinner="dots"
            ) as status:
                try:
                    from ...db.neo4j_connector import get_connector

                    connector = get_connector()
                    if connector.is_connected():
                        status.update("[bold green]Neo4j connection successful!")
                    else:
                        status.update("[bold red]Neo4j connection failed!")
                        warning(
                            "Could not connect to Neo4j database. Check your configuration."
                        )
                        if fix:
                            await self._fix_neo4j_connection()
                except Exception as e:
                    status.update("[bold red]Neo4j connection failed!")
                    warning(f"Neo4j connection error: {str(e)}")
                    if fix:
                        await self._fix_neo4j_connection()

        return 0

    async def _fix_configuration(self, issues: List[str]) -> bool:
        """Fix configuration issues interactively.

        Args:
            issues: List of configuration issues

        Returns:
            True if all issues were fixed, False otherwise
        """
        fixed = True

        # Fix OpenAI API configuration
        if (
            "OpenAI API key not configured" in issues
            or "OpenAI API endpoint not configured" in issues
        ):
            console.print(
                format_panel(
                    "Let's configure the OpenAI API settings.",
                    title="OpenAI API Configuration",
                    style="cyan",
                )
            )

            if "OpenAI API key not configured" in issues:
                api_key = prompt_for_api_key("OpenAI API")
                update_config("openai.api_key", api_key)

            if "OpenAI API endpoint not configured" in issues:
                endpoint = prompt_for_input("Enter OpenAI API endpoint:")
                update_config("openai.endpoint", endpoint)

            # Save updates
            save_config()
            success("OpenAI API configuration updated")

        # Fix Neo4j configuration
        if any(issue.startswith("Neo4j") for issue in issues):
            console.print(
                format_panel(
                    "Let's configure the Neo4j database settings.",
                    title="Neo4j Configuration",
                    style="cyan",
                )
            )

            if "Neo4j URI not configured" in issues:
                uri = prompt_for_input(
                    "Enter Neo4j URI:", default="bolt://localhost:7687"
                )
                update_config("database.uri", uri)

            if "Neo4j username not configured" in issues:
                username = prompt_for_input("Enter Neo4j username:", default="neo4j")
                update_config("database.username", username)

            if "Neo4j password not configured" in issues:
                password = prompt_for_input("Enter Neo4j password:", password=True)
                update_config("database.password", password)

            # Save updates
            save_config()
            success("Neo4j configuration updated")

        # Test if issues are fixed
        config = get_config()

        if "OpenAI API key not configured" in issues and not config.get(
            "openai", {}
        ).get("api_key"):
            fixed = False

        if "OpenAI API endpoint not configured" in issues and not config.get(
            "openai", {}
        ).get("endpoint"):
            fixed = False

        if "Neo4j URI not configured" in issues and not config.get("database", {}).get(
            "uri"
        ):
            fixed = False

        if "Neo4j username not configured" in issues and not config.get(
            "database", {}
        ).get("username"):
            fixed = False

        if "Neo4j password not configured" in issues and not config.get(
            "database", {}
        ).get("password"):
            fixed = False

        return fixed

    async def _fix_openai_connection(self) -> None:
        """Fix OpenAI API connection issues interactively."""
        console.print(
            format_panel(
                "Let's fix the OpenAI API connection. This could involve:\n"
                + "1. Checking your API key\n"
                + "2. Verifying the endpoint URL\n"
                + "3. Confirming your Azure subscription settings",
                title="OpenAI API Connection Fix",
                style="cyan",
            )
        )

        # Prompt for API key and endpoint
        api_key = prompt_for_api_key(
            "OpenAI API", get_config().get("openai", {}).get("api_key")
        )
        endpoint = prompt_for_input(
            "Enter OpenAI API endpoint:",
            default=get_config().get("openai", {}).get("endpoint", ""),
        )

        # Update configuration
        update_config("openai.api_key", api_key)
        update_config("openai.endpoint", endpoint)

        # Authentication type
        auth_type = prompt_for_input(
            "Authentication type (api_key or oauth):",
            default=get_config().get("openai", {}).get("auth_type", "api_key"),
        )
        update_config("openai.auth_type", auth_type)

        # Save updates
        save_config()
        success("OpenAI API configuration updated")

    async def _fix_neo4j_connection(self) -> None:
        """Fix Neo4j connection issues interactively."""
        console.print(
            format_panel(
                "Let's fix the Neo4j database connection. This could involve:\n"
                + "1. Checking if Neo4j is running\n"
                + "2. Verifying the connection URI\n"
                + "3. Confirming authentication credentials",
                title="Neo4j Connection Fix",
                style="cyan",
            )
        )

        # Prompt for connection details
        uri = prompt_for_input(
            "Enter Neo4j URI:",
            default=get_config()
            .get("database", {})
            .get("uri", "bolt://localhost:7687"),
        )
        username = prompt_for_input(
            "Enter Neo4j username:",
            default=get_config().get("database", {}).get("username", "neo4j"),
        )
        password = prompt_for_input("Enter Neo4j password:", password=True)

        # Update configuration
        update_config("database.uri", uri)
        update_config("database.username", username)
        update_config("database.password", password)

        # Save updates
        save_config()
        success("Neo4j configuration updated")
