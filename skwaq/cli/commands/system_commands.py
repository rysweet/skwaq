"""System-level commands for the Skwaq CLI."""

import subprocess
import sys
import webbrowser
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from rich.table import Table

from ...shared.service_manager import ServiceManager, ServiceStatus, ServiceType
from ..ui.console import console, error, info, success, warning, print_banner
from ..ui.progress import create_status_indicator
from .base import CommandHandler, handle_command_error


class VersionCommandHandler(CommandHandler):
    """Handler for the version command."""

    @handle_command_error
    async def handle(self) -> int:
        """Handle the version command.

        Returns:
            Exit code (0 for success, non-zero for errors)
        """
        # Import version from package or determine from git
        try:
            from ... import __version__
        except ImportError:
            __version__ = self._get_version_from_git()

        print_banner(include_version=True, version=__version__)

        # Display additional system information
        info("System Information:")
        console.print(f"  Python: [cyan]{sys.version.split()[0]}[/cyan]")
        console.print(f"  Platform: [cyan]{sys.platform}[/cyan]")

        # Display configuration status
        try:
            from ...utils.config import get_config

            config = get_config()
            has_openai_key = bool(config.get("openai.api_key"))
            console.print(
                f"  API Configuration: [{'green' if has_openai_key else 'red'}]{'Configured' if has_openai_key else 'Not Configured'}[/{'green' if has_openai_key else 'red'}]"
            )
        except Exception:
            console.print("  API Configuration: [red]Error loading configuration[/red]")

        return 0

    def _get_version_from_git(self) -> str:
        """Get the version from git if available.

        Returns:
            Version string
        """
        try:
            # Try to get version from git
            result = subprocess.run(
                ["git", "describe", "--tags", "--always"],
                capture_output=True,
                text=True,
                check=False,
            )

            if result.returncode == 0:
                return result.stdout.strip()
            else:
                return "1.0.0-dev"
        except Exception:
            return "1.0.0-dev"


class GuiCommandHandler(CommandHandler):
    """Handler for the GUI command."""

    @handle_command_error
    async def handle(self) -> int:
        """Handle the GUI command.

        Returns:
            Exit code (0 for success, non-zero for errors)
        """
        no_browser = self.args.no_browser

        # Create service manager
        service_manager = ServiceManager()

        # Start all required services with nice progress indicators
        with create_status_indicator(
            "[bold blue]Starting required services...", spinner="dots"
        ) as status:
            # First check database status
            status.update("[bold blue]Checking database status...")
            db_status = service_manager.check_service_status(ServiceType.DATABASE)
            
            if db_status != ServiceStatus.RUNNING:
                status.update("[bold blue]Starting database service...")
                success, message = service_manager.start_service(ServiceType.DATABASE, True, 60)
                if not success:
                    status.update("[bold red]Failed to start database service!")
                    error(message)
                    return 1
                status.update("[bold green]Database service started successfully")
            else:
                status.update("[bold green]Database service is already running")
                
            # Next check API status
            status.update("[bold blue]Checking API status...")
            api_status = service_manager.check_service_status(ServiceType.API)
            
            if api_status != ServiceStatus.RUNNING:
                status.update("[bold blue]Starting API service...")
                success, message = service_manager.start_service(ServiceType.API, True, 60)
                if not success:
                    status.update("[bold red]Failed to start API service!")
                    error(message)
                    return 1
                status.update("[bold green]API service started successfully")
            else:
                status.update("[bold green]API service is already running")
                
            # Finally start GUI
            status.update("[bold blue]Starting GUI frontend...")
            success, message = service_manager.start_service(ServiceType.GUI, True, 60)
            
            if not success:
                status.update("[bold red]Failed to start GUI frontend!")
                error(message)
                return 1
                
            status.update("[bold green]GUI frontend started successfully")
            
        # All services started successfully
        gui_service = service_manager.services[ServiceType.GUI]
        api_service = service_manager.services[ServiceType.API]
        
        # Open browser if requested
        if not no_browser and gui_service.url:
            webbrowser.open(gui_service.url)
            
        # Print summary
        console.print()
        console.print(f"[bold green]All services started successfully![/]")
        console.print(f"[bold]GUI:[/] [link={gui_service.url}]{gui_service.url}[/link]")
        console.print(f"[bold]API:[/] [link={api_service.url}]{api_service.url}[/link]")
        console.print()
        console.print("Press Ctrl+C in the terminal where the services are running to stop them")
        console.print("To stop services, use: skwaq service stop")

        return 0


class ServiceCommandHandler(CommandHandler):
    """Handler for service management commands."""

    @handle_command_error
    async def handle(self) -> int:
        """Handle service management commands.

        Returns:
            Exit code (0 for success, non-zero for errors)
        """
        subcommand = self.args.subcommand
        service_type = self.args.service if hasattr(self.args, "service") else None

        service_manager = ServiceManager()

        # Handle different subcommands
        if subcommand == "status":
            await self._handle_status(service_manager, service_type)
        elif subcommand == "start":
            await self._handle_start(service_manager, service_type)
        elif subcommand == "stop":
            await self._handle_stop(service_manager, service_type)
        elif subcommand == "restart":
            await self._handle_restart(service_manager, service_type)
        else:
            error(f"Unknown subcommand: {subcommand}")
            return 1

        return 0

    async def _handle_status(
        self, service_manager: ServiceManager, service_type: Optional[str]
    ) -> None:
        """Handle the status subcommand.

        Args:
            service_manager: Service manager instance.
            service_type: Specific service to check, or None for all.
        """
        console.print("[bold]Service Status:[/]")

        table = Table(show_header=True)
        table.add_column("Service", style="cyan")
        table.add_column("Status", style="")
        table.add_column("URL", style="")

        if service_type:
            # Check specific service
            try:
                service_enum = ServiceType(service_type)
                status = service_manager.check_service_status(service_enum)
                service = service_manager.services[service_enum]
                
                status_style = {
                    ServiceStatus.RUNNING: "green",
                    ServiceStatus.STOPPED: "red",
                    ServiceStatus.STARTING: "yellow",
                    ServiceStatus.ERROR: "red bold",
                    ServiceStatus.UNKNOWN: "dim",
                }
                
                table.add_row(
                    service.name,
                    f"[{status_style[status]}]{status.value}[/]",
                    service.url or "N/A"
                )
            except ValueError:
                error(f"Unknown service type: {service_type}")
                info(f"Available services: {', '.join([s.value for s in ServiceType])}")
                return
        else:
            # Check all services
            for service_enum in ServiceType:
                status = service_manager.check_service_status(service_enum)
                service = service_manager.services[service_enum]
                
                status_style = {
                    ServiceStatus.RUNNING: "green",
                    ServiceStatus.STOPPED: "red",
                    ServiceStatus.STARTING: "yellow",
                    ServiceStatus.ERROR: "red bold",
                    ServiceStatus.UNKNOWN: "dim",
                }
                
                table.add_row(
                    service.name,
                    f"[{status_style[status]}]{status.value}[/]",
                    service.url or "N/A"
                )
                
        console.print(table)

    async def _handle_start(
        self, service_manager: ServiceManager, service_type: Optional[str]
    ) -> None:
        """Handle the start subcommand.

        Args:
            service_manager: Service manager instance.
            service_type: Specific service to start, or None for all.
        """
        if service_type:
            # Start specific service
            try:
                service_enum = ServiceType(service_type)
                
                with create_status_indicator(
                    f"[bold blue]Starting {service_manager.services[service_enum].name}...",
                    spinner="dots"
                ) as status:
                    success, message = service_manager.start_service(service_enum, True, 60)
                    
                    if success:
                        status.update(f"[bold green]{message}")
                    else:
                        status.update(f"[bold red]Failed: {message}")
                        
            except ValueError:
                error(f"Unknown service type: {service_type}")
                info(f"Available services: {', '.join([s.value for s in ServiceType])}")
                return
                
        else:
            # Start all services in dependency order
            for service_enum in [ServiceType.DATABASE, ServiceType.API, ServiceType.GUI]:
                service = service_manager.services[service_enum]
                
                with create_status_indicator(
                    f"[bold blue]Starting {service.name}...",
                    spinner="dots"
                ) as status:
                    success, message = service_manager.start_service(service_enum, True, 60)
                    
                    if success:
                        status.update(f"[bold green]{message}")
                    else:
                        status.update(f"[bold red]Failed: {message}")
                        error(f"Failed to start {service.name}: {message}")
                        error("Aborting startup of remaining services")
                        return

            # Print summary if all services started
            console.print()
            success("All services started successfully!")
            for service_enum in ServiceType:
                service = service_manager.services[service_enum]
                console.print(f"[bold]{service.name}:[/] [link={service.url}]{service.url}[/link]")

    async def _handle_stop(
        self, service_manager: ServiceManager, service_type: Optional[str]
    ) -> None:
        """Handle the stop subcommand.

        Args:
            service_manager: Service manager instance.
            service_type: Specific service to stop, or None for all.
        """
        if service_type:
            # Stop specific service
            try:
                service_enum = ServiceType(service_type)
                
                with create_status_indicator(
                    f"[bold blue]Stopping {service_manager.services[service_enum].name}...",
                    spinner="dots"
                ) as status:
                    success, message = service_manager.stop_service(service_enum)
                    
                    if success:
                        status.update(f"[bold green]{message}")
                    else:
                        status.update(f"[bold red]Failed: {message}")
                        
            except ValueError:
                error(f"Unknown service type: {service_type}")
                info(f"Available services: {', '.join([s.value for s in ServiceType])}")
                return
                
        else:
            # Stop all services in reverse dependency order
            for service_enum in [ServiceType.GUI, ServiceType.API, ServiceType.DATABASE]:
                service = service_manager.services[service_enum]
                
                with create_status_indicator(
                    f"[bold blue]Stopping {service.name}...",
                    spinner="dots"
                ) as status:
                    success, message = service_manager.stop_service(service_enum)
                    
                    if success:
                        status.update(f"[bold green]{message}")
                    else:
                        status.update(f"[bold red]Failed: {message}")
                        warning(f"Failed to stop {service.name}: {message}")
                        # Continue with other services even if one fails

            success("All services stopped")

    async def _handle_restart(
        self, service_manager: ServiceManager, service_type: Optional[str]
    ) -> None:
        """Handle the restart subcommand.

        Args:
            service_manager: Service manager instance.
            service_type: Specific service to restart, or None for all.
        """
        # First stop the service(s)
        await self._handle_stop(service_manager, service_type)
        
        # Then start them again
        await self._handle_start(service_manager, service_type)