# Service Management in Skwaq

This document describes how to use the service management capabilities in the Skwaq CLI to manage the various services required by the application.

## Overview

Skwaq depends on several services to function properly:

1. **Database Service** (Neo4j): Stores the knowledge graph, code AST, and other data
2. **API Service**: Provides REST API endpoints for the frontend and CLI
3. **GUI Service**: Web-based user interface for visualization and interaction

The service management commands allow you to:
- Check the status of these services
- Start and stop services individually or all at once
- Restart services when needed
- Automatically start required dependencies

## Service Commands

### Checking Service Status

To check the status of all services:

```bash
skwaq service status
```

To check a specific service:

```bash
skwaq service status database
skwaq service status api
skwaq service status gui
```

### Starting Services

To start all services:

```bash
skwaq service start
```

This will start services in dependency order: Database → API → GUI.

To start a specific service (and its dependencies):

```bash
skwaq service start database
skwaq service start api     # Will also start database if needed
skwaq service start gui     # Will also start database and api if needed
```

### Stopping Services

To stop all services:

```bash
skwaq service stop
```

This will stop services in reverse dependency order: GUI → API → Database.

To stop a specific service:

```bash
skwaq service stop gui
skwaq service stop api
skwaq service stop database
```

Note that stopping a dependency doesn't stop services that depend on it. For example, stopping the database won't automatically stop the API or GUI.

### Restarting Services

To restart all services:

```bash
skwaq service restart
```

To restart a specific service:

```bash
skwaq service restart gui
skwaq service restart api
skwaq service restart database
```

## Service Dependencies

The services have the following dependency hierarchy:

```
GUI → API → Database
```

When starting a service, all of its dependencies will automatically be started if they're not already running. For example:

- Starting the GUI will automatically start the API and Database if needed
- Starting the API will automatically start the Database if needed

This ensures that services always have their required dependencies available.

## Using the GUI Command

The `skwaq gui` command has been enhanced to automatically ensure all required services are running. When you run:

```bash
skwaq gui
```

The CLI will:

1. Check if the Database is running, and start it if needed
2. Check if the API is running, and start it if needed
3. Start the GUI frontend
4. Open a web browser (unless `--no-browser` is specified)

This ensures a smooth experience when launching the GUI, without having to manually start each service.

## For Developers

### Logs

Service logs are stored in the `logs/` directory:
- `logs/database.log`: Neo4j database logs
- `logs/api.log`: API server logs
- `logs/gui.log`: GUI frontend logs

### Checking Port Usage

If you encounter issues starting services, you might have port conflicts. These are the default ports:

- Neo4j Database: 7474 (HTTP), 7687 (Bolt)
- API Service: 5001
- GUI Service: 3000

### Running in Development Mode

For development, you can use:

```bash
skwaq gui
```

This sets up all required services automatically, so you can focus on development.

## Troubleshooting

If services fail to start:

1. Check the logs in the `logs/` directory
2. Ensure ports are not already in use by other applications
3. For database issues, verify that Docker is running
4. Try restarting one service at a time with `skwaq service restart [service]`

For persistent issues:

1. Stop all services: `skwaq service stop`
2. Restart Docker
3. Start services again: `skwaq service start`