# Skwaq Development Guidelines

## Build & Test Commands
- Run all tests: `pytest tests/ --cov=skwaq`
- Run single test: `pytest tests/path/to/test_file.py::TestClass::test_function`
- Run linters: `pre-commit run --all-files`
- Format code: `black .`
- Check types: `mypy .`
- Run CI checks: `./scripts/ci/run-local-ci.sh`

## Code Style
- Line length: 100 characters
- Black + isort for formatting
- Google-style docstrings with type hints
- snake_case for functions/variables, PascalCase for classes
- Explicit type annotations (mypy strict mode)
- Absolute imports with isort profile=black
- Error handling: catch specific exceptions, log before re-raising
- Use dataclasses for configuration objects
- Documentation coverage required (pydocstyle)

## Project Structure
- Core logic in skwaq/ with modular components
- Tests mirror package structure in tests/
- Poetry for dependency management
- Neo4j for data storage
- Azure OpenAI for inference

## Status
Currently completed: Milestone F1 (Project Setup and Environment)
Next milestone: F2 (Core Utilities and Infrastructure)

### Milestone F2 Required Implementations:
1. Telemetry system implementation (skwaq/utils/telemetry.py)
   - Add structured event classes
   - Add telemetry data collection
   - Implement opt-out functionality
   - Add telemetry endpoint configuration

2. Configuration management (skwaq/utils/config.py)
   - Enhance configuration loading from multiple sources
   - Implement configuration validation
   - Add dynamic configuration updates

3. Event system implementation
   - Define event types for system components
   - Implement event emitters and subscribers
   - Add event handling infrastructure

4. Logging system enhancements (skwaq/utils/logging.py)
   - Add structured logging
   - Add log rotation
   - Implement log levels configuration
   - Add context-aware logging