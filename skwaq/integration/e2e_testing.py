"""End-to-end testing utilities for system validation.

This module provides utilities for creating and executing end-to-end tests
that validate the entire system works correctly together.
"""

from typing import Any, Dict, List, Optional, Set, Union, Callable, Awaitable
import time
import asyncio
import json
import os
import logging
from datetime import datetime
from pathlib import Path

from ..utils.logging import get_logger
from ..utils.config import get_config

# CodeAnalyzer import removed
from ..workflows.vulnerability_research import VulnerabilityResearchWorkflow
from ..workflows.qa_workflow import QAWorkflow
from ..db.neo4j_connector import get_connector
from .system_integration import get_system_manager

logger = get_logger(__name__)


class E2ETestScenario:
    """Represents an end-to-end test scenario.

    This class defines a complete end-to-end test scenario that exercises
    multiple components of the system together.
    """

    def __init__(
        self,
        name: str,
        description: str,
        components: List[str],
        setup: Optional[Callable[[], None]] = None,
        teardown: Optional[Callable[[], None]] = None,
    ):
        """Initialize a test scenario.

        Args:
            name: The name of the scenario
            description: Description of the scenario
            components: List of components used in this scenario
            setup: Optional setup function to run before the scenario
            teardown: Optional teardown function to run after the scenario
        """
        self.name = name
        self.description = description
        self.components = components
        self.setup_func = setup
        self.teardown_func = teardown
        self.steps: List[Dict[str, Any]] = []
        self.assertions: List[Dict[str, Any]] = []
        self.results: Dict[str, Any] = {
            "success": False,
            "steps_completed": 0,
            "assertions_passed": 0,
            "assertions_failed": 0,
            "execution_time": 0,
            "errors": [],
        }

    def add_step(
        self,
        name: str,
        func: Callable[..., Any],
        args: Optional[List[Any]] = None,
        kwargs: Optional[Dict[str, Any]] = None,
    ) -> "E2ETestScenario":
        """Add a step to the scenario.

        Args:
            name: The name of the step
            func: The function to execute
            args: Optional positional arguments for the function
            kwargs: Optional keyword arguments for the function

        Returns:
            Self for method chaining
        """
        self.steps.append(
            {
                "name": name,
                "func": func,
                "args": args or [],
                "kwargs": kwargs or {},
                "result": None,
                "success": False,
                "error": None,
            }
        )
        return self

    def add_assertion(
        self, name: str, condition: Callable[[Dict[str, Any]], bool], error_message: str
    ) -> "E2ETestScenario":
        """Add an assertion to the scenario.

        Args:
            name: The name of the assertion
            condition: Function that returns True if assertion passes, False otherwise
            error_message: Message to display if assertion fails

        Returns:
            Self for method chaining
        """
        self.assertions.append(
            {
                "name": name,
                "condition": condition,
                "error_message": error_message,
                "success": False,
            }
        )
        return self

    def run(self) -> Dict[str, Any]:
        """Run the test scenario.

        Returns:
            Dictionary with test results
        """
        start_time = time.time()

        # Initialize results
        self.results = {
            "success": False,
            "steps_completed": 0,
            "assertions_passed": 0,
            "assertions_failed": 0,
            "execution_time": 0,
            "errors": [],
        }

        # Run setup if provided
        if self.setup_func:
            try:
                self.setup_func()
            except Exception as e:
                logger.error(f"Error in test setup: {e}")
                self.results["errors"].append(f"Setup error: {str(e)}")
                self.results["execution_time"] = time.time() - start_time
                return self.results

        # Run each step
        step_results = {}
        try:
            for i, step in enumerate(self.steps):
                logger.info(f"Running step {i+1}/{len(self.steps)}: {step['name']}")

                try:
                    # Execute the step
                    result = step["func"](*step["args"], **step["kwargs"])

                    # Record step results
                    step["result"] = result
                    step["success"] = True
                    step_results[step["name"]] = result
                    self.results["steps_completed"] += 1

                except Exception as e:
                    logger.error(f"Error in step '{step['name']}': {e}")
                    step["error"] = str(e)
                    step["success"] = False
                    self.results["errors"].append(
                        f"Step '{step['name']}' error: {str(e)}"
                    )
                    break
        finally:
            # Run assertions even if steps fail
            for assertion in self.assertions:
                try:
                    result = assertion["condition"](step_results)
                    assertion["success"] = result

                    if result:
                        self.results["assertions_passed"] += 1
                    else:
                        self.results["assertions_failed"] += 1
                        self.results["errors"].append(assertion["error_message"])
                except Exception as e:
                    logger.error(f"Error in assertion '{assertion['name']}': {e}")
                    assertion["success"] = False
                    self.results["assertions_failed"] += 1
                    self.results["errors"].append(
                        f"Assertion '{assertion['name']}' error: {str(e)}"
                    )

            # Run teardown if provided
            if self.teardown_func:
                try:
                    self.teardown_func()
                except Exception as e:
                    logger.error(f"Error in test teardown: {e}")
                    self.results["errors"].append(f"Teardown error: {str(e)}")

            # Calculate final execution time
            self.results["execution_time"] = time.time() - start_time

            # Determine overall success
            self.results["success"] = (
                self.results["steps_completed"] == len(self.steps)
                and self.results["assertions_failed"] == 0
            )

        return self.results


class AsyncE2ETestScenario(E2ETestScenario):
    """Represents an asynchronous end-to-end test scenario.

    This class extends E2ETestScenario to support asynchronous test steps
    and assertions.
    """

    def __init__(
        self,
        name: str,
        description: str,
        components: List[str],
        setup: Optional[Callable[[], Awaitable[None]]] = None,
        teardown: Optional[Callable[[], Awaitable[None]]] = None,
    ):
        """Initialize an asynchronous test scenario.

        Args:
            name: The name of the scenario
            description: Description of the scenario
            components: List of components used in this scenario
            setup: Optional async setup function to run before the scenario
            teardown: Optional async teardown function to run after the scenario
        """
        super().__init__(name, description, components)
        self.setup_func = setup
        self.teardown_func = teardown

    def add_step(
        self,
        name: str,
        func: Callable[..., Awaitable[Any]],
        args: Optional[List[Any]] = None,
        kwargs: Optional[Dict[str, Any]] = None,
    ) -> "AsyncE2ETestScenario":
        """Add an asynchronous step to the scenario.

        Args:
            name: The name of the step
            func: The async function to execute
            args: Optional positional arguments for the function
            kwargs: Optional keyword arguments for the function

        Returns:
            Self for method chaining
        """
        return super().add_step(name, func, args, kwargs)

    async def run(self) -> Dict[str, Any]:
        """Run the test scenario asynchronously.

        Returns:
            Dictionary with test results
        """
        start_time = time.time()

        # Initialize results
        self.results = {
            "success": False,
            "steps_completed": 0,
            "assertions_passed": 0,
            "assertions_failed": 0,
            "execution_time": 0,
            "errors": [],
        }

        # Run setup if provided
        if self.setup_func:
            try:
                await self.setup_func()
            except Exception as e:
                logger.error(f"Error in test setup: {e}")
                self.results["errors"].append(f"Setup error: {str(e)}")
                self.results["execution_time"] = time.time() - start_time
                return self.results

        # Run each step
        step_results = {}
        try:
            for i, step in enumerate(self.steps):
                logger.info(f"Running step {i+1}/{len(self.steps)}: {step['name']}")

                try:
                    # Execute the step
                    result = await step["func"](*step["args"], **step["kwargs"])

                    # Record step results
                    step["result"] = result
                    step["success"] = True
                    step_results[step["name"]] = result
                    self.results["steps_completed"] += 1

                except Exception as e:
                    logger.error(f"Error in step '{step['name']}': {e}")
                    step["error"] = str(e)
                    step["success"] = False
                    self.results["errors"].append(
                        f"Step '{step['name']}' error: {str(e)}"
                    )
                    break
        finally:
            # Run assertions even if steps fail
            for assertion in self.assertions:
                try:
                    result = assertion["condition"](step_results)
                    assertion["success"] = result

                    if result:
                        self.results["assertions_passed"] += 1
                    else:
                        self.results["assertions_failed"] += 1
                        self.results["errors"].append(assertion["error_message"])
                except Exception as e:
                    logger.error(f"Error in assertion '{assertion['name']}': {e}")
                    assertion["success"] = False
                    self.results["assertions_failed"] += 1
                    self.results["errors"].append(
                        f"Assertion '{assertion['name']}' error: {str(e)}"
                    )

            # Run teardown if provided
            if self.teardown_func:
                try:
                    await self.teardown_func()
                except Exception as e:
                    logger.error(f"Error in test teardown: {e}")
                    self.results["errors"].append(f"Teardown error: {str(e)}")

            # Calculate final execution time
            self.results["execution_time"] = time.time() - start_time

            # Determine overall success
            self.results["success"] = (
                self.results["steps_completed"] == len(self.steps)
                and self.results["assertions_failed"] == 0
            )

        return self.results


class E2ETestRunner:
    """Runs end-to-end test scenarios.

    This class provides functionality for running test scenarios,
    collecting results, and generating reports.
    """

    def __init__(self):
        """Initialize the test runner."""
        self.scenarios = {}
        self.results = {}

    def register_scenario(
        self, scenario: Union[E2ETestScenario, AsyncE2ETestScenario]
    ) -> None:
        """Register a test scenario.

        Args:
            scenario: The test scenario to register
        """
        self.scenarios[scenario.name] = scenario

    def run_scenario(
        self, scenario_name: str, fail_fast: bool = False
    ) -> Dict[str, Any]:
        """Run a specific test scenario.

        Args:
            scenario_name: The name of the scenario to run
            fail_fast: If True, stop on first failure

        Returns:
            Dictionary with test results

        Raises:
            ValueError: If the scenario is not found
        """
        if scenario_name not in self.scenarios:
            raise ValueError(f"Test scenario '{scenario_name}' not found")

        scenario = self.scenarios[scenario_name]

        logger.info(f"Running test scenario: {scenario_name}")

        # Run the scenario
        if isinstance(scenario, AsyncE2ETestScenario):
            # Create event loop if not running in one
            try:
                loop = asyncio.get_event_loop()
            except RuntimeError:
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)

            # Run the async scenario
            results = loop.run_until_complete(scenario.run())
        else:
            # Run the sync scenario
            results = scenario.run()

        # Store the results
        self.results[scenario_name] = results

        # Log the results
        if results["success"]:
            logger.info(f"Scenario '{scenario_name}' completed successfully")
        else:
            logger.error(f"Scenario '{scenario_name}' failed: {results['errors']}")

            # Fail fast if requested
            if fail_fast:
                raise RuntimeError(
                    f"Test scenario '{scenario_name}' failed: {results['errors']}"
                )

        return results

    def run_all_scenarios(self, fail_fast: bool = False) -> Dict[str, Dict[str, Any]]:
        """Run all registered test scenarios.

        Args:
            fail_fast: If True, stop on first failure

        Returns:
            Dictionary with test results for all scenarios
        """
        self.results = {}

        for scenario_name in self.scenarios:
            try:
                self.run_scenario(scenario_name, fail_fast=fail_fast)
            except RuntimeError as e:
                if fail_fast:
                    break

        return self.results

    def generate_report(
        self, output_path: Optional[str] = None, format: str = "markdown"
    ) -> str:
        """Generate a report of test results.

        Args:
            output_path: Optional path to write the report to
            format: Report format ('markdown' or 'json')

        Returns:
            The generated report
        """
        if format == "json":
            report = json.dumps(self.results, indent=2)
        else:
            # Generate markdown report
            lines = [
                "# End-to-End Test Report",
                "",
                f"Generated: {datetime.now().isoformat()}",
                "",
            ]

            # Summary table
            lines.append("## Summary")
            lines.append("")
            lines.append("| Scenario | Status | Steps | Assertions | Time (s) |")
            lines.append("|----------|--------|-------|------------|----------|")

            total_scenarios = len(self.results)
            successful_scenarios = 0
            total_steps = 0
            successful_steps = 0
            total_assertions = 0
            successful_assertions = 0
            total_time = 0

            for name, result in self.results.items():
                status = "✅ Pass" if result["success"] else "❌ Fail"
                assertions = f"{result['assertions_passed']}/{result['assertions_passed'] + result['assertions_failed']}"
                time_s = f"{result['execution_time']:.2f}"

                lines.append(
                    f"| {name} | {status} | {result['steps_completed']}/{len(self.scenarios[name].steps)} | {assertions} | {time_s} |"
                )

                if result["success"]:
                    successful_scenarios += 1

                total_steps += len(self.scenarios[name].steps)
                successful_steps += result["steps_completed"]
                total_assertions += (
                    result["assertions_passed"] + result["assertions_failed"]
                )
                successful_assertions += result["assertions_passed"]
                total_time += result["execution_time"]

            # Overall summary
            lines.append("")
            lines.append("## Overall Results")
            lines.append("")
            lines.append(
                f"- Scenarios: {successful_scenarios}/{total_scenarios} passed"
            )
            lines.append(f"- Steps: {successful_steps}/{total_steps} completed")
            lines.append(
                f"- Assertions: {successful_assertions}/{total_assertions} passed"
            )
            lines.append(f"- Total execution time: {total_time:.2f}s")
            lines.append("")

            # Detailed results for each scenario
            lines.append("## Detailed Results")
            lines.append("")

            for name, result in self.results.items():
                scenario = self.scenarios[name]

                lines.append(f"### {name}")
                lines.append("")
                lines.append(f"**Description**: {scenario.description}")
                lines.append(f"**Components**: {', '.join(scenario.components)}")
                lines.append(
                    f"**Status**: {'Passed' if result['success'] else 'Failed'}"
                )
                lines.append(f"**Time**: {result['execution_time']:.2f}s")
                lines.append("")

                # Steps
                lines.append("#### Steps")
                lines.append("")
                for i, step in enumerate(scenario.steps):
                    status = "✅" if step.get("success", False) else "❌"
                    lines.append(f"{i+1}. {status} {step['name']}")
                    if step.get("error"):
                        lines.append(f"   - Error: {step['error']}")
                lines.append("")

                # Assertions
                lines.append("#### Assertions")
                lines.append("")
                for i, assertion in enumerate(scenario.assertions):
                    status = "✅" if assertion.get("success", False) else "❌"
                    lines.append(f"{i+1}. {status} {assertion['name']}")
                    if not assertion.get("success", False):
                        lines.append(f"   - {assertion['error_message']}")
                lines.append("")

                # Errors
                if result["errors"]:
                    lines.append("#### Errors")
                    lines.append("")
                    for error in result["errors"]:
                        lines.append(f"- {error}")
                    lines.append("")

            report = "\n".join(lines)

        # Write to file if output path is provided
        if output_path:
            with open(output_path, "w") as f:
                f.write(report)

        return report


class PredefinedScenarios:
    """Provides predefined end-to-end test scenarios.

    This class provides factory methods for creating commonly used
    test scenarios that validate key system functionality.
    """

    @staticmethod
    def create_vulnerability_research_scenario() -> AsyncE2ETestScenario:
        """Create a scenario for testing the vulnerability research workflow.

        Returns:
            AsyncE2ETestScenario for vulnerability research workflow
        """
        scenario = AsyncE2ETestScenario(
            name="vulnerability_research",
            description="Test the complete vulnerability research workflow",
            components=["code_analysis", "workflows", "db", "agents"],
        )

        # Define a test repository setup
        async def setup():
            # Here you would create a test repository in the database
            # This is just a placeholder - in practice you would create real test data
            pass

        scenario.setup_func = setup

        # Define a step to run the vulnerability research workflow
        async def run_workflow(repository_id: str = "test-repo"):
            workflow = VulnerabilityResearchWorkflow(
                repository_id=repository_id,
                focus_areas=["Injection", "Authentication"],
                enable_persistence=False,
            )

            await workflow.setup()

            results = []
            async for result in workflow.run():
                results.append(result)

            return results

        # Add the step to the scenario
        scenario.add_step(
            name="Run vulnerability research workflow",
            func=run_workflow,
            args=["test-repo"],
        )

        # Add assertions to validate the results
        scenario.add_assertion(
            name="Workflow produces results",
            condition=lambda results: "Run vulnerability research workflow" in results
            and len(results["Run vulnerability research workflow"]) > 0,
            error_message="Vulnerability research workflow did not produce any results",
        )

        return scenario

    @staticmethod
    def create_code_analysis_scenario() -> E2ETestScenario:
        """Create a scenario for testing the code analysis functionality.

        Returns:
            E2ETestScenario for code analysis
        """
        scenario = E2ETestScenario(
            name="code_analysis",
            description="Test code analysis functionality",
            components=["code_analysis"],
        )

        # Define steps to test code analysis
        def analyze_file(file_path: str):
            # CodeAnalyzer removed
            logger.warning("CodeAnalyzer has been removed from the codebase")

            # For testing, use a simple vulnerability
            code = """
            def unsafe_query(user_input):
                query = "SELECT * FROM users WHERE name = '" + user_input + "'"
                return execute_query(query)
            """

            result = analyzer.analyze_code(code, "python")
            return result

        # Add steps to the scenario
        scenario.add_step(
            name="Analyze vulnerable code", func=analyze_file, args=["test.py"]
        )

        # Add assertions
        scenario.add_assertion(
            name="Analysis finds SQL injection",
            condition=lambda results: "Analyze vulnerable code" in results
            and any(
                "SQL injection" in str(finding.get("vulnerability_type", "")).lower()
                for finding in results["Analyze vulnerable code"]
            ),
            error_message="Code analysis did not detect SQL injection vulnerability",
        )

        return scenario


# Singleton instance
_test_runner = None


def get_test_runner() -> E2ETestRunner:
    """Get the singleton test runner instance.

    Returns:
        The E2ETestRunner instance
    """
    global _test_runner
    if _test_runner is None:
        _test_runner = E2ETestRunner()
    return _test_runner
