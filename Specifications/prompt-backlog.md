# Prompt Backlog

These are prompts that we are writing in advance for future use. They are not currently in use.

Commit everything, update the status, and then we will move to the next step in the ImplementationPlan.md.  

Run the full test suite and fix any remaining failures. For any tests that are failing, do not move on, instead we stop, think carefully about the code being tested, consider carefully the necessary setup conditions, and then carefully construct the test to ensure it is validating the functionality of the code. Then we either fix the code being tested or fix the test. Do not create shared fixtures that may not work when tests are run together.                        

Please ensure that all the new code has thorough unit tests and that all the existing tests (unit, integration, milestone) pass. The tests need to pass when they are run in isolation as well as when they are run in the full test suite.

How many steps remain in the ImplementationPlan.md?

Please provide the current status of the ImplementationPlan.md and the number of steps remaining.

Let's create a comprehensive demonstration of all the CLI features implemented. The demonstration should include all the commands available in the CLI, including their options and expected outputs. It should be structured in a way that allows users to easily understand how to use each command and what the expected results are. The demonstration can be considered a tutorial for users to learn how to use the CLI effectively. after running the demonstration, create a doc file that includes the demonstration and the expected outputs. 

We are going to add a new feature to the codebase. The feature is described in the GraphicalUserInterface.md file. Ask any questions necessary to clarify the requirements and then update the file with the answers to the questions.  Then we need to update the ImplemenationPlan.md to include the new feature.  The new feature is a graphical user interface (GUI) for the Vulnerability Assessment Copilot. The GUI will provide a user-friendly way to interact with the copilot, allowing users to easily start investigations, visualize graphs, view results, and manage their vulnerability assessments. Once we have the new feature in the ImplementationPlan.md, we will move on to the next step in the plan.

We need to review the entire project for unused code and remove it. After each removal run the test suite to ensure that everything is stil working. 

We need to review every code file for comments that are 
necessary or no longer relevant and remove them. We also need to ensure that all files have throough and accurate docstrings.  Where complicated code is present, we need to think carefully ensure that there are comments that explain the code in concise but accurate terms.  

We are going to add a new feature to the codebase. We want to be able to expose the neo4j graph database as an MCP service. 

Before you are finished make sure that you have added unit tests for all new functionality. Make sure you remove any deprecated functionality. If new code is replacing previous placeholders remove the old placeholders. document all new functionality. When you are finished, update the end to end CLI demo / tests in order to make sure that all new functionality is included. Ensure that all dependencies get installed. 

We are going to add a new feature: as a user of the CLI, I want to be able to export a visualization of the Investigation graph in a format that can be easily shared with others, so that I can communicate my findings effectively.

We want to add a command to the CLI that will start the GUI using the existing scripts. Please updat the help, documentation, tests, and examples to include this new command. 

We want to add a demo mode to the CLI which walks through the CLI commands and demonstrates their using with the eShop Repository (https://github.com/dotnet/eShop). Update the documentation to include the demo mode and provide examples of how to use it. The demo mode should include the following features:
- A guided tour of the CLI commands
- Examples of how to use each command
- Runs the commands against the eShop repository

We want to analyze files across the project to see which are too large/too big for your token window These are good candidates for refactoring into smaller modules. I'd like to be strict about separation of concerns and single responsibility principle. Analyze the project and identify files that are too large or have too many functions. Think careully about how to refactor the code to make it more modular and easier to understand and test. then refactor the code accordingly. Make sure that you then also refactor the related tests and ensure that all tests are still passing. 
