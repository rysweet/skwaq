# Prompt Backlog

These are prompts that we are writing in advance for future use. They are not currently in use.

Commit everything, update the status, and then we will move to the next step in the ImplementationPlan.md.  

Run the full test suite and fix any remaining failures. For any tests that are failing, do not move on, instead we stop, think carefully about the code being tested, consider carefully the necessary setup conditions, and then carefully construct the test to ensure it is validating the functionality of the code. Then we either fix the code being tested or fix the test. Do not create shared fixtures that may not work when tests are run together.                        

Please ensure that all the new code has thorough unit tests and that all the existing tests (unit, integration, milestone) pass. The tests need to pass when they are run in isolation as well as when they are run in the full test suite.

How many steps remain in the ImplementationPlan.md?

Please provide the current status of the ImplementationPlan.md and the number of steps remaining.

We are going to add a new feature to the codebase. The feature is described in the GraphicalUserInterface.md file. Ask any questions necessary to clarify the requirements and then update the file with the answers to the questions.  Then we need to update the ImplemenationPlan.md to include the new feature.  The new feature is a graphical user interface (GUI) for the Vulnerability Assessment Copilot. The GUI will provide a user-friendly way to interact with the copilot, allowing users to easily start investigations, visualize graphs, view results, and manage their vulnerability assessments. Once we have the new feature in the ImplementationPlan.md, we will move on to the next step in the plan.

We need to review the entire project for unused code and remove it. After each removal run the test suite to ensure that everything is stil working. 

We need to review every code file for comments that are 
necessary or no longer relevant and remove them. We also need to ensure that all files have throough and accurate docstrings.  Where complicated code is present, we need to think carefully ensure that there are comments that explain the code in concise but accurate terms.  

We are going to add a new feature to the codebase. We want to be able to expose the neo4j graph database as an MCP service. 

