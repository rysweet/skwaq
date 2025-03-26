Please continue to implement the software described in the "/Specifications/Vulnerability Assessment Copilot.md" document by following the plan in the "/Specifications/ImplementationPlan.md" document. 
The plan should be followed step by step, and the code should be implemented in the order specified in the plan.
Keep the plan status up to date by updating a file called status.md in the root of the repository. You can check this file to find out the most recent status of the plan.

## Code Design Guidelines

Please follow these guidelines for code design and implementation:

### Modularity
- Maintain clear separation between different concerns (e.g., knowledge ingestion, code ingestion, analysis)
- Create dedicated modules for distinct functionality
- Use composition over inheritance where appropriate
- Design for extensibility with interfaces and dependency injection
- Follow the module structure established in the codebase (shared, code_analysis, etc.)

### Code Reuse
- Extract shared code into dedicated utility modules
- Avoid duplicating functionality across different modules
- Prefer composition and delegation over inheritance for code reuse
- Create reusable abstractions for common patterns
- Utilize the shared module for cross-cutting concerns

### Design Patterns
- Use the Strategy pattern for varying behaviors (as in code_analysis.strategies)
- Apply the Factory pattern for object creation where appropriate
- Implement interfaces (abstract base classes) for polymorphic behavior
- Use composition to combine behaviors flexibly
- Follow established patterns in the codebase for consistency

### Function/Method Design
- Keep functions and methods short (generally under 50 lines)
- Each function should have a single responsibility
- Extract complex logic into smaller, well-named helper functions
- Limit function parameters (generally 5 or fewer)
- Use descriptive naming that indicates purpose

### Error Handling
- Handle errors explicitly at appropriate levels
- Use specific exception types rather than generic exceptions
- Document expected exceptions in function docstrings
- Log errors with appropriate context before re-raising

### Testing
- Write tests for each component
- Write unit tests for individual functions and methods
- Write integration tests for module interactions
- Ensure public interfaces are well-tested
- Use dependency injection to make components testable
- Maintain test coverage during refactoring
- Follow the testing patterns in tests/milestones

### Code Organization
- Group related functionality in dedicated modules and packages
- Use a consistent file structure within modules
- Place interfaces in base.py files at the package root
- Follow the established project structure:
  - skwaq.shared: Common utilities and data models
  - skwaq.code_analysis: Code analysis functionality
  - skwaq.ingestion: Data ingestion pipelines
  - skwaq.utils: General utility functions
  - skwaq.db: Database access and schema

## Resources

You should also use the following resources to help you implement the software:
# - [Vulnerability Assessment Copilot.md](../Specifications/VulnerabilityAssessmentCopilot.md)
# - [ImplementationPlan.md](../Specifications/ImplementationPlan.md)
# - [AutoGen Core Documentation](https://microsoft.github.io/autogen/stable/user-guide/core-user-guide/index.html)
# - [AutoGen API Documentation](https://microsoft.github.io/autogen/stable/api/index.html)
# - [AutoGen Examples](https://microsoft.github.io/autogen/stable/examples/index.html)
# - [Neo4J Documentation](https://neo4j.com/docs/)
# - [Rich CLI Documentation](https://rich.readthedocs.io/en/stable/)
# - [Neo4J Blog on Semantic indexes](https://neo4j.com/blog/developer/knowledge-graph-structured-semantic-search/)

## Implementation Notes

You should not be using the autogen package, use autogen-core. 
Do not use autogen-agentchat, only autogen-core. 
Any modules that are using pyautogen should be corrected/rewritten to use autogen-core. 
For the implementation, you will need to use my az credentials to access the Azure OpenAI API using Tenant: Microsoft
Subscription: adapt-appsci1 (be51a72b-4d76-4627-9a17-7dd26245da7b). You will need to use my Github credentials using the gh cli. You will need to do a commit after each step of the implementation. If a step of the implementation is not clear, please ask me for clarification.
Do not move on to the next milestone until the current milestone is complete with all tests for all milestones passing.
Do not move on to the next milestone while there are problems in the workspace. 
If a step of the implementation fails, try again by attempting to correct the error. If you are unable to correct the error, update the status.md and please ask me for help.
