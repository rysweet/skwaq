Please contninue to implement the software described in the "/Specifications/Vulnerability Assessment Copilot.md" document by following the plan in the "/Specifications/ImplementationPlan.md" document. 
The plan should be followed step by step, and the code should be implemented in the order specified in the plan.
Keep the plan status up to date by updating a file called status.md in the root of the repository. You can check this file to find out the most recent status of the plan.

You should also use the following resources to help you implement the software:
# - [Vulnerability Assessment Copilot.md](Vulnerability%20Assessment%20Copilot.md)
# - [ImplementationPlan.md](ImplementationPlan.md)
# - [AutoGen Core Documentation](https://microsoft.github.io/autogen/stable/user-guide/core-user-guide/index.html)
# - [AutoGen API Documentation](https://microsoft.github.io/autogen/stable/api/index.html)
# - [AutoGen Examples](https://microsoft.github.io/autogen/stable/examples/index.html)
# - [Neo4J Documentation](https://neo4j.com/docs/)
# - [Rich CLI Documentation](https://rich.readthedocs.io/en/stable/)
# - [Neo4J Blog on Semantic indexes](https://neo4j.com/blog/developer/knowledge-graph-structured-semantic-search/)

You should not be using the autogen package, use autogen-core. 
Do not use autogen-agentchat, only autogen-core. 
Any modules that are using pyautogen should be corrected/rewritten to use autogen-core. 
For the implementation, you will need to use my az credentials to access the Azure OpenAI API using Tenant: Microsoft
Subscription: adapt-appsci1 (be51a72b-4d76-4627-9a17-7dd26245da7b). You will need to use my Github credentials using the gh cli. You will need to do a commit after each step of the implementation. If a step of the implementation is not clear, please ask me for clarification.
If a step of the implemenation fails, try again by attempting to correct the error. If you are unable to correct the error, updat the status.md and please ask me for help.
