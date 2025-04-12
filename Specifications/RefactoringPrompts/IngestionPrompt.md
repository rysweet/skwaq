We are working on improving a messy codebase that was largely written by AI. We have thrown out the old ingestion module. I have written a new ingestion module specification at Specifications/Ingestion.md. You are to focus only on the ingestion module and any tests you need to write for it. 

You can depend upon the utils module, the core module, and the db module as well as the packages mentioned in the specification. We are trying to improve the codebase so please prioritize known best practices and instructions you have been given over things that you find elsewhere in the codebase. 

Try to limit your work to the ingestion module and its dependencies. Read Specifications/Ingestion.md, think carefully about how to implement it, write a careful example and documentation, then write tests that will exercise the module's API, then write the module itself and any remaining tests necessary. 

Once you have written all the code, go back and review the documentation and make any updates that are needed. Continue to iterate until all the ingestion tests are passing. Do not worry about the other tests in the project.