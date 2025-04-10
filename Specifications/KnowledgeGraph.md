# Specification for the Knowledge Graph Modules of the Vulnerability Asessment Copilot

# Context and Purpose

The Knowledge Graph component provides a graph database and semantic index representing a collection of vulnerability discovery expertise. It also includes extracts from the repository of teh Common Weakness Enumeration (CWE) and the Common Vulnerabilities and Exposures (CVE) database. The Knowledge Graph is used to store and retrieve information about vulnerabilities, their relationships, and their context, as well as best practices for searching for vulnerabilities in code. The Knowledge Graph is used for LLM retrieval augmentation for the agents that are part of the Vulnerability Assessment Copilot plying the role of vulnerability researchers. Note that the Knowledge Graph is not related to the codebase and investigation graphs. 

## Inputs

The Knowledge Graph component ingests the documents and data collected in the /data/knowledge/ directory when the initialization operation is invoked. Users can also add new documents to the Knowledge Graph from the CLI, the API, or uploading them from the GUI. 

## Outcomes

- **Graph Representation**: A graph in the neo4j database that turns the plaintext documents into a graph representation including nodes for each section, concepts, edges between related concepts, edges to represent sequential relations between passages, summaries of each document, with edges between the summaries and the content, as well as a copy of the full documents, and the semantic index of that content. There will also be a related graph of all of the ingested CWE or CVE data.  Each document ingested will have a unique document ID with a property linking to the ingestion source, if avaiable.  When a Concept is extracted that concept can be referenced by edges from multiple passages in multiple documents. As new documents are ingested if they have similar concepts they should be linked. Each derived node will have edges indicating the document they were derived from. The graph representation shall be stored in the neo4j database and shall be used to provide content for retrieval augmentation for LLM agents that play the role of vulnerability researchers. Vulnerability Researchers may also add entries to the Knowledge Graph after the original document ingestion process.
- **Document Ingestion Status**: A status message indicating progress and evantually whether the document ingestion was successful or not. This should include any errors that occurred during the Knowledge Graph process.

## Key Operations or Methods

- **Reset Knowledge Graph**: The Knowledge Graph module shall have a reset method that clears the neo4j This is useful for testing and development purposes.
- **Ingest Document**: Ingests a single document into the Knowledge Graph. This method shall take a file path or a Git URI as input and shall return a document ingestion status object that can be used to track the ingestion progress. The document ingestion status object shall include a unique identifier for the document, the status of the ingestion process, and any errors that occurred during the ingestion process. The document ingestion status object shall also include a timestamp indicating when the ingestion process started and when it finished.
- **Ingest Directory**: Ingests all documents in a directory into the Knowledge Graph. This method shall take a directory path as input and shall return a document ingestion status object that can be used to track the ingestion progress. The document ingestion status object shall include a unique identifier for each document, the status of the ingestion process, and any errors that occurred during the ingestion process. The document ingestion status object shall also include a timestamp indicating when the ingestion process started and when it finished.
- **Ingest CWE**: 
  1. Fetches the latest CWE data and schema from these URLS: 
CWE_XML_URL = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"
CWE_XSD_URL = "https://cwe.mitre.org/data/xsd/cwe_schema_latest.xsd"
  2. Unzips the zip file and uses the schema to parse the resulting xml file into a graph representation in the neo4j database. The CWE data is used to provide content for retrieval augmentation for LLM agents that play the role of vulnerability researchers.
  3. Links the CWE data to the documents ingested in the Knowledge Graph. The CWE data is linked to the documents by creating edges between the CWE nodes and the document nodes. The edges shall be labeled with the type of relationship between the CWE and the document. For example, if a document describes a vulnerability that is related to a specific CWE, an edge shall be created between the CWE node and the document node with a label indicating that relationship. If a Concept node describes an issue that is represented by a CWE, an edge shall be created between the Concept node and the CWE node with a label indicating that relationship. The edges shall also include properties that describe the relationship between the nodes, such as the type of relationship, the strength of the relationship, and any other relevant information.
  4. Nodes created in this way should have metadata properties linking back

## Process

1. 
2.

## Dependencies

- **Neo4j**: The Knowledge Graph module shall use the neo4j database to ....  The neo4j connection shall be managed by the skwaq db module. The Knowledge Graph module shall use the skwaq db module to connect to the neo4j database and store the graph representation of the codebase.
- **Azure OpenAI**: The Knowledge Graph module shall use the Azure OpenAI model client to ...

## Documentation

- The Knowledge Graph module shall be documented in the codebase using docstrings and comments.
- The usage of the Knowledge Graph module shall also be documented in the docs folder of the codebase.
- The documentation shall include examples of how to use the Knowledge Graph module, including how to pass in a filesystem path or a Git URI, how to configure the LLM, and how to use the Knowledge Graph ID to track the Knowledge Graph process.

## Acceptance Criteria

## Code organization

consider having modules for:
 

## Testing
Outline:
- Unit testing requirements
- Integration testing approach
- Test data needs
- Edge cases to be tested
- there shall be unit tests for each of the functions in the module. Unit tests may use mocks for the neo4j database and the LLM.
- there shall be aspects of the tests to validate each of the acceptance criteria.
- there shall be integration tests for the module that test the entire process from start to finish.
  - the integration tests shall use 
  - the integration tests shall not use a mock neo4j database to test the Knowledge Graph process.
  - the integration tests shall not use a mock LLM to test the Knowledge Graph process.

### API Design and Interface
Consider adding details about:
- Method signatures or function interfaces
- Expected input/output data formats and structures
- Error handling and response codes
- Integration points with other components

## Example of using the Knowledge Graph Module

```python

...

```

### Performance Requirements
Consider specifying:
- Expected throughput or performance targets
- Memory constraints or considerations
- Scalability requirements
- Concurrency handling

### Security Considerations
Include guidance on:
- Authentication/authorization requirements
- Data protection needs
- Input validation expectations
- Secure coding practices specific to this component

### Implementation Guidelines
Provide
