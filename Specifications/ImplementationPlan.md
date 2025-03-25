# Skwaq - Vulnerability Assessment Copilot - Implementation Plan

## Overview

This document outlines a comprehensive implementation plan for the Vulnerability Assessment Copilot (codenamed "skwaq"), a multiagent AI system designed to assist vulnerability researchers in analyzing codebases to discover potential security vulnerabilities. The plan breaks down the system into manageable modules, provides implementation steps, and addresses technical requirements for each component.

### Project Name: Skwaq

The name "skwaq" is derived from the Lushootseed language of the Pacific Northwest, meaning "Raven." In many Pacific Northwest Indigenous traditions, Raven is a trickster and creator figure known for using wit and cleverness to uncover hidden things and reveal secrets. This name was chosen to reflect the project's purpose—intelligently discovering concealed vulnerabilities within software codebases, much as the mythological Raven brings hidden truths to light.

### Implementation Summary

The implementation follows a phased, milestone-driven approach spanning six major phases: Foundation, Knowledge Management, Code Analysis, Agent System, Workflow and UI, and Integration and Finalization. Each phase contains specific milestones with clear deliverables, validation criteria, and testing requirements. The system will be built using a modular architecture centered around Neo4J graph databases for knowledge and code representation, Azure OpenAI models for inference, and AutoGen Core for the multi-agent framework. The plan emphasizes comprehensive testing at each stage, including local CI pipeline execution, and incorporates documentation standards requiring 90% API documentation coverage with Google-style docstrings. Development will progress through incremental milestones, each requiring validation before proceeding, with GitHub Actions workflows automating testing, Docker builds, and documentation validation. This methodical approach ensures a robust, maintainable system that can assist vulnerability researchers in discovering security issues through various interactive workflows.

## System Architecture

The system architecture follows a modular design with the following high-level components:

```
Vulnerability Assessment Copilot
├── CLI Interface (Rich)
├── Neo4J Integration
│   ├── Background Knowledge Database
│   └── Code Ingestion Database
├── Agent System (AutoGen Core)
│   ├── Orchestrator Agent
│   ├── Background Knowledge Agents
│   ├── Code Ingestion Agents
│   ├── Retrieval Agents
│   ├── Workflow Agents
│   └── Subagents/Critic Agents
├── Prompt Management (Prompty.ai)
└── Event Handling System (Protobuf)
```

### Extensibility Architecture

The system is designed for extensibility through three primary mechanisms:

1. **Tool Integration Framework**: Allows adding new security tools beyond CodeQL
2. **Event-Driven Agent Architecture**: Enables additional agent integration through event subscription
3. **Knowledge Source Framework**: Supports incorporating new background knowledge sources

```
Extensibility Architecture
├── Tool Integration Framework
│   ├── Tool Registry
│   ├── Tool Execution Environment
│   └── Tool Result Processors
├── Event-Driven Agent Architecture
│   ├── Event Type Registry
│   ├── Event Subscription API
│   └── Agent Registration System
└── Knowledge Source Framework
    ├── Knowledge Source Registry
    ├── Source-Specific Ingestion Pipelines
    └── Schema Integration Templates
```

### Parallel Processing Architecture

The system employs parallel processing to maximize ingestion and analysis efficiency:

```
Parallel Processing Architecture
├── Task Scheduling System
│   ├── Dependency Graph Generator
│   ├── Parallel Task Executor
│   └── Resource Manager
├── Parallel Ingestion Pipelines
│   ├── Concurrent Repository Processing
│   ├── Parallel Document Analysis
│   └── Distributed AST Generation
└── Progress Tracking & Synchronization
    ├── Task Status Management
    ├── Result Aggregation
    └── Error Handling & Recovery
```

### Workflow Integration

The system integrates with vulnerability management workflows through GitHub:

```
Workflow Integration
├── Report Generation System
│   ├── Markdown Report Generator
│   └── Evidence Collection
├── GitHub Issues Integration
│   ├── Issue Template Generator
│   ├── Bash Script Generator
│   └── Issue Creation API Client
└── Investigation Persistence
    ├── Session Management
    ├── Investigation Export/Import
    └── Investigation Cleanup
```

## Development Environment Requirements

The implementation is designed to support cross-platform development across Windows, macOS, and Linux operating systems. The following considerations ensure consistent behavior across platforms:

1. **Cross-Platform Compatibility**:
   - All scripts will be provided in both shell (.sh) and PowerShell (.ps1) formats
   - Path handling will use platform-agnostic approaches (e.g., Path from pathlib)
   - Environment variables will be managed consistently across platforms

2. **Hardware Requirements**:
   - **Minimum Requirements**: Standard developer hardware (8GB RAM, 4 cores)
   - **Neo4j Configuration**: Optimized for minimal resource usage without special hardware
   - **No GPU Dependency**: All AI operations will function without GPU acceleration
   - **Storage**: 10GB for application code and dependencies, plus space for repositories

3. **Containerization for Consistency**:
   - Docker environments will be used to ensure identical behavior across platforms
   - Compose files will be designed to work on all major operating systems
   - Resource limits in containers will be set for standard hardware

### Setting Up the Development Environment

Follow these steps to set up your development environment:

1. **Clone the repository**:
   ```bash
   git clone https://github.com/rysweet/skwaq
   cd skwaq
   ```

2. **Install Python Dependencies Management Tools**:
   ```bash
   # Install uv
   pip install uv
   
   # Install poetry
   curl -sSL https://install.python-poetry.org | python3 -
   ```

3. **Create Virtual Environment and Install Dependencies**:
   ```bash
   # Using uv to create virtual environment
   uv venv

   # Activate the virtual environment
   source .venv/bin/activate  # On Unix/macOS
   # OR
   .\.venv\Scripts\activate   # On Windows
   
   # Install dependencies using poetry
   poetry install
   ```

4. **Install Development Dependencies**:
   ```bash
   poetry install --with dev
   ```

### Installing Neo4j

The system requires Neo4j for graph database functionality, configured to run with minimal hardware requirements:

1. **Using Docker (Recommended)**:
   ```bash
   # Create necessary directories
   mkdir -p neo4j/data neo4j/logs neo4j/import neo4j/plugins
   
   # Start Neo4j container with latest version
   docker pull neo4j:latest
   docker-compose up -d neo4j
   ```

2. **Manual Installation (Alternative)**:
   - Download Neo4j Community Edition (latest version) from [Neo4j Download Center](https://neo4j.com/download-center/)
   - Follow the installation instructions for your specific operating system (Windows, macOS, or Linux)
   - Configure Neo4j to use the appropriate ports (default: 7474 for HTTP, 7687 for Bolt)

3. **Neo4j Configuration for Standard Hardware**:
   - Set heap size to modest defaults (1GB initial, 2GB max)
   - Enable APOC and Graph Data Science libraries with minimal memory settings
   - Configure vector index with lower dimensionality options when possible
   - Enable disk-based page cache to reduce memory pressure

### Installing External Tools

The system integrates with several external tools:

1. **Blarify** (for code graph generation):
   ```bash
   pip install blarify
   ```

2. **Prompty.ai** (for prompt management):
   ```bash
   pip install prompty
   ```

3. **Protocol Buffers**:
   - Install protobuf compiler from [Protocol Buffers Releases](https://github.com/protocolbuffers/protobuf/releases)
   - Install Python protobuf package:
     ```bash
     pip install protobuf grpcio grpcio-tools
     ```

### Azure OpenAI Setup

To use Azure OpenAI services, automate the resource provisioning using Bicep and Azure CLI:

1. **Azure Authentication and Subscription Setup**:
   - Create an authentication script (`scripts/infrastructure/azure-auth.sh`):
   ```bash
   #!/bin/bash
   set -e

   echo "🔐 Setting up Azure authentication and subscription for Skwaq..."

   # Check if Azure CLI is installed
   if ! command -v az &> /dev/null; then
     echo "❌ Azure CLI is not installed. Please install it from https://docs.microsoft.com/en-us/cli/azure/install-azure-cli"
     exit 1
   fi

   # Authenticate with Azure
   echo "Authenticating with Azure..."
   az login

   # List available subscriptions
   echo "Available subscriptions:"
   az account list --output table

   # Prompt user to select subscription or use default
   read -p "Enter subscription ID to use (leave blank for default): " SUBSCRIPTION_ID
   
   if [ -z "$SUBSCRIPTION_ID" ]; then
     SUBSCRIPTION_ID=$(az account show --query id -o tsv)
     echo "Using default subscription: $SUBSCRIPTION_ID"
   else
     # Set the subscription
     az account set --subscription "$SUBSCRIPTION_ID"
     echo "Subscription set to: $SUBSCRIPTION_ID"
   fi

   # Verify OpenAI resource provider is registered
   PROVIDER_STATE=$(az provider show --namespace Microsoft.CognitiveServices --query "registrationState" -o tsv)
   
   if [ "$PROVIDER_STATE" != "Registered" ]; then
     echo "Registering Microsoft.CognitiveServices resource provider..."
     az provider register --namespace Microsoft.CognitiveServices
     echo "Waiting for registration to complete (this may take a few minutes)..."
     
     # Wait for registration to complete
     while [ "$(az provider show --namespace Microsoft.CognitiveServices --query "registrationState" -o tsv)" != "Registered" ]; do
       echo "Still registering... waiting 10 seconds"
       sleep 10
     done
     
     echo "✅ Microsoft.CognitiveServices resource provider registered successfully"
   else
     echo "✅ Microsoft.CognitiveServices resource provider already registered"
   fi

   # Verify OpenAI model availability in regions
   echo "Checking OpenAI model availability in regions..."
   AVAILABLE_REGIONS=$(az cognitiveservices account list-kinds -o json | \
                      jq -r '.[] | select(. == "OpenAI") | "OpenAI is available"')
   
   if [ -z "$AVAILABLE_REGIONS" ]; then
     echo "⚠️  Warning: OpenAI service may not be available in your subscription."
     echo "Please verify that your subscription has access to Azure OpenAI and that you have appropriate permissions."
     echo "Visit https://azure.microsoft.com/en-us/products/cognitive-services/openai-service to request access if needed."
     read -p "Do you want to continue anyway? (y/n): " CONTINUE
     if [ "$CONTINUE" != "y" ]; then
       echo "Exiting setup."
       exit 1
     fi
   else
     echo "✅ OpenAI service is available in your subscription"
   fi

   # Check for required permissions
   echo "Checking for required permissions..."
   PERMISSIONS=$(az role assignment list --assignee "$(az account show --query user.name -o tsv)" --query "[?roleDefinitionName=='Contributor' || roleDefinitionName=='Owner'].roleDefinitionName" -o tsv)
   
   if [ -z "$PERMISSIONS" ]; then
     echo "⚠️  Warning: You may not have Contributor or Owner permissions required to create resources."
     echo "The following steps may fail without proper permissions."
     read -p "Do you want to continue anyway? (y/n): " CONTINUE
     if [ "$CONTINUE" != "y" ]; then
       echo "Exiting setup."
       exit 1
     fi
   else
     echo "✅ You have sufficient permissions to create resources"
   fi

   # Check for existing deployments of required models
   echo "Checking for existing deployments of required models (o1, o3, gpt4o)..."
   
   # Store authentication info for later scripts
   mkdir -p config
   cat > config/azure_auth.json << EOF
   {
     "subscription_id": "$SUBSCRIPTION_ID",
     "tenant_id": "$(az account show --query tenantId -o tsv)"
   }
   EOF

   echo "✅ Azure authentication and subscription setup completed successfully!"
   echo "Subscription details saved to config/azure_auth.json"
   ```

2. **Make the authentication script executable**:
   ```bash
   chmod +x scripts/infrastructure/azure-auth.sh
   ```

3. **Update the deployment script to use authentication data**:
   - Modify the Azure OpenAI deployment script (`scripts/infrastructure/deploy-openai.sh`):
   ```bash
   #!/bin/bash
   set -e

   # Source authentication data
   if [ -f "config/azure_auth.json" ]; then
     echo "Loading Azure authentication data..."
     SUBSCRIPTION_ID=$(jq -r '.subscription_id' config/azure_auth.json)
     TENANT_ID=$(jq -r '.tenant_id' config/azure_auth.json)
     
     # Verify we're using the correct subscription
     CURRENT_SUB=$(az account show --query id -o tsv)
     if [ "$CURRENT_SUB" != "$SUBSCRIPTION_ID" ]; then
       echo "Switching to subscription: $SUBSCRIPTION_ID"
       az account set --subscription "$SUBSCRIPTION_ID"
     fi
   else
     echo "⚠️ No authentication data found. Running authentication setup first..."
     ./scripts/infrastructure/azure-auth.sh
     
     # Reload authentication data
     SUBSCRIPTION_ID=$(jq -r '.subscription_id' config/azure_auth.json)
     TENANT_ID=$(jq -r '.tenant_id' config/azure_auth.json)
   fi

   # Variables
   RESOURCE_GROUP="skwaq-rg"
   LOCATION="eastus"  # Choose a region where Azure OpenAI is available
   
   # Verify selected region supports the required models
   echo "Verifying $LOCATION supports required OpenAI models..."
   SUPPORTED_MODELS=$(az cognitiveservices account list-models --location $LOCATION --query "[?contains(name, 'gpt-4') || contains(name, 'o1') || contains(name, 'o3')].name" -o tsv 2>/dev/null || echo "")
   
   if [ -z "$SUPPORTED_MODELS" ]; then
     echo "⚠️ Warning: Unable to verify model availability in $LOCATION"
     echo "This might be due to permissions or the region not supporting the required models."
     echo "Available Azure OpenAI regions: East US, South Central US, West Europe, West US"
     read -p "Enter a different region or press Enter to continue with $LOCATION: " NEW_LOCATION
     if [ ! -z "$NEW_LOCATION" ]; then
       LOCATION=$NEW_LOCATION
       echo "Region updated to: $LOCATION"
     fi
   else
     echo "✅ Region $LOCATION supports OpenAI models"
   fi

   # Check if resource group exists
   if ! az group show --name "$RESOURCE_GROUP" &> /dev/null; then
     echo "Creating resource group $RESOURCE_GROUP in $LOCATION..."
     az group create --name "$RESOURCE_GROUP" --location "$LOCATION"
   else
     echo "Using existing resource group: $RESOURCE_GROUP"
   fi

   # Deploy the Bicep template
   echo "Deploying Azure OpenAI resources..."
   DEPLOYMENT_OUTPUT=$(az deployment group create \
     --resource-group "$RESOURCE_GROUP" \
     --template-file "scripts/infrastructure/bicep/azure-openai.bicep" \
     --parameters location=$LOCATION \
     --output json)

   # Extract endpoint and resource name
   ENDPOINT=$(echo $DEPLOYMENT_OUTPUT | jq -r '.properties.outputs.endpoint.value')
   RESOURCE_NAME=$(echo $DEPLOYMENT_OUTPUT | jq -r '.properties.outputs.name.value')

   # Get the API key
   API_KEY=$(az cognitiveservices account keys list \
     --resource-group "$RESOURCE_GROUP" \
     --name "$RESOURCE_NAME" \
     --query "key1" \
     --output tsv)

   # Create credentials file
   mkdir -p config
   cat > config/azure_openai_credentials.json << EOF
   {
     "api_key": "$API_KEY",
     "endpoint": "$ENDPOINT",
     "deployments": {
       "gpt4o": "gpt4o",
       "o1": "o1",
       "o3": "o3"
     },
     "subscription_id": "$SUBSCRIPTION_ID",
     "resource_group": "$RESOURCE_GROUP",
     "region": "$LOCATION"
   }
   EOF

   echo "✅ Azure OpenAI resources deployed successfully!"
   echo "Credentials saved to config/azure_openai_credentials.json"
   echo "Resource Group: $RESOURCE_GROUP"
   echo "OpenAI Service: $RESOURCE_NAME"
   echo "Region: $LOCATION"
   ```

4. **Create a Model Deployment Verification Script**:
   - Add a script to verify model deployments (`scripts/infrastructure/verify-openai-models.sh`):
   ```bash
   #!/bin/bash
   set -e

   echo "🔍 Verifying Azure OpenAI model deployments for Skwaq..."

   # Load credentials
   if [ ! -f "config/azure_openai_credentials.json" ]; then
     echo "❌ Azure OpenAI credentials not found. Please run deploy-openai.sh first."
     exit 1
   fi

   RESOURCE_NAME=$(az resource list --resource-group $(jq -r '.resource_group' config/azure_openai_credentials.json) --resource-type "Microsoft.CognitiveServices/accounts" --query "[0].name" -o tsv)
   
   echo "Checking model deployments in $RESOURCE_NAME..."
   
   # Get current deployments
   DEPLOYMENTS=$(az cognitiveservices account deployment list \
     --name "$RESOURCE_NAME" \
     --resource-group $(jq -r '.resource_group' config/azure_openai_credentials.json) \
     --query "[].name" -o tsv)
   
   # Check for required models
   REQUIRED_MODELS=("gpt4o" "o1" "o3")
   MISSING_MODELS=()
   
   for MODEL in "${REQUIRED_MODELS[@]}"; do
     if ! echo "$DEPLOYMENTS" | grep -q "$MODEL"; then
       MISSING_MODELS+=("$MODEL")
     fi
   done
   
   if [ ${#MISSING_MODELS[@]} -eq 0 ]; then
     echo "✅ All required models are deployed and available"
   else
     echo "⚠️ The following required models are not deployed: ${MISSING_MODELS[*]}"
     echo "This could be due to quota limitations or deployment delays."
     echo "The Azure OpenAI deployments may take up to 15 minutes to complete."
     echo "You can check deployment status in the Azure Portal or run this script again later."
     
     # Suggest quota increase if needed
     echo "If you need to request quota increases, visit:"
     echo "https://aka.ms/oai/quotaincrease"
   fi
   
   # Test a simple completion to verify connectivity
   echo "Testing API connectivity..."
   
   # Use variables from credentials file
   API_KEY=$(jq -r '.api_key' config/azure_openai_credentials.json)
   ENDPOINT=$(jq -r '.endpoint' config/azure_openai_credentials.json)
   MODEL=$(echo "$DEPLOYMENTS" | head -n 1)  # Use first available deployment
   
   if [ -z "$MODEL" ]; then
     echo "❌ No model deployments found to test connectivity"
   else
     # Simple API call to test connectivity
     RESPONSE=$(curl -s -X POST "$ENDPOINT/openai/deployments/$MODEL/chat/completions?api-version=2023-05-15" \
       -H "Content-Type: application/json" \
       -H "api-key: $API_KEY" \
       -d '{
         "messages": [{"role": "user", "content": "Say hello"}],
         "max_tokens": 10
       }')
     
     if echo "$RESPONSE" | jq -e '.choices[0].message.content' > /dev/null; then
       echo "✅ Successfully connected to Azure OpenAI API"
     else
       echo "❌ Failed to connect to Azure OpenAI API"
       echo "Response: $RESPONSE"
       echo "Please verify your credentials and network connectivity"
     fi
   fi
   
   echo "Model verification completed"
   ```

5. **Make the verification script executable**:
   ```bash
   chmod +x scripts/infrastructure/verify-openai-models.sh
   ```

6. **Update development environment setup to include all authentication and verification steps**:
   - Modify the main setup script (`scripts/setup/setup_dev_environment.sh`):
   ```bash
   # Add to scripts/setup/setup_dev_environment.sh
   echo "Setting up Azure resources for Skwaq..."
   
   # Run Azure authentication first
   ../infrastructure/azure-auth.sh
   
   # Deploy Azure OpenAI resources
   ../infrastructure/deploy-openai.sh
   
   # Verify model deployments
   ../infrastructure/verify-openai-models.sh
   
   echo "Azure setup completed"
   ```

These scripts provide a comprehensive approach to:
1. Authenticate with Azure and select the appropriate subscription
2. Verify necessary permissions and resource provider registrations
3. Check for model availability in the selected region
4. Deploy the Azure OpenAI resources using Bicep
5. Verify model deployments and API connectivity
6. Handle error cases and provide guidance for resolving common issues

The approach also stores authentication and configuration details for use in other parts of the application, ensuring consistent access to the Azure resources.

### Development Tools Setup

1. **Configure linting and formatting tools**:
   ```bash
   # Install pre-commit hooks
   pre-commit install
   
   # Run pre-commit hooks on all files
   pre-commit run --all-files
   ```

2. **Testing tools**:
   ```bash
   # Run tests using pytest
   poetry run pytest

   # Generate coverage report
   poetry run pytest --cov=skwaq
   ```

3. **API Documentation Standards**:
   ```bash
   # Install documentation generators
   poetry add sphinx sphinx-autodoc sphinx-rtd-theme
   
   # Install docstring linting tools
   poetry add --group dev pydocstyle docstr-coverage
   
   # Run docstring coverage check
   poetry run docstr-coverage ./skwaq --fail-under=90
   ```

## Documentation

### 9.4 API Documentation Standards

**Purpose**: Establish and enforce comprehensive API documentation standards throughout the codebase.

**Steps**:
1. Implement docstring standards:
   - Adopt Google-style docstrings as the project standard
   - Create templates for module, class, function, and method docstrings
   - Implement mandatory sections: summary, parameters, returns, raises, examples
   - Standardize type annotations in both signatures and docstrings
   - Define requirements for documenting complex algorithms and design decisions

2. Configure documentation automation:
   - Set up Sphinx for automatic API documentation generation
   - Create custom Sphinx extensions for project-specific documentation needs
   - Configure automatic cross-referencing between related components
   - Implement code example validation in documentation
   - Set up GitHub Pages or ReadTheDocs for hosted documentation

3. Implement documentation quality checks:
   - Add docstring coverage checking to CI pipeline
   - Implement pydocstyle validation in pre-commit hooks
   - Create custom validators for project-specific requirements
   - Add documentation quality checks to code review templates
   - Set up automated docstring previews for pull requests

**Example Google-style Docstring Template**:
```python
def function_name(param1: type1, param2: type2) -> return_type:
    """Summary line describing the function's purpose.
    
    Additional details about the function, its algorithm, and design decisions.
    Multiple paragraphs may be used as needed.
    
    Args:
        param1: Description of param1. Include value constraints, defaults,
            and behavior impact.
        param2: Description of param2. For complex parameters, explain
            format requirements and edge cases.
    
    Returns:
        Description of return value, including possible values and their meaning.
    
    Raises:
        ExceptionType: When and why this exception might be raised.
        AnotherException: Conditions causing this exception.
    
    Examples:
        >>> function_name('example', 42)
        'Expected output'
        
        For more complex examples:
        
        >>> complex_input = {'key': 'value'}
        >>> function_name('example', complex_input)
        {'processed': True}
    """
    # Function implementation
```

**Documentation Completeness Requirements**:
- **Modules**: Purpose, dependencies, main components, usage examples
- **Classes**: Purpose, attributes, initialization parameters, usage pattern, examples
- **Public Methods/Functions**: Full Google-style docstrings with all sections
- **Private Methods/Functions**: Purpose and parameter descriptions at minimum
- **Complex Algorithms**: Design decisions, algorithmic complexity, limitations
- **Events**: Event type, payload structure, subscribers, emission conditions

**Dependencies**:
- sphinx
- sphinx-autodoc
- sphinx-napoleon (for Google-style docstring support)
- sphinx-rtd-theme
- pydocstyle
- docstr-coverage

**Testing Strategy**:
- Automated docstring coverage checks (minimum 90% coverage)
- Docstring style validation (pydocstyle)
- Example code validation
- Sphinx build validation
- Documentation rendering verification

## Implementation Milestones and Validation Criteria

The implementation will proceed through a series of incremental milestones, each with specific validation criteria and testing requirements. Each milestone must pass its validation criteria before proceeding to the next milestone.

### Foundation Phase Milestones

#### Milestone F1: Project Setup and Environment
**Deliverables:**
- Project repository structure
- Development environment configuration
- Docker containerization
- CI/CD pipeline setup
- API documentation standards and tooling setup

**Validation Criteria:**
- All required directories and configuration files exist
- Docker container builds successfully
- Development environment scripts execute correctly
- CI pipeline succeeds with baseline tests
- API documentation templates and standards are defined
- Documentation generation pipeline works correctly

**Testing Requirements:**
- Script validation on all target platforms (Windows, macOS, Linux)
- Container startup and shutdown tests
- Environment variable configuration tests
- CI pipeline verification test
- Documentation generation tests
- Docstring style validation tests

#### Milestone F2: Core Utilities and Infrastructure
**Deliverables:**
- Telemetry system with opt-out functionality
- Configuration management
- Event system implementation
- Logging system

**Validation Criteria:**
- Telemetry data is captured and can be disabled via configuration
- Events can be emitted and consumed by subscribers
- Logging captures appropriate information and respects log levels
- Configuration changes are reflected in system behavior

**Testing Requirements:**
- Unit tests for each utility component
- Integration tests for interactions between components
- Configuration change tests
- Telemetry opt-out verification

#### Milestone F3: Database Integration
**Deliverables:**
- Neo4j connection module
- Schema implementation
- Database initialization
- Vector search integration

**Validation Criteria:**
- Stable connection to Neo4j can be established
- Schema is correctly initialized
- Queries can be executed and return expected results
- Vector search returns relevant results for test queries

**Testing Requirements:**
- Connection reliability tests (including failure recovery)
- Query performance benchmarks for common operations
- Schema validation tests
- Vector similarity search accuracy tests

### Knowledge Management Phase Milestones

#### Milestone K1: Knowledge Ingestion Pipeline
**Deliverables:**
- Document processing pipeline
- CWE database integration
- Core knowledge graph structure

**Validation Criteria:**
- Documents in various formats (Markdown, PDF) can be processed
- CWE data is correctly imported and linked
- Knowledge graph entities and relationships are created correctly

**Testing Requirements:**
- Document processing tests with various formats
- CWE data verification tests
- Graph consistency validation
- Processing error handling tests

#### Milestone K2: Knowledge Indexing and Retrieval
**Deliverables:**
- Document embedding generation
- Vector indexing in Neo4j
- Retrieval API implementation

**Validation Criteria:**
- Embeddings are generated consistently for similar text
- Vector indices correctly store embeddings
- Retrieval queries return relevant results
- Performance meets requirements for typical queries

**Testing Requirements:**
- Embedding consistency tests
- Retrieval accuracy evaluation
- Performance benchmarks for indexing operations
- Query latency tests

#### Milestone K3: Knowledge Source Extensibility
**Deliverables:**
- Knowledge source registry
- Source-specific ingestion pipelines
- Schema integration templates

**Validation Criteria:**
- New knowledge sources can be registered and ingested
- Source-specific processing correctly handles different formats
- Knowledge from different sources is integrated properly

**Testing Requirements:**
- Integration tests with sample custom knowledge sources
- Schema compatibility tests
- Source registration and discovery tests
- Error handling tests for invalid sources

### Code Analysis Phase Milestones

#### Milestone C1: Repository Fetching
**Deliverables:**
- GitHub API integration
- Repository cloning functionality
- Filesystem processing

**Validation Criteria:**
- Can successfully clone repositories from GitHub
- Authentication works for private repositories
- Repository structure is correctly processed
- Progress is reported accurately

**Testing Requirements:**
- Tests with public and private repositories
- Authentication failure handling tests
- Large repository handling tests
- Network failure recovery tests

#### Milestone C2: Basic Code Analysis
**Deliverables:**
- Blarify integration
- AST processing
- Code structure mapping
- Python and C# language support

**Validation Criteria:**
- AST is generated correctly for both Python and C# code
- Code structure is mapped to the graph database
- File relationships are correctly identified
- Analysis works for both reference repositories (eShop and autogen)

**Testing Requirements:**
- Analysis correctness tests for reference repositories
- Performance benchmarks for typical codebases
- Language-specific validation tests
- Error handling for malformed code

#### Milestone C3: Advanced Code Analysis
**Deliverables:**
- Parallel analysis orchestration
- CodeQL integration
- Code metrics collection
- Tool integration framework

**Validation Criteria:**
- Analysis tasks execute in parallel where appropriate
- CodeQL queries execute and results are processed
- Code metrics are calculated and stored
- External tools can be integrated and executed

**Testing Requirements:**
- Parallel efficiency measurements
- CodeQL result validation
- Metrics accuracy verification
- Tool integration tests with sample tools

#### Milestone C4: Code Understanding and Summarization
**Deliverables:**
- Code summarization at multiple levels
- Intent inference
- Architecture reconstruction
- Cross-reference linking

**Validation Criteria:**
- Summaries are generated at function, class, module, and system levels
- Developer intent is inferred accurately
- Architecture diagrams can be generated from analysis
- Cross-references correctly link related components

**Testing Requirements:**
- Summary quality evaluation (manual review)
- Cross-reference accuracy tests
- Architecture reconstruction validation
- Performance tests for large codebases

### Agent System Phase Milestones

#### Milestone A1: Agent Foundation
**Deliverables:**
- AutoGen Core integration
- Base agent classes
- Agent lifecycle management
- Agent registry

**Validation Criteria:**
- Agents can be created and destroyed
- Agents can communicate with each other
- Agent registry correctly manages agent instances
- Agent lifecycle events are properly tracked

**Testing Requirements:**
- Agent creation and destruction tests
- Inter-agent communication tests
- Registry functionality tests
- Resource usage monitoring

#### Milestone A2: Core Agents Implementation
**Deliverables:**
- Orchestrator agent
- Knowledge agents
- Code analysis agents
- Basic workflow agents

**Validation Criteria:**
- Orchestrator correctly manages other agents
- Knowledge agents retrieve relevant information
- Code analysis agents process code correctly
- Basic workflows can be executed

**Testing Requirements:**
- Agent behavior tests with mock inputs
- End-to-end tests for simple workflows
- Resource usage monitoring during agent operation
- Error handling and recovery tests

#### Milestone A3: Advanced Agent Capabilities
**Deliverables:**
- Agent communication patterns
- Specialized workflow agents
- Critic and verification agents
- Advanced orchestration

**Validation Criteria:**
- Complex multi-agent interactions work correctly
- Agents can critique and verify each other's work
- Workflows correctly use specialized agents
- Orchestration handles complex scenarios

**Testing Requirements:**
- Complex workflow tests
- Critic agent effectiveness evaluation
- Error recovery in multi-agent scenarios
- Performance benchmarks for agent interactions

### Workflow and UI Phase Milestones

#### Milestone W1: Command Line Interface
**Deliverables:**
- CLI command structure
- Interactive UI elements
- Progress visualization
- Investigation management commands

**Validation Criteria:**
- Commands work correctly and provide appropriate feedback
- Help and documentation are comprehensive
- Progress is visualized effectively
- Investigations can be listed, exported, and managed

**Testing Requirements:**
- Command execution tests
- User experience evaluation
- Error message clarity testing
- Investigation management functionality tests

#### Milestone W2: Basic Workflows
**Deliverables:**
- Q&A workflow
- Guided inquiry workflow
- Basic tool invocation

**Validation Criteria:**
- Q&A workflow provides accurate answers
- Guided inquiry workflow asks relevant questions
- Tools can be invoked and results processed
- Workflows persist across sessions

**Testing Requirements:**
- End-to-end workflow tests
- Answer accuracy evaluation
- Question relevance evaluation
- Session persistence tests

#### Milestone W3: Advanced Workflows
**Deliverables:**
- Vulnerability research workflow
- Investigation persistence
- Markdown reporting
- GitHub issue integration

**Validation Criteria:**
- Vulnerability research workflow identifies actual issues
- Investigations persist and can be resumed
- Reports are generated in well-formatted Markdown
- GitHub issue scripts are generated correctly

**Testing Requirements:**
- Vulnerability detection tests with known issues
- Report quality evaluation
- GitHub issue script validation
- Investigation persistence tests

#### Milestone W4: Workflow Refinement and Integration
**Deliverables:**
- Inter-workflow communication
- Context preservation
- Workflow chaining
- Performance optimization

**Validation Criteria:**
- Workflows can be chained together
- Context is preserved when switching workflows
- Performance meets requirements under typical load
- User experience is smooth and intuitive

**Testing Requirements:**
- Workflow transition tests
- Context preservation verification
- Performance benchmarks under various loads
- Usability testing with sample scenarios

### Integration and Finalization Phase Milestones

#### Milestone I1: System Integration
**Deliverables:**
- Full system integration
- End-to-end testing
- Performance optimization
- Documentation updates

**Validation Criteria:**
- All components work together seamlessly
- Performance meets requirements
- Documentation is complete and accurate
- No critical bugs or issues remain

**Testing Requirements:**
- End-to-end system tests
- Performance benchmarks
- Documentation verification
- Regression testing

#### Milestone I2: Security and Compliance
**Deliverables:**
- Security implementation
- Telemetry privacy controls
- Data protection
- Compliance verification

**Validation Criteria:**
- Security controls are properly implemented
- Telemetry respects privacy settings
- Sensitive data is protected
- System meets all compliance requirements

**Testing Requirements:**
- Security penetration testing
- Privacy control verification
- Data protection tests
- Compliance checklist verification

#### Milestone I3: Final Release Preparation
**Deliverables:**
- Release packaging
- Installation and deployment scripts
- Final documentation
- Deployment guides

**Validation Criteria:**
- Package can be installed and run correctly
- Documentation covers all aspects of the system
- Deployment guides are comprehensive
- Release meets all requirements and quality standards

**Testing Requirements:**
- Installation tests on all target platforms
- Documentation completeness verification
- Deployment guide validation
- Final acceptance testing

### Milestone Validation and Testing Process

For each milestone, the following validation and testing process will be followed:

1. **Unit Testing**: Each component must pass all unit tests with at least 80% code coverage.

2. **Integration Testing**: Components must work together as expected, with integration tests passing.

3. **Performance Testing**: Performance must meet or exceed the defined benchmarks for the milestone.

4. **Security Testing**: Security-related components must pass security review and testing.

5. **Code Review**: All code must pass peer review before milestone completion.

6. **Documentation Review**: Documentation must be updated to reflect the milestone deliverables.
   - API documentation coverage must meet or exceed 90% for all new code
   - API documentation must follow the established Google-style format
   - Documentation must be generated successfully with Sphinx
   - Code examples in docstrings must be valid and execute correctly

7. **Milestone Demo**: A demonstration of the milestone functionality must be presented and approved.

8. **Milestone Retrospective**: A retrospective must be conducted to identify lessons learned and improvements for future milestones.

9. **Local CI Validation**: Before marking a milestone as complete, run the full local CI pipeline to verify that all tests pass and all requirements are met:
   ```bash
   ./scripts/ci/run-local-ci.sh
   ```

This ensures that the milestone meets all technical requirements and will pass validation in the GitHub Actions pipeline.

## Development Phases Summary

The implementation will proceed in the following phases, with each phase building on the dependencies established in previous phases:

### Phase 1: Foundation
- **Milestone F1**: Project Setup and Environment
- **Milestone F2**: Core Utilities and Infrastructure
- **Milestone F3**: Database Integration

### Phase 2: Knowledge Management
- **Milestone K1**: Knowledge Ingestion Pipeline
- **Milestone K2**: Knowledge Indexing and Retrieval
- **Milestone K3**: Knowledge Source Extensibility

### Phase 3: Code Analysis
- **Milestone C1**: Repository Fetching
- **Milestone C2**: Basic Code Analysis
- **Milestone C3**: Advanced Code Analysis
- **Milestone C4**: Code Understanding and Summarization

### Phase 4: Agent System
- **Milestone A1**: Agent Foundation
- **Milestone A2**: Core Agents Implementation
- **Milestone A3**: Advanced Agent Capabilities

### Phase 5: Workflow and UI
- **Milestone W1**: Command Line Interface
- **Milestone W2**: Basic Workflows
- **Milestone W3**: Advanced Workflows
- **Milestone W4**: Workflow Refinement and Integration

### Phase 6: Integration and Finalization
- **Milestone I1**: System Integration
- **Milestone I2**: Security and Compliance
- **Milestone I3**: Final Release Preparation

### GitHub Actions CI Configuration

The project uses GitHub Actions for continuous integration and testing. The following workflows will be implemented:

1. **Create Tests and Linting Workflow**:
   - Create `.github/workflows/tests.yml` configuration:
   ```yaml
   name: Tests & Linting

   on:
     push:
       branches: [ main ]
     pull_request:
       branches: [ main ]
     # Run tests when milestones are tagged
     tags:
       - "milestone-*"

   jobs:
     test:
       runs-on: ubuntu-latest
       services:
         # Run Neo4j in a container for integration tests
         neo4j:
           image: neo4j:latest
           env:
             NEO4J_AUTH: neo4j/password
             NEO4J_ACCEPT_LICENSE_AGREEMENT: yes
           ports:
             - 7474:7474
             - 7687:7687
           options: --health-cmd "wget -O - http://localhost:7474 || exit 1" --health-interval 10s --health-timeout 5s --health-retries 3
       
       strategy:
         matrix:
           python-version: ['3.10', '3.11']

       steps:
         - uses: actions/checkout@v3
         
         - name: Set up Python ${{ matrix.python-version }}
           uses: actions/setup-python@v4
           with:
             python-version: ${{ matrix.python-version }}
             cache: 'pip'
         
         - name: Install uv
           run: pip install uv
         
         - name: Install dependencies
           run: |
             python -m uv venv .venv
             source .venv/bin/activate
             python -m uv pip install -e ".[dev,test]"
         
         - name: Run linting
           run: |
             source .venv/bin/activate
             python -m black --check .
             python -m flake8 .
             python -m mypy .
         
         - name: Run tests
           run: |
             source .venv/bin/activate
             python -m pytest --cov=skwaq tests/
             
         - name: Upload coverage report
           uses: codecov/codecov-action@v3
           with:
             fail_ci_if_error: false
   ```

2. **Create Docker Build Workflow**:
   - Create `.github/workflows/docker-build.yml` configuration:
   ```yaml
   name: Docker Build

   on:
     push:
       branches: [ main ]
     pull_request:
       branches: [ main ]
     # Build container when milestones are tagged
     tags:
       - "milestone-*"
       - "v*.*.*"

   jobs:
     build:
       runs-on: ubuntu-latest
       steps:
         - uses: actions/checkout@v3
         
         - name: Set up Docker Buildx
           uses: docker/setup-buildx-action@v2
         
         - name: Build Docker image
           uses: docker/build-push-action@v4
           with:
             context: .
             push: false
             tags: skwaq:latest
             cache-from: type=gha
             cache-to: type=gha,mode=max
             load: true
         
         - name: Test Docker image
           run: |
             docker run --rm skwaq:latest --version
   ```

3. **Create Release Automation Workflow**:
   - Create `.github/workflows/release.yml` configuration:
   ```yaml
   name: Release

   on:
     push:
       tags:
         - "v*.*.*"

   jobs:
     release:
       runs-on: ubuntu-latest
       steps:
         - uses: actions/checkout@v3
           with:
             fetch-depth: 0
         
         - name: Set up Python
           uses: actions/setup-python@v4
           with:
             python-version: '3.10'
         
         - name: Install dependencies
           run: |
             python -m pip install --upgrade pip
             pip install build wheel
         
         - name: Build package
           run: python -m build
         
         - name: Create Release
           uses: softprops/action-gh-release@v1
           with:
             files: |
               dist/*.whl
               dist/*.tar.gz
             generate_release_notes: true
   ```

4. **Create Milestone Validation Workflow**:
   - Create `.github/workflows/milestone-validation.yml` configuration:
   ```yaml
   name: Milestone Validation

   on:
     push:
       tags:
         - "milestone-*"

   jobs:
     validate:
       runs-on: ubuntu-latest
       steps:
         - uses: actions/checkout@v3
         
         - name: Set up Python
           uses: actions/setup-python@v4
           with:
             python-version: '3.10'
         
         - name: Install dependencies
           run: |
             python -m pip install --upgrade pip
             pip install -e ".[dev,test]"
         
         - name: Extract milestone information
           id: milestone
           run: |
             MILESTONE=$(echo ${{ github.ref_name }} | sed 's/milestone-//')
             echo "milestone=$MILESTONE" >> $GITHUB_OUTPUT
         
         - name: Run milestone-specific validation tests
           run: |
             python -m pytest tests/milestones/test_${{ steps.milestone.outputs.milestone }}.py -v
         
         - name: Create milestone documentation
           run: |
             python scripts/ci/generate_milestone_docs.py ${{ steps.milestone.outputs.milestone }}
   ```

These GitHub Actions workflows ensure:

1. **Continuous Testing**: All code is tested on multiple Python versions with coverage reporting
2. **Code Quality Checks**: Linting, formatting, and type checking are enforced
3. **Docker Builds**: Container builds are validated for every significant change
4. **Milestone Validation**: Specific tests run when milestone tags are pushed
5. **Release Automation**: Packages are built and published for version tags
6. **Documentation Quality**: API documentation is comprehensive, consistent, and accurate

Each workflow is designed to run on specific events (pushes, PRs, tags) and provides clear feedback on the build status. The milestone validation workflow in particular supports the milestone-based development approach by running milestone-specific tests when appropriate tags are pushed.

**CI Configuration Updates for Each Milestone**:

As milestones progress, specific test files should be added in the `tests/milestones/` directory following this pattern:
- `test_F1.py` - Project Setup and Environment tests
- `test_F2.py` - Core Utilities and Infrastructure tests
- And so on for each milestone

These dedicated test files will contain comprehensive validation tests for the specific functionality expected at each milestone, allowing the milestone validation workflow to verify that all requirements have been met.

**Milestone Tagging Process**:

When a milestone is completed and ready for validation:
1. Tag the commit representing the milestone completion:
   ```bash
   git tag milestone-F1  # For Milestone F1
   git push origin milestone-F1
   ```
2. The milestone validation workflow will automatically run
3. Results will be available in the GitHub Actions tab

**Security Considerations for CI**:

1. **Secret Management**: Sensitive values (API keys, credentials) should be stored as GitHub Secrets
2. **Dependency Scanning**: Workflows include security scanning for dependencies
3. **Container Scanning**: Docker images are scanned for vulnerabilities

These CI/CD workflows form a critical part of the development process, ensuring all deliverables meet the validation criteria specified for each milestone.

### Production Deployment Dependencies

For production deployment, additional steps are required:

1. **Containerization**:
   ```bash
   # Build the Docker image
   docker build -t skwaq:latest .
   
   # Run the container
   docker run -p 8000:8000 -v ./data:/app/data skwaq:latest
   ```

2. **Securing Neo4j**:
   - Configure authentication
   - Enable TLS for connections
   - Set up proper backup procedures

3. **Setting up Monitoring**:
   - Configure logging to external systems
   - Set up metrics collection
   - Implement health checks

## Implementation Milestones and Validation Criteria

The implementation will proceed through a series of incremental milestones, each with specific validation criteria and testing requirements. Each milestone must pass its validation criteria before proceeding to the next milestone.

### Foundation Phase Milestones

#### Milestone F1: Project Setup and Environment
**Deliverables:**
- Project repository structure
- Development environment configuration
- Docker containerization
- CI/CD pipeline setup
- API documentation standards and tooling setup

**Validation Criteria:**
- All required directories and configuration files exist
- Docker container builds successfully
- Development environment scripts execute correctly
- CI pipeline succeeds with baseline tests
- API documentation templates and standards are defined
- Documentation generation pipeline works correctly

**Testing Requirements:**
- Script validation on all target platforms (Windows, macOS, Linux)
- Container startup and shutdown tests
- Environment variable configuration tests
- CI pipeline verification test
- Documentation generation tests
- Docstring style validation tests

#### Milestone F2: Core Utilities and Infrastructure
**Deliverables:**
- Telemetry system with opt-out functionality
- Configuration management
- Event system implementation
- Logging system

**Validation Criteria:**
- Telemetry data is captured and can be disabled via configuration
- Events can be emitted and consumed by subscribers
- Logging captures appropriate information and respects log levels
- Configuration changes are reflected in system behavior

**Testing Requirements:**
- Unit tests for each utility component
- Integration tests for interactions between components
- Configuration change tests
- Telemetry opt-out verification

#### Milestone F3: Database Integration
**Deliverables:**
- Neo4j connection module
- Schema implementation
- Database initialization
- Vector search integration

**Validation Criteria:**
- Stable connection to Neo4j can be established
- Schema is correctly initialized
- Queries can be executed and return expected results
- Vector search returns relevant results for test queries

**Testing Requirements:**
- Connection reliability tests (including failure recovery)
- Query performance benchmarks for common operations
- Schema validation tests
- Vector similarity search accuracy tests

### Knowledge Management Phase Milestones

#### Milestone K1: Knowledge Ingestion Pipeline
**Deliverables:**
- Document processing pipeline
- CWE database integration
- Core knowledge graph structure

**Validation Criteria:**
- Documents in various formats (Markdown, PDF) can be processed
- CWE data is correctly imported and linked
- Knowledge graph entities and relationships are created correctly

**Testing Requirements:**
- Document processing tests with various formats
- CWE data verification tests
- Graph consistency validation
- Processing error handling tests

#### Milestone K2: Knowledge Indexing and Retrieval
**Deliverables:**
- Document embedding generation
- Vector indexing in Neo4j
- Retrieval API implementation

**Validation Criteria:**
- Embeddings are generated consistently for similar text
- Vector indices correctly store embeddings
- Retrieval queries return relevant results
- Performance meets requirements for typical queries

**Testing Requirements:**
- Embedding consistency tests
- Retrieval accuracy evaluation
- Performance benchmarks for indexing operations
- Query latency tests

#### Milestone K3: Knowledge Source Extensibility
**Deliverables:**
- Knowledge source registry
- Source-specific ingestion pipelines
- Schema integration templates

**Validation Criteria:**
- New knowledge sources can be registered and ingested
- Source-specific processing correctly handles different formats
- Knowledge from different sources is integrated properly

**Testing Requirements:**
- Integration tests with sample custom knowledge sources
- Schema compatibility tests
- Source registration and discovery tests
- Error handling tests for invalid sources

### Code Analysis Phase Milestones

#### Milestone C1: Repository Fetching
**Deliverables:**
- GitHub API integration
- Repository cloning functionality
- Filesystem processing

**Validation Criteria:**
- Can successfully clone repositories from GitHub
- Authentication works for private repositories
- Repository structure is correctly processed
- Progress is reported accurately

**Testing Requirements:**
- Tests with public and private repositories
- Authentication failure handling tests
- Large repository handling tests
- Network failure recovery tests

#### Milestone C2: Basic Code Analysis
**Deliverables:**
- Blarify integration
- AST processing
- Code structure mapping
- Python and C# language support

**Validation Criteria:**
- AST is generated correctly for both Python and C# code
- Code structure is mapped to the graph database
- File relationships are correctly identified
- Analysis works for both reference repositories (eShop and autogen)

**Testing Requirements:**
- Analysis correctness tests for reference repositories
- Performance benchmarks for typical codebases
- Language-specific validation tests
- Error handling for malformed code

#### Milestone C3: Advanced Code Analysis
**Deliverables:**
- Parallel analysis orchestration
- CodeQL integration
- Code metrics collection
- Tool integration framework

**Validation Criteria:**
- Analysis tasks execute in parallel where appropriate
- CodeQL queries execute and results are processed
- Code metrics are calculated and stored
- External tools can be integrated and executed

**Testing Requirements:**
- Parallel efficiency measurements
- CodeQL result validation
- Metrics accuracy verification
- Tool integration tests with sample tools

#### Milestone C4: Code Understanding and Summarization
**Deliverables:**
- Code summarization at multiple levels
- Intent inference
- Architecture reconstruction
- Cross-reference linking

**Validation Criteria:**
- Summaries are generated at function, class, module, and system levels
- Developer intent is inferred accurately
- Architecture diagrams can be generated from analysis
- Cross-references correctly link related components

**Testing Requirements:**
- Summary quality evaluation (manual review)
- Cross-reference accuracy tests
- Architecture reconstruction validation
- Performance tests for large codebases

### Agent System Phase Milestones

#### Milestone A1: Agent Foundation
**Deliverables:**
- AutoGen Core integration
- Base agent classes
- Agent lifecycle management
- Agent registry

**Validation Criteria:**
- Agents can be created and destroyed
- Agents can communicate with each other
- Agent registry correctly manages agent instances
- Agent lifecycle events are properly tracked

**Testing Requirements:**
- Agent creation and destruction tests
- Inter-agent communication tests
- Registry functionality tests
- Resource usage monitoring

#### Milestone A2: Core Agents Implementation
**Deliverables:**
- Orchestrator agent
- Knowledge agents
- Code analysis agents
- Basic workflow agents

**Validation Criteria:**
- Orchestrator correctly manages other agents
- Knowledge agents retrieve relevant information
- Code analysis agents process code correctly
- Basic workflows can be executed

**Testing Requirements:**
- Agent behavior tests with mock inputs
- End-to-end tests for simple workflows
- Resource usage monitoring during agent operation
- Error handling and recovery tests

#### Milestone A3: Advanced Agent Capabilities
**Deliverables:**
- Agent communication patterns
- Specialized workflow agents
- Critic and verification agents
- Advanced orchestration

**Validation Criteria:**
- Complex multi-agent interactions work correctly
- Agents can critique and verify each other's work
- Workflows correctly use specialized agents
- Orchestration handles complex scenarios

**Testing Requirements:**
- Complex workflow tests
- Critic agent effectiveness evaluation
- Error recovery in multi-agent scenarios
- Performance benchmarks for agent interactions

### Workflow and UI Phase Milestones

#### Milestone W1: Command Line Interface
**Deliverables:**
- CLI command structure
- Interactive UI elements
- Progress visualization
- Investigation management commands

**Validation Criteria:**
- Commands work correctly and provide appropriate feedback
- Help and documentation are comprehensive
- Progress is visualized effectively
- Investigations can be listed, exported, and managed

**Testing Requirements:**
- Command execution tests
- User experience evaluation
- Error message clarity testing
- Investigation management functionality tests

#### Milestone W2: Basic Workflows
**Deliverables:**
- Q&A workflow
- Guided inquiry workflow
- Basic tool invocation

**Validation Criteria:**
- Q&A workflow provides accurate answers
- Guided inquiry workflow asks relevant questions
- Tools can be invoked and results processed
- Workflows persist across sessions

**Testing Requirements:**
- End-to-end workflow tests
- Answer accuracy evaluation
- Question relevance evaluation
- Session persistence tests

#### Milestone W3: Advanced Workflows
**Deliverables:**
- Vulnerability research workflow
- Investigation persistence
- Markdown reporting
- GitHub issue integration

**Validation Criteria:**
- Vulnerability research workflow identifies actual issues
- Investigations persist and can be resumed
- Reports are generated in well-formatted Markdown
- GitHub issue scripts are generated correctly

**Testing Requirements:**
- Vulnerability detection tests with known issues
- Report quality evaluation
- GitHub issue script validation
- Investigation persistence tests

#### Milestone W4: Workflow Refinement and Integration
**Deliverables:**
- Inter-workflow communication
- Context preservation
- Workflow chaining
- Performance optimization

**Validation Criteria:**
- Workflows can be chained together
- Context is preserved when switching workflows
- Performance meets requirements under typical load
- User experience is smooth and intuitive

**Testing Requirements:**
- Workflow transition tests
- Context preservation verification
- Performance benchmarks under various loads
- Usability testing with sample scenarios

### Integration and Finalization Phase Milestones

#### Milestone I1: System Integration
**Deliverables:**
- Full system integration
- End-to-end testing
- Performance optimization
- Documentation updates

**Validation Criteria:**
- All components work together seamlessly
- Performance meets requirements
- Documentation is complete and accurate
- No critical bugs or issues remain

**Testing Requirements:**
- End-to-end system tests
- Performance benchmarks
- Documentation verification
- Regression testing

#### Milestone I2: Security and Compliance
**Deliverables:**
- Security implementation
- Telemetry privacy controls
- Data protection
- Compliance verification

**Validation Criteria:**
- Security controls are properly implemented
- Telemetry respects privacy settings
- Sensitive data is protected
- System meets all compliance requirements

**Testing Requirements:**
- Security penetration testing
- Privacy control verification
- Data protection tests
- Compliance checklist verification

#### Milestone I3: Final Release Preparation
**Deliverables:**
- Release packaging
- Installation and deployment scripts
- Final documentation
- Deployment guides

**Validation Criteria:**
- Package can be installed and run correctly
- Documentation covers all aspects of the system
- Deployment guides are comprehensive
- Release meets all requirements and quality standards

**Testing Requirements:**
- Installation tests on all target platforms
- Documentation completeness verification
- Deployment guide validation
- Final acceptance testing

### Milestone Validation and Testing Process

For each milestone, the following validation and testing process will be followed:

1. **Unit Testing**: Each component must pass all unit tests with at least 80% code coverage.

2. **Integration Testing**: Components must work together as expected, with integration tests passing.

3. **Performance Testing**: Performance must meet or exceed the defined benchmarks for the milestone.

4. **Security Testing**: Security-related components must pass security review and testing.

5. **Code Review**: All code must pass peer review before milestone completion.

6. **Documentation Review**: Documentation must be updated to reflect the milestone deliverables.
   - API documentation coverage must meet or exceed 90% for all new code
   - API documentation must follow the established Google-style format
   - Documentation must be generated successfully with Sphinx
   - Code examples in docstrings must be valid and execute correctly

7. **Milestone Demo**: A demonstration of the milestone functionality must be presented and approved.

8. **Milestone Retrospective**: A retrospective must be conducted to identify lessons learned and improvements for future milestones.

9. **Local CI Validation**: Before marking a milestone as complete, run the full local CI pipeline to verify that all tests pass and all requirements are met:
   ```bash
   ./scripts/ci/run-local-ci.sh
   ```

This ensures that the milestone meets all technical requirements and will pass validation in the GitHub Actions pipeline.

### Local CI Execution

To ensure developers can validate changes before pushing to GitHub, the project will include infrastructure for running the entire CI pipeline locally:

1. **Local GitHub Actions Runner Setup**:
   - Create a script in `scripts/ci/setup-local-actions.sh` that installs and configures [act](https://github.com/nektos/act), a tool for running GitHub Actions locally:
   ```bash
   #!/bin/bash
   set -e

   echo "🔄 Setting up local GitHub Actions runner (act)..."

   # Check if act is already installed
   if ! command -v act &> /dev/null; then
       echo "Installing act..."
       # For macOS
       if [[ "$OSTYPE" == "darwin"* ]]; then
           brew install act
       # For Linux
       elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
           curl -s https://raw.githubusercontent.com/nektos/act/master/install.sh | sudo bash
       # For Windows (WSL)
       elif [[ "$OSTYPE" == "msys" || "$OSTYPE" == "win32" ]]; then
           echo "Please install act manually on Windows: https://github.com/nektos/act#installation"
           exit 1
       fi
   else
       echo "✅ act is already installed"
   fi

   # Create a local configuration file for act
   cat > .actrc << EOF
   # Use a medium-sized runner image for more compatibility
   -P ubuntu-latest=ghcr.io/catthehacker/ubuntu:act-latest
   # Mount Docker socket to be able to use Docker
   --bind
   EOF

   # Create a basic secrets file for local testing (with placeholder values)
   if [ ! -f ".secrets" ]; then
       cat > .secrets << EOF
   # Local testing secrets - NEVER COMMIT THIS FILE
   AZURE_OPENAI_API_KEY=test-key
   AZURE_OPENAI_ENDPOINT=https://test-endpoint.openai.azure.com/
   GITHUB_TOKEN=github_pat_test
   EOF
       echo "Created .secrets file with placeholder values"
       echo "⚠️  Update .secrets with appropriate values for local testing"
   fi

   echo "✅ Local GitHub Actions environment configured"
   echo "To run GitHub Actions locally:"
   echo "  act -s GITHUB_TOKEN=\$GITHUB_TOKEN pull_request"
   echo "  act -s GITHUB_TOKEN=\$GITHUB_TOKEN push"
   ```

2. **Create a Local CI Runner Script**:
   - Add a comprehensive script in `scripts/ci/run-local-ci.sh` that executes all CI checks locally:
   ```bash
   #!/bin/bash
   set -e

   echo "🧪 Running CI pipeline locally..."

   # Check if venv exists and activate it
   if [ -d ".venv" ]; then
       source .venv/bin/activate
   else
       echo "⚠️  Virtual environment not found, creating one..."
       python -m venv .venv
       source .venv/bin/activate
       pip install -e ".[dev,test]"
   fi

   echo "Running linting checks..."
   python -m black --check .
   python -m flake8 .
   python -m mypy .
   python -m pydocstyle ./skwaq

   echo "Running unit tests..."
   python -m pytest --cov=skwaq tests/

   echo "Checking for documentation coverage..."
   python -m docstr_coverage ./skwaq --fail-under=90

   echo "Validating API docstrings..."
   python -m pytest --doctest-modules ./skwaq

   echo "Building documentation..."
   cd docs && make clean html && cd ..

   echo "Running milestone-specific tests..."
   # Determine the current milestone based on code state
   if [ -d "tests/milestones" ]; then
       for test_file in $(ls tests/milestones/test_*.py 2>/dev/null || echo ""); do
           echo "Running $test_file..."
           python -m pytest $test_file -v
       done
   fi

   # Optionally run full GitHub Actions simulation with act
   if command -v act &> /dev/null; then
       echo "Do you want to run full GitHub Actions workflows with act? (y/n)"
       read -r run_act
       if [ "$run_act" = "y" ]; then
           echo "Running GitHub Actions with act..."
           act -s GITHUB_TOKEN=local-token push
       fi
   fi

   echo "✅ Local CI completed successfully"
   ```

3. **Add Docker Validation Script**:
   - Create a script in `scripts/ci/validate-docker.sh` for validating Docker builds locally:
   ```bash
   #!/bin/bash
   set -e

   echo "🐳 Validating Docker build locally..."

   # Build the Docker image
   docker build -t skwaq:local .

   # Test the image
   echo "Testing Docker image..."
   docker run --rm skwaq:local --version

   # Run a simple functionality test
   echo "Running basic functionality test in container..."
   docker run --rm skwaq:local --help

   echo "✅ Docker validation completed successfully"
   ```

4. **Update Development Environment Setup**:
   - Modify `scripts/setup/setup_dev_environment.sh` to include local CI setup:
   ```bash
   # Add to scripts/setup/setup_dev_environment.sh
   echo "Setting up local CI environment..."
   
   # Make CI scripts executable
   chmod +x scripts/ci/setup-local-actions.sh
   chmod +x scripts/ci/run-local-ci.sh
   chmod +x scripts/ci/validate-docker.sh
   
   # Set up local GitHub Actions
   ./scripts/ci/setup-local-actions.sh
   
   echo "Local CI environment setup completed"
   echo "To run CI locally, use: ./scripts/ci/run-local-ci.sh"
   ```

5. **Document Local CI in README**:
   - Add a section to the README.md file describing local CI usage:
   ```markdown
   ## Local CI Pipeline

   To run the CI pipeline locally before pushing changes:

   ```bash
   # Run all linting, tests, and checks
   ./scripts/ci/run-local-ci.sh

   # Validate Docker build only
   ./scripts/ci/validate-docker.sh

   # Run GitHub Actions workflows locally (requires Docker)
   act -s GITHUB_TOKEN=your_github_token push
   ```

   This ensures your changes will pass on the GitHub CI pipeline.
   ```

6. **Add Pre-commit Hook for CI**:
   - Configure a pre-push hook in `.pre-commit-config.yaml` to run essential CI checks:
   ```yaml
   - repo: local
     hooks:
       - id: local-ci-check
         name: Local CI Quick Checks
         entry: bash -c "python -m black --check . && python -m flake8 . && python -m pytest"
         language: system
         pass_filenames: false
         stages: [push]
   ```

These additions ensure that developers can:
1. Set up the same environment locally that GitHub Actions uses
2. Run all the same checks that would run in the CI pipeline
3. Validate changes before pushing them to GitHub
4. Have confidence that if changes pass locally, they will pass in the GitHub Actions workflow

The local CI implementation follows the same milestone-based validation approach as the GitHub Actions workflows and provides similar feedback, making the development process more efficient by catching issues earlier.

## Development Phases Summary

The implementation will proceed in the following phases, with each phase building on the dependencies established in previous phases:

### Phase 1: Foundation
- **Milestone F1**: Project Setup and Environment
- **Milestone F2**: Core Utilities and Infrastructure
- **Milestone F3**: Database Integration

### Phase 2: Knowledge Management
- **Milestone K1**: Knowledge Ingestion Pipeline
- **Milestone K2**: Knowledge Indexing and Retrieval
- **Milestone K3**: Knowledge Source Extensibility

### Phase 3: Code Analysis
- **Milestone C1**: Repository Fetching
- **Milestone C2**: Basic Code Analysis
- **Milestone C3**: Advanced Code Analysis
- **Milestone C4**: Code Understanding and Summarization

### Phase 4: Agent System
- **Milestone A1**: Agent Foundation
- **Milestone A2**: Core Agents Implementation
- **Milestone A3**: Advanced Agent Capabilities

### Phase 5: Workflow and UI
- **Milestone W1**: Command Line Interface
- **Milestone W2**: Basic Workflows
- **Milestone W3**: Advanced Workflows
- **Milestone W4**: Workflow Refinement and Integration

### Phase 6: Integration and Finalization
- **Milestone I1**: System Integration
- **Milestone I2**: Security and Compliance
- **Milestone I3**: Final Release Preparation
