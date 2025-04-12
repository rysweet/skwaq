# Graphical User Interface for Vulnerability Assessment Copilot

## Overview

The new feature is a graphical user interface (GUI) for the Vulnerability Assessment Copilot. The GUI will provide a user-friendly way to interact with the copilot, allowing users to easily start investigations, visualize graphs, view results, and manage their vulnerability assessments. 

## User Stories to enable
- As a user, I want to be able to view and manage the knowledge graph, potentially adding new sources of knowledge, so that I can add or update knowledge in the system.
- As a user, I want to be able to start an investigation by entering a repository URI, so that I can quickly begin my vulnerability assessment.
- As a user, I want to be able to visualize the results of my vulnerability assessment in a graph format, so that I can easily understand the relationships between different components and potential vulnerabilities.
- As a user, I want to be able to use all of the same commands as in the CLI, so that I can have a consistent experience across both interfaces.
- Once a codebase is ingested, I want to be able to view the graph representation of the codebase, so that I can analyze its structure and identify potential vulnerabilities.
- As a user, I want to be able to perform chat based question and answer sessions with the copilot, so that I can get real-time assistance and insights during my vulnerability assessment.
- As a user, I want to be able to edit nodes, edges, metadata, and details of the Investigation graph, so that I can customize my analysis and focus on specific areas of interest.
- As a user, I want to be able to invoke the Guided Inquiry workflow, using the copilot to ask me questions about the codebase, systematically exploring potential vulnerabilities and areas of concern.
- As a user, I want to be able to Invoke the workflows for specific tools, so that I can leverage the copilot's capabilities to perform targeted vulnerability assessments.
- As a user, I want to be able to invoke the vulnerability assessment workflow, so that I can initiate a comprehensive analysis of the codebase for potential vulnerabilities.
- As a user, I want to be able to view detailed information about each potential vulnerability, so that I can understand the risks and take appropriate action.
- As a user, I would like to be able to view the emitted telemetry events, so that I can monitor the system's performance and behavior.

## GUI Design

The GUI will have the following main components:

1. **Main Window**: The main window will serve as the primary interface for the user, providing access to all features and functionalities of the copilot.
2. **Navigation Bar**: A navigation bar will allow users to easily switch between different sections of the GUI, such as the knowledge graph, investigation management, and vulnerability assessment results.
3. **Knowledge Graph Visualization**: A dedicated section for visualizing the knowledge graph, allowing users to explore the relationships between different components and potential vulnerabilities.
4. **Investigation Management**: A section for managing ongoing investigations, including starting new investigations, viewing results, and editing nodes and edges in the graph.
5. **Chat Interface**: A chat interface for interacting with the copilot, allowing users to ask questions and receive real-time assistance during their vulnerability assessments.
6. **Workflow Management**: A section for invoking different workflows, such as the Guided Inquiry workflow and specific tool workflows, to perform targeted vulnerability assessments.
7. **Telemetry Viewer**: A section for viewing emitted telemetry events, allowing users to monitor the system's performance and behavior.
8. **Settings**: A settings section for configuring the GUI and the copilot's behavior, including options for customizing the knowledge graph, investigation management, and workflow invocation.
9. **Help and Documentation**: A help section providing access to documentation, tutorials, and support resources for users to learn how to use the GUI effectively.
10. **Status Bar**: A status bar at the bottom of the window to display system status, notifications, and other relevant information.
11. **Search Bar**: A search bar for quickly finding specific nodes, edges, or vulnerabilities within the knowledge graph or investigation results.
12. **Export Options**: Options for exporting the knowledge graph, investigation results, and vulnerability assessment reports in various formats (e.g., PDF, CSV, JSON).

## Implementation Guidelines

The GUI code will be in TypeScript with a React frontend and a Python backend. The GUI will be designed to be modular and extensible, allowing for future enhancements and additional features as needed. The following guidelines should be followed during implementation:

### Technical Specifications

- **Frontend Framework**: React with TypeScript (no specific framework like Next.js or Create React App required)
- **Backend**: Python REST API leveraging the same APIs and libraries used in the CLI
- **Deployment**: Web application
- **User Management**: Single-user application without authentication/authorization requirements
- **Graph Visualization**: 3D visualization using the 3d-force-graph library (https://github.com/vasturiano/3d-force-graph) specifically for Neo4j integration
- **Testing**: Flexible choice of testing frameworks (Jest, React Testing Library, etc.) based on development needs

### Design and Development Guidelines

- Use a consistent design language and style throughout the GUI to ensure a cohesive user experience.
- Follow best practices for accessibility and usability, ensuring that the GUI is easy to navigate and use for all users.
- Implement responsive design principles to ensure the GUI works well on different screen sizes and devices.
- Use appropriate libraries and frameworks for graph visualization, chat interfaces, and workflow management to provide a smooth and efficient user experience. For 3D graph visualization we would like to use https://github.com/vasturiano/3d-force-graph
- Ensure that the GUI is well-documented, with clear instructions and examples for users to understand how to use each feature and functionality.
- Implement error handling and logging to capture any issues that may arise during the use of the GUI, providing users with helpful feedback and support.
- Ensure that the GUI is thoroughly tested, with unit tests and integration tests to verify the functionality and performance of each component.
- Use version control (e.g., Git) to manage changes to the GUI code, allowing for easy collaboration and tracking of modifications.

### Backend Integration

- The Python backend will expose REST API endpoints for the frontend to consume
- The backend will leverage the same APIs and libraries used in the CLI version of the copilot, ensuring consistency and compatibility between the two interfaces
- API endpoints should correspond to CLI commands where possible to maintain functionality parity
- Real-time updates for long-running processes should be implemented using appropriate techniques (polling, server-sent events, etc.)

### Data Flow

1. User interacts with React frontend
2. Frontend makes REST API calls to Python backend
3. Backend executes the same code/functionality as the CLI version
4. Results are returned to frontend as JSON
5. Frontend renders the results in an appropriate format (tables, graphs, etc.)

This architecture ensures that the GUI and CLI remain in sync with the same underlying functionality while providing a more visual and interactive experience through the web interface.