# Graphical User Interface for Vulnerability Assessment Copilot

## Overview

The new feature is a graphical user interface (GUI) for the Vulnerability Assessment Copilot. The GUI will provide a user-friendly way to interact with the copilot, allowing users to easily start investigations, visualize graphs, view results, and manage their vulnerability assessments. 

## User Stories to enable
- As a user, I want to be able to view and manage the knowledge graph, potentially adding new sourcesof knowledge, so that I can add or update knowledge in the system.
- As a user, I want to be able to start an investigation by entering a repository URI, so that I can quickly begin my vulnerability assessment.
- As a user, I want to be able to visualize the results of my vulnerability assessment in a graph format, so that I can easily understand the relationships between different components and potential vulnerabilities.
- As a user, I want to be able to use all of the same commands as in the CLI, so that I can have a consistent experience across both interfaces.
- Once a codebase is ingested, I want to be able to view the graph representation of the codebase, so that I can analyze its structure and identify potential vulnerabilities.
- As a user, I want to be able to perform chat based question and answer sessions with the copilot, so that I can get real-time assistance and insights during my vulnerability assessment.
- As user, I want to be able to edit nodes, edges, metadta, and details of the Investigation graph, so that I can customize my analysis and focus on specific areas of interest.
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