# Skwaq GUI Guide

## Overview

Skwaq's Graphical User Interface (GUI) provides a user-friendly way to interact with the Vulnerability Assessment Copilot. This web-based interface offers intuitive visualization, interactive workflows, and real-time feedback for vulnerability assessment tasks.

## Getting Started

### Prerequisites

Before running the GUI, ensure you have the following prerequisites installed:

- Node.js (v16.0.0 or later)
- npm (v8.0.0 or later)
- Python (v3.10 or later)
- Flask (v2.0.0 or later)

### Installation

1. Clone the repository if you haven't already:
   ```bash
   git clone https://github.com/rysweet/skwaq
   cd skwaq
   ```

2. Install Python dependencies:
   ```bash
   pip install -e .
   ```

3. Install frontend dependencies:
   ```bash
   cd skwaq/frontend
   npm install
   ```

### Running the GUI

The easiest way to run the GUI is using the provided development script:

```bash
./scripts/dev/run-dev.sh
```

This script will:
1. Start the Flask backend server on port 5000
2. Start the React development server on port 3000
3. Open your browser to http://localhost:3000

Alternatively, you can start the components separately:

1. Start the backend:
   ```bash
   cd /path/to/skwaq
   python -m skwaq.api.app
   ```

2. Start the frontend:
   ```bash
   cd /path/to/skwaq/skwaq/frontend
   npm start
   ```

## Main Features

### Dashboard

The dashboard provides an overview of your current vulnerability assessment activities, including:

- Active repositories under analysis
- Recent activities and notifications
- Quick actions for common tasks
- Current vulnerability statistics

### Knowledge Graph

The knowledge graph visualization allows you to explore the relationships between:

- Vulnerability types
- Common Weakness Enumerations (CWEs)
- Security concepts
- Mitigation strategies

The 3D interactive graph lets you:
- Rotate, zoom, and pan to explore relationships
- Click on nodes to see detailed information
- Filter by node types or relationship types
- Search for specific entities

### Code Analysis

The code analysis section enables you to:

- Add repositories for analysis
- View analysis progress in real-time
- See detected vulnerabilities and their details
- Re-analyze repositories with different settings

### Vulnerability Assessment

The vulnerability assessment section offers three ways to conduct assessments:

1. **Guided Assessment**: A step-by-step approach that walks you through the assessment process
2. **Chat Interface**: Natural language interaction with the Copilot to ask security questions
3. **Workflows**: Pre-configured assessment workflows for specific scenarios or standards

### Settings

The settings section allows you to configure:

- API connections
- Tool integrations
- User interface preferences
- Database management
- System information

## Keyboard Shortcuts

| Shortcut       | Action                       |
|----------------|------------------------------|
| `?`            | Show help overlay            |
| `Ctrl+/`       | Focus search bar             |
| `Esc`          | Close modal or cancel action |
| `Ctrl+Enter`   | Submit form                  |
| `Alt+1` to `5` | Navigate to main sections    |

## Tips & Tricks

- **Hover Tooltips**: Hover over elements to see additional information and guidance
- **Context Menus**: Right-click on elements for additional actions
- **Persistent Sessions**: Sessions are preserved when you close the browser
- **Dark Mode**: Toggle dark mode in the settings or press `Alt+D`
- **Export Reports**: Generate reports in various formats from the assessment results

## Troubleshooting

### Common Issues

1. **GUI fails to load**:
   - Ensure both backend and frontend servers are running
   - Check console for JavaScript errors
   - Verify your browser supports modern JavaScript features

2. **Backend connection errors**:
   - Verify Flask server is running on port 5000
   - Check for firewall or proxy issues
   - Ensure API base URL is correctly configured

3. **Slow graph visualization**:
   - Reduce the number of displayed nodes with filters
   - Enable performance mode in the graph settings
   - Use a more powerful GPU if available

### Support

If you encounter any issues or have questions about the GUI:

1. Check the [troubleshooting guide](troubleshooting.md)
2. Report issues on the GitHub repository
3. Refer to the [API documentation](api_reference.md)

## Integration with CLI

The GUI and CLI share the same underlying capabilities. You can:

- Start an assessment in the GUI and continue in the CLI
- Import CLI results into the GUI for visualization
- Use CLI for automation and GUI for exploration/visualization
- Share session data between both interfaces

## License and Credits

Skwaq GUI uses the following open-source libraries:

- React for the user interface
- 3d-force-graph for knowledge graph visualization
- Flask for the backend API
- TypeScript for type-safe code