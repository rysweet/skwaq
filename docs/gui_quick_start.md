# Skwaq GUI Quick Start Guide

This guide provides the essential information to get started with the Skwaq Vulnerability Assessment Copilot GUI.

## Installation & Setup

### Prerequisites
- Node.js v16+
- Python 3.10+
- Git

### Quick Install

1. Clone the repository:
   ```bash
   git clone https://github.com/rysweet/skwaq
   cd skwaq
   ```

2. Install all dependencies:
   ```bash
   pip install -e .
   cd skwaq/frontend
   npm install
   cd ../..
   ```

3. Start the GUI:
   ```bash
   ./scripts/dev/run-dev.sh
   ```

4. Open your browser to [http://localhost:3000](http://localhost:3000)

## 5-Minute Getting Started

### 1. Add a Repository

1. Click the "Code Analysis" tab in the sidebar
2. Click "Add Repository" 
3. Enter a GitHub repository URL (e.g., `https://github.com/example/vulnerable-app`)
4. Click "Add Repository" to start the analysis

### 2. Explore the Knowledge Graph

1. Click the "Knowledge Graph" tab in the sidebar
2. Use mouse to rotate, scroll to zoom, and drag to move
3. Click on nodes to see details about vulnerabilities and security concepts
4. Use filters to show only specific types of information

### 3. Perform a Vulnerability Assessment

1. Click the "Vulnerability Assessment" tab
2. Select the "Guided Assessment" tab
3. Select your repository and follow the step-by-step instructions
4. Alternatively, use the "Chat" tab to ask questions about security vulnerabilities

### 4. View Results

1. Return to the "Dashboard" to see an overview of findings
2. Click on vulnerabilities to see detailed information
3. Use the export options to generate reports

## Key Features

- **3D Knowledge Graph**: Interactive visualization of security knowledge
- **Repository Analysis**: Automatic scanning of code repositories
- **Guided Assessments**: Step-by-step vulnerability assessment workflows
- **Chat Interface**: Natural language interaction with the Copilot
- **Comprehensive Reporting**: Detailed vulnerability reports with remediation suggestions

## Getting Help

- Hover over UI elements to see tooltips with additional information
- Press `?` anywhere in the application to see keyboard shortcuts
- Click the help icon (❓) in the top-right corner for context-specific help
- Refer to the [Complete GUI Guide](gui_guide.md) for detailed documentation

## Next Steps

- [Complete GUI Guide](gui_guide.md)
- [CLI Documentation](cli_guide.md)
- [API Reference](api_reference.md)
- [Troubleshooting](troubleshooting.md)