# CLI Demo for Skwaq Vulnerability Assessment Tool

This demonstration shows how to use the Skwaq tool to analyze a codebase for potential vulnerabilities using the Sources and Sinks workflow with enhanced visualization.

## Step 1: Ingest a Repository

First, we ingest a repository to analyze:

```bash
skwaq repo ingest https://github.com/example/vulnerable-app --name "Vulnerable Demo App"
```

Output:
```
Ingesting repository: https://github.com/example/vulnerable-app
Repository ingested successfully with ID: 42
```

## Step 2: Create an Investigation

Next, we create a new investigation for this repository:

```bash
skwaq investigation create --title "Security Assessment" --repo 42 --description "Comprehensive security analysis of the application"
```

Output:
```
Investigation created successfully: Security Assessment
Investigation ID: inv-46dac8c5
```

## Step 3: Run Sources and Sinks Analysis

Now we run the sources and sinks analysis to identify potential vulnerabilities:

```bash
skwaq workflow sources-and-sinks --investigation inv-46dac8c5
```

Output:
```
Starting sources and sinks analysis on investigation ID: inv-46dac8c5
Analysis complete!

Found 12 sources, 8 sinks, and 5 data flow paths
Results saved to: reports/sources_and_sinks_inv-46dac8c5.markdown

Sources Identified:
1. getUserInput (user_input) - Function retrieves user input from HTTP request parameters...
2. readDatabase (database_read) - Queries database for user records...
... and 10 more sources

Sinks Identified:
1. executeQuery (database_write) - Executes SQL query on database...
2. renderTemplate (html_rendering) - Renders HTML template with dynamic content...
... and 6 more sinks

Potential Data Flow Vulnerabilities:
Vulnerability 1: SQL Injection
Source: getUserInput (user_input)
Sink: executeQuery (database_write)
Impact: high
Description: Unsanitized user input flows directly into SQL query
Recommendations: Use parameterized queries, Apply input validation...

... and 4 more potential vulnerabilities
```

## Step 4: Visualize the Investigation

Finally, we visualize the investigation to see the identified sources, sinks, and data flow paths:

```bash
skwaq investigation visualize --id inv-46dac8c5 --format html
```

Output:
```
Generating graph visualization for investigation inv-46dac8c5...
Visualization saved to: investigation-inv-46dac8c5.html
Graph statistics: 32 nodes, 45 relationships
```

## Interactive Visualization

The visualization below highlights the sources and sinks identified by the workflow, with special highlighting for funnel-identified nodes:

<div style="border: 1px solid #ddd; padding: 20px; margin: 20px 0; background: #f9f9fa;">
  <h3>Investigation Graph: Sources and Sinks Analysis</h3>
  <p>This is where the interactive visualization would be embedded. The actual visualization includes:</p>
  <ul>
    <li>Sources highlighted in bright blue with gold borders</li>
    <li>Sinks highlighted in orange with gold borders</li>
    <li>Data flow paths shown as connections between sources and sinks</li>
    <li>Filtering controls to focus on specific node types</li>
    <li>Interactive tooltips with detailed information</li>
  </ul>
  <div style="display: flex; margin-top: 20px;">
    <div style="flex: 1; padding: 10px;">
      <h4>Example Legend</h4>
      <div style="display: flex; align-items: center; margin-bottom: 5px;">
        <div style="width: 15px; height: 15px; background-color: #02ccfa; margin-right: 8px; border: 2px solid #FFD700;"></div>
        <div>Source (Funnel Identified)</div>
      </div>
      <div style="display: flex; align-items: center; margin-bottom: 5px;">
        <div style="width: 15px; height: 15px; background-color: #fa7602; margin-right: 8px; border: 2px solid #FFD700;"></div>
        <div>Sink (Funnel Identified)</div>
      </div>
      <div style="display: flex; align-items: center; margin-bottom: 5px;">
        <div style="width: 15px; height: 15px; background-color: #fa0290; margin-right: 8px; border: 2px solid #FFD700;"></div>
        <div>DataFlowPath</div>
      </div>
      <div style="display: flex; align-items: center; margin-bottom: 5px;">
        <div style="width: 15px; height: 15px; background-color: #4b76e8; margin-right: 8px;"></div>
        <div>Investigation</div>
      </div>
      <div style="display: flex; align-items: center; margin-bottom: 5px;">
        <div style="width: 15px; height: 15px; background-color: #f94144; margin-right: 8px;"></div>
        <div>Finding</div>
      </div>
    </div>
    <div style="flex: 1; padding: 10px;">
      <h4>Example Node Details</h4>
      <p><strong>getUserInput</strong>: Source (user_input)</p>
      <p>⭐ Funnel Identified</p>
      <p>Confidence: 85%</p>
      <p>Description: Function retrieves user input from HTTP request parameters without sufficient validation</p>
    </div>
  </div>
</div>

## Summary

In this demonstration, we've shown how to:

1. Ingest a repository for analysis
2. Create an investigation
3. Run the sources and sinks workflow to identify potential vulnerabilities
4. Visualize the results with special highlighting for funnel-identified nodes

The enhanced visualization makes it easy to identify potential security issues by highlighting sources and sinks identified by the funnel process, and showing the data flow paths between them.