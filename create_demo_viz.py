import asyncio
import os
import json
from skwaq.db.neo4j_connector import get_connector
from skwaq.visualization.graph_visualizer import GraphVisualizer


async def generate_demo():
    # Create test investigation if it doesn't exist
    connector = get_connector()

    # Check if test investigation exists
    result = connector.run_query(
        """
        MATCH (i:Investigation {id: 'inv-demo-viz'})
        RETURN i
        """
    )

    if not result:
        print("Creating test investigation")
        # Create test investigation node
        connector.run_query(
            """
            CREATE (i:Investigation {
                id: 'inv-demo-viz',
                title: 'Demo Investigation',
                description: 'Demo for visualization',
                created_at: datetime(),
                status: 'In Progress'
            })
            RETURN i
            """
        )

    # Create some test nodes (Source, Sink, DataFlowPath)
    # This would normally be done by the sources_and_sinks workflow
    print("Creating test source and sink nodes")
    connector.run_query(
        """
        MATCH (i:Investigation {id: 'inv-demo-viz'})
        
        // Create test files if they don't exist
        MERGE (f1:File {path: '/app/user/input.py', name: 'input.py'})
        MERGE (f2:File {path: '/app/db/query.py', name: 'query.py'})
        
        // Create source node
        MERGE (source:Source {
            name: 'getUserInput',
            source_type: 'user_input',
            description: 'Gets user input from request parameters',
            confidence: 0.85,
            metadata: '{}'
        })
        MERGE (i)-[:HAS_SOURCE]->(source)
        MERGE (source)-[:DEFINED_IN]->(f1)
        
        // Create sink node
        MERGE (sink:Sink {
            name: 'executeQuery',
            sink_type: 'database_write',
            description: 'Executes SQL query on database',
            confidence: 0.9,
            metadata: '{}'
        })
        MERGE (i)-[:HAS_SINK]->(sink)
        MERGE (sink)-[:DEFINED_IN]->(f2)
        
        // Create data flow path
        MERGE (path:DataFlowPath {
            vulnerability_type: 'SQL Injection',
            impact: 'high',
            description: 'Unsanitized user input flows directly into SQL query',
            recommendations: '["Use parameterized queries", "Apply input validation"]',
            confidence: 0.8,
            metadata: '{}'
        })
        MERGE (i)-[:HAS_DATA_FLOW_PATH]->(path)
        MERGE (source)-[:FLOWS_TO]->(path)
        MERGE (path)-[:FLOWS_TO]->(sink)
        
        RETURN *
        """
    )

    # Create the HTML visualization
    print("Generating visualization")
    visualizer = GraphVisualizer()
    graph_data = visualizer.get_investigation_graph(
        investigation_id="inv-demo-viz",
        include_findings=True,
        include_vulnerabilities=True,
        include_files=True,
        include_sources_sinks=True,
    )

    # Export as HTML
    output_path = "/Users/ryan/src/msechackathon/vuln-researcher/docs/demos/investigation-demo.html"
    visualizer.export_graph_as_html(
        graph_data, output_path=output_path, title="Demo Investigation Visualization"
    )

    print(f"Visualization saved to: {output_path}")


asyncio.run(generate_demo())
