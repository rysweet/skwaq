import asyncio
import os
import uuid
from datetime import datetime
from skwaq.db.neo4j_connector import get_connector
from skwaq.visualization.graph_visualizer import GraphVisualizer


async def main():
    """Create a demo visualization of the filesystem, AST, code summaries, and potential sources/sinks."""
    try:
        connector = get_connector()

        # Create a demo investigation
        investigation_id = f"inv-ai-samples-{uuid.uuid4().hex[:8]}"
        print(f"Creating investigation with ID: {investigation_id}")

        # Create investigation node
        connector.run_query(
            """
            CREATE (i:Investigation {
                id: $id,
                title: 'AI Samples Demo',
                description: 'Demo of dotnet/ai-samples',
                status: 'In Progress',
                created_at: datetime()
            })
            RETURN i
            """,
            {"id": investigation_id},
        )

        # Create sample repository
        connector.run_query(
            """
            MATCH (i:Investigation {id: $id})
            CREATE (r:Repository {
                name: 'dotnet/ai-samples',
                url: 'https://github.com/dotnet/ai-samples',
                description: 'AI samples repository from Microsoft'
            })
            CREATE (i)-[:HAS_REPOSITORY]->(r)
            RETURN r
            """,
            {"id": investigation_id},
        )

        # Create filesystem structure
        print("Creating filesystem structure")
        connector.run_query(
            """
            MATCH (i:Investigation {id: $id})
            MATCH (r:Repository)
            WHERE (i)-[:HAS_REPOSITORY]->(r)
            
            // Create some files
            CREATE (f1:File {
                path: '/src/dotnet/Program.cs',
                name: 'Program.cs',
                language: 'csharp'
            })
            CREATE (f2:File {
                path: '/src/dotnet/OpenAIService.cs',
                name: 'OpenAIService.cs',
                language: 'csharp'
            })
            CREATE (f3:File {
                path: '/src/dotnet/Configuration.cs',
                name: 'Configuration.cs',
                language: 'csharp'
            })
            
            // Connect files to repository
            CREATE (f1)-[:PART_OF]->(r)
            CREATE (f2)-[:PART_OF]->(r)
            CREATE (f3)-[:PART_OF]->(r)
            
            // Add a finding for demonstration
            CREATE (finding:Finding {
                type: 'api_key_exposure',
                vulnerability_type: 'Insecure Configuration',
                severity: 'High',
                confidence: 0.85,
                description: 'API key is exposed in configuration file',
                remediation: 'Use Azure Key Vault or other secure storage'
            })
            CREATE (i)-[:HAS_FINDING]->(finding)
            CREATE (finding)-[:FOUND_IN]->(f3)
            
            RETURN f1, f2, f3, finding
            """,
            {"id": investigation_id},
        )

        # Create AST structure
        print("Creating AST structure")
        connector.run_query(
            """
            MATCH (i:Investigation {id: $id})
            MATCH (f1:File {name: 'Program.cs'})
            MATCH (f2:File {name: 'OpenAIService.cs'})
            MATCH (f3:File {name: 'Configuration.cs'})
            WHERE (f1)-[:PART_OF]->()<-[:HAS_REPOSITORY]-(i)
            
            // Create AST nodes for Program.cs
            CREATE (c1:Class {
                name: 'Program',
                namespace: 'AIConsoleApp'
            })
            CREATE (m1:Method {
                name: 'Main',
                signature: 'static async Task Main(string[] args)',
                access: 'public'
            })
            CREATE (f1)-[:DEFINES]->(c1)
            CREATE (c1)-[:DEFINES]->(m1)
            
            // Create AST nodes for OpenAIService.cs
            CREATE (c2:Class {
                name: 'OpenAIService',
                namespace: 'AIConsoleApp.Services'
            })
            CREATE (m2:Method {
                name: 'GetCompletion',
                signature: 'public async Task<string> GetCompletion(string prompt)',
                access: 'public'
            })
            CREATE (f2)-[:DEFINES]->(c2)
            CREATE (c2)-[:DEFINES]->(m2)
            
            // Create AST nodes for Configuration.cs
            CREATE (c3:Class {
                name: 'Configuration',
                namespace: 'AIConsoleApp.Config'
            })
            CREATE (m3:Method {
                name: 'GetApiKey',
                signature: 'public static string GetApiKey()',
                access: 'public'
            })
            CREATE (f3)-[:DEFINES]->(c3)
            CREATE (c3)-[:DEFINES]->(m3)
            
            // Add relationships between classes
            CREATE (c1)-[:REFERENCES]->(c2)
            CREATE (c2)-[:REFERENCES]->(c3)
            
            // Add method calls
            CREATE (m1)-[:CALLS]->(m2)
            CREATE (m2)-[:CALLS]->(m3)
            
            RETURN c1, c2, c3, m1, m2, m3
            """,
            {"id": investigation_id},
        )

        # Create code summaries
        print("Creating code summaries")
        connector.run_query(
            """
            MATCH (i:Investigation {id: $id})
            MATCH (f1:File {name: 'Program.cs'})
            MATCH (f2:File {name: 'OpenAIService.cs'})
            MATCH (f3:File {name: 'Configuration.cs'})
            WHERE (f1)-[:PART_OF]->()<-[:HAS_REPOSITORY]-(i)
            
            // Create summaries
            CREATE (s1:CodeSummary {
                summary: 'Main entry point of the application. Initializes services and prompts user for input to send to OpenAI API.',
                created_at: datetime()
            })
            CREATE (s2:CodeSummary {
                summary: 'Service for interacting with the OpenAI API. Reads API key from configuration and handles API requests.',
                created_at: datetime()
            })
            CREATE (s3:CodeSummary {
                summary: 'Stores configuration values for the application. Contains API key in plain text which is a security concern.',
                created_at: datetime()
            })
            
            // Link summaries to files
            CREATE (f1)-[:HAS_SUMMARY]->(s1)
            CREATE (f2)-[:HAS_SUMMARY]->(s2)
            CREATE (f3)-[:HAS_SUMMARY]->(s3)
            
            RETURN s1, s2, s3
            """,
            {"id": investigation_id},
        )

        # Create sources and sinks
        print("Creating sources and sinks")
        connector.run_query(
            """
            MATCH (i:Investigation {id: $id})
            MATCH (c1:Class {name: 'Program'})
            MATCH (c2:Class {name: 'OpenAIService'})
            MATCH (c3:Class {name: 'Configuration'})
            MATCH (m1:Method {name: 'Main'})
            MATCH (m2:Method {name: 'GetCompletion'})
            MATCH (m3:Method {name: 'GetApiKey'})
            WHERE (c1)-[:DEFINES]->(m1)
            
            // Create sources
            CREATE (source1:Source {
                name: 'User Input',
                source_type: 'user_input',
                description: 'User input from console in Program.Main',
                confidence: 0.9,
                metadata: '{}'
            })
            CREATE (source2:Source {
                name: 'API Key',
                source_type: 'configuration',
                description: 'API key from Configuration.GetApiKey',
                confidence: 0.95,
                metadata: '{}'
            })
            
            // Create sinks
            CREATE (sink1:Sink {
                name: 'API Request',
                sink_type: 'network_send',
                description: 'API request in OpenAIService.GetCompletion',
                confidence: 0.9,
                metadata: '{}'
            })
            CREATE (sink2:Sink {
                name: 'Console Output',
                sink_type: 'logging',
                description: 'Console output in Program.Main',
                confidence: 0.85,
                metadata: '{}'
            })
            
            // Create data flow paths
            CREATE (path1:DataFlowPath {
                vulnerability_type: 'Information Disclosure',
                impact: 'medium',
                description: 'User input is sent to external API',
                recommendations: '["Add content filtering", "Implement rate limiting"]',
                confidence: 0.75,
                metadata: '{}'
            })
            CREATE (path2:DataFlowPath {
                vulnerability_type: 'API Key Exposure',
                impact: 'high',
                description: 'API key stored in plaintext can be exposed',
                recommendations: '["Use secure storage", "Use Azure Key Vault"]',
                confidence: 0.9,
                metadata: '{}'
            })
            
            // Link sources and sinks to the investigation
            CREATE (i)-[:HAS_SOURCE]->(source1)
            CREATE (i)-[:HAS_SOURCE]->(source2)
            CREATE (i)-[:HAS_SINK]->(sink1)
            CREATE (i)-[:HAS_SINK]->(sink2)
            CREATE (i)-[:HAS_DATA_FLOW_PATH]->(path1)
            CREATE (i)-[:HAS_DATA_FLOW_PATH]->(path2)
            
            // Link sources to methods
            CREATE (source1)-[:DEFINED_IN]->(m1)
            CREATE (source2)-[:DEFINED_IN]->(m3)
            
            // Link sinks to methods
            CREATE (sink1)-[:DEFINED_IN]->(m2)
            CREATE (sink2)-[:DEFINED_IN]->(m1)
            
            // Create data flow connections
            CREATE (source1)-[:FLOWS_TO]->(path1)
            CREATE (path1)-[:FLOWS_TO]->(sink1)
            CREATE (source2)-[:FLOWS_TO]->(path2)
            CREATE (path2)-[:FLOWS_TO]->(sink1)
            
            RETURN source1, source2, sink1, sink2, path1, path2
            """,
            {"id": investigation_id},
        )

        # Generate visualization
        print("Generating visualization")
        visualizer = GraphVisualizer()
        graph_data = visualizer.get_investigation_graph(
            investigation_id=investigation_id,
            include_findings=True,
            include_vulnerabilities=True,
            include_files=True,
            include_sources_sinks=True,
            max_nodes=1000,
        )

        # Export as HTML
        output_path = os.path.join(
            os.getcwd(), "docs/demos/ai-samples-visualization.html"
        )
        visualizer.export_graph_as_html(
            graph_data,
            output_path=output_path,
            title="AI Samples: Filesystem, AST, and Code Summary Relationships",
        )

        print(f"Visualization saved to: {output_path}")

    except Exception as e:
        print(f"Error: {str(e)}")
        import traceback

        traceback.print_exc()


if __name__ == "__main__":
    asyncio.run(main())
