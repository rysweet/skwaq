"""AST visualization module for Skwaq."""

import os
from typing import Any, Dict, List, Optional, Set

from ..db.neo4j_connector import get_connector
from ..utils.logging import get_logger
from .graph_visualizer import GraphVisualizer, create_interactive_html_visualization

logger = get_logger(__name__)


class ASTVisualizer:
    """AST visualizer for Skwaq.
    
    This class provides specialized functionality for visualizing Abstract Syntax Trees (AST)
    with AI-generated code summaries.
    """

    def __init__(self) -> None:
        """Initialize the AST visualizer."""
        self.connector = get_connector()
        self.logger = logger
        self.graph_visualizer = GraphVisualizer()

    def check_ast_summaries(self, investigation_id: Optional[str] = None) -> Dict[str, int]:
        """Check for AST nodes and code summaries in the database.
        
        Args:
            investigation_id: Optional ID of the investigation to check
            
        Returns:
            Dictionary with counts of different node types
        """
        return self.graph_visualizer.check_ast_summaries(investigation_id)

    def visualize_ast(
        self,
        investigation_id: Optional[str] = None,
        repo_id: Optional[str] = None,
        include_files: bool = True,
        include_summaries: bool = True,
        max_nodes: int = 1000,
        output_path: Optional[str] = None,
        title: str = "AST Visualization with Code Summaries",
    ) -> str:
        """Create an interactive visualization of AST nodes with summaries.
        
        Args:
            investigation_id: Optional ID of the investigation
            repo_id: Optional ID of the repository
            include_files: Whether to include file nodes
            include_summaries: Whether to include code summary nodes
            max_nodes: Maximum number of nodes to include
            output_path: Path to save the visualization HTML
            title: Title for the visualization
            
        Returns:
            Path to the saved visualization
        """
        # Set for tracking added node IDs
        node_ids: Set[str] = set()
        
        # Create graph data structure
        graph_data: Dict[str, Any] = {
            "nodes": [],
            "links": []
        }
        
        # Get repository information if repo_id is provided
        repo_info = None
        if repo_id:
            repo_query = """
            MATCH (r:Repository)
            WHERE r.ingestion_id = $repo_id OR elementId(r) = $repo_id
            RETURN r.name as name, elementId(r) as id, r.path as path
            """
            repo_results = self.connector.run_query(repo_query, {"repo_id": repo_id})
            if repo_results:
                repo_info = repo_results[0]
        
        # Get investigation information if investigation_id is provided
        investigation_info = None
        if investigation_id:
            inv_query = """
            MATCH (i:Investigation {id: $id})
            RETURN i.title as title, elementId(i) as id
            """
            inv_results = self.connector.run_query(inv_query, {"id": investigation_id})
            if inv_results:
                investigation_info = inv_results[0]
        
        # Add root node (repository or investigation)
        root_id = "root"
        root_label = "Code Graph"
        root_type = "Root"
        
        if repo_info:
            root_id = str(repo_info["id"])
            root_label = f"Repository: {repo_info['name']}"
            root_type = "Repository"
        elif investigation_info:
            root_id = str(investigation_info["id"])
            root_label = f"Investigation: {investigation_info['title']}"
            root_type = "Investigation"
        
        graph_data["nodes"].append({
            "id": root_id,
            "label": root_label,
            "type": root_type,
            "color": "#6610f2" if root_type == "Repository" else "#4b76e8" # Purple for repos, blue for investigations
        })
        node_ids.add(root_id)
        
        # Query for files
        file_query = """
        MATCH (file:File)
        """
        
        if repo_info:
            file_query += """
            MATCH (r:Repository)-[:CONTAINS]->(file)
            WHERE elementId(r) = $root_id
            """
        elif investigation_id:
            file_query += """
            MATCH (i:Investigation {id: $investigation_id})-[:HAS_FINDING]->(f:Finding)-[:FOUND_IN]->(file)
            """
        else:
            file_query += """
            WHERE true
            """
        
        file_query += """
        RETURN 
            elementId(file) as file_id,
            file.name as file_name,
            file.path as file_path,
            file.summary as file_summary
        LIMIT 100
        """
        
        params = {}
        if repo_info:
            params["root_id"] = repo_info["id"]
        if investigation_id:
            params["investigation_id"] = investigation_id
        
        file_results = self.connector.run_query(file_query, params)
        self.logger.info(f"Found {len(file_results)} files...")
        
        # Add file nodes and connect to root
        for file in file_results:
            file_id = str(file["file_id"])
            
            if file_id not in node_ids:
                node_ids.add(file_id)
                graph_data["nodes"].append({
                    "id": file_id,
                    "label": file["file_name"] or os.path.basename(file["file_path"] or "Unknown"),
                    "type": "File",
                    "properties": {
                        "path": file["file_path"],
                        "summary": file["file_summary"]
                    },
                    "color": "#20c997"  # Teal for files
                })
                
                # Connect to root
                graph_data["links"].append({
                    "source": root_id,
                    "target": file_id,
                    "type": "CONTAINS" if root_type == "Repository" else "FOUND_IN"
                })
        
        # Query for AST nodes connected to these files
        if file_results:
            file_ids = [file["file_id"] for file in file_results]
            
            ast_query = """
            MATCH (ast)-[:PART_OF]->(file)
            WHERE elementId(file) IN $file_ids 
                  AND (ast:Function OR ast:Class OR ast:Method)
            RETURN 
                elementId(ast) as ast_id,
                ast.name as ast_name,
                ast.code as ast_code,
                labels(ast) as ast_labels,
                ast.start_line as start_line,
                ast.end_line as end_line,
                elementId(file) as file_id
            LIMIT 1000
            """
            
            ast_results = self.connector.run_query(ast_query, {"file_ids": file_ids})
            self.logger.info(f"Found {len(ast_results)} AST nodes...")
            
            # Add AST nodes and connect to files
            for ast in ast_results:
                ast_id = str(ast["ast_id"])
                file_id = str(ast["file_id"])
                
                if ast_id not in node_ids:
                    node_ids.add(ast_id)
                    node_type = ast["ast_labels"][0] if ast["ast_labels"] else "Unknown"
                    
                    graph_data["nodes"].append({
                        "id": ast_id,
                        "label": ast["ast_name"] or "Unnamed AST Node",
                        "type": node_type,
                        "properties": {
                            "start_line": ast["start_line"],
                            "end_line": ast["end_line"],
                            "code": ast["ast_code"]
                        },
                        "color": "#8da0cb" if node_type == "Function" else 
                                "#e78ac3" if node_type == "Class" else
                                "#a6d854" if node_type == "Method" else "#999999"
                    })
                    
                    # Connect to file
                    graph_data["links"].append({
                        "source": ast_id,
                        "target": file_id,
                        "type": "PART_OF"
                    })
                    
                    graph_data["links"].append({
                        "source": file_id,
                        "target": ast_id,
                        "type": "DEFINES"
                    })
        
        # Query for summary nodes
        if include_summaries:
            summary_query = """
            MATCH (summary:CodeSummary)-[:DESCRIBES]->(target)
            WHERE elementId(target) IN $node_ids
            RETURN 
                elementId(summary) as summary_id,
                summary.summary as summary_text,
                summary.summary_type as summary_type,
                elementId(target) as target_id
            """
            
            all_ids = [int(node_id) for node_id in node_ids if node_id.isdigit()]
            summary_results = self.connector.run_query(summary_query, {"node_ids": all_ids})
            self.logger.info(f"Found {len(summary_results)} code summaries...")
            
            # Add summary nodes
            for summary in summary_results:
                summary_id = str(summary["summary_id"])
                target_id = str(summary["target_id"])
                
                if summary_id not in node_ids:
                    node_ids.add(summary_id)
                    summary_text = summary["summary_text"] or "No summary available"
                    short_summary = summary_text[:30] + "..." if len(summary_text) > 30 else summary_text
                    
                    # Determine summary type and color
                    summary_type = summary["summary_type"] or "unknown"
                    summary_color = "#ffd92f"  # Yellow for code summaries
                    if summary_type == "file":
                        summary_color = "#fc8d62"  # Orange-red for file summaries
                    
                    graph_data["nodes"].append({
                        "id": summary_id,
                        "label": f"Summary: {short_summary}",
                        "type": "CodeSummary",
                        "properties": {
                            "summary": summary_text,
                            "summary_type": summary_type
                        },
                        "color": summary_color
                    })
                    
                    # Connect to target
                    graph_data["links"].append({
                        "source": summary_id,
                        "target": target_id,
                        "type": "DESCRIBES"
                    })
        
        # Generate HTML with the advanced interactive visualization
        if not output_path:
            # Default output name based on source
            if investigation_id:
                output_path = f"investigation-{investigation_id}-ast-visualization.html"
            elif repo_id:
                output_path = f"repository-{repo_id}-ast-visualization.html"
            else:
                output_path = "ast-visualization.html"
        
        self.logger.info(f"Creating visualization with {len(graph_data['nodes'])} nodes and {len(graph_data['links'])} links...")
        
        # Create visualization HTML
        html_content = create_interactive_html_visualization(
            graph_data,
            title=title,
            enable_filtering=True,
            enable_search=True
        )
        
        # Write to file
        with open(output_path, "w") as f:
            f.write(html_content)
        
        self.logger.info(f"Visualization saved to {output_path}")
        
        # Show node statistics
        node_types = {}
        for node in graph_data['nodes']:
            node_type = node.get('type', 'Unknown')
            node_types[node_type] = node_types.get(node_type, 0) + 1
        
        node_stats = ", ".join([f"{count} {node_type}" for node_type, count in node_types.items()])
        self.logger.info(f"Graph statistics: {len(graph_data['nodes'])} nodes ({node_stats}), {len(graph_data['links'])} relationships")
                
        return output_path