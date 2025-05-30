"""Graph visualization for Skwaq investigations."""

import json
from typing import Any, Dict, List, Optional

from ..db.neo4j_connector import get_connector
from ..utils.logging import get_logger

logger = get_logger(__name__)


class GraphVisualizer:
    """Graph visualizer for Skwaq investigations.

    This class provides functionality to visualize investigation graphs
    using D3.js, NetworkX, or other visualization tools.
    """

    def __init__(self) -> None:
        """Initialize the graph visualizer."""
        self.connector = get_connector()
        self.logger = logger

    def get_investigation_graph(
        self,
        investigation_id: str,
        include_findings: bool = True,
        include_vulnerabilities: bool = True,
        include_files: bool = True,
        include_sources_sinks: bool = True,
        max_nodes: int = 100,
    ) -> Dict[str, Any]:
        """Get the graph data for an investigation.

        Args:
            investigation_id: ID of the investigation
            include_findings: Whether to include finding nodes
            include_vulnerabilities: Whether to include vulnerability nodes
            include_files: Whether to include file nodes
            include_sources_sinks: Whether to include Source and Sink nodes from the sources_and_sinks workflow
            max_nodes: Maximum number of nodes to include

        Returns:
            Dictionary with nodes and links
        """
        # Build query based on inclusion options
        included_relationships = []

        if include_findings:
            included_relationships.append("(i)-[:HAS_FINDING]->(f:Finding)")

        if include_vulnerabilities:
            included_relationships.append(
                "(f:Finding)-[:IDENTIFIES]->(v:Vulnerability)"
            )

        if include_files:
            included_relationships.append("(f:Finding)-[:FOUND_IN]->(file:File)")
            included_relationships.append("(file:File)-[:PART_OF]->(repo:Repository)")

        # If no specific inclusions, we'll handle it separately

        # Construct the query - let's rewrite it completely to avoid the variable issues
        query = """
        MATCH (i:Investigation {id: $id})
        """

        # Add each optional match separately
        if include_findings:
            query += """
            OPTIONAL MATCH (i)-[:HAS_FINDING]->(f:Finding)
            """
        else:
            query += """
            WITH i
            """

        if include_vulnerabilities:
            query += """
            OPTIONAL MATCH (f:Finding)-[:IDENTIFIES]->(v:Vulnerability)
            """

        if include_files:
            query += """
            OPTIONAL MATCH (f:Finding)-[:FOUND_IN]->(file:File)
            OPTIONAL MATCH (file:File)-[:PART_OF]->(repo:Repository)
            """

        # Complete the query
        query += """
        RETURN i, 
               COLLECT(DISTINCT f) as findings,
               COLLECT(DISTINCT v) as vulnerabilities,
               COLLECT(DISTINCT file) as files,
               COLLECT(DISTINCT repo) as repositories
        LIMIT $max_nodes
        """

        # Execute the query
        result = self.connector.run_query(
            query, {"id": investigation_id, "max_nodes": max_nodes}
        )

        # If sources_sinks is enabled, get those nodes separately
        sources_sinks_data = {}
        if include_sources_sinks:
            # Query for Source nodes
            sources_query = """
            MATCH (i:Investigation {id: $id})-[:HAS_SOURCE]->(source:Source)
            OPTIONAL MATCH (source)-[:DEFINED_IN]->(sourcefile:File)
            OPTIONAL MATCH (source)-[:REPRESENTS]->(sourcefunc)
            RETURN source, sourcefile, id(sourcefunc) as function_id
            LIMIT $max_nodes
            """
            sources_result = self.connector.run_query(
                sources_query, {"id": investigation_id, "max_nodes": max_nodes}
            )

            # Query for Sink nodes
            sinks_query = """
            MATCH (i:Investigation {id: $id})-[:HAS_SINK]->(sink:Sink)
            OPTIONAL MATCH (sink)-[:DEFINED_IN]->(sinkfile:File)
            OPTIONAL MATCH (sink)-[:REPRESENTS]->(sinkfunc)
            RETURN sink, sinkfile, id(sinkfunc) as function_id
            LIMIT $max_nodes
            """
            sinks_result = self.connector.run_query(
                sinks_query, {"id": investigation_id, "max_nodes": max_nodes}
            )

            # Query for DataFlowPath nodes
            dataflow_query = """
            MATCH (i:Investigation {id: $id})-[:HAS_DATA_FLOW_PATH]->(path:DataFlowPath),
                  (source:Source)-[:FLOWS_TO]->(path)-[:FLOWS_TO]->(sink:Sink)
            RETURN path, id(source) as source_id, id(sink) as sink_id
            LIMIT $max_nodes
            """
            dataflow_result = self.connector.run_query(
                dataflow_query, {"id": investigation_id, "max_nodes": max_nodes}
            )

            sources_sinks_data = {
                "sources": sources_result,
                "sinks": sinks_result,
                "paths": dataflow_result,
            }

        # Process query results into graph data
        return self._process_graph_data(result, investigation_id, sources_sinks_data)

    def _process_graph_data(
        self,
        query_result: List[Dict[str, Any]],
        investigation_id: str,
        sources_sinks_data: Dict[str, List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """Process Neo4j query results into a graph data structure.

        Args:
            query_result: Results from Neo4j query
            investigation_id: ID of the investigation
            sources_sinks_data: Optional data from sources and sinks queries

        Returns:
            Dictionary with nodes and links
        """
        nodes = []
        links = []
        node_ids = set()

        # Helper function to add a node if it doesn't exist yet
        def add_node(
            node_data: Dict[str, Any],
            node_type: str,
            is_funnel_identified: bool = False,
        ) -> None:
            node_id = node_data.get("id") or str(node_data.get("neo4j_id"))

            if node_id in node_ids:
                return

            node_ids.add(node_id)

            # Create node based on type
            node = {
                "id": node_id,
                "label": node_data.get("name") or node_data.get("title") or "Unknown",
                "type": node_type,
                "is_funnel_identified": is_funnel_identified,
                "properties": {
                    k: v for k, v in node_data.items() if k not in ["id", "neo4j_id"]
                },
            }

            # Add specific styling based on node type
            if node_type == "Investigation":
                node["group"] = 1
                node["color"] = "#4b76e8"
            elif node_type == "Finding":
                node["group"] = 2

                # Color based on severity
                severity = node_data.get("severity", "Unknown")
                node["color"] = {
                    "Critical": "#ff0000",
                    "High": "#ff4500",
                    "Medium": "#ffa500",
                    "Low": "#ffcc00",
                    "Info": "#00bfff",
                    "Unknown": "#c0c0c0",
                }.get(severity, "#c0c0c0")

            elif node_type == "Vulnerability":
                node["group"] = 3
                node["color"] = "#e83e8c"
            elif node_type == "File":
                node["group"] = 4
                node["color"] = "#20c997"
            elif node_type == "Repository":
                node["group"] = 5
                node["color"] = "#6610f2"
            elif node_type == "Source":
                node["group"] = 6
                node["color"] = "#02ccfa"  # Bright blue for sources
            elif node_type == "Sink":
                node["group"] = 7
                node["color"] = "#fa7602"  # Orange for sinks
            elif node_type == "DataFlowPath":
                node["group"] = 8
                node["color"] = "#fa0290"  # Pink for data flow paths
            elif node_type == "Function":
                node["group"] = 9
                node["color"] = "#8da0cb"  # Light blue for functions
            elif node_type == "Class":
                node["group"] = 10
                node["color"] = "#e78ac3"  # Pink for classes
            elif node_type == "Method":
                node["group"] = 11
                node["color"] = "#a6d854"  # Light green for methods
            elif node_type == "CodeSummary":
                node["group"] = 12
                node["color"] = "#ffd92f"  # Yellow for code summaries

            # If this is a funnel-identified node, add a highlight
            if is_funnel_identified:
                node["highlight"] = True
                node["stroke_width"] = 3
                node["stroke_color"] = "#FFD700"  # Gold highlight

            nodes.append(node)

        # Helper function to add a link if both nodes exist
        def add_link(source: str, target: str, relationship: str) -> None:
            if source in node_ids and target in node_ids:
                links.append({"source": source, "target": target, "type": relationship})

        # Process the query result - now with collected lists
        if not query_result or len(query_result) == 0:
            # No results found, add placeholder investigation node
            placeholder_node = {
                "id": investigation_id,
                "label": f"Investigation {investigation_id}",
                "type": "Investigation",
                "group": 1,
                "color": "#4b76e8",
                "is_funnel_identified": False,
            }
            nodes.append(placeholder_node)
            node_ids.add(investigation_id)
            return {"nodes": nodes, "links": links}

        row = query_result[0]  # Get the first row since we're using COLLECT

        # Extract investigation node
        investigation = row.get("i", {})
        if investigation:
            add_node(
                {
                    "id": investigation.get("id"),
                    "neo4j_id": id(investigation),
                    **investigation,
                },
                "Investigation",
            )
            investigation_node_id = investigation.get("id") or str(id(investigation))
        else:
            # If no investigation found, add a placeholder
            investigation_node_id = investigation_id
            add_node(
                {"id": investigation_id, "title": f"Investigation {investigation_id}"},
                "Investigation",
            )

        # Process findings
        findings_list = row.get("findings", [])
        for finding in findings_list:
            if finding is None:
                continue

            finding_id = str(id(finding))
            add_node({"neo4j_id": finding_id, **finding}, "Finding")

            # Link investigation to finding
            add_link(investigation_node_id, finding_id, "HAS_FINDING")

        # Process vulnerabilities
        vulnerabilities_list = row.get("vulnerabilities", [])
        for vulnerability in vulnerabilities_list:
            if vulnerability is None:
                continue

            vuln_id = str(id(vulnerability))
            add_node({"neo4j_id": vuln_id, **vulnerability}, "Vulnerability")

            # Find a matching finding to link to
            for finding in findings_list:
                if finding is None:
                    continue
                # Try to find a finding-vulnerability relationship
                add_link(str(id(finding)), vuln_id, "IDENTIFIES")

        # Process files
        files_list = row.get("files", [])
        for file_node in files_list:
            if file_node is None:
                continue

            file_id = str(id(file_node))
            add_node({"neo4j_id": file_id, **file_node}, "File")

            # Link findings to files
            for finding in findings_list:
                if finding is None:
                    continue
                # Try to find a finding-file relationship
                add_link(str(id(finding)), file_id, "FOUND_IN")

        # Process repositories
        repos_list = row.get("repositories", [])
        for repo in repos_list:
            if repo is None:
                continue

            repo_id = str(id(repo))
            add_node({"neo4j_id": repo_id, **repo}, "Repository")

            # Link files to repositories
            for file_node in files_list:
                if file_node is None:
                    continue
                # Try to find a file-repository relationship
                add_link(str(id(file_node)), repo_id, "PART_OF")

        # Process sources and sinks data if available
        if sources_sinks_data:
            # Process source nodes
            for row in sources_sinks_data.get("sources", []):
                source = row.get("source", {})
                if source:
                    # Mark source nodes as funnel-identified
                    add_node(
                        {"neo4j_id": id(source), **source},
                        "Source",
                        is_funnel_identified=True,
                    )

                    # Link to investigation
                    add_link(investigation_node_id, str(id(source)), "HAS_SOURCE")

                    # Link to source file if available
                    source_file = row.get("sourcefile", {})
                    if source_file:
                        file_id = str(id(source_file))

                        # Add file node if it doesn't exist
                        if file_id not in node_ids:
                            add_node(
                                {"neo4j_id": id(source_file), **source_file}, "File"
                            )

                        add_link(str(id(source)), file_id, "DEFINED_IN")

                    # Link to function if available
                    function_id = row.get("function_id")
                    if function_id:
                        function_id = str(function_id)
                        if function_id in node_ids:
                            add_link(str(id(source)), function_id, "REPRESENTS")

            # Process sink nodes
            for row in sources_sinks_data.get("sinks", []):
                sink = row.get("sink", {})
                if sink:
                    # Mark sink nodes as funnel-identified
                    add_node(
                        {"neo4j_id": id(sink), **sink},
                        "Sink",
                        is_funnel_identified=True,
                    )

                    # Link to investigation
                    add_link(investigation_node_id, str(id(sink)), "HAS_SINK")

                    # Link to sink file if available
                    sink_file = row.get("sinkfile", {})
                    if sink_file:
                        file_id = str(id(sink_file))

                        # Add file node if it doesn't exist
                        if file_id not in node_ids:
                            add_node({"neo4j_id": id(sink_file), **sink_file}, "File")

                        add_link(str(id(sink)), file_id, "DEFINED_IN")

                    # Link to function if available
                    function_id = row.get("function_id")
                    if function_id:
                        function_id = str(function_id)
                        if function_id in node_ids:
                            add_link(str(id(sink)), function_id, "REPRESENTS")

            # Process data flow paths
            for row in sources_sinks_data.get("paths", []):
                path = row.get("path", {})
                source_id = row.get("source_id")
                sink_id = row.get("sink_id")

                if path and source_id and sink_id:
                    # Add data flow path node
                    add_node(
                        {"neo4j_id": id(path), **path},
                        "DataFlowPath",
                        is_funnel_identified=True,
                    )

                    # Link to source and sink
                    source_id = str(source_id)
                    sink_id = str(sink_id)

                    # Add links if nodes exist
                    if source_id in node_ids:
                        add_link(source_id, str(id(path)), "FLOWS_TO")

                    if sink_id in node_ids:
                        add_link(str(id(path)), sink_id, "FLOWS_TO")

                    # Link to investigation
                    add_link(investigation_node_id, str(id(path)), "HAS_DATA_FLOW_PATH")

        # If no investigation node was found, add a placeholder
        if not any(node.get("type") == "Investigation" for node in nodes):
            investigation_node = {
                "id": investigation_id,
                "label": f"Investigation {investigation_id}",
                "type": "Investigation",
                "group": 1,
                "color": "#4b76e8",
                "properties": {"id": investigation_id},
                "is_funnel_identified": False,
            }
            nodes.append(investigation_node)

        # Process sources and sinks data if available
        if sources_sinks_data:
            # Process source nodes
            for row in sources_sinks_data.get("sources", []):
                source = row.get("source", {})
                if source:
                    # Mark source nodes as funnel-identified
                    add_node(
                        {"neo4j_id": id(source), **source},
                        "Source",
                        is_funnel_identified=True,
                    )

                    # Link to investigation
                    add_link(investigation_id, str(id(source)), "HAS_SOURCE")

                    # Link to source file if available
                    source_file = row.get("sourcefile", {})
                    if source_file:
                        file_id = str(id(source_file))

                        # Add file node if it doesn't exist
                        if file_id not in node_ids:
                            add_node(
                                {"neo4j_id": id(source_file), **source_file}, "File"
                            )

                        add_link(str(id(source)), file_id, "DEFINED_IN")

                    # Link to function if available
                    function_id = row.get("function_id")
                    if function_id:
                        function_id = str(function_id)
                        if function_id in node_ids:
                            add_link(str(id(source)), function_id, "REPRESENTS")

            # Process sink nodes
            for row in sources_sinks_data.get("sinks", []):
                sink = row.get("sink", {})
                if sink:
                    # Mark sink nodes as funnel-identified
                    add_node(
                        {"neo4j_id": id(sink), **sink},
                        "Sink",
                        is_funnel_identified=True,
                    )

                    # Link to investigation
                    add_link(investigation_id, str(id(sink)), "HAS_SINK")

                    # Link to sink file if available
                    sink_file = row.get("sinkfile", {})
                    if sink_file:
                        file_id = str(id(sink_file))

                        # Add file node if it doesn't exist
                        if file_id not in node_ids:
                            add_node({"neo4j_id": id(sink_file), **sink_file}, "File")

                        add_link(str(id(sink)), file_id, "DEFINED_IN")

                    # Link to function if available
                    function_id = row.get("function_id")
                    if function_id:
                        function_id = str(function_id)
                        if function_id in node_ids:
                            add_link(str(id(sink)), function_id, "REPRESENTS")

            # Process data flow paths
            for row in sources_sinks_data.get("paths", []):
                path = row.get("path", {})
                source_id = row.get("source_id")
                sink_id = row.get("sink_id")

                if path and source_id and sink_id:
                    # Add data flow path node
                    add_node(
                        {"neo4j_id": id(path), **path},
                        "DataFlowPath",
                        is_funnel_identified=True,
                    )

                    # Link to source and sink
                    source_id = str(source_id)
                    sink_id = str(sink_id)

                    # Add links if nodes exist
                    if source_id in node_ids:
                        add_link(source_id, str(id(path)), "FLOWS_TO")

                    if sink_id in node_ids:
                        add_link(str(id(path)), sink_id, "FLOWS_TO")

                    # Link to investigation
                    add_link(investigation_id, str(id(path)), "HAS_DATA_FLOW_PATH")

        # Return the graph data
        return {"nodes": nodes, "links": links}

    def check_ast_summaries(self, investigation_id: Optional[str] = None) -> Dict[str, int]:
        """Check for AST nodes and code summaries in the database.
        
        Args:
            investigation_id: Optional ID of the investigation to check
            
        Returns:
            Dictionary with counts of different node types
        """
        # If investigation_id is provided, check only for that investigation
        if investigation_id:
            ast_query = """
            MATCH (i:Investigation {id: $id})-[:HAS_FINDING]->(f:Finding)-[:FOUND_IN]->(file:File)
            OPTIONAL MATCH (file)-[:DEFINES]->(ast)
            WHERE ast:Function OR ast:Class OR ast:Method
            RETURN COUNT(DISTINCT ast) as ast_count,
                   COUNT(DISTINCT ast WHERE ast.code IS NOT NULL) as ast_with_code_count
            """
            
            summary_query = """
            MATCH (i:Investigation {id: $id})-[:HAS_FINDING]->(f:Finding)-[:FOUND_IN]->(file:File)
            OPTIONAL MATCH (file)-[:DEFINES]->(ast)
            WHERE ast:Function OR ast:Class OR ast:Method
            OPTIONAL MATCH (summary:CodeSummary)-[:DESCRIBES]->(ast)
            RETURN COUNT(DISTINCT summary) as summary_count,
                   COUNT(DISTINCT ast WHERE EXISTS((CodeSummary)-[:DESCRIBES]->(ast))) as ast_with_summary_count
            """
            
            params = {"id": investigation_id}
        else:
            # Check for all AST nodes and summaries in the database
            ast_query = """
            MATCH (ast)
            WHERE ast:Function OR ast:Class OR ast:Method
            RETURN COUNT(ast) as ast_count,
                   COUNT(ast WHERE ast.code IS NOT NULL) as ast_with_code_count
            """
            
            summary_query = """
            MATCH (summary:CodeSummary)-[:DESCRIBES]->(ast)
            WHERE ast:Function OR ast:Class OR ast:Method
            RETURN COUNT(DISTINCT summary) as summary_count,
                   COUNT(DISTINCT ast) as ast_with_summary_count
            """
            
            params = {}
        
        # Execute the queries
        ast_result = self.connector.run_query(ast_query, params)
        summary_result = self.connector.run_query(summary_query, params)
        
        # Extract the counts
        ast_count = 0
        ast_with_code_count = 0
        if ast_result and len(ast_result) > 0:
            ast_count = ast_result[0].get("ast_count", 0)
            ast_with_code_count = ast_result[0].get("ast_with_code_count", 0)
        
        summary_count = 0
        ast_with_summary_count = 0
        if summary_result and len(summary_result) > 0:
            summary_count = summary_result[0].get("summary_count", 0)
            ast_with_summary_count = summary_result[0].get("ast_with_summary_count", 0)
        
        # Log the results
        context = f"for investigation {investigation_id}" if investigation_id else "in the database"
        self.logger.info(f"AST nodes {context}: {ast_count}, AST nodes with code: {ast_with_code_count}")
        self.logger.info(f"Summary count {context}: {summary_count}, AST nodes with summary: {ast_with_summary_count}")
        
        # Return the counts
        return {
            "ast_count": ast_count,
            "ast_with_code_count": ast_with_code_count,
            "summary_count": summary_count,
            "ast_with_summary_count": ast_with_summary_count
        }

    def export_graph_as_json(
        self, graph_data: Dict[str, Any], output_path: Optional[str] = None
    ) -> str:
        """Export the graph data as JSON.

        Args:
            graph_data: Graph data to export
            output_path: Path to write the JSON file to

        Returns:
            Path to the exported file
        """
        # Determine output path
        if not output_path:
            output_path = "investigation_graph.json"

        # Write JSON to file
        with open(output_path, "w") as f:
            json.dump(graph_data, f, indent=2)

        return output_path

    def export_graph_as_html(
        self,
        graph_data: Dict[str, Any],
        output_path: Optional[str] = None,
        title: str = "Investigation Graph",
    ) -> str:
        """Export the graph data as an interactive HTML visualization.

        Args:
            graph_data: Graph data to export
            output_path: Path to write the HTML file to
            title: Title for the visualization

        Returns:
            Path to the exported file
        """
        # Determine output path
        if not output_path:
            output_path = "investigation_graph.html"

        # Create HTML with D3.js visualization
        html = create_interactive_html_visualization(graph_data, title)

        # Write HTML to file
        with open(output_path, "w") as f:
            f.write(html)

        return output_path

    def get_ast_graph(
        self,
        investigation_id: str,
        include_files: bool = True,
        include_summaries: bool = True,
        max_nodes: int = 1000,
    ) -> Dict[str, Any]:
        """Get the AST graph data for an investigation.

        Args:
            investigation_id: ID of the investigation
            include_files: Whether to include file nodes
            include_summaries: Whether to include CodeSummary nodes
            max_nodes: Maximum number of nodes to include

        Returns:
            Dictionary with nodes and links
        """
        # Build a query to fetch AST nodes
        query = """
        MATCH (i:Investigation {id: $id})-[:HAS_FINDING]->(f:Finding)-[:FOUND_IN]->(file:File)
        OPTIONAL MATCH (file)-[:DEFINES]->(ast)
        WHERE ast:Function OR ast:Class OR ast:Method
        """

        if include_summaries:
            query += """
            OPTIONAL MATCH (summary:CodeSummary)-[:DESCRIBES]->(ast)
            """

        # Complete the query
        query += """
        RETURN i, 
               COLLECT(DISTINCT f) as findings,
               COLLECT(DISTINCT file) as files,
               COLLECT(DISTINCT ast) as ast_nodes
        """

        if include_summaries:
            query += ", COLLECT(DISTINCT summary) as summaries"

        query += " LIMIT $max_nodes"

        # Execute the query
        self.logger.info(f"Fetching AST nodes for investigation {investigation_id}")
        result = self.connector.run_query(
            query, {"id": investigation_id, "max_nodes": max_nodes}
        )

        # Process query results into graph data
        return self._process_ast_graph_data(result, investigation_id, include_files, include_summaries)

    def _process_ast_graph_data(
        self,
        query_result: List[Dict[str, Any]],
        investigation_id: str,
        include_files: bool = True,
        include_summaries: bool = True,
    ) -> Dict[str, Any]:
        """Process Neo4j query results into an AST graph data structure.

        Args:
            query_result: Results from Neo4j query
            investigation_id: ID of the investigation
            include_files: Whether to include file nodes
            include_summaries: Whether to include CodeSummary nodes

        Returns:
            Dictionary with nodes and links
        """
        nodes = []
        links = []
        node_ids = set()

        # Helper function to add a node if it doesn't exist yet
        def add_node(
            node_data: Dict[str, Any],
            node_type: str,
            is_highlighted: bool = False,
        ) -> None:
            node_id = node_data.get("id") or str(node_data.get("neo4j_id"))

            if node_id in node_ids:
                return

            node_ids.add(node_id)

            # Create node based on type
            node = {
                "id": node_id,
                "label": node_data.get("name") or node_data.get("title") or "Unknown",
                "type": node_type,
                "properties": {
                    k: v for k, v in node_data.items() if k not in ["id", "neo4j_id"]
                },
            }

            # Add specific styling based on node type
            if node_type == "Investigation":
                node["group"] = 1
                node["color"] = "#4b76e8"
            elif node_type == "Finding":
                node["group"] = 2
                severity = node_data.get("severity", "Unknown")
                node["color"] = {
                    "Critical": "#ff0000",
                    "High": "#ff4500",
                    "Medium": "#ffa500",
                    "Low": "#ffcc00",
                    "Info": "#00bfff",
                    "Unknown": "#c0c0c0",
                }.get(severity, "#c0c0c0")
            elif node_type == "File":
                node["group"] = 4
                node["color"] = "#20c997"
            elif node_type == "Function":
                node["group"] = 9
                node["color"] = "#8da0cb"
            elif node_type == "Class":
                node["group"] = 10
                node["color"] = "#e78ac3"
            elif node_type == "Method":
                node["group"] = 11
                node["color"] = "#a6d854"
            elif node_type == "CodeSummary":
                node["group"] = 12
                node["color"] = "#ffd92f"

            # If this is a highlighted node, add a highlight
            if is_highlighted:
                node["highlight"] = True
                node["stroke_width"] = 3
                node["stroke_color"] = "#FFD700"  # Gold highlight

            nodes.append(node)

        # Helper function to add a link if both nodes exist
        def add_link(source: str, target: str, relationship: str) -> None:
            if source in node_ids and target in node_ids:
                links.append({"source": source, "target": target, "type": relationship})

        # Process the query result - now with collected lists
        if not query_result or len(query_result) == 0:
            # No results found, add placeholder investigation node
            placeholder_node = {
                "id": investigation_id,
                "label": f"Investigation {investigation_id}",
                "type": "Investigation",
                "group": 1,
                "color": "#4b76e8",
            }
            nodes.append(placeholder_node)
            node_ids.add(investigation_id)
            return {"nodes": nodes, "links": links}

        row = query_result[0]  # Get the first row since we're using COLLECT

        # Extract investigation node
        investigation = row.get("i", {})
        if investigation:
            add_node(
                {
                    "id": investigation.get("id"),
                    "neo4j_id": id(investigation),
                    **investigation,
                },
                "Investigation",
            )
            investigation_node_id = investigation.get("id") or str(id(investigation))
        else:
            # If no investigation found, add a placeholder
            investigation_node_id = investigation_id
            add_node(
                {"id": investigation_id, "title": f"Investigation {investigation_id}"},
                "Investigation",
            )

        # Process findings
        findings_list = row.get("findings", [])
        for finding in findings_list:
            if finding is None:
                continue

            finding_id = str(id(finding))
            add_node({"neo4j_id": finding_id, **finding}, "Finding")

            # Link investigation to finding
            add_link(investigation_node_id, finding_id, "HAS_FINDING")

        # Process files if include_files is True
        if include_files:
            files_list = row.get("files", [])
            for file_node in files_list:
                if file_node is None:
                    continue

                file_id = str(id(file_node))
                add_node({"neo4j_id": file_id, **file_node}, "File")

                # Link findings to files
                for finding in findings_list:
                    if finding is None:
                        continue
                    # Try to find a finding-file relationship
                    add_link(str(id(finding)), file_id, "FOUND_IN")

        # Process AST nodes
        ast_nodes_list = row.get("ast_nodes", [])
        for ast_node in ast_nodes_list:
            if ast_node is None:
                continue

            ast_node_id = str(id(ast_node))
            node_type = None
            
            # Determine node type from labels
            if "Function" in ast_node.get("labels", []):
                node_type = "Function"
            elif "Class" in ast_node.get("labels", []):
                node_type = "Class"
            elif "Method" in ast_node.get("labels", []):
                node_type = "Method"
            else:
                # Skip nodes that are not Function, Class, or Method
                continue

            add_node({"neo4j_id": ast_node_id, **ast_node}, node_type)

            # Link files to AST nodes if include_files is True
            if include_files:
                for file_node in files_list:
                    if file_node is None:
                        continue
                    # Check if this file defines the AST node
                    if ast_node.get("file_path") == file_node.get("path"):
                        add_link(str(id(file_node)), ast_node_id, "DEFINES")

        # Process summaries if include_summaries is True
        if include_summaries:
            summaries_list = row.get("summaries", [])
            for summary in summaries_list:
                if summary is None:
                    continue

                summary_id = str(id(summary))
                add_node({"neo4j_id": summary_id, **summary}, "CodeSummary")

                # Find the AST node this summary describes
                for ast_node in ast_nodes_list:
                    if ast_node is None:
                        continue
                    
                    # Check if this summary describes the AST node
                    if summary.get("ast_node_id") == ast_node.get("id"):
                        add_link(summary_id, str(id(ast_node)), "DESCRIBES")

        # Return the graph data
        return {"nodes": nodes, "links": links}

    def export_graph_as_svg(
        self, graph_data: Dict[str, Any], output_path: Optional[str] = None
    ) -> str:
        """Export the graph data as an SVG image.

        Args:
            graph_data: Graph data to export
            output_path: Path to write the SVG file to

        Returns:
            Path to the exported file
        """
        # Determine output path
        if not output_path:
            output_path = "investigation_graph.svg"

        try:
            # Try to use NetworkX and matplotlib for SVG export
            import matplotlib.pyplot as plt
            import networkx as nx

            # Create NetworkX graph
            G = nx.Graph()

            # Add nodes with attributes
            for node in graph_data["nodes"]:
                G.add_node(
                    node["id"],
                    label=node["label"],
                    group=node.get("group", 0),
                    node_type=node["type"],
                )

            # Add edges
            for link in graph_data["links"]:
                G.add_edge(link["source"], link["target"], type=link["type"])

            # Create colors based on node groups
            node_colors = [
                "#4b76e8",  # Investigation
                "#f94144",  # Finding
                "#f8961e",  # Vulnerability
                "#90be6d",  # File
                "#577590",  # Repository
            ]

            colors = [
                node_colors[G.nodes[node].get("group", 0) % len(node_colors)]
                for node in G.nodes()
            ]

            # Create the plot
            plt.figure(figsize=(12, 8))
            pos = nx.spring_layout(G, seed=42)
            nx.draw_networkx_nodes(G, pos, node_size=700, node_color=colors, alpha=0.9)
            nx.draw_networkx_edges(G, pos, width=1.0, alpha=0.7)

            # Add labels
            labels = {node: G.nodes[node]["label"] for node in G.nodes()}
            nx.draw_networkx_labels(G, pos, labels, font_size=8)

            # Save as SVG
            plt.axis("off")
            plt.tight_layout()
            plt.savefig(output_path, format="svg", bbox_inches="tight")
            plt.close()

            return output_path

        except ImportError:
            # Fallback to HTML if NetworkX is not available
            logger.warning(
                "NetworkX and matplotlib not available, falling back to HTML export"
            )
            return self.export_graph_as_html(
                graph_data, output_path.replace(".svg", ".html")
            )


def create_interactive_html_visualization(
    graph_data: Dict[str, Any], 
    title: str = "Graph Visualization",
    enable_filtering: bool = True,
    enable_search: bool = True
) -> str:
    """Create an interactive HTML visualization for graph data.
    
    This enhanced visualization includes:
    - Node type filtering through legend
    - Search functionality for finding nodes
    - Display of AI-generated code summaries
    - Interactive graph exploration
    
    Args:
        graph_data: Graph data with nodes and links
        title: Title for the visualization
        enable_filtering: Enable node type filtering
        enable_search: Enable search functionality
        
    Returns:
        HTML content as a string
    """
    # Import necessary libraries
    import datetime
    import json
    import os
    
    import neo4j.time
    
    # Define a custom encoder for Neo4j data types
    class CustomVisualizationEncoder(json.JSONEncoder):
        """Custom JSON encoder to handle Neo4j data types in visualization."""
        
        def default(self, obj):
            """Handle special types for JSON serialization."""
            if isinstance(obj, neo4j.time.DateTime):
                return obj.to_native().isoformat()
            if isinstance(obj, datetime.datetime):
                return obj.isoformat()
            return super().default(obj)
            
    # Preprocess data to handle special types
    def preprocess_ast_data(data):
        """Pre-process data to handle special data types in nested structures."""
        if isinstance(data, dict):
            for key, value in list(data.items()):
                if isinstance(value, (neo4j.time.DateTime, datetime.datetime)):
                    data[key] = value.isoformat() if hasattr(value, "isoformat") else str(value)
                elif isinstance(value, (dict, list)):
                    data[key] = preprocess_ast_data(value)
        elif isinstance(data, list):
            for i, item in enumerate(data):
                if isinstance(item, (neo4j.time.DateTime, datetime.datetime)):
                    data[i] = item.isoformat() if hasattr(item, "isoformat") else str(item)
                elif isinstance(item, (dict, list)):
                    data[i] = preprocess_ast_data(item)
        return data
        
    # Process graph data
    try:
        processed_data = preprocess_ast_data(graph_data)
        graph_data_json = json.dumps(processed_data, cls=CustomVisualizationEncoder)
    except Exception as e:
        logger.error(f"Error serializing graph data: {str(e)}")
        graph_data_json = json.dumps(graph_data, default=str)
        
    # CSS styles for the visualization
    css_styles = """
        body { 
            margin: 0; 
            font-family: Arial, sans-serif; 
            overflow: hidden; 
            background-color: #f9f9f9;
        }
        .container { 
            display: flex; 
            height: 100vh; 
        }
        .graph { 
            flex: 1; 
            background-color: #ffffff;
            box-shadow: inset 0 0 10px rgba(0,0,0,0.1);
        }
        .sidebar { 
            width: 350px; 
            padding: 20px; 
            background: #f0f2f5; 
            overflow-y: auto;
            box-shadow: -2px 0 5px rgba(0,0,0,0.1);
        }
        .node { 
            stroke: #fff; 
            stroke-width: 1.5px; 
            transition: opacity 0.3s;
        }
        .link { 
            stroke: #999; 
            stroke-opacity: 0.6; 
            transition: opacity 0.3s;
        }
        h1 { 
            font-size: 24px; 
            margin-top: 0; 
            color: #333;
            border-bottom: 1px solid #ddd;
            padding-bottom: 10px;
        }
        h2 { 
            font-size: 18px; 
            margin-top: 20px; 
            color: #444;
        }
        h3 {
            font-size: 16px;
            margin-top: 15px;
            color: #555;
        }
        pre { 
            background: #f1f1f1; 
            padding: 10px; 
            overflow: auto;
            border-radius: 4px;
            font-size: 12px;
            max-height: 300px;
        }
        .controls { 
            margin: 20px 0; 
            background: #fff;
            padding: 15px;
            border-radius: 4px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        }
        button { 
            background: #4b76e8; 
            color: white; 
            border: none; 
            padding: 8px 12px; 
            margin-right: 5px; 
            cursor: pointer;
            border-radius: 4px;
            transition: background-color 0.3s;
        }
        button:hover { 
            background: #3a5bbf; 
        }
        .node-details { 
            margin-top: 20px; 
            background: #fff;
            padding: 15px;
            border-radius: 4px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        }
        .legend { 
            margin-top: 20px; 
            background: #fff;
            padding: 15px;
            border-radius: 4px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        }
        .legend-item { 
            display: flex; 
            align-items: center; 
            margin-bottom: 5px;
            cursor: pointer;
        }
        .legend-item:hover {
            background-color: #f0f0f0;
        }
        .legend-color { 
            width: 15px; 
            height: 15px; 
            margin-right: 8px;
            border-radius: 50%;
        }
        .search-box {
            width: calc(100% - 16px);
            padding: 8px;
            margin-bottom: 10px;
            border: 1px solid #ddd;
            border-radius: 4px;
        }
        .tooltip {
            position: absolute;
            background: white;
            border: 1px solid #ddd;
            padding: 10px;
            border-radius: 5px;
            pointer-events: none;
            opacity: 0;
            max-width: 300px;
            font-size: 12px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.2);
            transition: opacity 0.3s;
        }
        .summary-container {
            background: #f8f8f8;
            border-left: 4px solid #4b76e8;
            padding: 10px;
            margin-top: 10px;
            font-size: 13px;
            white-space: pre-wrap;
            overflow-wrap: break-word;
            max-height: 200px;
            overflow-y: auto;
        }
        .search-results {
            margin-top: 10px;
            max-height: 200px;
            overflow-y: auto;
            background: #f8f8f8;
            border-radius: 4px;
            padding: 5px;
        }
        .search-result-item {
            padding: 5px;
            cursor: pointer;
            border-bottom: 1px solid #eee;
        }
        .search-result-item:hover {
            background-color: #e9f0fd;
        }
        .highlight {
            animation: highlight-pulse 2s infinite;
        }
        @keyframes highlight-pulse {
            0% { stroke-width: 1.5px; stroke: #fff; }
            50% { stroke-width: 4px; stroke: #ffcc00; }
            100% { stroke-width: 1.5px; stroke: #fff; }
        }
    """
    
    # D3.js script for the visualization
    d3_script = """
        // Graph data
        const graphData = """ + graph_data_json + """;
        
        // Track node visibility state
        const nodeVisibility = {};
        let searchHighlightedNodes = new Set();
        
        // Set up the simulation
        const width = document.getElementById('graph').clientWidth;
        const height = document.getElementById('graph').clientHeight;
        
        const svg = d3.select('#graph')
            .append('svg')
            .attr('width', width)
            .attr('height', height);
        
        // Create zoom behavior
        const zoom = d3.zoom()
            .scaleExtent([0.1, 8])
            .on('zoom', (event) => {
                g.attr('transform', event.transform);
            });
        
        // Apply zoom to SVG
        svg.call(zoom);
        
        // Create a group for the graph
        const g = svg.append('g');
        
        // Count node types for legend
        const nodeTypes = {};
        graphData.nodes.forEach(node => {
            nodeTypes[node.type] = (nodeTypes[node.type] || 0) + 1;
            
            // Initialize all nodes as visible
            nodeVisibility[node.id] = true;
        });
        
        // Color mapping for node types
        const colorMap = {
            'File': '#20c997',
            'Function': '#8da0cb',
            'Class': '#e78ac3',
            'Method': '#a6d854',
            'Module': '#fd7e14',
            'Variable': '#ffc107',
            'Parameter': '#17a2b8',
            'CodeSummary': '#ffd92f',
            'FileSummary': '#fc8d62',
            'Investigation': '#4b76e8',
            'Repository': '#6610f2',
            'Finding': '#f94144',
            'Vulnerability': '#e83e8c',
            'Source': '#02ccfa',
            'Sink': '#fa7602',
            'DataFlowPath': '#fa0290'
        };
        
        // Initialize the simulation
        const simulation = d3.forceSimulation(graphData.nodes)
            .force('link', d3.forceLink(graphData.links).id(d => d.id).distance(100))
            .force('charge', d3.forceManyBody().strength(-400))
            .force('center', d3.forceCenter(width / 2, height / 2))
            .force('x', d3.forceX(width / 2).strength(0.05))
            .force('y', d3.forceY(height / 2).strength(0.05))
            .on('tick', ticked);
        
        // Create links
        const link = g.append('g')
            .attr('class', 'links')
            .selectAll('line')
            .data(graphData.links)
            .enter().append('line')
            .attr('class', 'link')
            .attr('stroke', '#999')
            .attr('stroke-opacity', 0.6)
            .attr('stroke-width', d => d.type === 'DEFINES' ? 2 : 1);
        
        // Create nodes
        const node = g.append('g')
            .attr('class', 'nodes')
            .selectAll('circle')
            .data(graphData.nodes)
            .enter().append('circle')
            .attr('class', 'node')
            .attr('r', d => getNodeRadius(d))
            .attr('fill', d => d.color || getNodeColor(d))
            .attr('stroke', '#fff')
            .attr('stroke-width', 1.5)
            .call(d3.drag()
                .on('start', dragstarted)
                .on('drag', dragged)
                .on('end', dragended));
        
        // Add labels to nodes
        const label = g.append('g')
            .attr('class', 'labels')
            .selectAll('text')
            .data(graphData.nodes)
            .enter().append('text')
            .text(d => shortenLabel(d.label, 30))
            .attr('font-size', '10px')
            .attr('dx', 12)
            .attr('dy', 4);
        
        // Create tooltip
        const tooltip = d3.select('body')
            .append('div')
            .attr('class', 'tooltip')
            .style('opacity', 0);
        
        // Add tooltips and click behavior
        node
            .on('mouseover', function(event, d) {
                tooltip.transition()
                    .duration(200)
                    .style('opacity', .9);
                
                // Create tooltip content
                let tooltipContent = `<strong>${d.label}</strong><br/>${d.type}`;
                
                // Add summary if available
                if (d.properties && d.properties.summary) {
                    tooltipContent += `<br/><strong>Summary:</strong><br/><div class="summary-container">${d.properties.summary}</div>`;
                }
                
                tooltip.html(tooltipContent)
                    .style('left', (event.pageX + 10) + 'px')
                    .style('top', (event.pageY - 28) + 'px');
                
                // Highlight connected nodes
                highlightConnectedNodes(d.id);
            })
            .on('mouseout', function() {
                tooltip.transition()
                    .duration(500)
                    .style('opacity', 0);
                
                // Remove highlight
                unhighlightConnectedNodes();
            })
            .on('click', showNodeDetails);
        
        // Build and populate the legend
        buildLegend();
        
        // Setup search functionality
        setupSearch();
        
        // Simulation tick function
        function ticked() {
            link
                .attr('x1', d => d.source.x)
                .attr('y1', d => d.source.y)
                .attr('x2', d => d.target.x)
                .attr('y2', d => d.target.y);
            
            node
                .attr('cx', d => d.x)
                .attr('cy', d => d.y);
            
            label
                .attr('x', d => d.x)
                .attr('y', d => d.y);
        }
        
        // Drag functions
        function dragstarted(event, d) {
            if (!event.active) simulation.alphaTarget(0.3).restart();
            d.fx = d.x;
            d.fy = d.y;
        }
        
        function dragged(event, d) {
            d.fx = event.x;
            d.fy = event.y;
        }
        
        function dragended(event, d) {
            if (!event.active) simulation.alphaTarget(0);
            d.fx = null;
            d.fy = null;
        }
        
        // Helper to determine node radius
        function getNodeRadius(node) {
            switch(node.type) {
                case 'File':
                    return 12;
                case 'Function':
                    return 8;
                case 'Class':
                    return 10;
                case 'Method':
                    return 8;
                case 'Module':
                    return 10;
                case 'Variable':
                    return 6;
                case 'Parameter':
                    return 5;
                case 'CodeSummary':
                    return 9;
                case 'Investigation':
                    return 15;
                case 'Repository':
                    return 13;
                case 'Finding':
                    return 10;
                case 'Vulnerability':
                    return 12;
                case 'Source':
                    return 12;
                case 'Sink':
                    return 12;
                case 'DataFlowPath':
                    return 10;
                default:
                    return 7;
            }
        }
        
        // Helper to determine node color
        function getNodeColor(node) {
            return colorMap[node.type] || '#999';
        }
        
        // Helper to shorten long labels
        function shortenLabel(label, maxLength) {
            if (!label) return '';
            if (label.length <= maxLength) return label;
            return label.substring(0, maxLength - 3) + '...';
        }
        
        // Show node details in sidebar
        function showNodeDetails(event, d) {
            document.getElementById('node-title').textContent = d.label;
            document.getElementById('node-type').textContent = d.type;
            
            const detailsElem = document.getElementById('node-details-content');
            
            // Build details content
            let detailsHtml = '';
            
            // Add summary if available
            if (d.properties && d.properties.summary) {
                detailsHtml += '<h3>Summary</h3>';
                detailsHtml += `<div class="summary-container">${d.properties.summary}</div>`;
            }
            
            // Add code if available
            if (d.properties && d.properties.code) {
                detailsHtml += '<h3>Code</h3>';
                detailsHtml += `<pre>${d.properties.code}</pre>`;
            }
            
            // Add other properties
            detailsHtml += '<h3>Properties</h3>';
            const propertiesToShow = {...d.properties};
            
            // Remove large fields from display
            delete propertiesToShow.code;
            delete propertiesToShow.summary;
            
            detailsHtml += `<pre>${JSON.stringify(propertiesToShow, null, 2)}</pre>`;
            
            // Show relationships
            detailsHtml += '<h3>Relationships</h3>';
            
            // Find connected nodes
            const connections = getConnectedNodes(d.id);
            
            if (connections.sources.length > 0) {
                detailsHtml += '<h4>Incoming</h4>';
                detailsHtml += '<ul>';
                connections.sources.forEach(sourceId => {
                    const sourceNode = graphData.nodes.find(n => n.id === sourceId);
                    if (sourceNode) {
                        detailsHtml += `<li>${sourceNode.type}: ${sourceNode.label}</li>`;
                    }
                });
                detailsHtml += '</ul>';
            }
            
            if (connections.targets.length > 0) {
                detailsHtml += '<h4>Outgoing</h4>';
                detailsHtml += '<ul>';
                connections.targets.forEach(targetId => {
                    const targetNode = graphData.nodes.find(n => n.id === targetId);
                    if (targetNode) {
                        detailsHtml += `<li>${targetNode.type}: ${targetNode.label}</li>`;
                    }
                });
                detailsHtml += '</ul>';
            }
            
            detailsElem.innerHTML = detailsHtml;
        }
        
        // Get connected nodes (both incoming and outgoing)
        function getConnectedNodes(nodeId) {
            const sources = [];
            const targets = [];
            
            graphData.links.forEach(link => {
                if (link.target.id === nodeId || link.target === nodeId) {
                    sources.push(link.source.id || link.source);
                }
                if (link.source.id === nodeId || link.source === nodeId) {
                    targets.push(link.target.id || link.target);
                }
            });
            
            return { sources, targets };
        }
        
        // Highlight connected nodes
        function highlightConnectedNodes(nodeId) {
            // Find all connected nodes
            const connections = getConnectedNodes(nodeId);
            const connectedIds = new Set([...connections.sources, ...connections.targets, nodeId]);
            
            // Highlight/dim nodes
            node.each(function(d) {
                const isConnected = connectedIds.has(d.id);
                d3.select(this).transition().duration(300)
                    .attr('opacity', isConnected ? 1 : 0.3);
            });
            
            // Highlight/dim links
            link.each(function(d) {
                const sourceId = d.source.id || d.source;
                const targetId = d.target.id || d.target;
                const isConnected = (sourceId === nodeId || targetId === nodeId);
                d3.select(this).transition().duration(300)
                    .attr('opacity', isConnected ? 1 : 0.1);
            });
            
            // Highlight/dim labels
            label.each(function(d) {
                const isConnected = connectedIds.has(d.id);
                d3.select(this).transition().duration(300)
                    .attr('opacity', isConnected ? 1 : 0.3);
            });
        }
        
        // Remove highlighting
        function unhighlightConnectedNodes() {
            // Return everything to normal unless we have search highlights
            node.transition().duration(300)
                .attr('opacity', d => searchHighlightedNodes.size > 0 
                    ? (searchHighlightedNodes.has(d.id) ? 1 : 0.3) 
                    : (nodeVisibility[d.id] ? 1 : 0.1));
            
            link.transition().duration(300)
                .attr('opacity', d => {
                    const sourceId = d.source.id || d.source;
                    const targetId = d.target.id || d.target;
                    return (nodeVisibility[sourceId] && nodeVisibility[targetId]) ? 0.6 : 0.1;
                });
            
            label.transition().duration(300)
                .attr('opacity', d => nodeVisibility[d.id] ? 1 : 0.3);
        }
        
        // Build the legend with toggle functionality
        function buildLegend() {
            const legendDiv = document.getElementById('legend-items');
            let legendHtml = '';
            
            // Sort node types by count (descending)
            const sortedNodeTypes = Object.entries(nodeTypes)
                .sort((a, b) => b[1] - a[1]);
            
            sortedNodeTypes.forEach(([type, count]) => {
                const color = colorMap[type] || '#999';
                legendHtml += `
                    <div class="legend-item" data-type="${type}">
                        <div class="legend-color" style="background-color: ${color};"></div>
                        <div>${type} (${count})</div>
                    </div>
                `;
            });
            
            legendDiv.innerHTML = legendHtml;
            
            // Add event listeners to legend items
            document.querySelectorAll('.legend-item').forEach(item => {
                item.addEventListener('click', function() {
                    const nodeType = this.getAttribute('data-type');
                    toggleNodeType(nodeType);
                });
            });
        }
        
        // Toggle nodes of specific type
        function toggleNodeType(nodeType) {
            // Find legend item and toggle opacity
            const legendItem = document.querySelector(`.legend-item[data-type="${nodeType}"]`);
            const isVisible = legendItem.style.opacity !== '0.5';
            
            // Update legend item appearance
            legendItem.style.opacity = isVisible ? '0.5' : '1';
            
            // Update node visibility
            node.each(function(d) {
                if (d.type === nodeType) {
                    nodeVisibility[d.id] = !isVisible;
                    d3.select(this).transition().duration(300)
                        .attr('opacity', !isVisible ? 0.1 : 1);
                }
            });
            
            // Update label visibility
            label.each(function(d) {
                if (d.type === nodeType) {
                    d3.select(this).transition().duration(300)
                        .attr('opacity', !isVisible ? 0.1 : 1);
                }
            });
            
            // Update links
            link.each(function(d) {
                const sourceNode = graphData.nodes.find(n => n.id === (d.source.id || d.source));
                const targetNode = graphData.nodes.find(n => n.id === (d.target.id || d.target));
                
                if (sourceNode && targetNode) {
                    const sourceVisible = sourceNode.type !== nodeType ? nodeVisibility[sourceNode.id] : !isVisible;
                    const targetVisible = targetNode.type !== nodeType ? nodeVisibility[targetNode.id] : !isVisible;
                    
                    d3.select(this).transition().duration(300)
                        .attr('opacity', (sourceVisible && targetVisible) ? 0.6 : 0.1);
                }
            });
        }
        
        // Setup search functionality
        function setupSearch() {
            const searchInput = document.getElementById('search-input');
            const searchResultsDiv = document.getElementById('search-results');
            
            searchInput.addEventListener('input', function() {
                const searchTerm = this.value.toLowerCase().trim();
                
                if (searchTerm.length < 2) {
                    searchResultsDiv.innerHTML = '';
                    // Reset any search highlighting
                    searchHighlightedNodes.clear();
                    node.classed('highlight', false);
                    unhighlightConnectedNodes();
                    return;
                }
                
                // Find matching nodes
                const matchingNodes = graphData.nodes.filter(node => 
                    node.label.toLowerCase().includes(searchTerm) ||
                    (node.properties && node.properties.summary && 
                     node.properties.summary.toLowerCase().includes(searchTerm))
                );
                
                // Display search results
                if (matchingNodes.length > 0) {
                    let resultsHtml = `<div>Found ${matchingNodes.length} matches:</div>`;
                    
                    matchingNodes.forEach(node => {
                        resultsHtml += `
                            <div class="search-result-item" data-node-id="${node.id}">
                                ${node.type}: ${shortenLabel(node.label, 40)}
                            </div>
                        `;
                    });
                    
                    searchResultsDiv.innerHTML = resultsHtml;
                    
                    // Add click handlers to search results
                    document.querySelectorAll('.search-result-item').forEach(item => {
                        item.addEventListener('click', function() {
                            const nodeId = this.getAttribute('data-node-id');
                            centerAndHighlightNode(nodeId);
                        });
                    });
                    
                    // Update highlights on graph
                    searchHighlightedNodes = new Set(matchingNodes.map(n => n.id));
                    
                    // Highlight matching nodes, dim others
                    node.each(function(d) {
                        const isHighlighted = searchHighlightedNodes.has(d.id);
                        d3.select(this)
                            .classed('highlight', isHighlighted)
                            .transition().duration(300)
                            .attr('opacity', isHighlighted ? 1 : 0.3);
                    });
                    
                } else {
                    searchResultsDiv.innerHTML = '<div>No matching nodes found</div>';
                    searchHighlightedNodes.clear();
                    node.classed('highlight', false).attr('opacity', 1);
                }
            });
        }
        
        // Center and highlight a specific node
        function centerAndHighlightNode(nodeId) {
            const nodeData = graphData.nodes.find(n => n.id === nodeId);
            
            if (!nodeData) return;
            
            // Show node details
            showNodeDetails(null, nodeData);
            
            // Ensure node type is visible
            const legendItem = document.querySelector(`.legend-item[data-type="${nodeData.type}"]`);
            if (legendItem && legendItem.style.opacity === '0.5') {
                toggleNodeType(nodeData.type);
            }
            
            // Find the node element
            let nodeElement = null;
            node.each(function(d) {
                if (d.id === nodeId) nodeElement = this;
            });
            
            if (!nodeElement) return;
            
            // Calculate the transform to center on the node
            const transform = d3.zoomIdentity
                .translate(width / 2, height / 2)
                .scale(2)
                .translate(-nodeData.x, -nodeData.y);
            
            // Apply the transform with animation
            svg.transition().duration(750)
                .call(zoom.transform, transform);
            
            // Highlight the node
            d3.select(nodeElement)
                .classed('highlight', true)
                .attr('opacity', 1);
            
            // Highlight connected nodes
            highlightConnectedNodes(nodeId);
        }
        
        // Control buttons
        document.getElementById('zoom-in').addEventListener('click', () => {
            svg.transition().duration(500).call(zoom.scaleBy, 1.5);
        });
        
        document.getElementById('zoom-out').addEventListener('click', () => {
            svg.transition().duration(500).call(zoom.scaleBy, 0.75);
        });
        
        document.getElementById('reset').addEventListener('click', () => {
            svg.transition().duration(500).call(
                zoom.transform, 
                d3.zoomIdentity.translate(width / 2, height / 2).scale(1)
            );
            
            // Reset any search highlighting
            searchHighlightedNodes.clear();
            node.classed('highlight', false);
            unhighlightConnectedNodes();
            
            // Reset the search
            document.getElementById('search-input').value = '';
            document.getElementById('search-results').innerHTML = '';
        });
        
        // Initialize with zoom to fit all content
        document.getElementById('reset').click();
    """
    
    # Build the HTML page with advanced filtering
    html_content = [
        "<!DOCTYPE html>",
        "<html>",
        "<head>",
        "<meta charset='utf-8'>",
        f"<title>{title}</title>",
        "<script src='https://d3js.org/d3.v7.min.js'></script>",
        "<style>",
        css_styles,
        "</style>",
        "</head>",
        "<body>",
        "<div class='container'>",
        "<div class='graph' id='graph'></div>",
        "<div class='sidebar'>",
        f"<h1>{title}</h1>",
        "<div class='controls'>",
        "<button id='zoom-in'>Zoom In</button>",
        "<button id='zoom-out'>Zoom Out</button>",
        "<button id='reset'>Reset</button>",
        "</div>",
    ]
    
    # Add search if enabled
    if enable_search:
        html_content.extend([
            "<div class='controls'>",
            "<h3>Search</h3>",
            "<input type='text' id='search-input' class='search-box' placeholder='Search nodes by name or content...' />",
            "<div id='search-results' class='search-results'></div>",
            "</div>",
        ])
    
    # Add legend if filtering is enabled
    if enable_filtering:
        html_content.extend([
            "<div class='legend'>",
            "<h2>Node Types</h2>",
            "<p>Click a node type to toggle visibility</p>",
            "<div id='legend-items'></div>",
            "</div>",
        ])
    
    # Add node details section and close containers
    html_content.extend([
        "<div class='node-details'>",
        "<h2>Node Details</h2>",
        "<h3 id='node-title'>Select a node to view details</h3>",
        "<p id='node-type'></p>",
        "<div id='node-details-content'></div>",
        "</div>",
        "</div>",
        "</div>",
        "<script>",
        d3_script,
        "</script>",
        "</body>",
        "</html>",
    ])
    
    return "\n".join(html_content)