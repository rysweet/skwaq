"""API routes for knowledge graph visualization and interaction."""

from flask import Blueprint, jsonify, request, abort
from skwaq.db.graph_visualization import GraphVisualizer

bp = Blueprint("knowledge_graph", __name__, url_prefix="/api/knowledge-graph")

# Mock graph data for demonstration purposes
GRAPH_DATA = {
    "nodes": [
        {"id": "n1", "name": "SQL Injection", "type": "vulnerability", "group": 1},
        {
            "id": "n2",
            "name": "Cross-Site Scripting",
            "type": "vulnerability",
            "group": 1,
        },
        {"id": "n3", "name": "CWE-89", "type": "cwe", "group": 2},
        {"id": "n4", "name": "CWE-79", "type": "cwe", "group": 2},
        {"id": "n5", "name": "Input Validation", "type": "concept", "group": 3},
        {"id": "n6", "name": "Database Security", "type": "concept", "group": 3},
        {"id": "n7", "name": "Parameterized Queries", "type": "concept", "group": 3},
        {"id": "n8", "name": "Output Encoding", "type": "concept", "group": 3},
        {"id": "n9", "name": "Prepared Statements", "type": "concept", "group": 3},
        {"id": "n10", "name": "Content Security Policy", "type": "concept", "group": 3},
    ],
    "links": [
        {"source": "n1", "target": "n3", "type": "is_a"},
        {"source": "n2", "target": "n4", "type": "is_a"},
        {"source": "n1", "target": "n5", "type": "related_to"},
        {"source": "n1", "target": "n6", "type": "related_to"},
        {"source": "n2", "target": "n5", "type": "related_to"},
        {"source": "n1", "target": "n7", "type": "mitigated_by"},
        {"source": "n1", "target": "n9", "type": "mitigated_by"},
        {"source": "n2", "target": "n8", "type": "mitigated_by"},
        {"source": "n2", "target": "n10", "type": "mitigated_by"},
        {"source": "n7", "target": "n9", "type": "related_to"},
    ],
}


@bp.route("", methods=["GET"])
def get_graph_data():
    """Get the knowledge graph data with optional filtering."""
    # Extract filter parameters
    node_types = request.args.get("nodeTypes")
    relationship_types = request.args.get("relationshipTypes")
    search_term = request.args.get("searchTerm")

    # Apply filters
    filtered_data = GRAPH_DATA.copy()

    if node_types:
        node_type_list = node_types.split(",")
        filtered_data["nodes"] = [
            node for node in filtered_data["nodes"] if node["type"] in node_type_list
        ]

        # Keep only links where both source and target are in the filtered nodes
        node_ids = {node["id"] for node in filtered_data["nodes"]}
        filtered_data["links"] = [
            link
            for link in filtered_data["links"]
            if link["source"] in node_ids and link["target"] in node_ids
        ]

    if relationship_types:
        relationship_type_list = relationship_types.split(",")
        filtered_data["links"] = [
            link
            for link in filtered_data["links"]
            if link["type"] in relationship_type_list
        ]

    if search_term:
        # Search in node names (case-insensitive)
        search_term = search_term.lower()
        filtered_data["nodes"] = [
            node
            for node in filtered_data["nodes"]
            if search_term in node["name"].lower()
        ]

        # Keep only links where both source and target are in the filtered nodes
        node_ids = {node["id"] for node in filtered_data["nodes"]}
        filtered_data["links"] = [
            link
            for link in filtered_data["links"]
            if link["source"] in node_ids and link["target"] in node_ids
        ]

    return jsonify(filtered_data)


@bp.route("/node-types", methods=["GET"])
def get_node_types():
    """Get all available node types in the knowledge graph."""
    node_types = set(node["type"] for node in GRAPH_DATA["nodes"])
    return jsonify(list(node_types))


@bp.route("/relationship-types", methods=["GET"])
def get_relationship_types():
    """Get all available relationship types in the knowledge graph."""
    relationship_types = set(link["type"] for link in GRAPH_DATA["links"])
    return jsonify(list(relationship_types))


@bp.route("/nodes/<node_id>", methods=["GET"])
def get_node_details(node_id):
    """Get detailed information about a specific node."""
    node = next((node for node in GRAPH_DATA["nodes"] if node["id"] == node_id), None)
    if node is None:
        abort(404, description="Node not found")

    # Add details for demo purposes
    node_details = node.copy()

    if node["type"] == "vulnerability":
        node_details["properties"] = {
            "description": "A security vulnerability that allows attackers to inject malicious code.",
            "severity": "High",
            "impact": "Allows attackers to execute arbitrary commands or access sensitive data.",
            "references": [
                "https://owasp.org/www-community/attacks/SQL_Injection",
                "https://portswigger.net/web-security/sql-injection",
            ],
        }
    elif node["type"] == "cwe":
        node_details["properties"] = {
            "description": "Common Weakness Enumeration - a category of software security flaws.",
            "cweId": node["name"],
            "link": f'https://cwe.mitre.org/data/definitions/{node["name"].split("-")[1]}.html',
        }
    elif node["type"] == "concept":
        node_details["properties"] = {
            "description": "A security concept or principle related to vulnerabilities and mitigations.",
            "relatedConcepts": ["Defense in Depth", "Least Privilege"],
        }

    # Find related nodes through links
    related_nodes = []
    for link in GRAPH_DATA["links"]:
        if link["source"] == node_id:
            target_node = next(
                (n for n in GRAPH_DATA["nodes"] if n["id"] == link["target"]), None
            )
            if target_node:
                related_nodes.append(
                    {
                        "id": target_node["id"],
                        "name": target_node["name"],
                        "type": target_node["type"],
                        "relationshipType": link["type"],
                    }
                )
        elif link["target"] == node_id:
            source_node = next(
                (n for n in GRAPH_DATA["nodes"] if n["id"] == link["source"]), None
            )
            if source_node:
                related_nodes.append(
                    {
                        "id": source_node["id"],
                        "name": source_node["name"],
                        "type": source_node["type"],
                        "relationshipType": link["type"],
                    }
                )

    node_details["relatedNodes"] = related_nodes

    return jsonify(node_details)


@bp.route("/investigation/<investigation_id>", methods=["GET"])
def get_investigation_graph(investigation_id):
    """Get the graph data for a specific investigation.
    
    This endpoint retrieves the graph visualization data for a specific investigation,
    including related nodes like findings, vulnerabilities, and files.
    
    Args:
        investigation_id: The ID of the investigation
        
    Query Parameters:
        include_findings: Whether to include Finding nodes (default: true)
        include_vulnerabilities: Whether to include Vulnerability nodes (default: true)
        include_files: Whether to include File nodes (default: true)
        max_nodes: Maximum number of nodes to include (default: 100)
        
    Returns:
        A JSON object with nodes and links arrays for visualization
    """
    # Extract query parameters
    include_findings = request.args.get("include_findings", "true").lower() == "true"
    include_vulnerabilities = request.args.get("include_vulnerabilities", "true").lower() == "true"
    include_files = request.args.get("include_files", "true").lower() == "true"
    max_nodes = int(request.args.get("max_nodes", "100"))
    
    # Create graph visualizer and get investigation graph
    try:
        graph_visualizer = GraphVisualizer()
        graph_data = graph_visualizer.get_investigation_graph(
            investigation_id=investigation_id,
            include_findings=include_findings,
            include_vulnerabilities=include_vulnerabilities,
            include_files=include_files,
            max_nodes=max_nodes
        )
        
        # Transform the data format to be compatible with 3d-force-graph
        # GraphVisualizer returns nodes with "id" and "label", but we need "id" and "name"
        nodes = []
        for node in graph_data["nodes"]:
            formatted_node = {
                "id": node["id"],
                "name": node.get("label", ""),
                "type": node.get("type", "unknown"),
                "group": {
                    "investigation": 1,
                    "repository": 2,
                    "finding": 3,
                    "vulnerability": 4,
                    "file": 5,
                }.get(node.get("type", ""), 6),
                "properties": node.get("properties", {})
            }
            nodes.append(formatted_node)
        
        # Links should have source, target and type
        links = []
        for link in graph_data["links"]:
            formatted_link = {
                "source": link["source"],
                "target": link["target"],
                "type": link.get("type", "related")
            }
            links.append(formatted_link)
        
        return jsonify({"nodes": nodes, "links": links})
    
    except Exception as e:
        # Log the error and return a 500 error
        print(f"Error retrieving investigation graph: {str(e)}")
        abort(500, description=f"Error retrieving investigation graph: {str(e)}")
