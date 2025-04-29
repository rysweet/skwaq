"""Script to generate a graph visualization of the ingested Flask repository."""

from skwaq.db.graph_visualization import GraphVisualizer
from skwaq.db.neo4j_connector import get_connector

# Initialize the graph visualizer
viz = GraphVisualizer()
connector = get_connector()

# Get the nodes and relationships from Neo4j
results = connector.run_query(
    "MATCH (f:File)-[r:DEFINES]->(func:Function) RETURN f, r, func LIMIT 100"
)
print(f"Found {len(results)} file-function relationships")

# Prepare the graph data
nodes = []
links = []
node_ids = {}

for i, result in enumerate(results):
    file_node = result["f"]
    func_node = result["func"]

    # Assign unique IDs to nodes
    if file_node.element_id not in node_ids:
        file_id = len(node_ids)
        node_ids[file_node.element_id] = file_id
        nodes.append(
            {
                "id": file_id,
                "name": file_node["name"],
                "type": "File",
                "language": file_node.get("language", ""),
            }
        )
    else:
        file_id = node_ids[file_node.element_id]

    if func_node.element_id not in node_ids:
        func_id = len(node_ids)
        node_ids[func_node.element_id] = func_id
        nodes.append(
            {
                "id": func_id,
                "name": func_node["name"],
                "type": "Function",
                "language": func_node.get("language", ""),
            }
        )
    else:
        func_id = node_ids[func_node.element_id]

    # Create a link
    links.append({"source": file_id, "target": func_id, "type": "DEFINES"})

# Create the graph data
graph_data = {"nodes": nodes, "links": links}

# Export as HTML
print(f"Exporting graph with {len(nodes)} nodes and {len(links)} links")
viz.export_graph_as_html(
    graph_data=graph_data, output_path="flask-graph.html", title="Flask Code Graph"
)

print("Graph visualization saved to flask-graph.html")
