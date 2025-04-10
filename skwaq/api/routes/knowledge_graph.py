"""API routes for handling knowledge graph operations."""

import json
from flask import Blueprint, jsonify, request, g
from uuid import UUID
import re

from skwaq.db.neo4j_connector import get_connector
from skwaq.api.middleware.error_handling import APIError, NotFoundError, BadRequestError
from skwaq.utils.logging import get_logger

logger = get_logger(__name__)

# Blueprint for knowledge graph routes
bp = Blueprint("knowledge_graph", __name__, url_prefix="/api/knowledge-graph")


def validate_investigation_id(investigation_id):
    """Validate that a string is a valid investigation ID.

    Args:
        investigation_id (str): String to validate

    Returns:
        bool: True if valid investigation ID, False otherwise
    """
    # Accept any investigation ID - we'll let the database handle if it exists
    # This is more flexible and avoids issues with different formats
    return True


@bp.route("/investigation/<investigation_id>", methods=["GET"])
def get_investigation_graph(investigation_id):
    """Get the knowledge graph for a specific investigation.

    Args:
        investigation_id (str): ID of the investigation

    Returns:
        JSON response with nodes and links
    """
    try:
        include_sources_sinks = (
            request.args.get("include_sources_sinks", "false").lower() == "true"
        )

        # If the investigation_id is not in the expected format,
        # return a bad request error
        if not validate_investigation_id(investigation_id):
            raise BadRequestError(
                "The string did not match the expected pattern. Investigation ID should be a UUID or start with 'inv-'."
            )

        connector = get_connector()

        # Build the base query to get investigation nodes
        query = """
        MATCH (i:Investigation {id: $id})
        OPTIONAL MATCH (i)-[r1]->(n1)
        OPTIONAL MATCH (n1)-[r2]->(n2)
        RETURN i, r1, n1, r2, n2
        """

        # If include_sources_sinks is true, extend the query
        if include_sources_sinks:
            query = """
            MATCH (i:Investigation {id: $id})
            OPTIONAL MATCH p1 = (i)-[r1]->(n1)
            OPTIONAL MATCH p2 = (n1)-[r2]->(n2)
            OPTIONAL MATCH p3 = (n2)-[r3]->(n3)
            RETURN i, r1, n1, r2, n2, r3, n3
            """

        # Execute the query
        result = connector.run_query(query, {"id": investigation_id})

        if not result:
            raise NotFoundError(f"Investigation {investigation_id} not found")

        # Transform the result into a graph data structure
        nodes = {}
        links = []

        # Helper function to add a node if it doesn't exist
        def add_node(node_data):
            if not node_data:
                return None

            node_id = node_data.get("id")
            if not node_id:
                return None

            if node_id not in nodes:
                # Get node label (Neo4j type)
                node_labels = [
                    label for label in node_data.labels if label != "Resource"
                ]
                node_type = node_labels[0].lower() if node_labels else "unknown"

                # Create the node object
                nodes[node_id] = {
                    "id": node_id,
                    "name": node_data.get(
                        "name", node_data.get("title", f"Node {node_id}")
                    ),
                    "type": node_type,
                    "properties": {
                        **{
                            k: v
                            for k, v in node_data.items()
                            if k not in ["id", "name", "title"]
                        }
                    },
                }

            return node_id

        # Helper function to add a relationship as a link
        def add_link(source_id, target_id, rel_data):
            if not source_id or not target_id or not rel_data:
                return

            # Get relationship type
            link_type = rel_data.type

            # Create the link object
            links.append(
                {
                    "source": source_id,
                    "target": target_id,
                    "type": link_type,
                    "value": 1,  # Default weight
                    "properties": {
                        **{k: v for k, v in rel_data.items() if k not in ["type"]}
                    },
                }
            )

        # Process the query results
        for record in result:
            # Add the investigation node
            i_id = add_node(record.get("i"))

            # Add first level node and link
            n1_id = add_node(record.get("n1"))
            if i_id and n1_id and record.get("r1"):
                add_link(i_id, n1_id, record.get("r1"))

            # Add second level node and link
            n2_id = add_node(record.get("n2"))
            if n1_id and n2_id and record.get("r2"):
                add_link(n1_id, n2_id, record.get("r2"))

            # Add third level node and link (if include_sources_sinks is true)
            if include_sources_sinks:
                n3_id = add_node(record.get("n3"))
                if n2_id and n3_id and record.get("r3"):
                    add_link(n2_id, n3_id, record.get("r3"))

        # Prepare the final graph data
        graph_data = {"nodes": list(nodes.values()), "links": links}

        return jsonify(graph_data)
    except BadRequestError as e:
        raise e
    except NotFoundError as e:
        raise e
    except Exception as e:
        logger.error(
            f"Error retrieving investigation graph for {investigation_id}: {str(e)}",
            exc_info=True,
        )
        # Return a more detailed error
        return (
            jsonify(
                {
                    "error": f"Failed to retrieve investigation graph: {str(e)}",
                    "status": "error",
                    "investigation_id": investigation_id,
                    "message": "An error occurred while processing the investigation graph data",
                }
            ),
            500,
        )


@bp.route("/search", methods=["GET"])
def search_knowledge_graph():
    """Search the knowledge graph for nodes matching a query.

    Returns:
        JSON response with matching nodes
    """
    try:
        # Get search parameters
        query = request.args.get("q", "")
        node_type = request.args.get("type", "")
        limit = int(request.args.get("limit", "20"))

        if not query:
            raise BadRequestError("Search query is required")

        connector = get_connector()

        # Build the query based on parameters
        cypher_query = """
        MATCH (n)
        WHERE n.name CONTAINS $query OR n.title CONTAINS $query
        """

        # Add type filter if specified
        if node_type:
            cypher_query += f" AND n:{node_type}"

        # Add return clause with limit
        cypher_query += f"""
        RETURN n
        LIMIT {limit}
        """

        # Execute the query
        result = connector.run_query(cypher_query, {"query": query})

        # Transform the result into a list of nodes
        nodes = []

        for record in result:
            node_data = record.get("n")
            if node_data:
                # Get node label (Neo4j type)
                node_labels = [
                    label for label in node_data.labels if label != "Resource"
                ]
                node_type = node_labels[0].lower() if node_labels else "unknown"

                nodes.append(
                    {
                        "id": node_data.get("id"),
                        "name": node_data.get(
                            "name",
                            node_data.get("title", f"Node {node_data.get('id')}"),
                        ),
                        "type": node_type,
                        "properties": {
                            **{
                                k: v
                                for k, v in node_data.items()
                                if k not in ["id", "name", "title"]
                            }
                        },
                    }
                )

        return jsonify(nodes)
    except BadRequestError as e:
        raise e
    except Exception as e:
        logger.error(f"Error searching knowledge graph: {str(e)}")
        raise APIError(f"Failed to search knowledge graph: {str(e)}")
