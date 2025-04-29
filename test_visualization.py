import json

import requests


def test_investigation_visualization():
    """Test the investigation visualization endpoint."""
    investigation_id = "inv-ai-samples-8d357166"
    url = f"http://localhost:5001/api/investigations/{investigation_id}/visualization"

    response = requests.get(url)

    if response.status_code == 200:
        data = response.json()
        print(
            f"Success! Received graph data with {len(data['nodes'])} nodes and {len(data['links'])} links"
        )

        # Print counts of each node type
        node_types = {}
        for node in data["nodes"]:
            node_type = node.get("type", "unknown")
            node_types[node_type] = node_types.get(node_type, 0) + 1

        print("\nNode types:")
        for node_type, count in node_types.items():
            print(f"  {node_type}: {count}")

        # Print the first node of each type
        print("\nSample nodes:")
        seen_types = set()
        for node in data["nodes"]:
            node_type = node.get("type", "unknown")
            if node_type not in seen_types:
                seen_types.add(node_type)
                print(f"  {node_type}: {json.dumps(node, indent=2)}")
    else:
        print(f"Error: {response.status_code}")
        try:
            print(response.json())
        except json.JSONDecodeError:
            print(response.text)


if __name__ == "__main__":
    test_investigation_visualization()
