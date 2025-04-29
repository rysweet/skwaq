#!/usr/bin/env python
"""Test script to check the visualization API data."""

import sys

import requests


def check_visualization_api(investigation_id):
    """Check the visualization API for a given investigation ID."""
    url = f"http://localhost:5001/api/investigations/{investigation_id}/visualization"
    print(f"Testing visualization API for: {url}")

    try:
        response = requests.get(url)
        if response.status_code == 200:
            data = response.json()
            print(
                f"Success! API returned {len(data.get('nodes', []))} nodes and {len(data.get('links', []))} links"
            )

            # Count node types
            node_types = {}
            for node in data.get("nodes", []):
                node_type = node.get("type", "unknown")
                node_types[node_type] = node_types.get(node_type, 0) + 1

            print("\nNode types:")
            for node_type, count in sorted(node_types.items()):
                print(f"  {node_type}: {count}")

            # Print first node of each type
            print("\nExample nodes:")
            seen_types = set()
            for node in data.get("nodes", []):
                node_type = node.get("type", "unknown")
                if node_type not in seen_types:
                    seen_types.add(node_type)
                    print(
                        f"  {node_type}: {node.get('label', 'No label')} (id: {node.get('id', 'No id')})"
                    )

            # Print link stats
            link_types = {}
            for link in data.get("links", []):
                link_type = link.get("type", "unknown")
                link_types[link_type] = link_types.get(link_type, 0) + 1

            print("\nLink types:")
            for link_type, count in sorted(link_types.items()):
                print(f"  {link_type}: {count}")

            return True
        else:
            print(f"Error: {response.status_code} - {response.text}")
            return False
    except Exception as e:
        print(f"Error connecting to API: {e}")
        return False


if __name__ == "__main__":
    investigation_id = "inv-ai-samples-8d357166"
    if len(sys.argv) > 1:
        investigation_id = sys.argv[1]
    check_visualization_api(investigation_id)
