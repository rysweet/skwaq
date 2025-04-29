#!/usr/bin/env python3
"""Test script for the visualization API endpoint."""

import json
import sys

import requests


def test_visualization_api(investigation_id):
    """Test the visualization API endpoint."""
    url = f"http://localhost:5001/api/investigations/{investigation_id}/visualization"
    print(f"Requesting visualization data from: {url}")

    try:
        response = requests.get(url)
        print(f"Status code: {response.status_code}")
        print(f'Content-Type: {response.headers.get("Content-Type")}')

        if response.status_code == 200:
            try:
                data = response.json()
                print(f"Data is valid JSON: {bool(data)}")
                print(f'Number of nodes: {len(data.get("nodes", []))}')
                print(f'Number of links: {len(data.get("links", []))}')

                # Print node types
                node_types = {}
                for node in data.get("nodes", []):
                    node_type = node.get("type", "unknown")
                    node_types[node_type] = node_types.get(node_type, 0) + 1

                print("\nNode types:")
                for node_type, count in node_types.items():
                    print(f"  - {node_type}: {count}")

                # Print a few sample nodes
                print("\nSample nodes:")
                for i, node in enumerate(data.get("nodes", [])[:3]):
                    print(
                        f'  {i+1}. {node.get("type")}: {node.get("label")} (ID: {node.get("id")})'
                    )

                # Print a few sample links
                print("\nSample links:")
                for i, link in enumerate(data.get("links", [])[:3]):
                    print(
                        f'  {i+1}. {link.get("source")} -> {link.get("target")} ({link.get("type")})'
                    )

                # Check if any links have the investigation node as source
                inv_links = [
                    link
                    for link in data.get("links", [])
                    if isinstance(link.get("source"), str)
                    and link.get("source") == investigation_id
                ]
                print(f"\nLinks with investigation as source: {len(inv_links)}")

                # Save to a file for inspection
                output_file = f"visualization_{investigation_id}.json"
                with open(output_file, "w") as f:
                    json.dump(data, f, indent=2)
                print(f"\nSaved response to {output_file}")

            except json.JSONDecodeError as e:
                print("Response is not valid JSON")
                print(f"Error: {e}")
                print("\nResponse content (first 500 chars):")
                print(response.text[:500])
        else:
            print(f"Request failed with status code {response.status_code}")
            print("Response content:")
            print(response.text)
    except Exception as e:
        print(f"Error: {e}")


if __name__ == "__main__":
    investigation_id = sys.argv[1] if len(sys.argv) > 1 else "inv-ai-samples-8d357166"
    test_visualization_api(investigation_id)
