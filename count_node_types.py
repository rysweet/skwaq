#!/usr/bin/env python
"""Simple script to count node types in the visualization graph."""

import json
import sys

def main():
    """Count node types in a graph JSON file."""
    if len(sys.argv) < 2:
        print("Usage: python count_node_types.py <json_file>")
        return
    
    json_file = sys.argv[1]
    
    with open(json_file, 'r') as f:
        data = json.load(f)
    
    if 'nodes' not in data:
        print(f"Error: No 'nodes' field found in {json_file}")
        return
    
    node_types = {}
    for node in data['nodes']:
        node_type = node.get('type', 'unknown')
        node_types[node_type] = node_types.get(node_type, 0) + 1
    
    print(f"Node types in {json_file}:")
    for node_type, count in node_types.items():
        print(f"  {node_type}: {count}")
    
    print(f"Total nodes: {len(data['nodes'])}")
    print(f"Total links: {len(data['links'])}")

if __name__ == "__main__":
    main()