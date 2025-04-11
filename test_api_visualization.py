#!/usr/bin/env python
"""Script to directly test the visualization endpoint."""

from skwaq.api.routes.investigations import get_investigation_visualization
from flask import Response

# Mock the investigation ID
investigation_id = "inv-ai-samples-8d357166"

# Call the endpoint function directly
print(f"Testing visualization for investigation: {investigation_id}")
response_data = get_investigation_visualization(investigation_id)

# Check if it's a tuple (Flask endpoint response)
if isinstance(response_data, tuple):
    # Unpack the tuple
    json_data, status_code, headers = response_data
    print(f"Status code: {status_code}")
    print(f"Data type: {type(json_data)}")
    print(f"Data length: {len(json_data)}")
    print(f"First 200 chars: {json_data[:200]}")
elif isinstance(response_data, Response):
    # Flask response object
    print(f"Status code: {response_data.status_code}")
    print(f"Data type: {type(response_data.data)}")
    print(f"Data length: {len(response_data.data)}")
    print(f"First 200 chars: {response_data.data[:200]}")
else:
    # Just direct data
    print(f"Data type: {type(response_data)}")
    print(f"Data: {response_data}")

print("Test completed successfully.")
