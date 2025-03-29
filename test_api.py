import requests
import json
import sys

def test_api(investigation_id=None):
    """Test the API health endpoint and investigations endpoint."""
    base_url = "http://localhost:5001/api"
    
    # Test health endpoint
    try:
        response = requests.get(f"{base_url}/health")
        print("Health Status Response:")
        print(json.dumps(response.json(), indent=2))
        print(f"Status Code: {response.status_code}")
        print("=" * 50)
    except Exception as e:
        print(f"Error connecting to health endpoint: {str(e)}")
    
    if investigation_id:
        # Test specific investigation endpoint
        try:
            response = requests.get(f"{base_url}/investigations/{investigation_id}")
            print(f"Investigation {investigation_id} Response:")
            print(json.dumps(response.json(), indent=2))
            print(f"Status Code: {response.status_code}")
            print("=" * 50)
        except Exception as e:
            print(f"Error connecting to investigation endpoint: {str(e)}")
            
        # Test knowledge graph endpoint for the investigation
        try:
            response = requests.get(f"{base_url}/knowledge-graph/investigation/{investigation_id}")
            print(f"Knowledge Graph for Investigation {investigation_id} Response:")
            print(f"Status Code: {response.status_code}")
            print("Data contains:")
            data = response.json()
            print(f"Nodes: {len(data.get('nodes', []))} nodes")
            print(f"Links: {len(data.get('links', []))} links")
            print("=" * 50)
        except Exception as e:
            print(f"Error connecting to knowledge graph endpoint: {str(e)}")
    else:
        # Test investigations endpoint
        try:
            response = requests.get(f"{base_url}/investigations")
            print("Investigations Response:")
            print(json.dumps(response.json(), indent=2))
            print(f"Status Code: {response.status_code}")
            print("=" * 50)
        except Exception as e:
            print(f"Error connecting to investigations endpoint: {str(e)}")

if __name__ == "__main__":
    # If an investigation ID is provided as a command line argument, use it
    investigation_id = sys.argv[1] if len(sys.argv) > 1 else None
    test_api(investigation_id)