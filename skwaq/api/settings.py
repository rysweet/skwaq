"""API routes for application settings."""

from flask import Blueprint, jsonify, request, abort

bp = Blueprint('settings', __name__, url_prefix='/api/settings')

# Mock settings for demonstration
SETTINGS = {
    'general': {
        'telemetryEnabled': True,
        'darkMode': False,
        'autoSave': True,
        'defaultRepository': '',
    },
    'api': {
        'authMethod': 'api-key', # 'api-key' or 'entra-id'
        'apiKey': '••••••••••••••••',
        'apiEndpoint': 'https://api.openai.azure.com/',
        'apiVersion': '2023-05-15',
        'model': 'gpt4o',
        'maxTokens': 2000,
        'useEntraId': False,
        'tenantId': '',
        'clientId': '',
        'clientSecret': '••••••••••••••••',
        'modelDeployments': {
            'chat': 'gpt4o',
            'code': 'o3',
            'reasoning': 'o1'
        }
    },
    'tools': {
        'codeqlEnabled': True,
        'codeqlPath': '/usr/local/bin/codeql',
        'blarifyEnabled': True,
        'customToolsEnabled': False,
    },
    'database': {
        'connectionString': 'bolt://localhost:7687',
        'username': 'neo4j',
        'databaseName': 'skwaq',
        'status': 'connected',
        'version': '5.10.0',
        'size': '125 MB',
    }
}

@bp.route('', methods=['GET'])
def get_all_settings():
    """Get all application settings."""
    return jsonify(SETTINGS)

@bp.route('/<section>', methods=['GET'])
def get_settings_section(section):
    """Get settings for a specific section."""
    if section not in SETTINGS:
        abort(404, description=f"Settings section '{section}' not found")
    
    return jsonify(SETTINGS[section])

@bp.route('/<section>', methods=['PUT'])
def update_settings_section(section):
    """Update settings for a specific section."""
    if not request.is_json:
        abort(400, description="Content-Type must be application/json")
    
    if section not in SETTINGS:
        abort(404, description=f"Settings section '{section}' not found")
    
    data = request.get_json()
    
    # Update only the provided settings
    for key, value in data.items():
        if key in SETTINGS[section]:
            SETTINGS[section][key] = value
    
    return jsonify(SETTINGS[section])

@bp.route('/database/status', methods=['GET'])
def get_database_status():
    """Get the current status of the database connection."""
    # In a real implementation, this would check the actual database connection
    return jsonify({
        'status': SETTINGS['database']['status'],
        'version': SETTINGS['database']['version'],
        'connectionString': SETTINGS['database']['connectionString'],
        'size': SETTINGS['database']['size'],
    })

@bp.route('/database/clear', methods=['POST'])
def clear_database():
    """Clear all data from the database."""
    # In a real implementation, this would actually clear the database
    return jsonify({'status': 'success', 'message': 'Database cleared successfully'})

@bp.route('/database/backup', methods=['POST'])
def backup_database():
    """Create a backup of the database."""
    # In a real implementation, this would create a backup file
    return jsonify({
        'status': 'success', 
        'message': 'Database backed up successfully',
        'backupFile': '/path/to/backup/skwaq_backup_2025-03-26.db'
    })

@bp.route('/cache/clear', methods=['POST'])
def clear_cache():
    """Clear the application cache."""
    # In a real implementation, this would clear cached data
    return jsonify({'status': 'success', 'message': 'Cache cleared successfully'})

@bp.route('/api/test', methods=['POST'])
def test_api_connection():
    """Test the connection to the AI API."""
    # In a real implementation, this would test the API connection with the provided settings
    api_settings = SETTINGS['api']
    
    # Create a message specific to the authentication method
    auth_method = "API Key" if api_settings['authMethod'] == 'api-key' else "Microsoft Entra ID"
    
    # In a real implementation, we would attempt to initialize the OpenAI client
    # with the specified authentication method and catch any errors
    
    return jsonify({
        'status': 'success',
        'message': f'Azure OpenAI connection successful using {auth_method} authentication',
        'model': api_settings['model'],
        'endpoint': api_settings['apiEndpoint'],
        'authMethod': api_settings['authMethod'],
        'apiVersion': api_settings['apiVersion'],
        'modelDeployments': api_settings['modelDeployments']
    })

@bp.route('/tools/verify', methods=['POST'])
def verify_tools():
    """Verify the availability and configuration of external tools."""
    # In a real implementation, this would check each tool
    tools_status = {
        'codeql': {
            'available': SETTINGS['tools']['codeqlEnabled'],
            'version': '2.15.0',
            'path': SETTINGS['tools']['codeqlPath'],
        },
        'blarify': {
            'available': SETTINGS['tools']['blarifyEnabled'],
            'version': '1.3.2',
        }
    }
    
    return jsonify(tools_status)

@bp.route('/api/export-env', methods=['GET'])
def export_env_file():
    """Export API settings as a .env file."""
    api_settings = SETTINGS['api']
    
    # Create .env file content
    env_content = []
    env_content.append("# Azure OpenAI Configuration")
    
    # Common configuration
    env_content.append(f"AZURE_OPENAI_ENDPOINT={api_settings['apiEndpoint']}")
    env_content.append(f"AZURE_OPENAI_API_VERSION={api_settings['apiVersion']}")
    
    # Authentication-specific configuration
    if api_settings['authMethod'] == 'api-key':
        env_content.append("AZURE_OPENAI_USE_ENTRA_ID=false")
        env_content.append(f"AZURE_OPENAI_API_KEY={api_settings['apiKey']}")
    else:  # entra-id
        env_content.append("AZURE_OPENAI_USE_ENTRA_ID=true")
        env_content.append(f"AZURE_TENANT_ID={api_settings['tenantId']}")
        env_content.append(f"AZURE_CLIENT_ID={api_settings['clientId']}")
        if api_settings['clientSecret']:
            env_content.append(f"AZURE_CLIENT_SECRET={api_settings['clientSecret']}")
    
    # Model deployments
    model_deployments = api_settings['modelDeployments']
    env_content.append(f"AZURE_OPENAI_MODEL_DEPLOYMENTS={{\"chat\":\"{model_deployments['chat']}\",\"code\":\"{model_deployments['code']}\",\"reasoning\":\"{model_deployments['reasoning']}\"}}")
    
    # Return the .env file content
    return jsonify({
        'status': 'success',
        'env_content': "\n".join(env_content)
    })