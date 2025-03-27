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
        'apiKey': '••••••••••••••••',
        'apiEndpoint': 'https://api.openai.azure.com/',
        'model': 'gpt4o',
        'maxTokens': 2000,
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
    # In a real implementation, this would test the API connection
    return jsonify({
        'status': 'success',
        'message': 'API connection successful',
        'model': SETTINGS['api']['model'],
        'endpoint': SETTINGS['api']['apiEndpoint'],
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