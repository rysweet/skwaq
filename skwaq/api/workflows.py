"""API endpoints for workflows."""

from typing import Dict, Any, List, Optional
from flask import Blueprint, jsonify, request, current_app
import uuid
from datetime import datetime

from skwaq.utils.logging import get_logger
from skwaq.core.openai_client import get_openai_client
from skwaq.workflows.sources_and_sinks import SourcesAndSinksWorkflow
from .events import publish_system_event

logger = get_logger(__name__)

bp = Blueprint("workflows", __name__, url_prefix="/api/workflows")

# In-memory storage for available workflows
AVAILABLE_WORKFLOWS = [
    {
        "id": "sources_and_sinks",
        "name": "Sources and Sinks Analysis",
        "description": "Analyze code for potential sources and sinks, identifying data flow paths for vulnerability assessment.",
        "parameters": [
            {
                "name": "investigation_id",
                "type": "string",
                "required": True,
                "description": "ID of the investigation to analyze",
                "default": None
            },
            {
                "name": "output_format",
                "type": "string",
                "required": False,
                "description": "Output format for the results (markdown or json)",
                "default": "markdown"
            }
        ]
    },
    {
        "id": "vulnerability_research",
        "name": "Vulnerability Research",
        "description": "Research potential vulnerabilities in a repository.",
        "parameters": [
            {
                "name": "repository_id",
                "type": "string",
                "required": True,
                "description": "ID of the repository to analyze",
                "default": None
            },
            {
                "name": "cve_id",
                "type": "string",
                "required": False,
                "description": "Specific CVE to research (optional)",
                "default": None
            }
        ]
    },
    {
        "id": "guided_inquiry",
        "name": "Guided Vulnerability Assessment",
        "description": "Interactive guided assessment of security vulnerabilities.",
        "parameters": [
            {
                "name": "repository_id",
                "type": "string",
                "required": True,
                "description": "ID of the repository to analyze",
                "default": None
            },
            {
                "name": "prompt",
                "type": "string",
                "required": False,
                "description": "Initial prompt to start the inquiry",
                "default": None
            }
        ]
    }
]

# In-memory storage for active workflows
active_workflows = {}

@bp.route("", methods=["GET"])
def get_available_workflows():
    """Get available workflows.
    
    Returns:
        JSON response with available workflows
    """
    return jsonify(AVAILABLE_WORKFLOWS)

@bp.route("/active", methods=["GET"])
def get_active_workflows():
    """Get active workflows.
    
    Returns:
        JSON response with active workflows
    """
    return jsonify(list(active_workflows.values()))

@bp.route("/history", methods=["GET"])
def get_workflow_history():
    """Get workflow history.
    
    Returns:
        JSON response with workflow history
    """
    # Mock implementation - would be replaced with database query
    limit = request.args.get("limit", 10, type=int)
    offset = request.args.get("offset", 0, type=int)
    
    # In a real implementation, this would query the database
    return jsonify([])

@bp.route("/<workflow_id>/start", methods=["POST"])
def start_workflow(workflow_id):
    """Start a workflow.
    
    Args:
        workflow_id: ID of the workflow to start
        
    Returns:
        JSON response with workflow ID
    """
    parameters = request.json or {}
    
    # Check if workflow exists
    workflow_def = next((w for w in AVAILABLE_WORKFLOWS if w["id"] == workflow_id), None)
    if not workflow_def:
        return jsonify({"error": f"Workflow {workflow_id} not found"}), 404
    
    # Check required parameters
    for param in workflow_def["parameters"]:
        if param["required"] and param["name"] not in parameters:
            return jsonify({"error": f"Missing required parameter: {param['name']}"}), 400
    
    # Generate a unique ID for this workflow instance
    instance_id = str(uuid.uuid4())
    
    # Record the workflow
    active_workflows[instance_id] = {
        "id": instance_id,
        "workflow_id": workflow_id,
        "name": workflow_def["name"],
        "status": "pending",
        "progress": 0,
        "parameters": parameters,
        "started_at": datetime.now().isoformat(),
        "updated_at": datetime.now().isoformat()
    }
    
    # Publish event for workflow started
    publish_system_event("workflow_status_update", {
        "workflow_id": instance_id,
        "workflow_name": workflow_def["name"],
        "status": "pending",
        "progress": 0
    })
    
    # For sources_and_sinks workflow, run it asynchronously
    if workflow_id == "sources_and_sinks":
        # In a production environment, this would be handled by a queue system
        # For this implementation, we'll use a separate thread
        import threading
        threading.Thread(
            target=run_sources_and_sinks_workflow,
            args=(instance_id, parameters)
        ).start()
    
    return jsonify({
        "workflow_id": instance_id,
        "status": "pending"
    })

@bp.route("/<workflow_id>/status", methods=["GET"])
def get_workflow_status(workflow_id):
    """Get workflow status.
    
    Args:
        workflow_id: ID of the workflow
        
    Returns:
        JSON response with workflow status
    """
    if workflow_id not in active_workflows:
        return jsonify({"error": f"Workflow {workflow_id} not found"}), 404
    
    return jsonify(active_workflows[workflow_id])

@bp.route("/<workflow_id>/stop", methods=["POST"])
def stop_workflow(workflow_id):
    """Stop a workflow.
    
    Args:
        workflow_id: ID of the workflow to stop
        
    Returns:
        JSON response with status
    """
    if workflow_id not in active_workflows:
        return jsonify({"error": f"Workflow {workflow_id} not found"}), 404
    
    # Update workflow status
    active_workflows[workflow_id]["status"] = "stopped"
    active_workflows[workflow_id]["updated_at"] = datetime.now().isoformat()
    
    # Publish event for workflow stopped
    publish_system_event("workflow_status_update", {
        "workflow_id": workflow_id,
        "status": "stopped",
        "progress": active_workflows[workflow_id]["progress"]
    })
    
    return jsonify({"status": "success", "message": f"Workflow {workflow_id} stopped"})

@bp.route("/<workflow_id>/results", methods=["GET"])
def get_workflow_results(workflow_id):
    """Get workflow results.
    
    Args:
        workflow_id: ID of the workflow
        
    Returns:
        JSON response with workflow results
    """
    if workflow_id not in active_workflows:
        return jsonify({"error": f"Workflow {workflow_id} not found"}), 404
    
    # In a real implementation, this would query the database
    # For now, return a simple response
    workflow = active_workflows[workflow_id]
    
    # Format varies by workflow type
    if workflow["workflow_id"] == "sources_and_sinks":
        # Return the stored results if available
        results = workflow.get("results", [])
        return jsonify(results)
    
    # Default empty results
    return jsonify([])

# Async function to run the sources and sinks workflow
async def run_sources_and_sinks_workflow(instance_id, parameters):
    """Run the sources and sinks workflow asynchronously.
    
    Args:
        instance_id: ID of the workflow instance
        parameters: Parameters for the workflow
    """
    try:
        # Update status to running
        active_workflows[instance_id]["status"] = "running"
        active_workflows[instance_id]["progress"] = 10
        active_workflows[instance_id]["updated_at"] = datetime.now().isoformat()
        
        # Publish event
        publish_system_event("workflow_status_update", {
            "workflow_id": instance_id,
            "status": "running",
            "progress": 10
        })
        
        # Get parameters
        investigation_id = parameters.get("investigation_id")
        output_format = parameters.get("output_format", "markdown")
        
        # Initialize OpenAI client
        openai_client = get_openai_client(async_mode=True)
        
        # Create workflow
        workflow = SourcesAndSinksWorkflow(
            llm_client=openai_client,
            investigation_id=investigation_id
        )
        
        # Update progress
        active_workflows[instance_id]["progress"] = 20
        active_workflows[instance_id]["updated_at"] = datetime.now().isoformat()
        publish_system_event("workflow_status_update", {
            "workflow_id": instance_id,
            "status": "running",
            "progress": 20,
            "message": "Initializing analysis..."
        })
        
        # Run workflow
        result = await workflow.run()
        
        # Update progress
        active_workflows[instance_id]["progress"] = 90
        active_workflows[instance_id]["updated_at"] = datetime.now().isoformat()
        publish_system_event("workflow_status_update", {
            "workflow_id": instance_id,
            "status": "running",
            "progress": 90,
            "message": "Processing results..."
        })
        
        # Format results based on requested format
        if output_format == "json":
            output = result.to_dict()
        else:  # markdown
            output = result.to_markdown()
        
        # Store results in memory (in a real implementation, this would be in a database)
        active_workflows[instance_id]["results"] = [
            {
                "workflow_id": instance_id,
                "status": "completed",
                "progress": 100,
                "data": {
                    "investigation_id": investigation_id,
                    "sources_count": len(result.sources),
                    "sinks_count": len(result.sinks),
                    "paths_count": len(result.data_flow_paths),
                    "summary": result.summary,
                    "output_format": output_format,
                    "output": output
                }
            }
        ]
        
        # Publish results event
        publish_system_event("workflow_result_update", {
            "workflow_id": instance_id,
            "status": "completed",
            "progress": 100,
            "data": {
                "investigation_id": investigation_id,
                "sources_count": len(result.sources),
                "sinks_count": len(result.sinks),
                "paths_count": len(result.data_flow_paths),
                "summary": result.summary
            }
        })
        
        # Update workflow status to completed
        active_workflows[instance_id]["status"] = "completed"
        active_workflows[instance_id]["progress"] = 100
        active_workflows[instance_id]["updated_at"] = datetime.now().isoformat()
        active_workflows[instance_id]["completed_at"] = datetime.now().isoformat()
        
        # Publish completion event
        publish_system_event("workflow_status_update", {
            "workflow_id": instance_id,
            "status": "completed",
            "progress": 100
        })
        
    except Exception as e:
        logger.error(f"Error running sources and sinks workflow: {str(e)}")
        
        # Update workflow status to failed
        active_workflows[instance_id]["status"] = "failed"
        active_workflows[instance_id]["updated_at"] = datetime.now().isoformat()
        active_workflows[instance_id]["error"] = str(e)
        
        # Publish event
        publish_system_event("workflow_status_update", {
            "workflow_id": instance_id,
            "status": "failed",
            "progress": active_workflows[instance_id]["progress"],
            "error": str(e)
        })