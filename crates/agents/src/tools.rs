//! Tool definitions available to vulnerability assessment agents.

use skwaq_core::llm::ToolDefinition;

/// Return the full set of tools that agents can call during analysis.
pub fn agent_tools() -> Vec<ToolDefinition> {
    vec![
        ToolDefinition {
            name: "query_graph".into(),
            description: "Run a Cypher query against the code property graph and return results."
                .into(),
            parameters: serde_json::json!({
                "type": "object",
                "properties": {
                    "cypher": {
                        "type": "string",
                        "description": "Cypher query to execute"
                    }
                },
                "required": ["cypher"]
            }),
        },
        ToolDefinition {
            name: "read_function".into(),
            description: "Read the decompiled or source code of a function by name or address."
                .into(),
            parameters: serde_json::json!({
                "type": "object",
                "properties": {
                    "name": {
                        "type": "string",
                        "description": "Function name or address"
                    }
                },
                "required": ["name"]
            }),
        },
        ToolDefinition {
            name: "get_callers".into(),
            description: "Return all functions that call the specified function.".into(),
            parameters: serde_json::json!({
                "type": "object",
                "properties": {
                    "function": {
                        "type": "string",
                        "description": "Function name or address"
                    }
                },
                "required": ["function"]
            }),
        },
        ToolDefinition {
            name: "get_callees".into(),
            description: "Return all functions called by the specified function.".into(),
            parameters: serde_json::json!({
                "type": "object",
                "properties": {
                    "function": {
                        "type": "string",
                        "description": "Function name or address"
                    }
                },
                "required": ["function"]
            }),
        },
        ToolDefinition {
            name: "lookup_cwe".into(),
            description: "Look up a CWE entry by ID and return its name, description, and mitigations.".into(),
            parameters: serde_json::json!({
                "type": "object",
                "properties": {
                    "cwe_id": {
                        "type": "string",
                        "description": "CWE identifier, e.g. CWE-787"
                    }
                },
                "required": ["cwe_id"]
            }),
        },
        ToolDefinition {
            name: "create_finding".into(),
            description: "Record a new vulnerability finding in the graph database.".into(),
            parameters: serde_json::json!({
                "type": "object",
                "properties": {
                    "title": {
                        "type": "string",
                        "description": "Short title for the finding"
                    },
                    "severity": {
                        "type": "string",
                        "enum": ["critical", "high", "medium", "low", "info"],
                        "description": "Severity level"
                    },
                    "description": {
                        "type": "string",
                        "description": "Detailed description of the vulnerability"
                    },
                    "function": {
                        "type": "string",
                        "description": "Affected function name"
                    },
                    "cwe_id": {
                        "type": "string",
                        "description": "Associated CWE identifier"
                    }
                },
                "required": ["title", "severity", "description"]
            }),
        },
        ToolDefinition {
            name: "search_similar".into(),
            description:
                "Search for code patterns similar to a given snippet using embeddings.".into(),
            parameters: serde_json::json!({
                "type": "object",
                "properties": {
                    "code": {
                        "type": "string",
                        "description": "Code snippet to find similar patterns for"
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Maximum number of results",
                        "default": 10
                    }
                },
                "required": ["code"]
            }),
        },
    ]
}
