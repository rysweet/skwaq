//! Tool definitions for vulnerability assessment agents.

use crate::llm::ToolDefinition;

/// Return the full set of tool definitions that agents can call during analysis.
pub fn agent_tools() -> Vec<ToolDefinition> {
    vec![
        ToolDefinition::new(
            "query_graph",
            "Run a Cypher query against the code property graph and return results.",
            serde_json::json!({
                "type": "object",
                "properties": {
                    "cypher": {
                        "type": "string",
                        "description": "Cypher query to execute"
                    }
                },
                "required": ["cypher"]
            }),
        ),
        ToolDefinition::new(
            "read_function",
            "Read the decompiled or source code of a function by name or address.",
            serde_json::json!({
                "type": "object",
                "properties": {
                    "name": {
                        "type": "string",
                        "description": "Function name or address"
                    }
                },
                "required": ["name"]
            }),
        ),
        ToolDefinition::new(
            "get_callers",
            "Return all functions that call the specified function.",
            serde_json::json!({
                "type": "object",
                "properties": {
                    "function": {
                        "type": "string",
                        "description": "Function name or address"
                    }
                },
                "required": ["function"]
            }),
        ),
        ToolDefinition::new(
            "get_callees",
            "Return all functions called by the specified function.",
            serde_json::json!({
                "type": "object",
                "properties": {
                    "function": {
                        "type": "string",
                        "description": "Function name or address"
                    }
                },
                "required": ["function"]
            }),
        ),
        ToolDefinition::new(
            "lookup_cwe",
            "Look up a CWE entry by ID and return its name, description, and mitigations.",
            serde_json::json!({
                "type": "object",
                "properties": {
                    "cwe_id": {
                        "type": "string",
                        "description": "CWE identifier, e.g. CWE-787"
                    }
                },
                "required": ["cwe_id"]
            }),
        ),
        ToolDefinition::new(
            "create_finding",
            "Record a new vulnerability finding in the graph database.",
            serde_json::json!({
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
        ),
        ToolDefinition::new(
            "rename_function",
            "Rename a decompiler-generated variable or update the renamed decompiled code for a function. \
             Use this to store an improved version of decompiled code with meaningful variable names.",
            serde_json::json!({
                "type": "object",
                "properties": {
                    "function": {
                        "type": "string",
                        "description": "Function name to update"
                    },
                    "renamed_code": {
                        "type": "string",
                        "description": "The renamed/improved decompiled code"
                    },
                    "annotations": {
                        "type": "string",
                        "description": "Optional type annotations or struct layout notes"
                    }
                },
                "required": ["function", "renamed_code"]
            }),
        ),
        ToolDefinition::new(
            "search_similar",
            "Search for code patterns similar to a given snippet using pattern matching.",
            serde_json::json!({
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
        ),
    ]
}

/// Return Ghidra MCP tool definitions for agents that need Ghidra access.
///
/// These tools are routed to a GhidraMCP server via the MCP protocol.
/// They are only available when a Ghidra MCP server is running.
pub fn ghidra_mcp_tools() -> Vec<ToolDefinition> {
    vec![
        ToolDefinition::new(
            "ghidra_decompile",
            "Get decompiled C output for a function at the given address or name via Ghidra.",
            serde_json::json!({
                "type": "object",
                "properties": {
                    "function": {
                        "type": "string",
                        "description": "Function name or hex address (e.g., '0x401000' or 'main')"
                    }
                },
                "required": ["function"]
            }),
        ),
        ToolDefinition::new(
            "ghidra_rename",
            "Rename a symbol (function or variable) in the Ghidra project.",
            serde_json::json!({
                "type": "object",
                "properties": {
                    "address": {
                        "type": "string",
                        "description": "Address of the symbol to rename"
                    },
                    "new_name": {
                        "type": "string",
                        "description": "New name for the symbol"
                    }
                },
                "required": ["address", "new_name"]
            }),
        ),
        ToolDefinition::new(
            "ghidra_set_type",
            "Set a data type annotation at an address in the Ghidra project.",
            serde_json::json!({
                "type": "object",
                "properties": {
                    "address": {
                        "type": "string",
                        "description": "Address to annotate"
                    },
                    "type_name": {
                        "type": "string",
                        "description": "Data type (e.g., 'int', 'char *', 'struct_t')"
                    }
                },
                "required": ["address", "type_name"]
            }),
        ),
        ToolDefinition::new(
            "ghidra_get_xrefs",
            "Get all cross-references to/from an address.",
            serde_json::json!({
                "type": "object",
                "properties": {
                    "address": {
                        "type": "string",
                        "description": "Address to find cross-references for"
                    }
                },
                "required": ["address"]
            }),
        ),
        ToolDefinition::new(
            "ghidra_search_strings",
            "Search for strings matching a pattern in the binary.",
            serde_json::json!({
                "type": "object",
                "properties": {
                    "pattern": {
                        "type": "string",
                        "description": "String pattern to search for (supports basic glob)"
                    }
                },
                "required": ["pattern"]
            }),
        ),
        ToolDefinition::new(
            "ghidra_get_segments",
            "List binary segments with their permissions (R/W/X).",
            serde_json::json!({
                "type": "object",
                "properties": {},
                "required": []
            }),
        ),
    ]
}

/// Filter the full tool set to only tools listed in an agent's definition.
pub fn filter_tools(all_tools: &[ToolDefinition], allowed: &[String]) -> Vec<ToolDefinition> {
    if allowed.is_empty() {
        return all_tools.to_vec();
    }
    all_tools
        .iter()
        .filter(|t| allowed.contains(&t.name))
        .cloned()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_filter_tools() {
        let all = agent_tools();
        let filtered = filter_tools(&all, &["query_graph".into(), "read_function".into()]);
        assert_eq!(filtered.len(), 2);
        assert!(filtered.iter().any(|t| t.name == "query_graph"));
        assert!(filtered.iter().any(|t| t.name == "read_function"));
    }

    #[test]
    fn test_filter_tools_empty_allows_all() {
        let all = agent_tools();
        let filtered = filter_tools(&all, &[]);
        assert_eq!(filtered.len(), all.len());
    }
}
