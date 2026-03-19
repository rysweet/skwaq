//! Tree-sitter based variable flow extraction for C/C++ source code.
//!
//! Uses tree-sitter-c to parse source into a concrete syntax tree and extract:
//! - Variable declarations with their types and sizes
//! - Variable assignments (ASSIGNS relationships)
//! - Variable usage in function calls (USES relationships)
//! - Function call arguments (which variables flow into which sinks)
//!
//! These relationships populate the `flows_to` table in the graph DB,
//! enabling the taint analyzer to trace intraprocedural data flow like:
//!   recv → inputBuffer → atoi(inputBuffer) → data → buffer[data]

use tree_sitter::{Language, Parser, Tree};

/// A variable assignment extracted from C source.
#[derive(Debug, Clone)]
pub struct VariableAssignment {
    pub variable: String,
    pub source_expression: String,
    pub line: usize,
    /// If the source is a function call, the function name
    pub source_function: Option<String>,
}

/// A variable use in a function call argument.
#[derive(Debug, Clone)]
pub struct VariableUse {
    pub variable: String,
    pub used_in_function: String,
    pub argument_position: usize,
    pub line: usize,
}

/// Extracted data flow relationships from a C source file.
#[derive(Debug, Clone)]
pub struct DataFlowGraph {
    pub assignments: Vec<VariableAssignment>,
    pub uses: Vec<VariableUse>,
}

/// Parse C source code and extract variable assignment and usage relationships.
pub fn extract_c_data_flow(source: &str) -> DataFlowGraph {
    let mut parser = Parser::new();
    let language = tree_sitter_c::LANGUAGE;
    parser
        .set_language(&Language::new(language))
        .expect("Failed to set C language for tree-sitter");

    let tree = match parser.parse(source, None) {
        Some(t) => t,
        None => {
            return DataFlowGraph {
                assignments: vec![],
                uses: vec![],
            }
        }
    };

    let mut assignments = Vec::new();
    let mut uses = Vec::new();

    extract_from_node(
        &tree,
        tree.root_node(),
        source.as_bytes(),
        &mut assignments,
        &mut uses,
    );

    DataFlowGraph { assignments, uses }
}

fn extract_from_node(
    _tree: &Tree,
    node: tree_sitter::Node,
    source: &[u8],
    assignments: &mut Vec<VariableAssignment>,
    uses: &mut Vec<VariableUse>,
) {
    match node.kind() {
        // Variable declarations: int data = atoi(input);
        "declaration" | "init_declarator" => {
            extract_declaration(node, source, assignments);
        }
        // Assignments: data = atoi(input);
        "assignment_expression" => {
            extract_assignment(node, source, assignments);
        }
        // Function calls: strcpy(buf, input); system(cmd);
        "call_expression" => {
            extract_call_uses(node, source, uses);
        }
        // Array subscript: buffer[data] — data flows into index
        "subscript_expression" => {
            extract_subscript_use(node, source, uses);
        }
        _ => {}
    }

    // Recurse into children
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        extract_from_node(_tree, child, source, assignments, uses);
    }
}

fn node_text<'a>(node: tree_sitter::Node, source: &'a [u8]) -> &'a str {
    node.utf8_text(source).unwrap_or("")
}

fn extract_declaration(
    node: tree_sitter::Node,
    source: &[u8],
    assignments: &mut Vec<VariableAssignment>,
) {
    // Look for init_declarator children: type name = expression
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "init_declarator" {
            if let (Some(declarator), Some(value)) = (
                child.child_by_field_name("declarator"),
                child.child_by_field_name("value"),
            ) {
                let var_name = node_text(declarator, source).to_string();
                let source_expr = node_text(value, source).to_string();
                let source_fn = if value.kind() == "call_expression" {
                    value
                        .child_by_field_name("function")
                        .map(|f| node_text(f, source).to_string())
                } else {
                    None
                };

                assignments.push(VariableAssignment {
                    variable: var_name,
                    source_expression: source_expr,
                    line: child.start_position().row + 1,
                    source_function: source_fn,
                });
            }
        }
    }
}

fn extract_assignment(
    node: tree_sitter::Node,
    source: &[u8],
    assignments: &mut Vec<VariableAssignment>,
) {
    if let (Some(left), Some(right)) = (
        node.child_by_field_name("left"),
        node.child_by_field_name("right"),
    ) {
        let var_name = node_text(left, source).to_string();
        let source_expr = node_text(right, source).to_string();
        let source_fn = if right.kind() == "call_expression" {
            right
                .child_by_field_name("function")
                .map(|f| node_text(f, source).to_string())
        } else {
            None
        };

        assignments.push(VariableAssignment {
            variable: var_name,
            source_expression: source_expr,
            line: node.start_position().row + 1,
            source_function: source_fn,
        });
    }
}

fn extract_call_uses(node: tree_sitter::Node, source: &[u8], uses: &mut Vec<VariableUse>) {
    let func_name = node
        .child_by_field_name("function")
        .map(|f| node_text(f, source).to_string())
        .unwrap_or_default();

    if func_name.is_empty() {
        return;
    }

    // Extract arguments
    if let Some(args) = node.child_by_field_name("arguments") {
        let mut cursor = args.walk();
        let mut arg_pos = 0;
        for child in args.children(&mut cursor) {
            if child.kind() == "," || child.kind() == "(" || child.kind() == ")" {
                continue;
            }
            let arg_text = node_text(child, source).to_string();
            // Only track identifier arguments (variable references)
            if child.kind() == "identifier" {
                uses.push(VariableUse {
                    variable: arg_text,
                    used_in_function: func_name.clone(),
                    argument_position: arg_pos,
                    line: child.start_position().row + 1,
                });
            }
            arg_pos += 1;
        }
    }
}

fn extract_subscript_use(node: tree_sitter::Node, source: &[u8], uses: &mut Vec<VariableUse>) {
    // buffer[index] — both buffer and index are "used"
    if let Some(index) = node.child_by_field_name("index") {
        if index.kind() == "identifier" {
            let var = node_text(index, source).to_string();
            let array = node
                .child_by_field_name("argument")
                .map(|a| node_text(a, source).to_string())
                .unwrap_or_else(|| "array".to_string());
            uses.push(VariableUse {
                variable: var,
                used_in_function: format!("{}[]", array),
                argument_position: 0,
                line: node.start_position().row + 1,
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_assignment_from_function_call() {
        let src = r#"
void bad() {
    char inputBuffer[100];
    int data;
    data = atoi(inputBuffer);
    buffer[data] = 'A';
}
"#;
        let flow = extract_c_data_flow(src);

        // Should find: data = atoi(inputBuffer)
        let atoi_assign = flow
            .assignments
            .iter()
            .find(|a| a.variable == "data" && a.source_function.as_deref() == Some("atoi"));
        assert!(
            atoi_assign.is_some(),
            "Should extract data = atoi(...) assignment. Got: {:?}",
            flow.assignments
        );

        // Should find: inputBuffer used in atoi()
        let input_use = flow
            .uses
            .iter()
            .find(|u| u.variable == "inputBuffer" && u.used_in_function == "atoi");
        assert!(
            input_use.is_some(),
            "Should extract inputBuffer used in atoi(). Got: {:?}",
            flow.uses
        );

        // Should find: data used as array index
        let index_use = flow
            .uses
            .iter()
            .find(|u| u.variable == "data" && u.used_in_function.contains("[]"));
        assert!(
            index_use.is_some(),
            "Should extract data used as array index. Got: {:?}",
            flow.uses
        );
    }

    #[test]
    fn test_extract_recv_to_strcpy_flow() {
        let src = r#"
void vuln() {
    char buf[64];
    char input[256];
    int n = recv(sock, input, sizeof(input), 0);
    strcpy(buf, input);
}
"#;
        let flow = extract_c_data_flow(src);

        // n = recv(sock, input, ...)
        assert!(
            flow.assignments
                .iter()
                .any(|a| a.source_function.as_deref() == Some("recv")),
            "Should extract recv assignment"
        );

        // input used in strcpy
        assert!(
            flow.uses
                .iter()
                .any(|u| u.variable == "input" && u.used_in_function == "strcpy"),
            "Should extract input used in strcpy. Got: {:?}",
            flow.uses
        );
    }
}
