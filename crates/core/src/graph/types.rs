//! Graph node and relationship type enums for the Kùzu property graph.
//!
//! These enums define the schema labels used in Cypher queries and
//! graph construction throughout the analysis pipeline.

use serde::{Deserialize, Serialize};
use std::fmt;

/// Labels for node tables in the graph database.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum NodeLabel {
    Function,
    BasicBlock,
    DataSource,
    DataSink,
    Vulnerability,
    Cwe,
    Investigation,
    Annotation,
    Hypothesis,
}

impl fmt::Display for NodeLabel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Function => "Function",
            Self::BasicBlock => "BasicBlock",
            Self::DataSource => "DataSource",
            Self::DataSink => "DataSink",
            Self::Vulnerability => "Vulnerability",
            Self::Cwe => "CWE",
            Self::Investigation => "Investigation",
            Self::Annotation => "Annotation",
            Self::Hypothesis => "Hypothesis",
        };
        write!(f, "{s}")
    }
}

/// Relationship types connecting nodes in the graph.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RelationshipType {
    Calls,
    Contains,
    FlowsTo,
    LocatedIn,
    Matches,
    TaintFlow,
}

impl fmt::Display for RelationshipType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Calls => "CALLS",
            Self::Contains => "CONTAINS",
            Self::FlowsTo => "FLOWS_TO",
            Self::LocatedIn => "LOCATED_IN",
            Self::Matches => "MATCHES",
            Self::TaintFlow => "TAINT_FLOW",
        };
        write!(f, "{s}")
    }
}
