//! Dynamic agent system: load agent definitions from markdown files at runtime.
//!
//! Agents are defined as markdown files with YAML frontmatter specifying their
//! name, description, model, tools, and max_turns. The body of the file is the
//! system prompt.
//!
//! Search order for agent files:
//! 1. `.skwaq/agents/{name}.md` (project-local)
//! 2. `~/.skwaq/agents/{name}.md` (user-global)
//! 3. `agents/{name}.md` (bundled with the binary)

pub mod definition;
pub mod discovery;
pub mod mcp_client;
pub mod output_schema;
pub mod pipeline;
pub mod runner;
pub mod tool_definitions;
pub mod tool_executor;
pub mod tool_translate;

pub use definition::{load_agent, AgentDefinition, AgentRoleMetadata};
pub use discovery::discover_agents;
pub use output_schema::{
    ParsedAgentOutput, VulnHunterStructuredFinding, VulnHunterStructuredOutput,
};
pub use pipeline::{
    deep_pipeline, deep_pipeline_debate, deep_pipeline_for_target, default_pipeline,
    pipeline_from_names, run_deep_pipeline_with_debate, select_vuln_hunter, AnalysisPipeline,
    DebateGroup, PipelineStage,
};
pub use runner::{AgentContextFrame, AgentResult, AgentRunner};
pub use tool_definitions::{agent_tools, filter_tools};
pub use tool_executor::{execute_tool, execute_tool_with_memory};
