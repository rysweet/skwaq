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
pub mod pipeline;
pub mod runner;
pub mod tools;

pub use definition::{load_agent, AgentDefinition};
pub use discovery::discover_agents;
pub use pipeline::{default_pipeline, pipeline_from_names, AnalysisPipeline, PipelineStage};
pub use runner::{AgentResult, AgentRunner};
pub use tools::{agent_tools, execute_tool};
