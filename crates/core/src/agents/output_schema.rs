use serde::{Deserialize, Serialize};

pub const VULN_HUNTER_V1_SCHEMA: &str = "vuln-hunter-v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VulnHunterStructuredFinding {
    pub title: String,
    pub severity: String,
    pub cwe_id: String,
    pub function: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VulnHunterStructuredOutput {
    pub summary: String,
    #[serde(default)]
    pub findings: Vec<VulnHunterStructuredFinding>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParsedAgentOutput {
    VulnHunterV1(VulnHunterStructuredOutput),
}

impl ParsedAgentOutput {
    pub fn schema_name(&self) -> &'static str {
        match self {
            Self::VulnHunterV1(_) => VULN_HUNTER_V1_SCHEMA,
        }
    }

    pub fn key_points(&self) -> Vec<String> {
        match self {
            Self::VulnHunterV1(output) => {
                let mut points = Vec::with_capacity(output.findings.len() + 1);
                points.push(format!("summary: {}", output.summary));
                for finding in &output.findings {
                    points.push(format!(
                        "finding: [{}] {} ({}) in {}",
                        finding.severity, finding.title, finding.cwe_id, finding.function
                    ));
                }
                points
            }
        }
    }

    pub fn context_summary(&self) -> String {
        self.key_points().join("\n")
    }
}

pub fn output_schema_contract(schema_name: &str) -> Option<&'static str> {
    match schema_name {
        VULN_HUNTER_V1_SCHEMA => Some(
            "\n\n--- Structured Output Contract ---\n\
             At the end of your final response, append a fenced JSON block labelled `json`.\n\
             The JSON MUST match this schema exactly:\n\
             ```json\n\
             {\n\
               \"summary\": \"One concise summary of what you found or why you rejected candidates\",\n\
               \"findings\": [\n\
                 {\n\
                   \"title\": \"Specific vulnerability title\",\n\
                   \"severity\": \"critical|high|medium|low\",\n\
                   \"cwe_id\": \"CWE-XXX\",\n\
                   \"function\": \"function_name\"\n\
                 }\n\
               ]\n\
             }\n\
             ```\n\
             Include every finding you created with `create_finding` in this JSON. If you created no findings, return an empty `findings` array.",
        ),
        _ => None,
    }
}

pub fn parse_structured_output(
    schema_name: &str,
    output: &str,
) -> anyhow::Result<ParsedAgentOutput> {
    let json_block = extract_last_json_code_block(output)
        .ok_or_else(|| anyhow::anyhow!("Missing fenced JSON block for schema '{schema_name}'"))?;

    match schema_name {
        VULN_HUNTER_V1_SCHEMA => {
            let parsed: VulnHunterStructuredOutput =
                serde_json::from_str(&json_block).map_err(|e| {
                    anyhow::anyhow!("Failed to parse vuln-hunter structured output: {e}")
                })?;
            Ok(ParsedAgentOutput::VulnHunterV1(parsed))
        }
        _ => anyhow::bail!("Unknown agent output schema '{schema_name}'"),
    }
}

fn extract_last_json_code_block(output: &str) -> Option<String> {
    let mut cursor = 0usize;
    let mut last_block = None;

    while let Some(relative_start) = output[cursor..].find("```json") {
        let start = cursor + relative_start + "```json".len();
        let rest = &output[start..];
        let end = rest.find("```")?;
        last_block = Some(rest[..end].trim().to_string());
        cursor = start + end + "```".len();
    }

    last_block
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_vuln_hunter_structured_output() {
        let output = r#"Findings recorded.

```json
{
  "summary": "Two exploitable bugs found",
  "findings": [
    {
      "title": "Stack buffer overflow in parse_header",
      "severity": "high",
      "cwe_id": "CWE-121",
      "function": "parse_header"
    }
  ]
}
```"#;

        let parsed = parse_structured_output(VULN_HUNTER_V1_SCHEMA, output).unwrap();
        assert_eq!(parsed.schema_name(), VULN_HUNTER_V1_SCHEMA);
        assert!(parsed
            .context_summary()
            .contains("Two exploitable bugs found"));
        assert!(parsed.context_summary().contains("parse_header"));
    }

    #[test]
    fn prefers_last_json_code_block() {
        let output = r#"```json
{"summary":"old","findings":[]}
```

```json
{"summary":"new","findings":[]}
```"#;

        let parsed = parse_structured_output(VULN_HUNTER_V1_SCHEMA, output).unwrap();
        match parsed {
            ParsedAgentOutput::VulnHunterV1(data) => assert_eq!(data.summary, "new"),
        }
    }

    #[test]
    fn rejects_missing_json_code_block() {
        let error = parse_structured_output(VULN_HUNTER_V1_SCHEMA, "plain text only").unwrap_err();
        assert!(error.to_string().contains("Missing fenced JSON block"));
    }
}
