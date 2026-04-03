use serde::{Deserialize, Deserializer, Serialize};
use std::fmt;

pub const VULN_HUNTER_V1_SCHEMA: &str = "vuln-hunter-v1";
pub const EXPLOIT_ANALYST_V1_SCHEMA: &str = "exploit-analyst-v1";
pub const DEFENSE_ANALYST_V1_SCHEMA: &str = "defense-analyst-v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum VulnHunterSeverity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl fmt::Display for VulnHunterSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Critical => write!(f, "critical"),
            Self::High => write!(f, "high"),
            Self::Medium => write!(f, "medium"),
            Self::Low => write!(f, "low"),
            Self::Info => write!(f, "info"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum ExploitAnalystVerdict {
    Confirmed,
    Downgraded,
    Rejected,
}

impl fmt::Display for ExploitAnalystVerdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Confirmed => write!(f, "CONFIRMED"),
            Self::Downgraded => write!(f, "DOWNGRADED"),
            Self::Rejected => write!(f, "REJECTED"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum DefenseAnalystVerdict {
    Vulnerable,
    Mitigated,
    Safe,
}

impl fmt::Display for DefenseAnalystVerdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Vulnerable => write!(f, "VULNERABLE"),
            Self::Mitigated => write!(f, "MITIGATED"),
            Self::Safe => write!(f, "SAFE"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VulnHunterStructuredFinding {
    pub title: String,
    pub severity: VulnHunterSeverity,
    pub cwe_id: String,
    pub function: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VulnHunterStructuredOutput {
    pub summary: String,
    #[serde(default)]
    pub findings: Vec<VulnHunterStructuredFinding>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExploitAnalystAssessment {
    pub finding_title: String,
    pub verdict: ExploitAnalystVerdict,
    pub confidence_percent: u8,
    #[serde(default, deserialize_with = "deserialize_null_as_empty_vec")]
    pub evidence: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExploitAnalystStructuredOutput {
    pub summary: String,
    #[serde(default)]
    pub assessments: Vec<ExploitAnalystAssessment>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DefenseAnalystAssessment {
    pub finding_title: String,
    pub verdict: DefenseAnalystVerdict,
    pub confidence_percent: u8,
    #[serde(default, deserialize_with = "deserialize_null_as_empty_vec")]
    pub evidence: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DefenseAnalystStructuredOutput {
    pub summary: String,
    #[serde(default)]
    pub assessments: Vec<DefenseAnalystAssessment>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParsedAgentOutput {
    VulnHunterV1(VulnHunterStructuredOutput),
    ExploitAnalystV1(ExploitAnalystStructuredOutput),
    DefenseAnalystV1(DefenseAnalystStructuredOutput),
}

impl ParsedAgentOutput {
    pub fn schema_name(&self) -> &'static str {
        match self {
            Self::VulnHunterV1(_) => VULN_HUNTER_V1_SCHEMA,
            Self::ExploitAnalystV1(_) => EXPLOIT_ANALYST_V1_SCHEMA,
            Self::DefenseAnalystV1(_) => DEFENSE_ANALYST_V1_SCHEMA,
        }
    }

    pub fn as_exploit_analyst_v1(&self) -> Option<&ExploitAnalystStructuredOutput> {
        match self {
            Self::ExploitAnalystV1(output) => Some(output),
            _ => None,
        }
    }

    pub fn as_defense_analyst_v1(&self) -> Option<&DefenseAnalystStructuredOutput> {
        match self {
            Self::DefenseAnalystV1(output) => Some(output),
            _ => None,
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
            Self::ExploitAnalystV1(output) => {
                let mut points = Vec::with_capacity(output.assessments.len() + 1);
                points.push(format!("summary: {}", output.summary));
                for assessment in &output.assessments {
                    points.push(format!(
                        "assessment: {} [{} @ {}%] evidence: {}",
                        assessment.finding_title,
                        assessment.verdict,
                        assessment.confidence_percent,
                        format_evidence_list(&assessment.evidence)
                    ));
                }
                points
            }
            Self::DefenseAnalystV1(output) => {
                let mut points = Vec::with_capacity(output.assessments.len() + 1);
                points.push(format!("summary: {}", output.summary));
                for assessment in &output.assessments {
                    points.push(format!(
                        "assessment: {} [{} @ {}%] evidence: {}",
                        assessment.finding_title,
                        assessment.verdict,
                        assessment.confidence_percent,
                        format_evidence_list(&assessment.evidence)
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
                   \"severity\": \"critical|high|medium|low|info\",\n\
                   \"cwe_id\": \"CWE-XXX\",\n\
                   \"function\": \"function_name\"\n\
                 }\n\
               ]\n\
             }\n\
             ```\n\
             Include every finding you created with `create_finding` in this JSON. If you created no findings, return an empty `findings` array.",
        ),
        EXPLOIT_ANALYST_V1_SCHEMA => Some(
            "\n\n--- Structured Output Contract ---\n\
             At the end of your final response, append a fenced JSON block labelled `json`.\n\
             The JSON MUST match this schema exactly:\n\
             ```json\n\
             {\n\
               \"summary\": \"One concise exploitability summary\",\n\
               \"assessments\": [\n\
                 {\n\
                   \"finding_title\": \"Exact finding title under review\",\n\
                   \"verdict\": \"CONFIRMED|DOWNGRADED|REJECTED\",\n\
                    \"confidence_percent\": 1,\n\
                    \"evidence\": [\"Concrete reachability or attacker-control evidence\"]\n\
                  }\n\
                ]\n\
              }\n\
              ```\n\
             Include every finding you assessed. Use confidence_percent in the 1-100 range and include at least one evidence item per assessment.",
        ),
        DEFENSE_ANALYST_V1_SCHEMA => Some(
            "\n\n--- Structured Output Contract ---\n\
             At the end of your final response, append a fenced JSON block labelled `json`.\n\
             The JSON MUST match this schema exactly:\n\
             ```json\n\
             {\n\
               \"summary\": \"One concise defensive-mitigation summary\",\n\
               \"assessments\": [\n\
                 {\n\
                   \"finding_title\": \"Exact finding title under review\",\n\
                   \"verdict\": \"VULNERABLE|MITIGATED|SAFE\",\n\
                    \"confidence_percent\": 1,\n\
                    \"evidence\": [\"Concrete mitigation or missing-control evidence\"]\n\
                  }\n\
                ]\n\
              }\n\
              ```\n\
             Include every finding you assessed. Use confidence_percent in the 1-100 range and include at least one evidence item per assessment.",
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
            validate_vuln_hunter_output(&parsed)?;
            Ok(ParsedAgentOutput::VulnHunterV1(parsed))
        }
        EXPLOIT_ANALYST_V1_SCHEMA => {
            let parsed: ExploitAnalystStructuredOutput = serde_json::from_str(&json_block)
                .map_err(|e| {
                    anyhow::anyhow!("Failed to parse exploit-analyst structured output: {e}")
                })?;
            validate_exploit_analyst_output(&parsed)?;
            Ok(ParsedAgentOutput::ExploitAnalystV1(parsed))
        }
        DEFENSE_ANALYST_V1_SCHEMA => {
            let parsed: DefenseAnalystStructuredOutput = serde_json::from_str(&json_block)
                .map_err(|e| {
                    anyhow::anyhow!("Failed to parse defense-analyst structured output: {e}")
                })?;
            validate_defense_analyst_output(&parsed)?;
            Ok(ParsedAgentOutput::DefenseAnalystV1(parsed))
        }
        _ => anyhow::bail!("Unknown agent output schema '{schema_name}'"),
    }
}

fn validate_vuln_hunter_output(output: &VulnHunterStructuredOutput) -> anyhow::Result<()> {
    for finding in &output.findings {
        if !is_valid_cwe_id(&finding.cwe_id) {
            anyhow::bail!("Invalid CWE id '{}'", finding.cwe_id);
        }
    }
    Ok(())
}

fn validate_exploit_analyst_output(output: &ExploitAnalystStructuredOutput) -> anyhow::Result<()> {
    for assessment in &output.assessments {
        validate_confidence_and_title(
            assessment.finding_title.as_str(),
            assessment.confidence_percent,
            "exploit assessment",
        )?;
        validate_assessment_evidence(&assessment.evidence, assessment.finding_title.as_str())?;
    }
    Ok(())
}

fn validate_defense_analyst_output(output: &DefenseAnalystStructuredOutput) -> anyhow::Result<()> {
    for assessment in &output.assessments {
        validate_confidence_and_title(
            assessment.finding_title.as_str(),
            assessment.confidence_percent,
            "defense assessment",
        )?;
        validate_assessment_evidence(&assessment.evidence, assessment.finding_title.as_str())?;
    }
    Ok(())
}

fn validate_confidence_and_title(
    finding_title: &str,
    confidence_percent: u8,
    label: &str,
) -> anyhow::Result<()> {
    if finding_title.trim().is_empty() {
        anyhow::bail!("{label} must include a non-empty finding_title");
    }
    if confidence_percent == 0 {
        anyhow::bail!("{label} confidence_percent must be in the 1-100 range");
    }
    if confidence_percent > 100 {
        anyhow::bail!("{label} confidence_percent must be in the 1-100 range");
    }
    Ok(())
}

fn validate_assessment_evidence(evidence: &[String], finding_title: &str) -> anyhow::Result<()> {
    if evidence.iter().all(|item| item.trim().is_empty()) {
        anyhow::bail!(
            "assessment '{}' must include at least one evidence item",
            finding_title
        );
    }
    Ok(())
}

fn format_evidence_list(evidence: &[String]) -> String {
    let filtered: Vec<&str> = evidence
        .iter()
        .map(String::as_str)
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .collect();
    if filtered.is_empty() {
        "none".into()
    } else {
        filtered.join(" | ")
    }
}

fn deserialize_null_as_empty_vec<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: Deserializer<'de>,
{
    Ok(Option::<Vec<String>>::deserialize(deserializer)?.unwrap_or_default())
}

fn is_valid_cwe_id(value: &str) -> bool {
    let Some(rest) = value.strip_prefix("CWE-") else {
        return false;
    };
    !rest.is_empty() && rest.chars().all(|ch| ch.is_ascii_digit())
}

fn extract_last_json_code_block(output: &str) -> Option<String> {
    let mut cursor = 0usize;
    let mut last_block = None;

    while let Some(relative_start) = output[cursor..].find("```json") {
        let block_start = cursor + relative_start + "```json".len();
        let rest = &output[block_start..];
        let mut block_end = None;
        let mut closing_offset = 0usize;

        for line in rest.split_inclusive('\n') {
            let trimmed = line.trim_end_matches(['\r', '\n']);
            closing_offset += line.len();
            if trimmed == "```" {
                block_end = Some(closing_offset - line.len());
                break;
            }
        }

        let Some(end) = block_end else {
            break;
        };

        last_block = Some(rest[..end].trim().to_string());
        cursor = block_start + closing_offset;
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
            other => panic!("expected vuln hunter output, got {:?}", other),
        }
    }

    #[test]
    fn rejects_missing_json_code_block() {
        let error = parse_structured_output(VULN_HUNTER_V1_SCHEMA, "plain text only").unwrap_err();
        assert!(error.to_string().contains("Missing fenced JSON block"));
    }

    #[test]
    fn keeps_last_complete_json_block_when_trailing_block_is_unclosed() {
        let output = r#"```json
{"summary":"complete","findings":[]}
```

```json
{"summary":"incomplete","findings":[]}"#;

        let parsed = parse_structured_output(VULN_HUNTER_V1_SCHEMA, output).unwrap();
        match parsed {
            ParsedAgentOutput::VulnHunterV1(data) => assert_eq!(data.summary, "complete"),
            other => panic!("expected vuln hunter output, got {:?}", other),
        }
    }

    #[test]
    fn allows_backticks_inside_json_string_values() {
        let output = r#"```json
{"summary":"Has ``` in string","findings":[]}
```"#;

        let parsed = parse_structured_output(VULN_HUNTER_V1_SCHEMA, output).unwrap();
        match parsed {
            ParsedAgentOutput::VulnHunterV1(data) => assert_eq!(data.summary, "Has ``` in string"),
            other => panic!("expected vuln hunter output, got {:?}", other),
        }
    }

    #[test]
    fn rejects_invalid_cwe_id() {
        let output = r#"```json
{"summary":"one","findings":[{"title":"Overflow","severity":"high","cwe_id":"121","function":"parse_header"}]}
```"#;

        let error = parse_structured_output(VULN_HUNTER_V1_SCHEMA, output).unwrap_err();
        assert!(error.to_string().contains("Invalid CWE id"));
    }

    #[test]
    fn rejects_unknown_fields() {
        let output = r#"```json
{"summary":"one","unexpected":"field","findings":[]}
```"#;

        let error = parse_structured_output(VULN_HUNTER_V1_SCHEMA, output).unwrap_err();
        assert!(error.to_string().contains("unknown field"));
    }

    #[test]
    fn parses_exploit_analyst_structured_output() {
        let output = r#"```json
{
  "summary": "One finding is clearly exploitable",
  "assessments": [
    {
      "finding_title": "Buffer overflow in parse_header",
      "verdict": "CONFIRMED",
      "confidence_percent": 88,
      "evidence": ["Attacker controls packet length", "No bounds check before copy"]
    }
  ]
}
```"#;

        let parsed = parse_structured_output(EXPLOIT_ANALYST_V1_SCHEMA, output).unwrap();
        assert_eq!(parsed.schema_name(), EXPLOIT_ANALYST_V1_SCHEMA);
        assert!(parsed.context_summary().contains("CONFIRMED"));
        assert!(parsed.context_summary().contains("88%"));
    }

    #[test]
    fn parses_defense_analyst_structured_output() {
        let output = r#"```json
{
  "summary": "One mitigation is incomplete",
  "assessments": [
    {
      "finding_title": "Buffer overflow in parse_header",
      "verdict": "MITIGATED",
      "confidence_percent": 62,
      "evidence": ["Caller caps normal inputs but not crafted packets"]
    }
  ]
}
```"#;

        let parsed = parse_structured_output(DEFENSE_ANALYST_V1_SCHEMA, output).unwrap();
        assert_eq!(parsed.schema_name(), DEFENSE_ANALYST_V1_SCHEMA);
        assert!(parsed.context_summary().contains("MITIGATED"));
        assert!(parsed.context_summary().contains("62%"));
    }

    #[test]
    fn rejects_zero_confidence_exploit_assessments() {
        let output = r#"```json
{
  "summary": "invalid exploit confidence",
  "assessments": [
    {
      "finding_title": "Buffer overflow in parse_header",
      "verdict": "CONFIRMED",
      "confidence_percent": 0,
      "evidence": ["Attacker controls packet length"]
    }
  ]
}
```"#;

        let error = parse_structured_output(EXPLOIT_ANALYST_V1_SCHEMA, output).unwrap_err();
        assert!(error.to_string().contains("1-100"));
    }

    #[test]
    fn rejects_empty_defense_assessment_evidence() {
        let output = r#"```json
{
  "summary": "missing defense evidence",
  "assessments": [
    {
      "finding_title": "Buffer overflow in parse_header",
      "verdict": "SAFE",
      "confidence_percent": 55,
      "evidence": []
    }
  ]
}
```"#;

        let error = parse_structured_output(DEFENSE_ANALYST_V1_SCHEMA, output).unwrap_err();
        assert!(error.to_string().contains("at least one evidence item"));
    }

    #[test]
    fn rejects_null_exploit_assessment_evidence_via_validation() {
        let output = r#"```json
{
  "summary": "null exploit evidence",
  "assessments": [
    {
      "finding_title": "Buffer overflow in parse_header",
      "verdict": "CONFIRMED",
      "confidence_percent": 80,
      "evidence": null
    }
  ]
}
```"#;

        let error = parse_structured_output(EXPLOIT_ANALYST_V1_SCHEMA, output).unwrap_err();
        assert!(error.to_string().contains("at least one evidence item"));
    }

    #[test]
    fn parses_info_severity_finding() {
        let output = r#"```json
{
  "summary": "Informational observation",
  "findings": [
    {
      "title": "Unused import detected",
      "severity": "info",
      "cwe_id": "CWE-561",
      "function": "main"
    }
  ]
}
```"#;

        let parsed = parse_structured_output(VULN_HUNTER_V1_SCHEMA, output).unwrap();
        match parsed {
            ParsedAgentOutput::VulnHunterV1(data) => {
                assert_eq!(data.findings[0].severity, VulnHunterSeverity::Info);
                assert_eq!(data.findings[0].severity.to_string(), "info");
            }
            other => panic!("expected vuln hunter output, got {:?}", other),
        }
    }

    #[test]
    fn output_contract_includes_info_severity() {
        let contract = output_schema_contract(VULN_HUNTER_V1_SCHEMA).unwrap();
        assert!(contract.contains("info"));
    }
}
