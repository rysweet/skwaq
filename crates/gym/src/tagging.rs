//! Eval result tagging: create git tags and GitHub releases from eval results.

use anyhow::{bail, Context};
use serde::Serialize;
use std::path::Path;

/// All data needed to create an eval release tag.
#[derive(Debug, Clone, Serialize)]
pub struct EvalTagPayload {
    pub tag_name: String,
    pub commit: String,
    pub timestamp: String,
    pub mode: String,
    pub suites: String,
    pub procs_per_suite: usize,
    pub concurrency: usize,
    pub llm_backend: String,
    pub llm_model: String,
    pub binary_mode: bool,
    pub skwaq_version: String,
    pub git_dirty: bool,
    pub suite_results: Vec<SuiteTagResult>,
    pub per_cwe: Vec<CweTagResult>,
    pub reproducible_command: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct SuiteTagResult {
    pub suite: String,
    pub f1: f64,
    pub precision: f64,
    pub recall: f64,
    pub true_positives: u32,
    pub false_positives: u32,
    pub false_negatives: u32,
    pub true_negatives: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct CweTagResult {
    pub suite: String,
    pub cwe_id: u32,
    pub total_cases: u32,
    pub true_positives: u32,
    pub false_positives: u32,
    pub false_negatives: u32,
    pub detection_rate: f64,
    pub precision: f64,
}

/// Compute the next available tag name for today (eval-YYYY-MM-DD or eval-YYYY-MM-DD-vN).
pub fn next_tag_name(repo: &Path) -> anyhow::Result<String> {
    let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
    let prefix = format!("eval-{}", today);

    let output = std::process::Command::new("git")
        .args(["tag", "--list", &format!("{}*", prefix)])
        .current_dir(repo)
        .output()
        .context("failed to list git tags")?;

    if !output.status.success() {
        bail!(
            "git tag --list failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }

    let existing: Vec<String> = String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    if existing.is_empty() {
        return Ok(prefix);
    }

    // Find the highest version number
    let mut max_version = 0u32;
    for tag in &existing {
        if tag == &prefix {
            max_version = max_version.max(1);
        } else if let Some(suffix) = tag.strip_prefix(&format!("{}-v", prefix)) {
            if let Ok(v) = suffix.parse::<u32>() {
                max_version = max_version.max(v);
            }
        }
    }

    Ok(format!("{}-v{}", prefix, max_version + 1))
}

/// Render the release body as markdown.
pub fn render_release_body(payload: &EvalTagPayload) -> String {
    let mut body = String::new();

    body.push_str("# Skwaq Gym Eval Results\n\n");

    // Metadata
    body.push_str("## Metadata\n\n");
    body.push_str(&format!("- **Commit**: `{}`\n", payload.commit));
    body.push_str(&format!("- **Timestamp**: {}\n", payload.timestamp));
    body.push_str(&format!("- **Mode**: {}\n", payload.mode));
    body.push_str(&format!("- **Suites**: {}\n", payload.suites));
    body.push_str(&format!("- **Procs/suite**: {}\n", payload.procs_per_suite));
    body.push_str(&format!("- **Concurrency**: {}\n", payload.concurrency));
    body.push_str(&format!("- **LLM backend**: {}\n", payload.llm_backend));
    body.push_str(&format!("- **LLM model**: {}\n", payload.llm_model));
    body.push_str(&format!("- **Binary mode**: {}\n", payload.binary_mode));
    body.push_str(&format!("- **Version**: {}\n", payload.skwaq_version));
    body.push_str(&format!("- **Git dirty**: {}\n", payload.git_dirty));

    // Results table
    body.push_str("\n## Results\n\n");
    body.push_str("| Suite | F1 | Precision | Recall | TP | FP | FN | TN |\n");
    body.push_str("|-------|----|-----------|--------|----|----|----|----|----|\n");
    for s in &payload.suite_results {
        body.push_str(&format!(
            "| {} | {:.1}% | {:.1}% | {:.1}% | {} | {} | {} | {} |\n",
            s.suite,
            s.f1 * 100.0,
            s.precision * 100.0,
            s.recall * 100.0,
            s.true_positives,
            s.false_positives,
            s.false_negatives,
            s.true_negatives,
        ));
    }

    // Per-CWE breakdown
    if !payload.per_cwe.is_empty() {
        body.push_str("\n## Per-CWE Breakdown\n\n");
        body.push_str("| Suite | CWE | Cases | TP | FP | FN | Detection | Precision |\n");
        body.push_str("|-------|-----|-------|----|----|----|-----------|----------|\n");
        for c in &payload.per_cwe {
            body.push_str(&format!(
                "| {} | CWE-{} | {} | {} | {} | {} | {:.1}% | {:.1}% |\n",
                c.suite,
                c.cwe_id,
                c.total_cases,
                c.true_positives,
                c.false_positives,
                c.false_negatives,
                c.detection_rate * 100.0,
                c.precision * 100.0,
            ));
        }
    }

    // Reproducible command
    body.push_str("\n## Reproduce\n\n");
    body.push_str("```bash\n");
    body.push_str(&payload.reproducible_command);
    body.push_str("\n```\n");

    body
}

/// Create a git tag at the current HEAD.
pub fn create_git_tag(repo: &Path, tag_name: &str, message: &str) -> anyhow::Result<()> {
    let output = std::process::Command::new("git")
        .args(["tag", "-a", tag_name, "-m", message])
        .current_dir(repo)
        .output()
        .context("failed to create git tag")?;

    if !output.status.success() {
        bail!(
            "git tag failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(())
}

/// Push the tag to origin.
pub fn push_tag(repo: &Path, tag_name: &str) -> anyhow::Result<()> {
    let output = std::process::Command::new("git")
        .args(["push", "origin", tag_name])
        .current_dir(repo)
        .output()
        .context("failed to push git tag")?;

    if !output.status.success() {
        bail!(
            "git push tag failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(())
}

/// Create a GitHub release using `gh release create`.
/// Attaches the results JSON as an asset.
pub fn create_github_release(
    repo: &Path,
    tag_name: &str,
    title: &str,
    body: &str,
    assets: &[&Path],
) -> anyhow::Result<()> {
    let mut cmd = std::process::Command::new("gh");
    cmd.args(["release", "create", tag_name])
        .args(["--title", title])
        .args(["--notes", body])
        .current_dir(repo);

    for asset in assets {
        cmd.arg(asset);
    }

    let output = cmd.output().context("failed to run gh release create")?;

    if !output.status.success() {
        bail!(
            "gh release create failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(())
}

/// Build the reproducible command string from eval parameters.
pub fn build_reproducible_command(
    suites: &str,
    max_cases: usize,
    procs: usize,
    concurrency: usize,
    quick: bool,
    llm_only: bool,
    adaptive: bool,
) -> String {
    let mut cmd = format!(
        "skwaq gym eval --suites {} --procs {} -j {}",
        suites, procs, concurrency
    );
    if max_cases > 0 {
        cmd.push_str(&format!(" --max-cases {}", max_cases));
    }
    if quick {
        cmd.push_str(" --quick");
    } else if llm_only {
        cmd.push_str(" --llm-only");
    }
    if adaptive {
        cmd.push_str(" --adaptive");
    }
    cmd.push_str(" --tag");
    cmd
}

/// Full tagging workflow: create tag, push, create GitHub release with assets.
pub fn tag_eval_results(
    repo: &Path,
    payload: &EvalTagPayload,
    results_json_path: &Path,
) -> anyhow::Result<String> {
    let tag_name = &payload.tag_name;

    // Write the full payload JSON next to the results
    let payload_path = results_json_path
        .parent()
        .unwrap_or(Path::new("."))
        .join("eval-tag-payload.json");
    std::fs::write(&payload_path, serde_json::to_string_pretty(payload)?)?;

    // Create annotated git tag
    let tag_message = format!(
        "Eval results: {} mode={} F1=[{}]",
        payload.suites,
        payload.mode,
        payload
            .suite_results
            .iter()
            .map(|s| format!("{}={:.1}%", s.suite, s.f1 * 100.0))
            .collect::<Vec<_>>()
            .join(", ")
    );
    create_git_tag(repo, tag_name, &tag_message)?;
    println!("  Created git tag: {}", tag_name);

    // Push tag
    push_tag(repo, tag_name)?;
    println!("  Pushed tag to origin");

    // Create GitHub release with assets
    let title = format!(
        "Eval {} — {}",
        payload.mode,
        payload
            .suite_results
            .iter()
            .map(|s| format!("{} F1={:.1}%", s.suite, s.f1 * 100.0))
            .collect::<Vec<_>>()
            .join(", ")
    );
    let body = render_release_body(payload);
    let assets: Vec<&Path> = vec![results_json_path, &payload_path];
    create_github_release(repo, tag_name, &title, &body, &assets)?;
    println!("  Created GitHub release: {}", tag_name);

    Ok(tag_name.clone())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_reproducible_command_hybrid() {
        let cmd = build_reproducible_command("fixtures,juliet,owasp", 0, 5, 2, false, false, false);
        assert_eq!(
            cmd,
            "skwaq gym eval --suites fixtures,juliet,owasp --procs 5 -j 2 --tag"
        );
    }

    #[test]
    fn test_build_reproducible_command_quick() {
        let cmd = build_reproducible_command("fixtures", 100, 3, 1, true, false, true);
        assert_eq!(
            cmd,
            "skwaq gym eval --suites fixtures --procs 3 -j 1 --max-cases 100 --quick --adaptive --tag"
        );
    }

    #[test]
    fn test_build_reproducible_command_llm_only() {
        let cmd = build_reproducible_command("juliet", 50, 2, 4, false, true, false);
        assert_eq!(
            cmd,
            "skwaq gym eval --suites juliet --procs 2 -j 4 --max-cases 50 --llm-only --tag"
        );
    }

    #[test]
    fn test_render_release_body_contains_sections() {
        let payload = EvalTagPayload {
            tag_name: "eval-2026-03-26".to_string(),
            commit: "abc123".to_string(),
            timestamp: "2026-03-26T00:00:00Z".to_string(),
            mode: "pattern-only".to_string(),
            suites: "fixtures".to_string(),
            procs_per_suite: 1,
            concurrency: 2,
            llm_backend: "copilot".to_string(),
            llm_model: "claude-opus-4.6".to_string(),
            binary_mode: true,
            skwaq_version: "0.1.0".to_string(),
            git_dirty: false,
            suite_results: vec![SuiteTagResult {
                suite: "fixtures".to_string(),
                f1: 0.6,
                precision: 0.75,
                recall: 0.5,
                true_positives: 3,
                false_positives: 1,
                false_negatives: 3,
                true_negatives: 7,
            }],
            per_cwe: vec![CweTagResult {
                suite: "fixtures".to_string(),
                cwe_id: 121,
                total_cases: 6,
                true_positives: 3,
                false_positives: 1,
                false_negatives: 3,
                detection_rate: 0.5,
                precision: 0.75,
            }],
            reproducible_command: "skwaq gym eval --suites fixtures --procs 1 -j 2 --quick --tag"
                .to_string(),
        };

        let body = render_release_body(&payload);
        assert!(body.contains("# Skwaq Gym Eval Results"));
        assert!(body.contains("## Metadata"));
        assert!(body.contains("abc123"));
        assert!(body.contains("## Results"));
        assert!(body.contains("fixtures"));
        assert!(body.contains("## Per-CWE Breakdown"));
        assert!(body.contains("CWE-121"));
        assert!(body.contains("## Reproduce"));
        assert!(body.contains("skwaq gym eval"));
    }

    #[test]
    fn test_render_release_body_no_cwe_section_when_empty() {
        let payload = EvalTagPayload {
            tag_name: "eval-2026-03-26".to_string(),
            commit: "abc123".to_string(),
            timestamp: "2026-03-26T00:00:00Z".to_string(),
            mode: "quick".to_string(),
            suites: "fixtures".to_string(),
            procs_per_suite: 1,
            concurrency: 1,
            llm_backend: "none".to_string(),
            llm_model: "none".to_string(),
            binary_mode: false,
            skwaq_version: "0.1.0".to_string(),
            git_dirty: false,
            suite_results: vec![],
            per_cwe: vec![],
            reproducible_command: "skwaq gym eval --tag".to_string(),
        };
        let body = render_release_body(&payload);
        assert!(!body.contains("Per-CWE Breakdown"));
    }
}
