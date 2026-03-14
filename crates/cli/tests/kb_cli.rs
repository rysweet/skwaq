use std::path::{Path, PathBuf};
use std::process::Command;

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .canonicalize()
        .unwrap()
}

fn create_temp_workspace() -> tempfile::TempDir {
    let temp = tempfile::tempdir().unwrap();
    let root = workspace_root();
    let data_dir = temp.path().join("data").join("knowledge");
    std::fs::create_dir_all(&data_dir).unwrap();

    let source_dir = root.join("data").join("knowledge");
    for entry in std::fs::read_dir(source_dir).unwrap() {
        let entry = entry.unwrap();
        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("md") {
            continue;
        }
        std::fs::copy(&path, data_dir.join(path.file_name().unwrap())).unwrap();
    }

    std::fs::write(
        temp.path().join("skwaq.toml"),
        format!(
            "[general]\ndatabase_path = '{}'\n",
            temp.path().join(".skwaq").join("graph").display()
        ),
    )
    .unwrap();

    temp
}

fn run_cli(workspace: &Path, args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_skwaq"))
        .current_dir(workspace)
        .args(args)
        .output()
        .unwrap()
}

#[test]
fn test_kb_init_populates_cwe_catalog_via_cli() {
    let workspace = create_temp_workspace();
    let output = run_cli(workspace.path(), &["kb", "init"]);
    assert!(output.status.success(), "{output:?}");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Knowledge base initialized"));
    assert!(stdout.contains("knowledge pack files"));
}

#[test]
fn test_kb_search_json_returns_cwe_and_pack_results() {
    let workspace = create_temp_workspace();
    let init = run_cli(workspace.path(), &["kb", "init"]);
    assert!(init.status.success(), "{init:?}");

    let output = run_cli(
        workspace.path(),
        &["kb", "search", "cwe-119 buffer overflow", "--json"],
    );
    assert!(output.status.success(), "{output:?}");

    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["status"], "ok");
    let results = json["results"].as_array().unwrap();
    assert!(results.iter().any(|entry| entry["source"] == "cwe"));
    assert!(results
        .iter()
        .any(|entry| entry["source"] == "knowledge-pack"));
}
