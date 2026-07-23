# Design: Empty-Patch Pre-Screen (#509)

## Classification: TRIVIAL

Single `.retain()` insertion + one unit test in `improve.rs`.

## Consolidated Implementation Plan

```json
{
  "components": [
    {
      "name": "analyze_false_negatives() — empty-patch pre-screen",
      "action": "modify",
      "purpose": "Filter out proposals with empty or whitespace-only patches before they consume reviewer LLM budget"
    },
    {
      "name": "mod tests — test_empty_patch_pre_screen",
      "action": "modify",
      "purpose": "Unit test verifying empty and whitespace-only patches are rejected while real patches pass"
    }
  ],
  "files_to_change": [
    "crates/gym/src/improve.rs"
  ],
  "new_files": [],
  "test_files": [
    "crates/gym/src/improve.rs (inline #[cfg(test)] mod tests)"
  ],
  "implementation_order": [
    "1. Insert .retain() empty-patch pre-screen block at improve.rs line 677",
    "2. Add test_empty_patch_pre_screen to existing #[cfg(test)] mod tests block",
    "3. Run cargo clippy --all-targets — zero warnings",
    "4. Run cargo test -p skwaq-gym test_empty_patch_pre_screen — new test passes",
    "5. Run cargo test -p skwaq-gym — no regressions"
  ],
  "risks": [
    "Line numbers may shift from concurrent PRs — verified against current file: insertion point is line 677"
  ],
  "security_considerations": [
    "No security concerns. Marginally improves security posture by reducing unnecessary LLM calls.",
    "Do not log p.patch.replace content — only log truncated p.description (80 chars).",
    "Preserve apply-phase skipped_empty_patch counter as defense-in-depth."
  ]
}
```

## Insertion Point

File: `crates/gym/src/improve.rs`
Location: Line 677 (blank line between forbidden-vocabulary pre-screen summary at line 675-676 and overfitting review call at line 678).

## Change 1: Empty-patch pre-screen filter

Insert after the forbidden-vocabulary pre-screen, before the overfitting review call:

```rust
// Empty-patch pre-screen: reject proposals with no actual patch content
// before wasting reviewer LLM budget (#509).
let empty_patch_pre_count = proposals.len();
proposals.retain(|p| {
    if p.patch.replace.trim().is_empty() {
        tracing::warn!(
            "Pre-screen rejected proposal '{}': empty patch (guidance-only)",
            p.description.chars().take(80).collect::<String>()
        );
        false
    } else {
        true
    }
});
let empty_patch_rejected = empty_patch_pre_count - proposals.len();
if empty_patch_rejected > 0 {
    tracing::info!("Empty-patch pre-screen rejected {empty_patch_rejected} proposal(s)");
}
```

**Design decisions:**
- `trim().is_empty()` — catches both `""` and `"  \n  "` (strict superset of `.is_empty()`)
- `tracing::warn!` per-proposal — matches forbidden-vocabulary pattern (line 664)
- `tracing::info!` summary — matches forbidden-vocabulary pattern (line 675)
- `.chars().take(80)` — matches existing truncation pattern (line 666)
- Comment references `#509` — traceability

## Change 2: Unit test

Add to `#[cfg(test)] mod tests`:

```rust
#[test]
fn test_empty_patch_pre_screen() {
    let mut proposals = vec![
        Improvement {
            kind: ImprovementKind::NewPattern,
            description: "Valid pattern with real patch".to_string(),
            target_cwes: vec![79],
            target_file: PathBuf::from("crates/core/src/analysis/patterns_source.rs"),
            patch: Patch {
                find: String::new(),
                replace: r"\beval\s*\(".to_string(),
            },
            source_case: "case_1".to_string(),
            priority: Priority::High,
            supporting_evidence: Vec::new(),
            review: None,
        },
        Improvement {
            kind: ImprovementKind::NewPattern,
            description: "Empty patch — guidance only".to_string(),
            target_cwes: vec![89],
            target_file: PathBuf::from("crates/core/src/analysis/patterns_source.rs"),
            patch: Patch {
                find: String::new(),
                replace: String::new(),
            },
            source_case: "case_2".to_string(),
            priority: Priority::High,
            supporting_evidence: Vec::new(),
            review: None,
        },
        Improvement {
            kind: ImprovementKind::NewPattern,
            description: "Whitespace-only patch".to_string(),
            target_cwes: vec![78],
            target_file: PathBuf::from("crates/core/src/analysis/patterns_source.rs"),
            patch: Patch {
                find: String::new(),
                replace: "   \n  ".to_string(),
            },
            source_case: "case_3".to_string(),
            priority: Priority::Medium,
            supporting_evidence: Vec::new(),
            review: None,
        },
    ];

    proposals.retain(|p| !p.patch.replace.trim().is_empty());

    assert_eq!(proposals.len(), 1);
    assert!(proposals[0].description.contains("Valid pattern"));
}
```

## What Does NOT Change

- `Improvement` struct, `Patch` struct, `ApplyReport` struct — unchanged
- `apply_improvements()` — the `skipped_empty_patch` counter stays as defense-in-depth
- No other functions, no cross-crate changes, no new dependencies

## Security Assessment

No security concerns. Pure in-memory filter on a local `Vec`. No network I/O, no user input parsing, no auth boundaries. Marginally improves security by reducing unnecessary LLM reviewer calls on invalid proposals.

## Validation Plan

1. `cargo clippy --all-targets` — zero warnings
2. `cargo test -p skwaq-gym test_empty_patch_pre_screen` — new test passes
3. `cargo test -p skwaq-gym` — all existing tests pass
