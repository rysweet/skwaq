# Skwaq Gym Implementation Handoff

## For the Next Agent

You are implementing the Skwaq Gym benchmark harness. All design work is done. Your job is to build it.

## Key Documents

1. **Full design**: `Specifications/skwaq-gym-design.md` (~2000 lines, complete with Rust structs, SQL schema, algorithms, file paths)
2. **Review findings**: Bottom of the design doc, section "Review Findings & Required Changes" - 13 issues identified by 2 independent reviewers that MUST be addressed
3. **Roadmap issue**: https://github.com/rysweet/skwaq/issues/25
4. **Vulnerability intelligence roadmap**: https://github.com/rysweet/skwaq/issues/24

## Project State

- **Repo**: https://github.com/rysweet/skwaq
- **Main branch**: protected (PRs required)
- **Pre-commit hooks**: cargo fmt + clippy on commit, cargo test on push
- **Tests**: 139 passing
- **Crates**: `core` (library) + `cli` (binary) - the `agents` crate was deleted
- **LLM**: Delegates to RustyClawd's Client (Anthropic + Copilot backends)
- **Default model**: claude-opus-4-6 via ANTHROPIC_API_KEY
- **Agents**: Dynamic markdown definitions in `agents/` directory
- **Skills**: Agent Skills standard (SKILL.md) in `skills/` directory
- **Ghidra**: Installed at /opt/ghidra, integrated with caching
- **Self-test**: `skwaq self-test` runs analysis on own code (must pass)

## Mandatory Process

**You MUST follow the default workflow** at `~/.amplihack/.claude/workflow/DEFAULT_WORKFLOW.md` for ALL code changes:

1. Create GitHub issue
2. Create worktree + branch (`git worktree add ./worktrees/feat-xxx -b feat/xxx`)
3. Implement in the worktree
4. Run tests: `cargo test -- --test-threads=1`
5. Run self-test: `./target/debug/skwaq self-test`
6. Commit (pre-commit hooks enforce fmt + clippy)
7. Push branch, create PR
8. Merge via `gh pr merge N -R rysweet/skwaq --merge --admin`
9. Sync main: `git fetch origin main && git reset --hard origin/main`
10. Clean up worktree: `git worktree remove worktrees/feat-xxx`

**Direct pushes to main are blocked.** Branch protection is enforced.

## Implementation Order (from design doc)

1. Workspace setup: add `crates/gym` to `Cargo.toml`
2. `BenchmarkAdapter` trait + ground truth loader
3. Fixtures adapter (smallest, tests the framework)
4. Scoring engine
5. Terminal + JSON + Markdown reports
6. History database
7. CLI integration (`skwaq gym run/report/compare/history`)
8. Juliet adapter (download, compile, manifest)
9. CGC adapter
10. CyberSecEval adapter
11. Self-improvement loop (with human gate)
12. CI integration
13. Run full benchmarks, establish baseline
14. First improvement cycle
15. Documentation

## Critical Review Issues to Address

From the security + code reviews (details in design doc):

- **Mandatory SHA-256 on downloads** (no empty checksums)
- **Human approval gate on self-improvement patches**
- **Per-case analysis timeouts** (30s quick, 300s AI)
- **Safe archive extraction** (validate paths, reject `..`)
- **Fix API mismatches** (use `DangerousApiDetector::detect_in_source_content()`, not `SourcePatternDetector`)
- **One CWE matching strategy** (not two stacked)
- **Compilation sandboxing** (ulimit at minimum)

## Environment

- Rust 1.93, cargo
- Ghidra 11.3 at /opt/ghidra (set GHIDRA_INSTALL_DIR=/opt/ghidra)
- Python 3.13
- ANTHROPIC_API_KEY set in env
- GitHub CLI (`gh`) authenticated as `rysweet`
- Pre-commit hooks installed

## Quick Verification

```bash
cd /home/azureuser/src/skwaq
cargo test -- --test-threads=1        # 139 tests pass
cargo build                           # Compiles cleanly
./target/debug/skwaq self-test        # Self-analysis passes
./target/debug/skwaq agents list      # 5 agents (claude-opus-4-6)
./target/debug/skwaq skills list      # 7 skills
./target/debug/skwaq doctor           # Shows deps status
```
