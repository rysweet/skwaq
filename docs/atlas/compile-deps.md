# Layer 2 — Compile Dependencies

## What this layer shows

The Cargo dependency graph between workspace crates and their key external dependencies.

## Workspace dependency chain

```
skwaq (cli)
├── skwaq-core        (path = "../core")
├── skwaq-gym         (path = "../gym")
│   └── skwaq-core    (path = "../core")
└── rustyclawd-tools  (workspace git dep)

skwaq-core
└── rustyclawd-core   (workspace git dep)
```

## Internal git dependencies

Both `rustyclawd-core` and `rustyclawd-tools` come from the same Git repo:

| Crate | Source |
|-------|--------|
| `rustyclawd-core` | `github.com/rysweet/RustyClawd` @ `8bf3b07` |
| `rustyclawd-tools` | same repo/rev |
| `rustyclawd-cli` | declared in workspace but not used by any member |

> **Note**: `rustyclawd-cli` is declared as a workspace dependency but is not referenced in any crate's `[dependencies]`. This may be dead configuration.

## Key external dependencies by category

| Category | Crates | Used by |
|----------|--------|---------|
| Async / Runtime | `tokio`, `futures`, `async-trait` | all |
| CLI / TUI | `clap`, `ratatui`, `crossterm`, `indicatif` | cli, gym |
| Serialization | `serde`, `serde_json`, `serde_yaml_ng`, `toml` | all |
| Errors | `anyhow`, `thiserror` | all |
| Logging | `tracing`, `tracing-subscriber` | all |
| Binary analysis | `goblin`, `tree-sitter`, `tree-sitter-c` | core |
| Storage | `rusqlite` | core, gym |
| Network | `reqwest` | core, gym |
| Archive / Parallel | `flate2`, `tar`, `zip`, `walkdir`, `rayon` | gym |

## Diagram files

- [compile-deps.mmd](compile-deps.mmd) — Mermaid source
- [compile-deps.dot](compile-deps.dot) — Graphviz source
