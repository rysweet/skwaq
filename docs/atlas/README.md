# Skwaq Code Atlas

A multi-layer architecture document derived from code-first truth.

| Layer | What it shows | Files |
|-------|--------------|-------|
| [repo-surface](repo-surface.md) | Top-level directory structure, crate organisation, build system | [.mmd](repo-surface.mmd) · [.dot](repo-surface.dot) |
| [compile-deps](compile-deps.md) | Cargo dependency graph — workspace crates and key external deps | [.mmd](compile-deps.mmd) · [.dot](compile-deps.dot) |
| [service-components](service-components.md) | Module structure within each crate (core, gym, cli) | [.mmd](service-components.mmd) · [.dot](service-components.dot) |
| [data-flow](data-flow.md) | The 5-layer detection pipeline: patterns → dataflow → context → agents → synthesis | [.mmd](data-flow.mmd) · [.dot](data-flow.dot) |

## Rendering

```bash
# Mermaid → SVG
mmdc -i docs/atlas/repo-surface.mmd -o docs/atlas/repo-surface.svg

# Graphviz → SVG
dot -Tsvg docs/atlas/repo-surface.dot -o docs/atlas/repo-surface.svg
```

## Bug Hunt

Pass 1 findings are filed as GitHub issues with label `code-atlas-bughunt`.
