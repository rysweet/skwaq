# LadybugDB Buffer Pool Configuration

LadybugDB instances created by `in_memory()` use constrained resource limits
to support high-concurrency workloads like gym benchmarks, where dozens of
instances run simultaneously.

## Problem

LadybugDB's `SystemConfig::default()` auto-detects system resources and
allocates accordingly. On a machine with 200GB+ RAM and 32 cores, each
instance reserves ~204GB of virtual address space and 32 threads. When the
gym benchmark creates 96 concurrent instances, this exceeds kernel limits
(`vm.max_map_count`, thread caps) and causes `mmap` or thread-creation
failures.

## Solution

The `in_memory()` constructor passes explicit resource limits:

```rust
lbug::SystemConfig::default()
    .buffer_pool_size(64 * 1024 * 1024)  // 64 MB
    .max_num_threads(1)
```

| Setting | Default | In-memory | Reduction |
|---|---|---|---|
| Buffer pool | ~200 GB (auto) | 64 MB | ~3000x |
| Threads | 32 (auto) | 1 | 32x |
| Virtual address space per instance | ~204 GB | ~4 GB | ~50x |

## Scope

Only `in_memory()` is affected. Production constructors retain defaults:

| Constructor | Buffer pool | Threads | Rationale |
|---|---|---|---|
| `open()` | default (auto) | default (auto) | Single long-lived production instance |
| `open_read_only()` | default (auto) | default (auto) | Single read-only instance |
| `in_memory()` | 64 MB | 1 | Many concurrent short-lived test/benchmark instances |

## Capacity

With 64 MB buffer and 1 thread per instance, the system supports ~96
concurrent `in_memory()` instances within typical Linux defaults
(`vm.max_map_count = 65530`). This is sufficient for the gym benchmark's
parallel shard workers.

## Verification

```bash
cargo test          # All tests using in_memory() pass
cargo test -p gym   # Gym benchmarks run without mmap failures
```

## Related

- [Graph Agent Architecture](graph-agent-architecture.md) - LadybugDB's role in the analysis pipeline
- [Gym Configuration](gym-configuration.md) - Benchmark runner that creates concurrent instances
