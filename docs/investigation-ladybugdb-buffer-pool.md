# Investigation: LadybugDB Buffer Pool for In-Memory Instances

**Issue:** #437
**Status:** Fixed (PR #438 merged)
**Date:** 2026-04-02

## Problem

`LadybugGraphDb::in_memory()` used `SystemConfig::default()` which auto-detects
system resources, allocating ~200GB virtual address space and 32 threads per
instance. When running gym benchmarks with many concurrent cases, this exhausted
the system's virtual memory map limit (`vm.max_map_count`).

## Root Cause

LadybugDB's `SystemConfig::default()` is designed for production single-instance
use. For temporary per-test/per-case instances, the defaults are vastly
oversized.

## Fix

In `crates/core/src/graph/ladybug_db.rs`, the `in_memory()` constructor now
configures:

- `buffer_pool_size(64 * 1024 * 1024)` - 64MB instead of auto-detected ~200GB
- `max_num_threads(1)` - single thread instead of 32

## Impact

- Per-instance virtual address space: ~204GB -> ~4GB (50x reduction)
- Concurrent instance capacity: ~3 -> ~96 within default system limits
- No impact on production `open()` or `open_read_only()` paths
- No schema or data format changes
