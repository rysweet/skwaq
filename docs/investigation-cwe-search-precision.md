# Investigation: CWE Search Precision After KG Expansion

**Date**: 2026-04-02
**PR**: #446
**Issues**: Follow-up to #423 (CWE KG expansion) and #432 (LadybugDB flock)

## Summary

After expanding the CWE knowledge graph from 145 to 944 entries (PR #434), two regressions were discovered in the KB search system:

1. **CWE ID prefix collision**: Searching for `cwe-119` also matched CWE-1190, CWE-1191, CWE-1192, CWE-1193 because the LIKE query used `%cwe-119%` patterns
2. **Source crowding**: With 944 CWEs, broad queries returned only CWE entries in the top-5 results, crowding out knowledge-pack results entirely

## Root Cause

### Prefix collision
`search_cwes()` used `LIKE '%term%'` for all search terms including CWE identifiers. With 145 entries, no CWE ID was a prefix of another. With 944 entries, CWE-119 is a prefix of CWE-119x entries.

### Source crowding
`search_knowledge_with_dir()` sorted all results by score and truncated to `KB_SEARCH_LIMIT=5`. CWE entries had higher relevance scores than knowledge-pack markdown files for CWE-related queries, so the top 5 were always CWEs.

## Fix

1. **Exact CWE ID matching**: When a search term matches `cwe-NNN` pattern, use `lower(cwe_id) = ?` instead of `LIKE`. Non-ID terms still use fuzzy matching.
2. **Source diversity**: Guarantee at least one result per source type before filling remaining slots by score.

## Verification

- All 929 workspace tests pass (0 failures)
- `test_overfitting_knowledge_context_deduplicates_repeated_cwes` — now passes
- `test_kb_search_json_returns_cwe_and_pack_results` — now passes (was pre-existing failure)
- Clippy clean, cargo fmt clean

## Status of Original Tasks

Both tasks from the original request were already complete:

| Task | Status | PR |
|------|--------|-----|
| LadybugDB flock serialization (Issue #432) | Merged | #434, #438, #443 |
| CWE KG expansion to 944 entries (Issue #423) | Merged | #434 |
| CWE search precision regressions | Fixed | #446 |
