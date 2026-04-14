#!/usr/bin/env python3
"""Workstream launcher - Rust recipe runner execution."""
import sys
import json
import logging
from pathlib import Path

repo_root = Path(__file__).resolve().parent
src_path = repo_root / "src"
if src_path.exists():
    sys.path.insert(0, str(src_path))

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)

try:
    from amplihack.recipes import run_recipe_by_name
except ImportError:
    print("ERROR: amplihack package not importable. Falling back to classic mode.")
    sys.exit(2)

user_context = json.loads("{\"task_description\": \"Add integration tests for the PoC system. At minimum: one happy-path prove test that exercises the full flow (disagree \\u2192 prove \\u2192 adjudicate) to catch C1/H2/M4. Place tests in crates/gym/tests/ or as #[cfg(test)] modules. Verify cargo test and cargo clippy pass. Create feature branch and PR.\", \"repo_path\": \".\", \"issue_number\": 482, \"workstream_state_file\": \"/tmp/amplihack-workstreams/state/ws-482.json\", \"workstream_progress_file\": \"/tmp/amplihack-workstreams/state/ws-482.progress.json\"}")
result = run_recipe_by_name(
    "default-workflow",
    user_context=user_context,
    progress=True,
)

print()
print("=" * 60)
print("RECIPE EXECUTION RESULTS")
print("=" * 60)
for sr in result.step_results:
    print(f"  [{sr.status.value:>9}] {sr.step_id}")
print(f"\nOverall: {'SUCCESS' if result.success else 'FAILED'}")
sys.exit(0 if result.success else 1)
