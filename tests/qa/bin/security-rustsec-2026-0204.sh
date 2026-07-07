#!/usr/bin/env bash
set -euo pipefail

# Verifies the fix for RUSTSEC-2026-0204 (invalid pointer dereference in
# crossbeam-epoch's fmt::Pointer impl). The advisory is patched in >= 0.9.20.
#
# Two independent checks:
#   1. Cargo.lock pins crossbeam-epoch to a patched version (>= 0.9.20).
#   2. cargo audit no longer reports RUSTSEC-2026-0204.

repo_root="${SKWAQ_REPO_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)}"
cd "$repo_root"

echo "=== security check: RUSTSEC-2026-0204 (crossbeam-epoch) ==="

# --- Check 1: Cargo.lock pins a patched crossbeam-epoch version ---------------
# Extract the version string that immediately follows the crossbeam-epoch
# package stanza in Cargo.lock.
locked_version="$(
  awk '
    /^name = "crossbeam-epoch"$/ { in_pkg = 1; next }
    in_pkg && /^version = "/ {
      match($0, /"[^"]+"/)
      print substr($0, RSTART + 1, RLENGTH - 2)
      exit
    }
  ' Cargo.lock
)"

if [[ -z "$locked_version" ]]; then
  echo "crossbeam-epoch version check ... FAIL (package not found in Cargo.lock)"
  exit 1
fi

# Semver >= 0.9.20 comparison using sort -V (patch line is 0.9.x).
min_patched="0.9.20"
lowest="$(printf '%s\n%s\n' "$locked_version" "$min_patched" | sort -V | head -n1)"
if [[ "$lowest" != "$min_patched" && "$locked_version" != "$min_patched" ]]; then
  echo "crossbeam-epoch version check ... FAIL (locked $locked_version < $min_patched)"
  exit 1
fi

echo "crossbeam-epoch version check ... OK (locked $locked_version >= $min_patched)"

# --- Check 2: cargo audit no longer reports RUSTSEC-2026-0204 -----------------
# cargo audit exits non-zero when *any* advisory is present, and other
# out-of-scope advisories may exist in the tree, so we assert on the specific
# advisory id rather than the exit code. We must never silently "pass" when the
# audit did not actually run (no-silent-degradation), so we require cargo-audit
# to be present and verify the run produced real audit output.
if ! cargo audit --version >/dev/null 2>&1; then
  echo "cargo audit check ......... FAIL (cargo-audit is not installed; cannot verify)"
  exit 1
fi

audit_output="$(cargo audit 2>&1 || true)"

if ! grep -qi "Scanning Cargo.lock" <<<"$audit_output"; then
  echo "cargo audit check ......... FAIL (audit did not scan Cargo.lock)"
  echo "--- cargo audit output ---"
  echo "$audit_output"
  exit 1
fi

if grep -q "RUSTSEC-2026-0204" <<<"$audit_output"; then
  echo "cargo audit check ......... FAIL (RUSTSEC-2026-0204 still reported)"
  echo "--- cargo audit output ---"
  grep -A2 "RUSTSEC-2026-0204" <<<"$audit_output" || true
  exit 1
fi

echo "cargo audit check ......... OK (RUSTSEC-2026-0204 not reported)"
echo "All RUSTSEC-2026-0204 security checks passed."
