#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
cd "$repo_root"

version="$(
  awk '
    $0 == "name = \"crossbeam-epoch\"" { in_pkg = 1; next }
    in_pkg && $1 == "version" {
      gsub(/"/, "", $3)
      print $3
      exit
    }
  ' Cargo.lock
)"

if [[ "$version" != "0.9.20" ]]; then
  echo "crossbeam-epoch version: ${version:-missing}"
  echo "expected crossbeam-epoch version: 0.9.20"
  exit 1
fi

echo "crossbeam-epoch version: $version"

deny_log="$(mktemp)"
trap 'rm -f "$deny_log"' EXIT

set +e
cargo deny check advisories >"$deny_log" 2>&1
deny_status=$?
set -e

if grep -Eq 'ID: RUSTSEC-2026-0204|advisories/RUSTSEC-2026-0204' "$deny_log"; then
  echo "RUSTSEC-2026-0204: present"
  sed -n '/RUSTSEC-2026-0204/,+20p' "$deny_log"
  exit 1
fi

echo "RUSTSEC-2026-0204: absent"

if (( deny_status != 0 )); then
  echo "unrelated advisories: out of scope"
else
  echo "unrelated advisories: none reported"
fi
