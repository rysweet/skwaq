#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
run_dir="$(mktemp -d "$repo_root/.tmp-gym-eval-shard-profile-XXXXXX")"
temp_home="$(mktemp -d)"
temp_out="$(mktemp -d)"

cleanup() {
  rm -rf "$run_dir" "$temp_home" "$temp_out"
}

trap cleanup EXIT

mkdir -p "$run_dir/.skwaq" "$temp_home/.skwaq/profiles/azure"

cat >"$run_dir/.skwaq/config.toml" <<'EOF'
[llm]
reasoning = "copilot"
decompilation = "copilot"
EOF

cat >"$temp_home/.skwaq/profiles/azure/config.toml" <<'EOF'
[llm]
reasoning = "azure"
decompilation = "azure"

[llm.azure]
endpoint = "https://example.cognitiveservices.azure.com/"
deployment = "gpt-54-test"
api_version = "2024-10-21"
EOF

cd "$run_dir"
HOME="$temp_home" "$repo_root/target/debug/skwaq" gym eval \
  --quick \
  --suites fixtures \
  --max-cases 20 \
  --procs 2 \
  -j 2 \
  --profile azure \
  --output "$temp_out" >"$temp_out/cmd.log" 2>&1 &
parent_pid=$!

shard_pids=""
for _ in $(seq 1 100); do
  if ! kill -0 "$parent_pid" 2>/dev/null; then
    break
  fi
  shard_pids="$(
    ps -eo pid=,args= \
      | grep "$repo_root/target/debug/skwaq gym run fixtures" \
      | grep -- "--shard-total" \
      | grep -v grep \
      | awk '{print $1}' \
      || true
  )"
  if [[ -n "$shard_pids" ]]; then
    break
  fi
  sleep 0.1
done

if [[ -z "$shard_pids" ]]; then
  echo "failed to observe shard subprocesses"
  echo "=== command.log ==="
  cat "$temp_out/cmd.log"
  exit 1
fi

echo "=== observed shard processes ==="
for pid in $shard_pids; do
  cwd="$(readlink -f "/proc/$pid/cwd")"
  cmdline="$(tr '\0' ' ' <"/proc/$pid/cmdline")"
  echo "PID: $pid"
  echo "CWD: $cwd"
  echo "CMD: $cmdline"

  [[ "$cwd" == "$repo_root" ]]
  [[ "$cmdline" == *"--profile azure"* ]]
done

wait "$parent_pid"

echo
echo "=== command.log ==="
cat "$temp_out/cmd.log"
echo
echo "=== metadata.json ==="
jq '{llm_backend, profile, procs_per_suite, concurrency}' "$temp_out/metadata.json"
jq -e '.llm_backend == "azure" and .profile == "azure"' "$temp_out/metadata.json" >/dev/null
