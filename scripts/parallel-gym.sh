#!/usr/bin/env bash
# parallel-gym.sh — Run gym benchmarks across N parallel processes.
#
# Each process handles a slice of cases using --skip and --max-cases.
# Results are written to separate JSON files, then merged.
#
# Usage:
#   ./scripts/parallel-gym.sh <suite> [total_cases] <num_procs> [extra_args...]
#
# Examples:
#   # 10 processes across the full Juliet manifest
#   ./scripts/parallel-gym.sh juliet 10
#
#   # 5 processes across the full OWASP manifest with concurrency 4
#   ./scripts/parallel-gym.sh owasp 5 -j 4
#
#   # Quick mode (pattern only), 10 procs, explicit temporary override
#   SKWAQ_SUITE_CASES_JULIET=1000 ./scripts/parallel-gym.sh juliet 10 --quick

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
# shellcheck source=lib/suite_cases.sh
source "$SCRIPT_DIR/lib/suite_cases.sh"

SUITE="${1:?Usage: parallel-gym.sh <suite> [total_cases] <num_procs> [extra_args...]}"
shift

if [[ $# -ge 2 && "$1" =~ ^[0-9]+$ && "$2" =~ ^[0-9]+$ ]]; then
    TOTAL="$1"
    NPROCS="$2"
    shift 2
else
    NPROCS="${1:?Specify num_procs}"
    TOTAL="$(get_suite_cases "$REPO_ROOT" "$SUITE")"
    shift
fi

validate_suite_case_count "$TOTAL" "total_cases" || exit 1
validate_suite_case_count "$NPROCS" "num_procs" || exit 1
EXTRA_ARGS=("$@")

CASES_PER_PROC=$(( (TOTAL + NPROCS - 1) / NPROCS ))  # ceiling division
SKWAQ="${SKWAQ:-./target/release/skwaq}"
OUTDIR=$(mktemp -d /tmp/gym-parallel-${SUITE}-XXXXXX)

echo "=== Parallel Gym Run ==="
echo "Suite:      $SUITE"
echo "Total:      $TOTAL cases"
echo "Processes:  $NPROCS"
echo "Per proc:   $CASES_PER_PROC cases (last shard may be smaller)"
echo "Binary:     $SKWAQ"
echo "Output:     $OUTDIR"
echo "Extra args: ${EXTRA_ARGS[*]}"
echo ""

# Verify binary exists
if [ ! -f "$SKWAQ" ]; then
    echo "Building release binary..."
    cargo build --release
fi

# Launch N processes with non-overlapping shard ranges.
# Each shard gets exactly [SKIP, SKIP+COUNT) where COUNT is capped so the
# last shard never extends beyond TOTAL, preventing double-counting.
PIDS=()
ASSIGNED=0
for i in $(seq 0 $((NPROCS - 1))); do
    SKIP=$ASSIGNED
    REMAINING=$((TOTAL - ASSIGNED))

    # Cap this shard's size so it never exceeds the remaining cases
    if [ "$REMAINING" -le 0 ]; then
        echo "  Process $i: skipped (no remaining cases)"
        continue
    fi
    COUNT=$CASES_PER_PROC
    if [ "$COUNT" -gt "$REMAINING" ]; then
        COUNT=$REMAINING
    fi
    ASSIGNED=$((ASSIGNED + COUNT))

    LOG="$OUTDIR/proc-${i}.log"
    JSON="$OUTDIR/proc-${i}.json"

    echo "  Process $i: skip=$SKIP count=$COUNT -> $LOG"

    "$SKWAQ" gym run "$SUITE" \
        --skip "$SKIP" \
        --max-cases "$COUNT" \
        --json "$JSON" \
        "${EXTRA_ARGS[@]}" \
        > "$LOG" 2>&1 &

    PIDS+=($!)
done

echo ""
echo "Waiting for $NPROCS processes..."

# Wait and collect exit codes
FAILURES=0
for i in "${!PIDS[@]}"; do
    if wait "${PIDS[$i]}"; then
        echo "  Process $i: done"
    else
        echo "  Process $i: FAILED (exit $?)"
        FAILURES=$((FAILURES + 1))
    fi
done

echo ""
echo "=== Results ==="

# Show individual results
for i in $(seq 0 $((NPROCS - 1))); do
    LOG="$OUTDIR/proc-${i}.log"
    echo "--- Process $i ---"
    grep -E "F1|Precision|Recall|TP:|FP:|FN:" "$LOG" 2>/dev/null || echo "  (no results)"
done

# Merge JSON results if jq is available
if command -v jq &>/dev/null; then
    echo ""
    echo "--- Merged Summary ---"
    # Sum TP/FP/FN across all process results
    TP=$(jq -s '[.[].true_positives // 0] | add' "$OUTDIR"/proc-*.json 2>/dev/null || echo 0)
    FP=$(jq -s '[.[].false_positives // 0] | add' "$OUTDIR"/proc-*.json 2>/dev/null || echo 0)
    FN=$(jq -s '[.[].false_negatives // 0] | add' "$OUTDIR"/proc-*.json 2>/dev/null || echo 0)
    TN=$(jq -s '[.[].true_negatives // 0] | add' "$OUTDIR"/proc-*.json 2>/dev/null || echo 0)

    if [ "$TP" != "0" ] || [ "$FP" != "0" ] || [ "$FN" != "0" ]; then
        PREC=$(echo "scale=3; $TP / ($TP + $FP + 0.001)" | bc 2>/dev/null || echo "?")
        REC=$(echo "scale=3; $TP / ($TP + $FN + 0.001)" | bc 2>/dev/null || echo "?")
        echo "  TP=$TP  FP=$FP  FN=$FN  TN=$TN"
        echo "  Precision: $PREC"
        echo "  Recall:    $REC"
    fi
fi

echo ""
echo "Logs: $OUTDIR/"
[ $FAILURES -gt 0 ] && echo "WARNING: $FAILURES processes failed" && exit 1
exit 0
