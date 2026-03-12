#!/usr/bin/env bash
# parallel-gym.sh — Run gym benchmarks across N parallel processes.
#
# Each process handles a slice of cases using --skip and --max-cases.
# Results are written to separate JSON files, then merged.
#
# Usage:
#   ./scripts/parallel-gym.sh <suite> <total_cases> <num_procs> [extra_args...]
#
# Examples:
#   # 10 processes, 500 cases each for Juliet
#   ./scripts/parallel-gym.sh juliet 5000 10
#
#   # 5 processes, 100 cases each for OWASP with concurrency 4
#   ./scripts/parallel-gym.sh owasp 500 5 -j 4
#
#   # Quick mode (pattern only), 10 procs
#   ./scripts/parallel-gym.sh juliet 5000 10 --quick

set -euo pipefail

SUITE="${1:?Usage: parallel-gym.sh <suite> <total_cases> <num_procs> [extra_args...]}"
TOTAL="${2:?Specify total cases}"
NPROCS="${3:?Specify number of processes}"
shift 3
EXTRA_ARGS=("$@")

CASES_PER_PROC=$(( (TOTAL + NPROCS - 1) / NPROCS ))  # ceiling division
SKWAQ="${SKWAQ:-./target/release/skwaq}"
OUTDIR=$(mktemp -d /tmp/gym-parallel-${SUITE}-XXXXXX)

echo "=== Parallel Gym Run ==="
echo "Suite:      $SUITE"
echo "Total:      $TOTAL cases"
echo "Processes:  $NPROCS"
echo "Per proc:   $CASES_PER_PROC cases"
echo "Binary:     $SKWAQ"
echo "Output:     $OUTDIR"
echo "Extra args: ${EXTRA_ARGS[*]}"
echo ""

# Verify binary exists
if [ ! -f "$SKWAQ" ]; then
    echo "Building release binary..."
    cargo build --release
fi

# Launch N processes
PIDS=()
for i in $(seq 0 $((NPROCS - 1))); do
    SKIP=$((i * CASES_PER_PROC))
    LOG="$OUTDIR/proc-${i}.log"
    JSON="$OUTDIR/proc-${i}.json"

    echo "  Process $i: skip=$SKIP max=$CASES_PER_PROC -> $LOG"

    "$SKWAQ" gym run "$SUITE" \
        --skip "$SKIP" \
        --max-cases "$CASES_PER_PROC" \
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
