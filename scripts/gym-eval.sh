#!/usr/bin/env bash
# gym-eval.sh — Full evaluation pipeline: parallel run → monitor → collect → report.
#
# Single command that runs all benchmarks in parallel, monitors progress,
# collects results, and generates a summary report.
#
# Usage:
#   ./scripts/gym-eval.sh [--quick] [--procs N] [--concurrency N] [--suites "juliet,owasp,..."]
#
# Examples:
#   # Full hybrid eval across all suites (default)
#   ./scripts/gym-eval.sh
#
#   # Quick pattern-only eval
#   ./scripts/gym-eval.sh --quick
#
#   # Custom parallelism
#   ./scripts/gym-eval.sh --procs 5 --concurrency 2
#
#   # Specific suites only
#   ./scripts/gym-eval.sh --suites "juliet,owasp"

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
# shellcheck source=lib/suite_cases.sh
source "$SCRIPT_DIR/lib/suite_cases.sh"

# Defaults
PROCS=5
CONCURRENCY=2  # Conservative to avoid API rate limits
QUICK=""
SUITES="juliet,owasp,cyberseceval,cgc"
SKWAQ="${SKWAQ:-./target/release/skwaq}"
MONITOR_INTERVAL=30

# Parse args
while [[ $# -gt 0 ]]; do
    case $1 in
        --quick) QUICK="--quick"; CONCURRENCY=1; shift ;;
        --procs) PROCS="$2"; shift 2 ;;
        --concurrency|-j) CONCURRENCY="$2"; shift 2 ;;
        --suites) SUITES="$2"; shift 2 ;;
        --help|-h)
            echo "Usage: gym-eval.sh [--quick] [--procs N] [--concurrency N] [--suites 'suite1,suite2']"
            echo ""
            echo "Options:"
            echo "  --quick          Pattern-only mode (no LLM agents)"
            echo "  --procs N        Number of parallel processes per suite (default: 5)"
            echo "  --concurrency N  In-process async concurrency (default: 2)"
            echo "  --suites S       Comma-separated suite list (default: juliet,owasp,cyberseceval,cgc)"
            exit 0 ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

EVAL_DIR=$(mktemp -d /tmp/gym-eval-XXXXXX)

echo "╔══════════════════════════════════════════════════╗"
echo "║           SKWAQ GYM EVALUATION                  ║"
echo "╠══════════════════════════════════════════════════╣"
echo "║  Mode:        $([ -n "${QUICK:+$QUICK}" ] && echo "Pattern-only (quick)" || echo "Hybrid (LLM + Pattern)")            ║"
echo "║  Processes:   $PROCS per suite                          ║"
echo "║  Concurrency: $CONCURRENCY per process                        ║"
echo "║  Output:      $EVAL_DIR  ║"
echo "╚══════════════════════════════════════════════════╝"
echo ""

# Build if needed
if [ ! -f "$SKWAQ" ]; then
    echo "[build] Building release binary..."
    cargo build --release 2>&1 | tail -1
fi

IFS=',' read -ra SUITE_LIST <<< "$SUITES"
declare -A SUITE_CASES
for suite in "${SUITE_LIST[@]}"; do
    suite="${suite// /}"
    [ -z "$suite" ] && continue
    SUITE_CASES["$suite"]="$(get_suite_cases "$REPO_ROOT" "$suite")"
done

# Always run fixtures sequentially.
echo "[fixtures] Running fixtures..."
"$SKWAQ" gym run fixtures ${QUICK:+$QUICK} -j 1 \
    --json "$EVAL_DIR/fixtures.json" \
    > "$EVAL_DIR/fixtures.log" 2>&1
echo "[fixtures] Done"
grep -E "F1|Precision|Recall" "$EVAL_DIR/fixtures.log" | head -3

# Launch parallel runs for each suite
declare -A SUITE_PIDS
declare -A SUITE_DIRS

for suite in "${SUITE_LIST[@]}"; do
    suite="${suite// /}"
    [ "$suite" = "fixtures" ] && continue  # Already ran

    total=${SUITE_CASES[$suite]}
    cases_per=$(( (total + PROCS - 1) / PROCS ))
    suite_dir="$EVAL_DIR/$suite"
    mkdir -p "$suite_dir"

    echo ""
    echo "[$suite] Launching $PROCS processes ($total cases, $cases_per each)..."

    pids=()
    for i in $(seq 0 $((PROCS - 1))); do
        skip=$((i * cases_per))
        "$SKWAQ" gym run "$suite" \
            --skip "$skip" \
            --max-cases "$cases_per" \
            -j "$CONCURRENCY" \
            ${QUICK:+$QUICK} \
            --json "$suite_dir/shard-${i}.json" \
            > "$suite_dir/shard-${i}.log" 2>&1 &
        pids+=($!)
    done

    SUITE_PIDS[$suite]="${pids[*]}"
    SUITE_DIRS[$suite]="$suite_dir"
done

# Monitor loop
echo ""
echo "═══ Monitoring Progress ═══"

all_done=false
while ! $all_done; do
    sleep "$MONITOR_INTERVAL"
    all_done=true

    echo ""
    echo "--- $(date +%H:%M:%S) ---"
    for suite in "${SUITE_LIST[@]}"; do
        suite="${suite// /}"
        [ "$suite" = "fixtures" ] && continue
        dir="${SUITE_DIRS[$suite]}"

        running=0
        completed_cases=0
        for pid in ${SUITE_PIDS[$suite]}; do
            if kill -0 "$pid" 2>/dev/null; then
                running=$((running + 1))
                all_done=false
            fi
        done

        # Count completed agents across all shards
        for shard_log in "$dir"/shard-*.log; do
            agents=$(grep -c "Agent.*completed.*tokens" "$shard_log" 2>/dev/null || echo 0)
            completed_cases=$((completed_cases + agents / 5))
        done

        retries=$(grep -c "Retrying request" "$dir"/shard-*.log 2>/dev/null || echo 0)
        total=${SUITE_CASES[$suite]}
        pct=$((completed_cases * 100 / (total + 1)))

        echo "  $suite: $completed_cases/$total cases ($pct%) | $running procs running | $retries retries"
    done
done

# Collect results
echo ""
echo "═══ Collecting Results ═══"

SUMMARY="$EVAL_DIR/summary.md"
cat > "$SUMMARY" << 'HEADER'
# Gym Evaluation Results

| Suite | F1 | Precision | Recall | TP | FP | FN | TN | Cases |
|-------|-----|-----------|--------|-----|-----|-----|-----|-------|
HEADER

# Add fixtures
if [ -f "$EVAL_DIR/fixtures.json" ]; then
    f1=$(grep "F1" "$EVAL_DIR/fixtures.log" | head -1 | grep -oE '[0-9.]+' | head -1)
    prec=$(grep "Precision" "$EVAL_DIR/fixtures.log" | head -1 | grep -oE '[0-9.]+' | head -1)
    rec=$(grep "Recall" "$EVAL_DIR/fixtures.log" | head -1 | grep -oE '[0-9.]+' | head -1)
    echo "| Fixtures | ${f1}% | ${prec}% | ${rec}% | - | - | - | - | ${SUITE_CASES[fixtures]} |" >> "$SUMMARY"
fi

for suite in "${SUITE_LIST[@]}"; do
    suite="${suite// /}"
    [ "$suite" = "fixtures" ] && continue
    dir="${SUITE_DIRS[$suite]}"

    # Collect per-shard results
    total_tp=0; total_fp=0; total_fn=0; total_tn=0
    for shard_log in "$dir"/shard-*.log; do
        tp=$(grep "TP:" "$shard_log" 2>/dev/null | grep -oE 'TP: [0-9]+' | head -1 | grep -oE '[0-9]+' || echo 0)
        fp=$(grep "FP:" "$shard_log" 2>/dev/null | grep -oE 'FP: [0-9]+' | head -1 | grep -oE '[0-9]+' || echo 0)
        fn=$(grep "FN:" "$shard_log" 2>/dev/null | grep -oE 'FN: [0-9]+' | head -1 | grep -oE '[0-9]+' || echo 0)
        tn=$(grep "TN:" "$shard_log" 2>/dev/null | grep -oE 'TN: [0-9]+' | head -1 | grep -oE '[0-9]+' || echo 0)
        total_tp=$((total_tp + tp))
        total_fp=$((total_fp + fp))
        total_fn=$((total_fn + fn))
        total_tn=$((total_tn + tn))
    done

    cases=$((total_tp + total_fp + total_fn + total_tn))
    if [ $((total_tp + total_fp)) -gt 0 ]; then
        prec=$(echo "scale=1; $total_tp * 100 / ($total_tp + $total_fp)" | bc)
    else
        prec="0.0"
    fi
    if [ $((total_tp + total_fn)) -gt 0 ]; then
        rec=$(echo "scale=1; $total_tp * 100 / ($total_tp + $total_fn)" | bc)
    else
        rec="0.0"
    fi
    if [ "$(echo "$prec + $rec" | bc)" != "0" ] 2>/dev/null; then
        f1=$(echo "scale=1; 2 * $prec * $rec / ($prec + $rec)" | bc)
    else
        f1="0.0"
    fi

    echo "| $suite | ${f1}% | ${prec}% | ${rec}% | $total_tp | $total_fp | $total_fn | $total_tn | $cases |" >> "$SUMMARY"

    echo "[$suite] TP=$total_tp FP=$total_fp FN=$total_fn TN=$total_tn P=${prec}% R=${rec}% F1=${f1}%"
done

echo ""
echo "═══ Summary ═══"
cat "$SUMMARY"
echo ""
echo "Full results: $EVAL_DIR/"
echo "Summary: $SUMMARY"
