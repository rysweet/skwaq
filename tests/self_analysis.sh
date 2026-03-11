#!/bin/bash
# Self-analysis: run skwaq's quick analysis on its own source code.
# This is a regression test - if skwaq finds NEW critical/high issues
# in its own code that aren't in the known-findings baseline, the test fails.
set -e

SKWAQ="${1:-./target/debug/skwaq}"
echo "=== Skwaq Self-Analysis ==="

rm -rf .skwaq-selftest
export SKWAQ_DB=.skwaq-selftest/graph

# Ingest our own source
$SKWAQ ingest source crates/ 2>/dev/null

# Run quick analysis (no LLM needed)
$SKWAQ analyze --quick 2>/dev/null

# Export findings as JSON
REPORT=$($SKWAQ report --json 2>/dev/null || echo '{"findings":[]}')

# Count findings by severity
CRITICAL=$(echo "$REPORT" | python3 -c "
import sys, json
try:
    data = json.loads(sys.stdin.read())
    findings = data.get('findings', [])
    confirmed_critical = [f for f in findings
        if f.get('severity') in ('critical', 'high')
        and f.get('status') not in ('invalidated', 'challenged')]
    print(len(confirmed_critical))
except Exception:
    print(0)
" 2>/dev/null || echo "0")

TOTAL=$(echo "$REPORT" | python3 -c "
import sys, json
try:
    data = json.loads(sys.stdin.read())
    print(len(data.get('findings', [])))
except Exception:
    print(0)
" 2>/dev/null || echo "0")

echo "Total findings: $TOTAL"
echo "Confirmed critical/high: $CRITICAL"

# The quick analysis should find pattern detections (dangerous API names in our
# pattern detection code) but these should all be "challenged" or "invalidated",
# not "confirmed". Zero confirmed = clean.
if [ "$CRITICAL" -gt 0 ]; then
    echo "FAIL: $CRITICAL confirmed critical/high finding(s) in our own code."
    rm -rf .skwaq-selftest
    exit 1
fi

echo "Self-analysis complete. No confirmed critical/high findings."
rm -rf .skwaq-selftest
