#!/bin/bash
# Run the full workspace test suite and report summary
# Usage: ./docs/qa/tools/run-full-test-suite.sh

set -euo pipefail

WORKSPACE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
cd "$WORKSPACE_ROOT"

echo "=== GAP Full Test Suite ==="
echo "Workspace: $WORKSPACE_ROOT"
echo ""

# Run all tests, capture output
OUTPUT=$(cargo test --workspace 2>&1)
EXIT_CODE=$?

# Extract summary lines
echo "$OUTPUT" | grep -E "^test result:" | while read -r line; do
    echo "  $line"
done

echo ""

# Report ignored tests
IGNORED=$(echo "$OUTPUT" | grep "ignored" | grep -v "0 ignored" || true)
if [ -n "$IGNORED" ]; then
    echo "Ignored tests:"
    echo "$OUTPUT" | grep -B0 "... ignored" | while read -r line; do
        echo "  $line"
    done
    echo ""
fi

# Report overall status
if [ $EXIT_CODE -eq 0 ]; then
    TOTAL_PASSED=$(echo "$OUTPUT" | grep -E "^test result:" | grep -oE "[0-9]+ passed" | awk '{sum += $1} END {print sum}')
    TOTAL_IGNORED=$(echo "$OUTPUT" | grep -E "^test result:" | grep -oE "[0-9]+ ignored" | awk '{sum += $1} END {print sum}')
    echo "PASS: $TOTAL_PASSED tests passed, $TOTAL_IGNORED ignored"
else
    echo "FAIL: Some tests failed"
    echo "$OUTPUT" | grep -E "^test .* FAILED" || true
fi

exit $EXIT_CODE
