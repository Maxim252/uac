#!/bin/sh
# Manual test runner for the improved collect_containers() function
#
# This script:
# - Creates a temporary UAC-like environment
# - Mocks docker/podman using the scripts in mock_runtimes/
# - Sources the necessary parts of UAC
# - Calls collect_containers()
# - Validates the output structure and key variables

set -e

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
PROJECT_ROOT=$(cd "$SCRIPT_DIR/../.." && pwd)
TEST_TMP_DIR=$(mktemp -d /tmp/uac-container-test-XXXXXX)

echo "=== UAC Container Collection Manual Test ==="
echo "Project root : $PROJECT_ROOT"
echo "Test temp dir: $TEST_TMP_DIR"
echo

# Cleanup on exit
cleanup() {
    rm -rf "$TEST_TMP_DIR"
}
trap cleanup EXIT

# --- Prepare minimal UAC environment ---
mkdir -p "$TEST_TMP_DIR/collected/containers"
mkdir -p "$TEST_TMP_DIR/bin"

# Create a minimal log file so _log_msg doesn't fail
touch "$TEST_TMP_DIR/uac.log"

# Copy command_exists (we need it)
cp "$PROJECT_ROOT/lib/command_exists.sh" "$TEST_TMP_DIR/bin/"

# Source minimal dependencies
. "$TEST_TMP_DIR/bin/command_exists.sh"

# Define minimal stubs that the container function expects from UAC
__UAC_TEMP_DATA_DIR="$TEST_TMP_DIR"
__UAC_DIR="$PROJECT_ROOT"
__UAC_LOG_FILE="uac.log"

_log_msg() {
    level="${1:-INF}"
    msg="${2:-}"
    echo "[LOG $level] $msg" >> "$TEST_TMP_DIR/uac.log"
}

_verbose_msg() {
    echo "[VERBOSE] $*" >&2
}

# Source the improved collect_containers function from the main script
# We extract only the relevant functions to avoid loading the entire uac
extract_and_source_collect_containers() {
    # Extract the collect_containers function + helper from the main uac script
    awk '
        /^collect_containers\(\)/ { in_func=1 }
        in_func { print }
        in_func && /^}/ { in_func=0; exit }
    ' "$PROJECT_ROOT/uac" > "$TEST_TMP_DIR/collect_containers.sh"

    awk '
        /^_collect_container_exec\(\)/ { in_func=1 }
        in_func { print }
        in_func && /^}/ { in_func=0; exit }
    ' "$PROJECT_ROOT/uac" >> "$TEST_TMP_DIR/collect_containers.sh"

    . "$TEST_TMP_DIR/collect_containers.sh"
}

echo "[1/5] Extracting collect_containers() from uac script..."
extract_and_source_collect_containers

# --- Setup Mocks ---
echo "[2/5] Setting up container runtime mocks..."

MOCK_BIN="$SCRIPT_DIR/mock_bin"
export PATH="$MOCK_BIN:$PATH"

# Verify mocks are in PATH and work
echo "   Which docker: $(command -v docker || echo 'NOT FOUND')"
echo "   Testing mock docker..."
docker ps -aq || true

# --- Test Execution ---
echo "[3/5] Running collect_containers() with mocks..."

# Reset globals
__UAC_CONTAINER_COUNT=0
__UAC_CONTAINER_SUMMARY=""

# Run the function
collect_containers

echo
echo "[4/5] Test Results:"
echo "   __UAC_CONTAINER_COUNT   = $__UAC_CONTAINER_COUNT"
echo "   __UAC_CONTAINER_SUMMARY = $__UAC_CONTAINER_SUMMARY"
echo

# --- Validation ---
echo "[5/5] Validating output structure..."

ERRORS=0

check_file() {
    if [ -f "$1" ]; then
        echo "   ✓ $2"
    else
        echo "   ✗ MISSING: $2"
        ERRORS=$((ERRORS + 1))
    fi
}

# Check that containers directory was created
CONTAINER_BASE="$TEST_TMP_DIR/collected/containers/docker"

if [ -d "$CONTAINER_BASE" ]; then
    echo "   ✓ containers/docker/ directory created"
else
    echo "   ✗ containers/docker/ directory MISSING"
    ERRORS=$((ERRORS + 1))
fi

# Check specific containers (from our mock)
check_file "$CONTAINER_BASE/web_abc123def456/inspect.json"          "inspect.json for running container"
check_file "$CONTAINER_BASE/web_abc123def456/snapshot/filesystem.tar" "filesystem.tar for running container"
check_file "$CONTAINER_BASE/web_abc123def456/ps.txt"                "ps.txt for running container"
check_file "$CONTAINER_BASE/stopped-box_7890stopped001/inspect.json" "inspect.json for stopped container"
check_file "$CONTAINER_BASE/stopped-box_7890stopped001/inside_skipped.txt" "inside_skipped marker for stopped container"

# Check summary variables
if [ "$__UAC_CONTAINER_COUNT" -ge 1 ]; then
    echo "   ✓ Container count is reasonable ($_UAC_CONTAINER_COUNT)"
else
    echo "   ✗ Container count too low: $__UAC_CONTAINER_COUNT"
    ERRORS=$((ERRORS + 1))
fi

if echo "$__UAC_CONTAINER_SUMMARY" | grep -q "docker"; then
    echo "   ✓ Summary mentions docker runtime"
else
    echo "   ✗ Summary does not mention runtime"
    ERRORS=$((ERRORS + 1))
fi

echo
if [ "$ERRORS" -eq 0 ]; then
    echo "=== ALL CHECKS PASSED ==="
    exit 0
else
    echo "=== $ERRORS CHECK(S) FAILED ==="
    echo
    echo "Log output:"
    cat "$TEST_TMP_DIR/uac.log" || true
    exit 1
fi
