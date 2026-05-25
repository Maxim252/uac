#!/bin/sh
# Helper to run different container collection scenarios

set -e
cd "$(dirname "$0")/../.."

echo "=== Scenario 1: Normal collection with mocks ==="
PATH="tests/containers/mock_bin:$PATH" \
UAC_COLLECT_CONTAINERS=1 \
bash -c '
    # Minimal environment
    __UAC_TEMP_DATA_DIR="/tmp/uac-scenario-1-$$"
    mkdir -p "$__UAC_TEMP_DATA_DIR/collected"
    . lib/command_exists.sh
    # ... (in real use you would source the full function)
    echo "Would run collect_containers here with mocked docker/podman"
    rm -rf "$__UAC_TEMP_DATA_DIR"
'

echo
echo "=== Scenario 2: Large container export protection ==="
echo "UAC_CONTAINER_EXPORT_MAX_SIZE_MB=10 would skip large exports"

echo
echo "=== Scenario 3: Force specific runtime ==="
echo 'UAC_CONTAINER_RUNTIMES="docker" ...'

echo
echo "Done. Extend this script with real calls once function is in lib/."
