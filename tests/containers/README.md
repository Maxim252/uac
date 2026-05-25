# Manual Tests for Enhanced Container Collection

This directory contains manual test scenarios for the improved `collect_containers()` function in UAC.

## Why Manual Tests?

The `collect_containers()` function is complex because it:
- Interacts with external container runtimes (docker, podman, etc.)
- Uses `nsenter` (requires privileges)
- Performs filesystem exports
- Has multiple fallback paths

Full automation is difficult without real containers or heavy mocking.

## Quick Start

```bash
cd /home/admib/uac

# Recommended: Run the improved self-contained smoke test
bash tests/containers/test_collect_containers_v2.sh

# Alternative (may have extraction issues):
# bash tests/containers/test_collect_containers.sh
```

## Test Scenarios Included

| File | Purpose |
|------|---------|
| `test_collect_containers.sh` | Main test runner with PATH mocking |
| `mock_runtimes/mock_docker.sh` | Fake `docker` that simulates 2 containers (1 running, 1 stopped) |
| `mock_runtimes/mock_podman.sh` | Example for podman (extend as needed) |

## What the Tests Verify

- Function executes without crashing
- Correct directory structure is created under `collected/containers/`
- Metadata (`inspect.json`, `logs.txt`) is written
- Snapshot export logic works (or is skipped when configured)
- Inside-container collection vs "not running" handling
- nsenter fallback path (simulated)
- Environment variable configuration (`UAC_CONTAINER_RUNTIMES`, size limits, etc.)
- Proper population of `__UAC_CONTAINER_COUNT` and `__UAC_CONTAINER_SUMMARY`

## Extending the Mocks

The mock scripts are simple shell scripts that respond to specific `docker` subcommands:
- `docker ps -aq`
- `docker inspect ...`
- `docker export ...`
- `docker logs ...`

You can extend them to test edge cases:
- Very large containers (trigger `UAC_CONTAINER_EXPORT_MAX_SIZE_MB`)
- Containers without `ps` / `ss` inside
- Failed `export`
- Missing `nsenter`

## Running Against Real Docker (Advanced)

```bash
# WARNING: This will actually collect from your containers
UAC_COLLECT_CONTAINERS=1 ./uac -p ir_triage --output-format none /tmp/uac-test-real
```

Then inspect:
```bash
find /tmp/uac-test-real/uac-data.tmp/collected/containers -type f | head -30
```

## Future Improvements

- [ ] Add BATS (Bash Automated Testing System) tests
- [ ] Create a more advanced mock framework
- [ ] Add assertions on output files content
- [ ] CI integration (GitHub Actions) with Docker-in-Docker
