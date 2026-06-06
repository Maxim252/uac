# Manual / Legacy Tests for Container Collection

> **Внимание:** Эти тесты являются устаревшими (legacy/manual).  
> Для актуального тестирования используйте:
> - `tests/functional/containers/`
> - `tests/integration/test_containers_with_security_monitor.sh`
> - `./tests/run_vkr_tests.sh` (рекомендуется для ВКР)

Этот каталог содержит старые ручные тесты и моки для отладки `lib_collect_containers.sh`.

## Моки (актуальны)

Моки в `mock_bin/` и `mock_runtimes/` до сих пор активно используются в современных интеграционных тестах.

## Рекомендация

Для разработки и защиты ВКР используйте централизованный раннер:

```bash
./tests/run_vkr_tests.sh
```

## Test Scenarios Included (legacy)
| `test_collect_containers.sh` | Main test runner with PATH mocking |
| `mock_runtimes/mock_docker.sh` | Fake `docker` that simulates 2 containers (1 running, 1 stopped) |
| `mock_runtimes/mock_podman.sh` | Example for podman (extend as needed) |

## What the Tests Verify

- Function executes without crashing
- Correct directory structure is created under `collected/containers/`
- Metadata (`inspect.json`, `logs.txt`) is written
- Snapshot logic (export + commit+save image.tar) works (or is skipped when configured)
- Inside-container collection vs "not running" handling
- nsenter fallback path (simulated)
- Environment variable configuration (`UAC_CONTAINER_RUNTIMES`, size limits, etc.)
- Proper population of `__UAC_CONTAINER_COUNT` and `__UAC_CONTAINER_SUMMARY`

## Extending the Mocks

The mock scripts are simple shell scripts that respond to specific `docker` subcommands:
- `docker ps -aq`
- `docker inspect ...`
- `docker export ...`
- `docker commit ...`, `docker save -o ...`, `docker rmi ...` (for the 2nd image snapshot method)
- `docker logs ...`

You can extend them to test edge cases:
- Very large containers (trigger `UAC_CONTAINER_EXPORT_MAX_SIZE_MB`)
- Containers without `ps` / `ss` inside
- Failed `export`
- Failed `commit` / `save` (image method)
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
