# UAC Tests — Security Monitor & Container Collection

This test suite validates the major features we built and hardened:

- **Enhanced Container Collection** (multi-runtime, deep forensics, stopped containers, nsenter)
- **Security Monitor** (authorization on every command, tamper protection via signatures, detailed auditing)

## Strong Focus on Negative Testing

We deliberately added many **negative test cases**:
- Whitelist tampering detection (profiles + binaries)
- Invalid/missing signatures
- Dangerous command patterns
- Monitor + container collection under tampered policy conditions
- Audit log behavior and integrity

## Directory Layout

```
tests/
├── functional/
│   ├── containers/
│   │   ├── test_container_collection.sh
│   │   └── test_deep_container_artifacts.sh
│   └── security_monitor/
│       ├── test_monitor_core.sh
│       ├── test_whitelist_tampering.sh          ← Negative
│       ├── test_audit_logging.sh
│       └── test_dangerous_command_logging.sh    ← Negative
├── integration/
│   ├── test_monitor_with_containers.sh
│   └── test_monitor_containers_with_mocks.sh    ← Strong integration + many negative cases (uses existing mocks)
├── mocks/          (shared with old container tests)
└── README.md
```

## Recommended Run Order

```bash
chmod +x tests/functional/**/*.sh tests/integration/*.sh tests/run_vkr_tests.sh

# Самый удобный способ для ВКР — запустить один скрипт:
./tests/run_vkr_tests.sh
# Он запустит все важные тесты монитора + контейнеров,
# сохранит ПОЛНЫЙ вывод в /tmp/uac_vkr_full_*.log
# и в конце напишет, где лежат все артефакты и логи.

# Или запускать вручную по отдельности:
bash tests/functional/security_monitor/test_security_monitor_comprehensive.sh
bash tests/integration/test_containers_with_security_monitor.sh
```

### Для ВКР (рекомендуется)

Используйте `./tests/run_vkr_tests.sh` — он:
- Сохраняет вывод **всех** тестов монитора в один файл `/tmp/uac_vkr_full_YYYYMMDD_HHMMSS.log`
- В конце печатает подробную сводку со всеми путями к собранным данным, audit-логам и временным каталогам.

These tests are designed to be runnable with or without real container runtimes (thanks to the existing mock infrastructure in `tests/containers/mock_runtimes/`).