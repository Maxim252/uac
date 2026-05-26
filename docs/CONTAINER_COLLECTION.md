# Расширенный сбор артефактов из контейнеров

**Модуль:** `lib_collect_containers.sh`  
**Версия:** Улучшенная (с поддержкой остановленных контейнеров, nsenter, глубокого анализа конфигурации)  
**Интеграция:** Полностью совместим с Монитором безопасности UAC

---

## 1. Назначение

Стандартные артефакты в `artifacts/live_response/containers/` дают базовую информацию. Расширенный сборщик (`_collect_containers`) обеспечивает **глубокий forensic-сбор** из container runtimes:

- docker
- podman
- nerdctl
- crictl (частично)

Модуль **дополняет**, а не заменяет декларативные артефакты.

---

## 2. Основные возможности

### 2.1 Runtime-level артефакты

Для каждого обнаруженного runtime собираются:

- `info.txt`, `version.txt`
- `system_df_v.txt` (подробная информация о storage)
- Журналы systemd (`journalctl -u docker/podman/containerd/buildkit`)
- Файловые логи из `/var/log/docker*`, `/var/log/containers/`
- Специфичные для storage артефакты (overlay2 listing, build cache и т.д.)

### 2.2 Per-container артефакты

Для каждого контейнера (running + stopped):

| Артефакт | Описание | running | stopped |
|----------|----------|---------|---------|
| `inspect.json` | Полная мета-информация | ✓ | ✓ |
| `config.json` / `hostconfig.json` | Конфигурация | ✓ | ✓ |
| `suspicious_config.txt` | Выделенные индикаторы риска (privileged, hostPid, capabilities, seccomp=unconfined и т.д.) | ✓ | ✓ |
| `logs.txt` | Логи контейнера (`docker logs --since 24h`) | ✓ | частично |
| `snapshot/filesystem.tar` | Полный filesystem export | — | ✓ (если возможно) |
| `snapshot/snapshot_manifest.txt` | Манифест экспорта | — | ✓ |
| `cgroup.txt`, `namespaces.txt`, `cmdline`, `environ`, `status` | Host-side информация через nsenter | ✓ | — |

### 2.3 Особенности для остановленных контейнеров

- Автоматический filesystem export через `docker export` / `podman export`
- Сохранение manifest'а
- Сбор исторических логов

### 2.4 Fallback через nsenter

Для запущенных контейнеров, когда exec внутрь невозможен или ограничен, используется `nsenter` для получения информации из `/proc` хоста.

---

## 3. Переменные окружения

| Переменная | По умолчанию | Описание |
|------------|--------------|----------|
| `UAC_COLLECT_CONTAINERS` | `1` | Включить/выключить расширенный сбор контейнеров |
| `UAC_CONTAINER_RUNTIMES` | `docker podman nerdctl crictl` | Список рантаймов для проверки |
| `UAC_CONTAINER_EXEC_TIMEOUT` | `5` | Таймаут для команд внутри контейнера (сек) |
| `UAC_CONTAINER_EXPORT_MAX_SIZE_MB` | `0` | Максимальный размер контейнера для filesystem export (0 = без ограничений) |

Пример:
```bash
UAC_CONTAINER_RUNTIMES="docker podman" \
UAC_CONTAINER_EXPORT_MAX_SIZE_MB=500 \
./uac -p ir_triage /mnt/evidence
```

---

## 4. Интеграция с Монитором безопасности

При включённом Security Monitor (`UAC_SECURITY_MONITOR=1`):

- Монитор инициализируется **до** вызова `_collect_containers`
- Проверяется целостность активного профиля
- Критические операции (особенно `execute_binary` для `avml`, `timeout.sh` и т.д.) проходят через `_sm_authorize`
- Все события контейнерного сбора могут логироваться в `uac_security_monitor_audit.log`
- Механизм tamper detection работает даже во время глубокого анализа контейнеров

**Известное ограничение:** Часть команд (`docker inspect`, `podman logs`) в текущей версии `lib_collect_containers.sh` выполняется напрямую. Они частично покрываются через основной `command_collector`, но не все пути проходят через `_sm_authorize`. Это учтено в тестах.

Подробно о мониторе — в [SECURITY_MONITOR.md](SECURITY_MONITOR.md).

---

## 5. Собираемые артефакты (примеры структуры)

```
collected/containers/
├── docker/
│   ├── info.txt
│   ├── version.txt
│   ├── system_df_v.txt
│   ├── journal_docker.log
│   ├── overlay2_layers.txt
│   └── <container_name>_<container_id>/
│       ├── inspect.json
│       ├── config.json
│       ├── hostconfig.json
│       ├── suspicious_config.txt
│       ├── logs.txt
│       └── snapshot/
│           ├── filesystem.tar
│           └── snapshot_manifest.txt
├── podman/
└── nerdctl/
```

---

## 6. Тестирование

### 6.1 Моки

В `tests/containers/` находятся качественные моки:
- `mock_bin/docker`, `mock_bin/podman`
- `mock_runtimes/mock_docker.sh`, `mock_podman.sh`

Они позволяют детерминированно тестировать сбор без реальных контейнеров.

### 6.2 Автоматизированные тесты

- `tests/functional/containers/test_deep_container_artifacts.sh`
- `tests/integration/test_containers_with_security_monitor.sh` (включая работу с Монитором)
- `tests/run_vkr_tests.sh` — рекомендуемый способ для ВКР

---

## 7. Рекомендации по использованию

### Для обычного сбора
```bash
./uac -p full /mnt/evidence
```
(Контейнеры соберутся автоматически)

### Для фокуса только на контейнерах (быстрый сбор)
```bash
UAC_COLLECT_CONTAINERS=1 \
UAC_CONTAINER_RUNTIMES="docker podman" \
./uac -a "live_response/containers/*.yaml" -f none /tmp/containers-only
```

### Для ВКР / демонстрации
```bash
./tests/run_vkr_tests.sh
```
Скрипт покажет реальные артефакты + аудит монитора.

---

## 8. Ограничения

- Filesystem export возможен в основном для stopped-контейнеров.
- nsenter требует прав root и наличия утилиты в PATH.
- Некоторые рантаймы (crictl) поддерживаются ограниченно.
- При очень большом количестве контейнеров сбор может занять значительное время.

---

## 9. Связанные файлы и артефакты

- `lib_collect_containers.sh`
- `artifacts/live_response/containers/` (декларативная часть)
- `security/security_monitor.sh` (интеграция)
- `tests/containers/` (моки и тесты)
- `docs/SECURITY_MONITOR.md`

---

*Документ создан в рамках подготовки к защите ВКР (2026).*