# Сбор артефактов контейнеров (CRIU hot copy)

**Модуль:** `lib_collect_containers.sh`  
**Механизм:** Только CRIU checkpoint (полный отказ от legacy export/commit/save).  
**Поддержка:** podman (полная), containerd (хорошая), docker (базовая, experimental с предупреждением).  
**Интеграция:** Совместим с Security Monitor.

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
| `snapshot/checkpoint.tar.gz` | CRIU checkpoint (горячее копирование). Основной артефакт состояния. Для podman — готов к `podman container restore --import`. | running only | — |
| `snapshot/checkpoint_info.txt` | Метод сбора, флаги, статус, предупреждения (для docker — обязательно "EXPERIMENTAL") | running only | — |
| `snapshot/checkpoint_manifest.txt` | Перечень реально созданных checkpoint-артефактов | — | ✓ |
| `snapshot/checkpoint_skipped.txt` | Причина пропуска (контейнер не running / CRIU недоступен / лимит размера / UAC_CONTAINER_CHECKPOINT=0) | — | ✓ |
| `cgroup.txt`, `namespaces.txt`, `cmdline`, `environ`, `status` | Host-side информация через nsenter | ✓ | — |

### Поддержка горячего копирования

**Жёсткое требование:** legacy команды (`export`, `commit`, `save` и аналоги ctr) не используются никогда.

Горячее копирование (CRIU checkpoint с `--leave-running` по умолчанию) — единственный механизм снимков состояния.

**Уровни поддержки:**

| Runtime          | Уровень     | Реализация                                      | Примечание |
|------------------|-------------|-------------------------------------------------|------------|
| podman           | Полная (№1) | `podman container checkpoint --leave-running --export=...` | Восстанавливаемый tar. |
| containerd/nerdctl/crictl | Хорошая    | `ctr checkpoint` + прямой `criu dump`           | Best-effort. |
| docker           | Базовая     | `docker checkpoint create` (экспериментально)   | Обязательное предупреждение "EXPERIMENTAL" в `checkpoint_info.txt`. |

**Артефакты в `snapshot/` (running-контейнеры):**
- `checkpoint.tar.gz`
- `checkpoint_info.txt` (метод, статус, предупреждения)
- `checkpoint_manifest.txt`

**Для stopped:** `checkpoint_skipped.txt` + host overlay layers (собираются на уровне runtime).

**Переменные окружения:**
- `UAC_CONTAINER_CHECKPOINT=1` (по умолчанию)
- `UAC_CONTAINER_CHECKPOINT_MAX_SIZE_MB=0`
- `UAC_CONTAINER_CHECKPOINT_LEAVE_RUNNING=1`

Пример:
```bash
UAC_CONTAINER_CHECKPOINT=0 ./uac -p full /mnt/evidence
```

### Fallback через nsenter

Для запущенных контейнеров, когда exec внутрь невозможен или ограничен, используется `nsenter` для получения информации из `/proc` хоста (см. раздел 2.4 в DATA_REFERENCE).

---

## 3. Переменные окружения

| Переменная | По умолчанию | Описание |
|------------|--------------|----------|
| `UAC_COLLECT_CONTAINERS` | `1` | Включить/выключить расширенный сбор контейнеров |
| `UAC_CONTAINER_RUNTIMES` | `docker podman nerdctl crictl` | Список рантаймов для проверки |
| `UAC_CONTAINER_EXEC_TIMEOUT` | `5` | Таймаут для команд внутри контейнера (сек) |
| `UAC_CONTAINER_CHECKPOINT_MAX_SIZE_MB` | `0` | Пропуск CRIU checkpoint, если контейнер больше лимита в MB (0 = без лимита). Старое имя UAC_CONTAINER_EXPORT_MAX_SIZE_MB тоже читается для обратной совместимости |
| `UAC_CONTAINER_CHECKPOINT_LEAVE_RUNNING` | `1` | Не останавливать контейнер после checkpoint (рекомендуется) |

Пример:
```bash
UAC_CONTAINER_RUNTIMES="docker podman" \
UAC_CONTAINER_CHECKPOINT_MAX_SIZE_MB=500 \
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
│   ├── criu_version.txt
│   ├── journal_docker.log
│   ├── overlay2_layers.txt
│   └── <container_name>_<container_id>/
│       ├── inspect.json
│       ├── config.json
│       ├── hostconfig.json
│       ├── suspicious_config.txt
│       ├── logs.txt
│       └── snapshot/
│           ├── checkpoint.tar.gz       # CRIU hot copy (podman native / docker exp / direct)
│           ├── checkpoint_info.txt     # method, status, warnings (for docker: EXPERIMENTAL)
│           ├── checkpoint_manifest.txt
│           └── checkpoint_skipped.txt  # for stopped containers or when disabled
├── podman/
└── nerdctl/
```

**Полное описание каждого файла, его значения и forensic-ценности** — см. отдельный справочник: [CONTAINER_DATA_REFERENCE.md](CONTAINER_DATA_REFERENCE.md).

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

- CRIU checkpoint (hot copy) работает **только для running** контейнеров. Для stopped создаётся маркер `checkpoint_skipped.txt`.
- Docker: только experimental путь (требует явного предупреждения в артефактах и логе).
- Прямой criu dump (fallback) — best-effort; на реальных контейнерах с сетью, unix sockets, cgroupsv2 и т.д. может потребовать дополнительных флагов ядра / CRIU.
- Для восстановления checkpoint'ов (podman container restore --import) — ответственность оператора; UAC только собирает.
- nsenter требует прав root и наличия утилиты в PATH.
- Некоторые рантаймы (crictl) поддерживаются через fallback'и.
- При очень большом количестве контейнеров сбор может занять значительное время + checkpoint'ы весят много (память + ФС).

## 9. История изменений (2026)

- Переход на CRIU hot copy как единственный механизм снимков состояния контейнеров.
- Полный отказ от legacy export/commit/save.
- Введены уровни поддержки и новые артефакты (см. выше).
- Обновлены моки, тесты и документация.

---

## 10. Связанные файлы и артефакты

- `lib_collect_containers.sh`
- `artifacts/live_response/containers/` (декларативная часть)
- `security/security_monitor.sh` (интеграция)
- `tests/containers/` (моки и тесты)
- `docs/SECURITY_MONITOR.md`

---

*Документ обновлён под новую модель сбора контейнеров (CRIU hot copy, полный отказ от legacy) — 2026.*