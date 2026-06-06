# Расширенный сбор артефактов из контейнеров

**Модуль:** `lib_collect_containers.sh`  
**Версия:** Улучшенная (двойной метод снимков контейнеров: export + commit+save, поддержка остановленных контейнеров, nsenter, глубокий анализ конфигурации)  
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
| `snapshot/filesystem.tar` | Полный filesystem export (method 1: `export`, плоский rootfs) | — | ✓ (если возможно) |
| `snapshot/image.tar` | Образ контейнера через commit+save (method 2, слои + diff-слой) | — | ✓ (если возможно) |
| `snapshot/snapshot_manifest.txt` | Манифест (список реально созданных snapshot-файлов) | — | ✓ |
| `cgroup.txt`, `namespaces.txt`, `cmdline`, `environ`, `status` | Host-side информация через nsenter | ✓ | — |

### 2.3 Особенности для остановленных контейнеров

- Два метода получения snapshot'а контейнера:
  - Method 1: `docker export` / `podman export` → `snapshot/filesystem.tar` (плоский tar rootfs)
  - Method 2 (дополнительный): `commit` + `save` → `snapshot/image.tar` (полноценный образ с слоями и diff-слоем контейнера)
- Сохранение manifest'а (`snapshot_manifest.txt`)
- Сбор исторических логов

### 2.4 Два метода получения снимков контейнера (export vs commit + save)

**Мотивация**

Оригинальный метод `export` (и его аналоги в podman/nerdctl) создаёт плоский tar-архив текущего состояния файловой системы контейнера. Это просто «слепок корневой ФС» на момент сбора. У такого подхода есть существенные недостатки:

- **Неэффективность по размеру** — весь filesystem выгружается целиком, без переиспользования слоёв базового образа.
- **Потеря forensic-информации** — теряется история слоёв, метаданные образа, diff между базовым образом и изменениями, внесёнными в контейнере.
- При больших образах и большом количестве контейнеров это приводит к избыточному размеру итогового архива UAC.

**Решение (дополнительный метод)**

Добавлен второй метод на базе `commit` + `save`:

1. `docker commit <container> <temp-image>` — создаёт новый образ из текущего состояния контейнера (все изменения контейнера сохраняются в виде нового слоя поверх существующей истории образа).
2. `docker save <temp-image> -o snapshot/image.tar` — сохраняет образ в стандартном формате Docker image tar (слои + манифест + конфигурация).
3. `docker rmi -f <temp-image>` — обязательная очистка временного образа (чтобы не засорять систему сборщика).

**Сравнение методов**

| Характеристика                  | `filesystem.tar` (export)          | `image.tar` (commit + save)                          |
|--------------------------------|------------------------------------|-----------------------------------------------------|
| Формат                         | Плоский tar rootfs                 | Полноценный Docker/OCI image tar                    |
| Размер                         | Обычно больше (всё «расплющивается») | Часто меньше (переиспользуются слои базового образа) |
| Сохранение слоёв / истории     | Нет                                | Да                                                  |
| Метаданные образа (labels, config, entrypoint и т.д.) | Частично (только то, что есть в ФС) | Полностью                                           |
| Возможность `docker load`      | Нет                                | Да                                                  |
| Forensic-ценность              | Базовая (только текущие файлы)     | Высокая (видны изменения относительно базового образа) |
| Поддержка runtime              | docker, podman, nerdctl, crictl    | docker, podman, nerdctl (crictl — не поддерживается) |
| Очистка временных объектов     | Не требуется                       | Обязательный `rmi` временного образа                |

**Рекомендации**

- По умолчанию включены **оба** метода (`UAC_CONTAINER_IMAGE_SNAPSHOT=1`).
- Для большинства forensic-задач предпочтительнее `image.tar` (method 2).
- `filesystem.tar` оставлен для совместимости и для случаев, когда нужен именно «сырой» вид файловой системы без слоёв.
- Ограничение размера (`UAC_CONTAINER_EXPORT_MAX_SIZE_MB`) применяется одновременно к обоим методам.

**Пример отключения второго метода**

```bash
UAC_CONTAINER_IMAGE_SNAPSHOT=0 ./uac -p full /mnt/evidence
```

### 2.5 Fallback через nsenter

Для запущенных контейнеров, когда exec внутрь невозможен или ограничен, используется `nsenter` для получения информации из `/proc` хоста.

---

## 3. Переменные окружения

| Переменная | По умолчанию | Описание |
|------------|--------------|----------|
| `UAC_COLLECT_CONTAINERS` | `1` | Включить/выключить расширенный сбор контейнеров |
| `UAC_CONTAINER_RUNTIMES` | `docker podman nerdctl crictl` | Список рантаймов для проверки |
| `UAC_CONTAINER_EXEC_TIMEOUT` | `5` | Таймаут для команд внутри контейнера (сек) |
| `UAC_CONTAINER_EXPORT_MAX_SIZE_MB` | `0` | Пропуск обоих snapshot-методов, если контейнер больше лимита в MB (0 = без лимита) |
| `UAC_CONTAINER_IMAGE_SNAPSHOT` | `1` | Включить 2-й метод снимка через `commit` + `save` (`snapshot/image.tar`). 0 — отключить |

Пример:
```bash
UAC_CONTAINER_RUNTIMES="docker podman" \
UAC_CONTAINER_EXPORT_MAX_SIZE_MB=500 \
UAC_CONTAINER_IMAGE_SNAPSHOT=1 \
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
│           ├── filesystem.tar          # method 1 (export)
│           ├── image.tar               # method 2 (commit+save) — рекомендуется для forensics
│           └── snapshot_manifest.txt   # перечень реально созданных файлов
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

- Snapshot'ы (и export, и commit+save) работают для stopped и running контейнеров.
- `commit` + `save` (method 2) не поддерживается для crictl (только docker/podman/nerdctl).
- После `commit` сборщик всегда выполняет `rmi -f` временного образа (чтобы не засорять систему сборщика).
- nsenter требует прав root и наличия утилиты в PATH.
- Некоторые рантаймы (crictl) поддерживаются ограниченно.
- При очень большом количестве контейнеров сбор может занять значительное время.

## 9. История доработок модуля (2026)

### Двойной метод снимков контейнера
- Реализован дополнительный метод получения образа контейнера через `commit` + `save` (`snapshot/image.tar`).
- `export` сохранён как method 1 (`snapshot/filesystem.tar`) для совместимости.
- Добавлена переменная окружения `UAC_CONTAINER_IMAGE_SNAPSHOT` (по умолчанию `1`).
- Лимит размера (`UAC_CONTAINER_EXPORT_MAX_SIZE_MB`) теперь применяется к обоим методам.
- Обновлены все моки, тесты и документация.
- **Мотивация**: классический `export` неэффективен (создаёт плоский tar без переиспользования слоёв) и теряет важную forensic-информацию (история слоёв, метаданные образа, точный diff контейнера).

### Стабильность
- Исправлена ошибка `__cc_pid: parameter not set`, возникавшая при наличии `XDG_RUNTIME_DIR` в окружении или при имени контейнера, содержащем "rootless".
  - PID теперь запрашивается сразу после определения имени контейнера.
  - Доступ к `uid_map` / `gid_map` выполняется только при наличии валидного PID > 0.

---

## 10. Связанные файлы и артефакты

- `lib_collect_containers.sh`
- `artifacts/live_response/containers/` (декларативная часть)
- `security/security_monitor.sh` (интеграция)
- `tests/containers/` (моки и тесты)
- `docs/SECURITY_MONITOR.md`

---

*Документ создан в рамках подготовки к защите ВКР (2026).*